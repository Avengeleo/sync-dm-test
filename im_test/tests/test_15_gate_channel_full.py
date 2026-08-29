"""版本兼容门 · 渠道分档 —— 群/超级群在线 + 离线链路覆盖。

test_14 只覆盖了「单聊在线」这一条路径,但门控代码有 7 个调用点:
  在线 3 处:im-gateway WS 转发 / TCP 转发 / DLQ 重投
  离线 4 处:msg-srv(单聊)、group-srv(群,含会话列表)、channel-pull-server(超级群)
本文件补齐「群/超级群在线」与「离线拉取」两类,确保渠道参数在每条路径都真的传到了。

离线门控读的是 **Redis 里登录时写入的 channel_type / app_version**,
所以模拟方式同在线:先用目标「版本+渠道」登录一次刷新 Redis,断开后走 HTTP 拉。

前置同 test_14(代码已部署 + 18 行渠道配置已入库)。
群/超级群用例还需 IM_GROUP_ID / IM_CHANNEL_ID,且该账号是其成员。
"""

import time
import uuid

import pytest
import requests

from im_test.client import (
    ImWsClient, NON_ERR,
    GROUP_REACTION_DELIVER, RADIO_REACTION_DELIVER,
    SINGLE_REACTION_DELIVER, SINGLE_DELIVER,
)
from im_test.http_offline import OfflineHttpClient
from im_test.tests.test_14_gate_channel import (
    CH_IOS_LISTING, CH_IOS_OVERSIGN,
    VER_LISTING_OK, VER_OVERSIGN_OLD,
    _receiver,
)


@pytest.fixture
def group_id(im_config):
    gid = im_config.get("group_id")
    if not gid:
        pytest.skip("未配置 IM_GROUP_ID,跳过群用例")
    return int(gid)


@pytest.fixture
def channel_id(im_config):
    cid = im_config.get("channel_id")
    if not cid:
        pytest.skip("未配置 IM_CHANNEL_ID,跳过超级群用例")
    return int(cid)


# ══════════════════════════════════════════════════════════════════
# 群 / 超级群 在线(另外两个被门控的 cmd)
# ══════════════════════════════════════════════════════════════════

@pytest.mark.write
def test_group_reaction_listing_receives(im_config, logged_in_client, group_id):
    """群回应 0x2314:上架包 1.5.4 应能收到。"""
    b = _receiver(im_config, VER_LISTING_OK, CH_IOS_LISTING)
    try:
        r = logged_in_client.send_group_reaction(group_id, parent_msg_id=uuid.uuid4().hex)
        assert r["errcode"] == NON_ERR
        try:
            b.recv_deliver(GROUP_REACTION_DELIVER)
        except Exception as e:
            raise AssertionError(
                f"上架包 1.5.4 应收到群回应 0x2314({type(e).__name__});"
                f"收不到=群链路(group-srv/网关)的渠道参数没传到") from None
    finally:
        b.close()


@pytest.mark.write
def test_group_reaction_old_oversign_blocked(im_config, logged_in_client, group_id):
    """群回应 0x2314:老超签 2.21.2 仍应被拦。"""
    b = _receiver(im_config, VER_OVERSIGN_OLD, CH_IOS_OVERSIGN)
    try:
        r = logged_in_client.send_group_reaction(group_id, parent_msg_id=uuid.uuid4().hex)
        assert r["errcode"] == NON_ERR
        assert b.expect_no_deliver(GROUP_REACTION_DELIVER), \
            "老超签 2.21.2 不应收到群回应;收到了=群链路门槛被降成上架档"
    finally:
        b.close()


@pytest.mark.write
def test_channel_reaction_listing_receives(im_config, logged_in_client, channel_id):
    """超级群回应 0x3213:上架包 1.5.4 应能收到。"""
    b = _receiver(im_config, VER_LISTING_OK, CH_IOS_LISTING)
    try:
        r = logged_in_client.send_channel_reaction(channel_id, parent_msg_id=uuid.uuid4().hex)
        assert r["errcode"] == NON_ERR
        try:
            b.recv_deliver(RADIO_REACTION_DELIVER)
        except Exception as e:
            raise AssertionError(
                f"上架包 1.5.4 应收到超级群回应 0x3213({type(e).__name__});"
                f"收不到=超级群链路的渠道参数没传到") from None
    finally:
        b.close()


@pytest.mark.write
def test_channel_reaction_old_oversign_blocked(im_config, logged_in_client, channel_id):
    """超级群回应 0x3213:老超签 2.21.2 仍应被拦。"""
    b = _receiver(im_config, VER_OVERSIGN_OLD, CH_IOS_OVERSIGN)
    try:
        r = logged_in_client.send_channel_reaction(channel_id, parent_msg_id=uuid.uuid4().hex)
        assert r["errcode"] == NON_ERR
        assert b.expect_no_deliver(RADIO_REACTION_DELIVER), \
            "老超签 2.21.2 不应收到超级群回应;收到了=超级群链路门槛被降成上架档"
    finally:
        b.close()


# ══════════════════════════════════════════════════════════════════
# 离线链路(msg-srv Mongo 查询条件层过滤)
# ══════════════════════════════════════════════════════════════════

OFFLINE_CLIENT_TYPE = 0  # App 端作为离线端


def _offline_http_as(im_config, app_version, channel_type):
    """用指定「版本+渠道」登录一次刷新 Redis,断开后返回离线 HTTP 客户端。"""
    base = im_config.get("http_base")
    if not base:
        pytest.skip("未配置 IM_HTTP_BASE_URL,跳过离线用例")
    c = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type_b"], im_config["timeout"],
                   app_version=app_version, channel_type=channel_type)
    try:
        c.connect()
    except Exception as e:
        pytest.skip(f"登录连接失败:{e}")
    if (err := c.login()) != NON_ERR:
        c.close()
        pytest.skip(f"登录失败 nErr=0x{err:04x}")
    c.close()  # 断开=离线,但 Redis 里 app_version/channel_type 已是目标值
    return OfflineHttpClient(base, im_config["token"], im_config["user_id"],
                             im_config["http_timeout"])


def _pull_single(http, tries=3):
    rows = []
    for _ in range(tries):
        try:
            code, batch = http.offline_chat(client_type=OFFLINE_CLIENT_TYPE, limit=100)
        except requests.exceptions.RequestException:
            continue
        assert code == 200, f"离线拉取 HTTP {code}"
        rows.extend(batch)
        if not batch:
            break
    return rows


def _wait_row(http, msg_id, timeout=45):
    deadline = time.time() + timeout
    last = []
    while time.time() < deadline:
        try:
            code, rows = http.offline_chat(client_type=OFFLINE_CLIENT_TYPE, limit=100)
        except requests.exceptions.RequestException:
            continue
        assert code == 200, f"离线拉取 HTTP {code}"
        last = rows
        if hit := next((r for r in rows if r["msg_id"] == msg_id), None):
            return hit, rows
        time.sleep(0.6)
    return None, last


@pytest.mark.write
def test_offline_listing_gets_reaction(im_config, logged_in_client):
    """【离线链路核心】上架包 1.5.4 离线拉取应能拿到心情回应行。

    这是 msg-srv 的 Mongo 查询条件层过滤(与在线是完全不同的代码路径),
    渠道参数若没传到,回应行会被 filter 掉 → 本用例红。
    """
    a = logged_in_client
    react = a.send_reaction(to_id=a.user_id, parent_msg_id=uuid.uuid4().hex)
    assert react["errcode"] == NON_ERR

    http = _offline_http_as(im_config, VER_LISTING_OK, CH_IOS_LISTING)
    hit, _ = _wait_row(http, react["sent_msg_id"])
    assert hit is not None, (
        "上架包 1.5.4 离线应能拉到回应行;拉不到=离线过滤仍在用超签门槛判上架包")
    assert hit["cmd_id"] == SINGLE_REACTION_DELIVER


@pytest.mark.write
def test_offline_old_oversign_excluded_but_not_starved(im_config, logged_in_client):
    """【离线链路】老超签 2.21.2 离线拉取:回应行被排除,但普通消息照常拿得到。

    后半句是反饿死校验——被排除的行不能占 limit、不能卡游标。
    """
    a = logged_in_client
    react = a.send_reaction(to_id=a.user_id, parent_msg_id=uuid.uuid4().hex)
    assert react["errcode"] == NON_ERR
    normal = a.send_chat(to_id=a.user_id, content="[selftest] ch-off-" + uuid.uuid4().hex[:8])
    assert normal["errcode"] == NON_ERR

    http = _offline_http_as(im_config, VER_OVERSIGN_OLD, CH_IOS_OVERSIGN)
    hit, rows = _wait_row(http, normal["sent_msg_id"])
    assert hit is not None, "普通消息应能拉到(证明拉取链路本身可用,且未被过滤行饿死)"
    assert hit["cmd_id"] == SINGLE_DELIVER
    assert not any(r["msg_id"] == react["sent_msg_id"] for r in rows), \
        "老超签 2.21.2 不应拉到回应行;拉到了=离线门槛被降成上架档"
    assert all(r["cmd_id"] != SINGLE_REACTION_DELIVER for r in rows), \
        "结果中不应出现任何回应行"


@pytest.mark.write
def test_offline_upgrade_backfill_across_channel(im_config, logged_in_client):
    """被渠道门排除的回应行,换成达标身份后应能补拉到(证明没被误标已拉取)。

    老超签阶段排除的行,换上架包 1.5.4 身份(同样达标)后必须还在,
    否则就是消息永久丢失 —— 比"暂时看不到"严重得多。
    """
    a = logged_in_client
    react = a.send_reaction(to_id=a.user_id, parent_msg_id=uuid.uuid4().hex)
    assert react["errcode"] == NON_ERR

    # ① 老超签身份拉一轮:应拉不到
    time.sleep(2)
    http_old = _offline_http_as(im_config, VER_OVERSIGN_OLD, CH_IOS_OVERSIGN)
    rows = _pull_single(http_old)
    assert not any(r["msg_id"] == react["sent_msg_id"] for r in rows), "老超签阶段不应拉到回应"

    # ② 换上架包达标身份:应能补到
    http_new = _offline_http_as(im_config, VER_LISTING_OK, CH_IOS_LISTING)
    hit, _ = _wait_row(http_new, react["sent_msg_id"])
    assert hit is not None, (
        "换达标身份后应能补拉到之前被排除的回应;拉不到=被排除的行被误标已拉取(消息永久丢失)")
    assert hit["cmd_id"] == SINGLE_REACTION_DELIVER
