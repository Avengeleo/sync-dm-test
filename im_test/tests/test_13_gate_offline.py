"""版本兼容门②离线:老版本客户端拉离线拉不到回应,普通消息完整,且**不被饿死**。

门控实现:各服务在 Mongo 查询条件层排除回应行(不是响应层丢行),见设计文档 §7。
最关键的两条安全保证在这里守住:
  1. 反饿死:被排除的行不占 limit、不推进游标 → 老版本仍能拉到普通消息(test_old_not_starved)
  2. 升级补拉:被排除的行未被标记已拉取 → 换新版本重登后能补看(test_upgrade_backfill)

前置:门控代码已部署;IM_OLD_APP_VERSION < 门槛 <= IM_NEW_APP_VERSION;App 端(clientType_b)当前离线。
"""

import time
import uuid

import pytest
import requests

from im_test.client import (
    ImWsClient, NON_ERR,
    SINGLE_DELIVER, SINGLE_REACTION_DELIVER,
)

OFFLINE_CLIENT_TYPE = 0  # App 端作为离线端


def _pull_all(http, tries=3):
    """拉几轮离线单聊,返回累计行(容忍冷调用超时)。"""
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


def _wait_rows(http, msg_id, timeout=45):
    """轮询到出现目标 msg_id 为止;返回 (命中行 or None, 最后一次全量行)。"""
    deadline = time.time() + timeout
    last = []
    while time.time() < deadline:
        try:
            code, rows = http.offline_chat(client_type=OFFLINE_CLIENT_TYPE, limit=100)
        except requests.exceptions.RequestException:
            continue
        assert code == 200, f"离线拉取 HTTP {code}"
        last = rows
        hit = next((r for r in rows if r["msg_id"] == msg_id), None)
        if hit:
            return hit, rows
        time.sleep(0.6)
    return None, last


@pytest.mark.write
def test_old_client_offline_excludes_reaction(logged_in_client, old_version_offline_http):
    """老版本身份拉单聊离线:普通消息拿得到,回应行被排除。"""
    a = logged_in_client
    react = a.send_reaction(to_id=a.user_id, parent_msg_id=uuid.uuid4().hex)
    assert react["errcode"] == NON_ERR
    normal = a.send_chat(to_id=a.user_id, content="[selftest] gate-off-" + uuid.uuid4().hex[:8])
    assert normal["errcode"] == NON_ERR

    hit, rows = _wait_rows(old_version_offline_http, normal["sent_msg_id"])
    assert hit is not None, "普通消息应能离线拉到(证明拉取链路本身可用)"
    assert hit["cmd_id"] == SINGLE_DELIVER
    assert not any(r["msg_id"] == react["sent_msg_id"] for r in rows), (
        "老版本不应拉到心情回应行 0x122d(门未生效?)"
    )
    assert all(r["cmd_id"] != SINGLE_REACTION_DELIVER for r in rows), "结果中不应出现任何回应行"


@pytest.mark.write
def test_old_not_starved_by_reactions(logged_in_client, old_version_offline_http):
    """反饿死:先堆多条回应再发普通消息,老版本仍应拉到普通消息。
    若门控错在响应层过滤,被滤行会占满 limit 并永不推进 → 普通消息永远拉不到。"""
    a = logged_in_client
    for _ in range(8):
        assert a.send_reaction(to_id=a.user_id, parent_msg_id=uuid.uuid4().hex)["errcode"] == NON_ERR
    normal = a.send_chat(to_id=a.user_id, content="[selftest] gate-starve-" + uuid.uuid4().hex[:8])
    assert normal["errcode"] == NON_ERR

    hit, _ = _wait_rows(old_version_offline_http, normal["sent_msg_id"])
    assert hit is not None, (
        "堆积回应后老版本仍应拉到普通消息;拉不到=被饿死(门控可能错在响应层过滤而非查询层)"
    )


@pytest.mark.write
def test_upgrade_backfill(im_config, logged_in_client, old_version_offline_http):
    """升级补拉:老版本期间被排除的回应,换新版本登录后应能拉到
    (证明被排除的行没有被误标为已拉取)。"""
    a = logged_in_client
    react = a.send_reaction(to_id=a.user_id, parent_msg_id=uuid.uuid4().hex)
    assert react["errcode"] == NON_ERR

    # 1) 老版本身份拉一轮:应拉不到该回应
    time.sleep(2)
    rows = _pull_all(old_version_offline_http)
    assert not any(r["msg_id"] == react["sent_msg_id"] for r in rows), "老版本阶段不应拉到回应"

    # 2) 以新版本登录刷新 Redis 版本,再拉:应能补到
    c = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type_b"], im_config["timeout"],
                   app_version=im_config["new_app_version"])
    c.connect()
    assert c.login() == NON_ERR, "新版本登录应成功"
    c.close()

    hit, _ = _wait_rows(old_version_offline_http, react["sent_msg_id"])
    assert hit is not None, (
        "升级后应能补拉到之前被排除的回应;拉不到=被排除的行被误标已拉取(严重:消息永久丢失)"
    )
    assert hit["cmd_id"] == SINGLE_REACTION_DELIVER
