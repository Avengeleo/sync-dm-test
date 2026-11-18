"""消息漫游 · 社群 ACK 带 seq(feature/msg-roaming 一期)。

新架构客户端发社群普通消息、心情回应:channel-srv 不立即回 ACK,channel-job 在事务里取号落库后
推送 ACK(命令不变,RadioChatAck 多一个 seq=8)。老客户端仍立即回 ACK,不带 seq。

前置:
- sync-dm-im feature/msg-roaming 已部署到该环境(channel-srv、channel-job)
- im_feature_gate 没有配置消息漫游(门控键 65281 / 0xFF01)时,服务端用占位门槛 99.0.0:
  IM_ROAMING_APP_VERSION 默认 99.0.0,登录即被判为新架构客户端;若已配置真实门槛,填 >= 门槛的版本
- IM_CHANNEL_ID:有发言权限的频道;IM_CLIENT_TYPE 与 IM_CLIENT_TYPE_B 不同(新旧两条连接)
- 落库核对(可选):Archery 查 channelSvr.chnn_<频道ID> 的 seq、convSrv.convMeta 的 maxSeq/lastMsg

⚠️ 会往频道发若干条 [selftest] 消息和一条回应。
"""

import os
import uuid

import pytest

from im_test.client import ImWsClient, NON_ERR

SEQ_BASE = 100_000_000  # seq 起始号(im-common convmeta.SeqBase)
ROAMING_APP_VERSION = os.environ.get("IM_ROAMING_APP_VERSION", "").strip() or "99.0.0"


@pytest.fixture
def channel_id(im_config):
    cid = im_config.get("channel_id")
    if not cid:
        pytest.skip("未配置 IM_CHANNEL_ID,跳过社群 ACK 用例")
    return int(cid)


def _login(im_config, client_type, app_version, label):
    c = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   client_type, im_config["timeout"], app_version=app_version)
    try:
        c.connect()
    except Exception as e:
        pytest.skip(f"{label} 连接失败:{e}")
    if (err := c.login()) != NON_ERR:
        c.close()
        pytest.skip(f"{label} 登录失败 nErr=0x{err:04x}")
    return c


@pytest.fixture
def new_client(im_config):
    """新架构客户端:A 端类型 + 消息漫游版本号。"""
    c = _login(im_config, im_config["client_type"], ROAMING_APP_VERSION, "新架构客户端")
    yield c
    c.close()


@pytest.fixture
def old_client(im_config):
    """老客户端:B 端类型 + 老版本号。"""
    if im_config["client_type_b"] == im_config["client_type"]:
        pytest.skip("IM_CLIENT_TYPE_B 与 IM_CLIENT_TYPE 相同,双连接会互踢")
    c = _login(im_config, im_config["client_type_b"], im_config["old_app_version"], "老客户端")
    yield c
    c.close()


def _send_ok(client, channel_id, **kw):
    r = client.send_channel_chat_seq(channel_id, content="[selftest] roaming-ack-" + uuid.uuid4().hex[:8], **kw)
    assert r["errcode"] == NON_ERR, f"社群上行未被接受 errcode=0x{r['errcode']:04x}"
    return r


@pytest.mark.write
def test_new_client_ack_has_seq(new_client, channel_id):
    r = _send_ok(new_client, channel_id)
    assert r["seq"] >= SEQ_BASE, (
        f"新架构客户端的 ACK 应带 seq(>= {SEQ_BASE}),实际 {r['seq']}。"
        f"seq=0 说明被判为老客户端:检查服务是否已部署、版本号 {ROAMING_APP_VERSION} 是否达到门槛")


@pytest.mark.write
def test_new_client_seq_increases(new_client, channel_id):
    r1 = _send_ok(new_client, channel_id)
    r2 = _send_ok(new_client, channel_id)
    # 频道里可能有别人同时发言,只断言递增,不断言 +1
    assert r2["seq"] > r1["seq"] >= SEQ_BASE, f"同一频道后发的消息 seq 应更大:{r1['seq']} → {r2['seq']}"


@pytest.mark.write
def test_resend_same_msg_id_returns_same_seq(new_client, channel_id):
    r1 = _send_ok(new_client, channel_id)
    r2 = _send_ok(new_client, channel_id, msg_id=r1["sent_msg_id"])  # 模拟 ACK 超时后用同一 msgId 重发
    assert r2["seq"] == r1["seq"], f"重发同一 msgId 应返回原 seq,不重复入库:{r1['seq']} vs {r2['seq']}"


@pytest.mark.write
def test_new_client_reaction_ack_has_seq(new_client, channel_id):
    parent = _send_ok(new_client, channel_id)
    r = new_client.send_channel_reaction_seq(channel_id, parent_msg_id=parent["sent_msg_id"])
    assert r["errcode"] == NON_ERR, f"回应上行未被接受 errcode=0x{r['errcode']:04x}"
    assert r["seq"] > parent["seq"], f"心情回应也占 seq,应大于被回应消息:{parent['seq']} → {r['seq']}"


@pytest.mark.write
def test_old_client_ack_without_seq(old_client, channel_id):
    r = _send_ok(old_client, channel_id)
    assert r["seq"] == 0, f"老客户端仍立即回 ACK,不应带 seq,实际 {r['seq']}"
