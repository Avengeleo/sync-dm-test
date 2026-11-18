"""消息漫游 · 社群在线推送与按 msgId 回源带 seq(feature/msg-roaming 一期)。

A(新架构客户端,默认 99.0.0)发社群消息/回应,B(同账号另一端)收到的在线推送 RadioChat 带 seq(17),
且等于 A 收到的 ACK 里的 seq;/channel/v1/msg/by_id 回源结果也带 seq(ChnnChat.seq=18)。

前置:同 test_18、test_19;B 端类型 IM_CLIENT_TYPE_B 必须与 A 不同;回源用例需 IM_HTTP_BASE_URL。
⚠️ 会往频道发若干条 [selftest] 消息和一条回应。
"""

import os
import time
import uuid

import pytest

from im_test import proto_min
from im_test.client import ImWsClient, NON_ERR, RADIO_DELIVER, RADIO_REACTION_DELIVER

SEQ_BASE = 100_000_000
ROAMING_APP_VERSION = os.environ.get("IM_ROAMING_APP_VERSION", "").strip() or "99.0.0"


@pytest.fixture
def channel_id(im_config):
    cid = im_config.get("channel_id")
    if not cid:
        pytest.skip("未配置 IM_CHANNEL_ID,跳过社群推送用例")
    return int(cid)


@pytest.fixture
def new_client(im_config):
    c = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type"], im_config["timeout"], app_version=ROAMING_APP_VERSION)
    try:
        c.connect()
    except Exception as e:
        pytest.skip(f"新架构客户端连接失败:{e}")
    if (err := c.login()) != NON_ERR:
        c.close()
        pytest.skip(f"新架构客户端登录失败 nErr=0x{err:04x}")
    yield c
    c.close()


def _recv_deliver_for(client, cmd, msg_id, timeout=15):
    """收到指定 msgId 的下行为止(频道里可能有别人的消息)。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        d = proto_min.parse_radio_deliver_seq(client.recv_deliver(cmd, max(0.5, deadline - time.time())))
        if d["msg_id"] == msg_id:
            return d
    raise TimeoutError(f"未在 {timeout}s 内收到 msgId={msg_id} 的 cmd=0x{cmd:04x}")


@pytest.mark.write
def test_online_deliver_has_seq(new_client, receiver_client, channel_id):
    r = new_client.send_channel_chat_seq(channel_id, content="[selftest] push-seq-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == NON_ERR and r["seq"] >= SEQ_BASE, f"ACK 应带 seq:{r}"
    d = _recv_deliver_for(receiver_client, RADIO_DELIVER, r["sent_msg_id"])
    assert d["seq"] == r["seq"], f"在线推送的 seq 应与 ACK 一致:{d['seq']} vs {r['seq']}"


@pytest.mark.write
def test_reaction_deliver_has_seq(new_client, receiver_client, channel_id):
    parent = new_client.send_channel_chat_seq(channel_id, content="[selftest] push-seq-parent")
    assert parent["errcode"] == NON_ERR
    _recv_deliver_for(receiver_client, RADIO_DELIVER, parent["sent_msg_id"])
    r = new_client.send_channel_reaction_seq(channel_id, parent_msg_id=parent["sent_msg_id"])
    assert r["errcode"] == NON_ERR and r["seq"] > parent["seq"]
    d = _recv_deliver_for(receiver_client, RADIO_REACTION_DELIVER, r["sent_msg_id"])
    assert d["seq"] == r["seq"], f"回应推送的 seq 应与 ACK 一致:{d['seq']} vs {r['seq']}"


@pytest.mark.write
def test_msg_by_id_returns_seq(new_client, offline_http, channel_id):
    r = new_client.send_channel_chat_seq(channel_id, content="[selftest] by-id-seq-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == NON_ERR and r["seq"] >= SEQ_BASE
    code, seqs = offline_http.channel_msg_by_id_seqs(channel_id, [r["sent_msg_id"]])
    assert code == 200, f"按 msgId 回源失败 HTTP {code}"
    assert seqs.get(r["sent_msg_id"]) == r["seq"], f"回源结果的 seq 应与 ACK 一致:{seqs} vs {r['seq']}"
