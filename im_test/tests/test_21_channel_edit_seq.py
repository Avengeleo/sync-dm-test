"""消息漫游 · 社群编辑事件(feature/msg-roaming 一期)。

每次编辑都追加一条编辑事件(占新 seq),按 seq 拉取时 eventType=3、oldMsgId=原消息、内容为这次编辑的内容;
原消息本身更新为最终内容。老客户端的离线拉取本就排除编辑行,不受影响。

前置:同 test_19(channel-srv、channel-job、channel-pull-server、http-gateway 已部署),需 IM_HTTP_BASE_URL、IM_CHANNEL_ID。
⚠️ 会往频道发 1 条 [selftest] 消息并编辑 2 次。
"""

import os
import time
import uuid

import pytest

from im_test.client import ImWsClient, NON_ERR

SEQ_BASE = 100_000_000
ROAMING_APP_VERSION = os.environ.get("IM_ROAMING_APP_VERSION", "").strip() or "99.0.0"
EVENT_EDIT = 3


@pytest.fixture
def channel_id(im_config):
    cid = im_config.get("channel_id")
    if not cid:
        pytest.skip("未配置 IM_CHANNEL_ID,跳过社群编辑用例")
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


def _edit_events(offline_http, channel_id, after_seq, orig_id, want, timeout=20):
    """编辑是异步落库,轮询到出现 want 条指向 orig_id 的编辑事件。"""
    deadline = time.time() + timeout
    events = []
    while time.time() < deadline:
        code, rsp = offline_http.channel_msg_by_seq(channel_id, 2, base_seq=after_seq, count=100, client_type=0)
        assert code == 200, f"按 seq 拉取失败 HTTP {code}"
        events = [m for m in rsp["msgs"] if m["old_msg_id"] == orig_id]
        if len(events) >= want:
            return events
        time.sleep(1)
    return events


@pytest.mark.write
def test_each_edit_appends_event(new_client, offline_http, channel_id):
    tag = uuid.uuid4().hex[:8]
    orig = new_client.send_channel_chat_seq(channel_id, content=f"[selftest] edit-orig-{tag}")
    assert orig["errcode"] == NON_ERR and orig["seq"] >= SEQ_BASE, f"ACK 应带 seq:{orig}"

    v1, v2 = f"[selftest] edit-v1-{tag}", f"[selftest] edit-v2-{tag}"
    assert new_client.send_channel_edit(channel_id, orig["sent_msg_id"], v1)["errcode"] == NON_ERR
    time.sleep(1)  # 两次编辑按顺序落库
    assert new_client.send_channel_edit(channel_id, orig["sent_msg_id"], v2)["errcode"] == NON_ERR

    events = _edit_events(offline_http, channel_id, orig["seq"], orig["sent_msg_id"], want=2)
    assert len(events) == 2, f"两次编辑应各追加一条编辑事件,实际 {len(events)} 条(改造前再次编辑会覆盖,只有 1 条)"
    assert all(e["event_type"] == EVENT_EDIT for e in events), f"编辑事件 eventType 应为 3:{events}"
    assert events[0]["seq"] < events[1]["seq"] and events[0]["seq"] > orig["seq"]
    assert [e["content"] for e in events] == [v1.encode(), v2.encode()], "编辑事件内容应为每次编辑的内容,按先后排列"

    code, msgs, _ = offline_http.channel_msg_by_id(channel_id, [orig["sent_msg_id"]])
    assert code == 200 and msgs and msgs[0]["content"] == v2.encode(), "原消息应已更新为最后一次编辑的内容"
