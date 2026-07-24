"""单聊在线投递(收方视角):A 发 → B 实时收到下行 deliver。

A=logged_in_client(默认 Web=2),B=receiver_client(同账号另一端,默认 App=0)。
单聊 sToId=self:跳好友校验,消息扇给本人全部在线端 → B 必收下行。
现有 test_01 只断言发送方 ACK;这里补的是"收方到底收没收到"。
"""

import uuid

import pytest

from im_test import proto_min
from im_test.client import NON_ERR, SINGLE_DELIVER, SINGLE_REACTION_DELIVER


@pytest.mark.write
def test_single_normal_online_delivery(logged_in_client, receiver_client):
    a, b = logged_in_client, receiver_client
    text = "[selftest] online-single-" + uuid.uuid4().hex[:8]
    r = a.send_chat(to_id=a.user_id, content=text)
    assert r["errcode"] == NON_ERR, f"单聊上行未被接受 errcode=0x{r['errcode']:04x}"

    d = proto_min.parse_single_deliver(b.recv_deliver(SINGLE_DELIVER))
    assert d["msg_id"] == r["sent_msg_id"], "B 收到的下行 sMsgId 应与 A 发送一致"
    assert d["from_id"] == a.user_id, "下行 sFromId 应为发送者"
    assert d["content"] == text.encode(), "下行 sContent 应与发送内容一致(服务端对 content 透传)"


@pytest.mark.write
def test_single_reaction_online_delivery(logged_in_client, receiver_client):
    a, b = logged_in_client, receiver_client
    parent = uuid.uuid4().hex
    r = a.send_reaction(to_id=a.user_id, parent_msg_id=parent, emoji="👍", action=0)
    assert r["errcode"] == NON_ERR, f"回应上行未被接受 errcode=0x{r['errcode']:04x}"

    d = proto_min.parse_single_deliver(b.recv_deliver(SINGLE_REACTION_DELIVER))
    assert d["msg_id"] == r["sent_msg_id"], "B 收到的回应下行 sMsgId 应与上行一致"
    assert d["parent_msg_id"] == parent, "回应下行 parentMsgId 应为被回应消息 id"
