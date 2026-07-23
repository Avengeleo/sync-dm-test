"""心情回应上行端到端(登录 → 发单聊回应 0x122a → 收 ACK 0x122c)。

覆盖:网关鉴权 → msg-srv 路由 → onReactionMsg 校验(msgId/parentMsgId/sContent 非空)
→ 好友校验门控(自反应跳过)→ 发 Kafka → 同步回 ACK NON_ERR。
不需要真好友、不需要 mongo:sToId=自己(sFromId==sToId 跳好友校验),只断言 ACK。
"""

import pytest

from im_test.client import NON_ERR


@pytest.mark.write
def test_reaction_uplink_acked(logged_in_client):
    # 自反应:sToId 默认=自己的 user_id → 跳好友校验
    r = logged_in_client.send_reaction(emoji="👍", action=0)
    assert r["errcode"] == NON_ERR, (
        f"回应上行未被接受 errcode=0x{r['errcode']:04x}(0x8000=成功)。raw sent_msg_id={r['sent_msg_id']}"
    )
    assert r["ack_msg_id"] == r["sent_msg_id"], "ACK 的 sMsgId 应与上行一致"


@pytest.mark.write
def test_reaction_remove_action(logged_in_client):
    # action=1(移除回应)同样应被接受(服务端不解析 content)
    r = logged_in_client.send_reaction(emoji="👍", action=1)
    assert r["errcode"] == NON_ERR


@pytest.mark.write
def test_reaction_opposite_end_acked(logged_in_client):
    # 对端副本 0x122b(恒跳好友校验),也应回 ACK
    r = logged_in_client.send_reaction(opposite=True)
    assert r["errcode"] == NON_ERR


@pytest.mark.write
def test_reaction_empty_content_rejected(logged_in_client):
    # sContent 为空 → 服务端硬前置拒绝(errcode 非 NON_ERR)。直接发一条空 content 的回应
    from im_test import proto_min
    import uuid
    body = proto_min.mes_chat_reaction(
        to_id=logged_in_client.user_id, msg_id=uuid.uuid4().hex,
        parent_msg_id=uuid.uuid4().hex, content=b"",
    )
    logged_in_client._send(0x122A, body)
    ack = proto_min.decode(logged_in_client._recv_until(0x122C))
    assert ack.get(4, 0) != NON_ERR, "空 sContent 应被拒(非 NON_ERR)"
