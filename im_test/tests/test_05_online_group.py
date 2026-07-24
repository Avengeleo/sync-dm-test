"""群在线投递(收方视角):A 发群消息 → B(同账号另一端)收到群下行。

需 IM_GROUP_ID 且该账号是群成员。B 是发送者本人的另一端,靠 group-job dealMsgOwner 扇出下行。
⚠️ 会往真实群发一条 [selftest] 文本/一次回应,注意别用生产大群。
"""

import uuid

import pytest

from im_test import proto_min
from im_test.client import NON_ERR, GROUP_DELIVER, GROUP_REACTION_DELIVER


@pytest.fixture
def group_id(im_config):
    gid = im_config.get("group_id")
    if not gid:
        pytest.skip("未配置 IM_GROUP_ID,跳过群投递用例")
    return int(gid)


@pytest.mark.write
def test_group_normal_online_delivery(logged_in_client, receiver_client, group_id):
    a, b = logged_in_client, receiver_client
    text = "[selftest] online-group-" + uuid.uuid4().hex[:8]
    r = a.send_group_chat(group_id, content=text)
    assert r["errcode"] == NON_ERR, f"群上行未被接受 errcode=0x{r['errcode']:04x}"

    d = proto_min.parse_group_deliver(b.recv_deliver(GROUP_DELIVER))
    assert d["msg_id"] == r["sent_msg_id"], "B 收到的群下行 sMsgId 应与发送一致"
    assert d["grp_id"] == group_id, "下行 sGrpId 应为目标群"
    assert d["from_id"] == a.user_id, "下行 sFromId 应为发送者"


@pytest.mark.write
def test_group_reaction_online_delivery(logged_in_client, receiver_client, group_id):
    a, b = logged_in_client, receiver_client
    parent = uuid.uuid4().hex
    r = a.send_group_reaction(group_id, parent_msg_id=parent)
    assert r["errcode"] == NON_ERR, f"群回应上行未被接受 errcode=0x{r['errcode']:04x}"

    d = proto_min.parse_group_deliver(b.recv_deliver(GROUP_REACTION_DELIVER))
    assert d["msg_id"] == r["sent_msg_id"], "B 收到的群回应下行 sMsgId 应与上行一致"
    assert d["parent_msg_id"] == parent, "群回应下行 parentMsgId 应为被回应消息 id"
