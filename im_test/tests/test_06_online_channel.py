"""超级群(频道/radio)在线投递(收方视角):A 发频道消息 → B(同账号另一端)收到下行。

需 IM_CHANNEL_ID 且该账号在频道有权限。channel-job 遍历全体成员不排除发送者 → B 端收到。
⚠️ 会往真实频道发一条 [selftest] 文本/一次回应。超级群离线是游标拉取,另见离线用例。
"""

import uuid

import pytest

from im_test import proto_min
from im_test.client import NON_ERR, RADIO_DELIVER, RADIO_REACTION_DELIVER


@pytest.fixture
def channel_id(im_config):
    cid = im_config.get("channel_id")
    if not cid:
        pytest.skip("未配置 IM_CHANNEL_ID,跳过超级群投递用例")
    return int(cid)


@pytest.mark.write
def test_channel_normal_online_delivery(logged_in_client, receiver_client, channel_id):
    a, b = logged_in_client, receiver_client
    text = "[selftest] online-channel-" + uuid.uuid4().hex[:8]
    r = a.send_channel_chat(channel_id, content=text)
    assert r["errcode"] == NON_ERR, f"超级群上行未被接受 errcode=0x{r['errcode']:04x}"

    d = proto_min.parse_radio_deliver(b.recv_deliver(RADIO_DELIVER))
    assert d["msg_id"] == r["sent_msg_id"], "B 收到的超级群下行 sMsgId 应与发送一致"
    assert d["radio_id"] == channel_id, "下行 sRadioId 应为目标频道"
    assert d["from_id"] == a.user_id, "下行 sFromId 应为发送者"


@pytest.mark.write
def test_channel_reaction_online_delivery(logged_in_client, receiver_client, channel_id):
    a, b = logged_in_client, receiver_client
    parent = uuid.uuid4().hex
    r = a.send_channel_reaction(channel_id, parent_msg_id=parent)
    assert r["errcode"] == NON_ERR, f"超级群回应上行未被接受 errcode=0x{r['errcode']:04x}"

    d = proto_min.parse_radio_deliver(b.recv_deliver(RADIO_REACTION_DELIVER))
    assert d["msg_id"] == r["sent_msg_id"], "B 收到的超级群回应下行 sMsgId 应与上行一致"
    assert d["parent_msg_id"] == parent, "超级群回应下行 parentMsgId 应为被回应消息 id"
