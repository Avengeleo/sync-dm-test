"""版本兼容门①在线:老版本客户端收不到心情回应,但普通消息照常。

门控实现:im-gateway 转发前按连接登录时上报的 sVersionCode 判定(见
需求文档/IM灰度-版本兼容门/版本兼容门设计文档.md §6)。

前置:
- 门控代码已部署到该环境(未部署时"老版本仍收到回应"会失败——那是预期的未部署信号)
- IM_OLD_APP_VERSION(默认 2.20.0)必须 < 门槛值;门槛在 bi 后台 im_feature_gate 表配置
- 老版本端是 App(clientType=IM_CLIENT_TYPE_B,默认 0);Web/PC 按设计豁免,不在此验证
"""

import uuid

import pytest

from im_test import proto_min
from im_test.client import (
    NON_ERR,
    SINGLE_DELIVER, SINGLE_REACTION_DELIVER,
    GROUP_DELIVER, GROUP_REACTION_DELIVER,
    RADIO_DELIVER, RADIO_REACTION_DELIVER,
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


# ── 老版本收不到回应(门生效)──

@pytest.mark.write
def test_single_reaction_blocked_for_old(logged_in_client, old_receiver_client):
    a, b = logged_in_client, old_receiver_client
    r = a.send_reaction(to_id=a.user_id, parent_msg_id=uuid.uuid4().hex)
    assert r["errcode"] == NON_ERR, "上行仍应被接受(门只挡下发,不挡上行)"
    assert b.expect_no_deliver(SINGLE_REACTION_DELIVER), (
        "老版本端不应收到单聊回应下行 0x122d(门未生效?门槛值是否 > IM_OLD_APP_VERSION?)"
    )


@pytest.mark.write
def test_group_reaction_blocked_for_old(logged_in_client, old_receiver_client, group_id):
    a, b = logged_in_client, old_receiver_client
    r = a.send_group_reaction(group_id, parent_msg_id=uuid.uuid4().hex)
    assert r["errcode"] == NON_ERR
    assert b.expect_no_deliver(GROUP_REACTION_DELIVER), "老版本端不应收到群回应下行 0x2314"


@pytest.mark.write
def test_channel_reaction_blocked_for_old(logged_in_client, old_receiver_client, channel_id):
    a, b = logged_in_client, old_receiver_client
    r = a.send_channel_reaction(channel_id, parent_msg_id=uuid.uuid4().hex)
    assert r["errcode"] == NON_ERR
    assert b.expect_no_deliver(RADIO_REACTION_DELIVER), "老版本端不应收到超级群回应下行 0x3213"


# ── 对照:普通消息不受影响(门没误伤)──

@pytest.mark.write
def test_single_normal_still_delivered_to_old(logged_in_client, old_receiver_client):
    a, b = logged_in_client, old_receiver_client
    text = "[selftest] gate-normal-" + uuid.uuid4().hex[:8]
    r = a.send_chat(to_id=a.user_id, content=text)
    assert r["errcode"] == NON_ERR
    d = proto_min.parse_single_deliver(b.recv_deliver(SINGLE_DELIVER))
    assert d["msg_id"] == r["sent_msg_id"], "老版本端仍应正常收到普通单聊消息(门只挡新类型)"


@pytest.mark.write
def test_group_normal_still_delivered_to_old(logged_in_client, old_receiver_client, group_id):
    a, b = logged_in_client, old_receiver_client
    r = a.send_group_chat(group_id, content="[selftest] gate-gnormal-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == NON_ERR
    d = proto_min.parse_group_deliver(b.recv_deliver(GROUP_DELIVER))
    assert d["msg_id"] == r["sent_msg_id"], "老版本端仍应正常收到普通群消息"


@pytest.mark.write
def test_channel_normal_still_delivered_to_old(logged_in_client, old_receiver_client, channel_id):
    a, b = logged_in_client, old_receiver_client
    r = a.send_channel_chat(channel_id, content="[selftest] gate-cnormal-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == NON_ERR
    d = proto_min.parse_radio_deliver(b.recv_deliver(RADIO_DELIVER))
    assert d["msg_id"] == r["sent_msg_id"], "老版本端仍应正常收到普通超级群消息"
