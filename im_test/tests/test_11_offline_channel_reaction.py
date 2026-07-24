"""超级群心情回应 离线 = 「在线态,离线不可得」(设计验证;第二账号 B 作离线收方)。

超级群回应既不进未读会话(eventType=2 不计未读),离线拉取端点 /channel/v1/offlineMessages
也**硬过滤 Chnn_MsgType_Normal**(channel-pull-server 只查普通消息)→ 回应无离线获取路径,
属在线态消息。此用例锁定该行为:A 发 1 条普通 + 1 条回应,B 离线拉取 → 普通在、回应不在、返回项全为普通(eventType=0)。
需:A、B 均为 IM_CHANNEL_ID 成员;B 的 IM_USER_ID2/IM_TOKEN2;B 当前不在线。建议用安静的测试频道。
"""

import time
import uuid

import pytest
import requests

from im_test.client import NON_ERR


@pytest.fixture
def channel_id(im_config):
    cid = im_config.get("channel_id")
    if not cid:
        pytest.skip("未配置 IM_CHANNEL_ID,跳过超级群回应离线用例")
    return int(cid)


def _has(rows, mid):
    return any(r["msg_id"] == mid for r in rows)


@pytest.mark.write
def test_channel_reaction_offline_is_online_only(logged_in_client, offline_http_b, channel_id):
    a = logged_in_client
    normal = a.send_channel_chat(channel_id, content="[selftest] chn-normal-" + uuid.uuid4().hex[:8])
    assert normal["errcode"] == NON_ERR, f"超级群普通上行未被接受 0x{normal['errcode']:04x}"
    parent = uuid.uuid4().hex
    react = a.send_channel_reaction(channel_id, parent_msg_id=parent)
    assert react["errcode"] == NON_ERR, f"超级群回应上行未被接受 0x{react['errcode']:04x}"

    # 轮询到「普通消息可离线拉到」——证明游标/端点工作(否则回应不在是假阳性)
    rows = []
    deadline = time.time() + 45
    while time.time() < deadline:
        try:
            code, rows = offline_http_b.channel_offline_messages(channel_id, count=100, direction=1)
        except requests.exceptions.RequestException:
            continue
        assert code == 200, f"超级群离线拉取 HTTP {code}(鉴权/域名?)"
        if _has(rows, normal["sent_msg_id"]):
            break
        time.sleep(0.6)

    assert _has(rows, normal["sent_msg_id"]), "普通消息应能离线拉到(证明游标端点可用)"
    assert not _has(rows, react["sent_msg_id"]), "超级群回应按设计不进离线拉取(eventType=2 被硬过滤)——在线态,离线不可得"
    assert all(r["event_type"] == 0 for r in rows), "offlineMessages 只应返回普通消息(eventType=0)"
