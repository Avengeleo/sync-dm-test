"""超级群心情回应 离线拉取(游标端点 /channel/v1/offlineMessages;第二账号 B 作离线收方)。

v2.21.2 已把频道离线拉取的 msgType 过滤放宽为 $in [Normal, 心情回应](im-common/dao/msg_dao/
channel_bson.go:16/118,注释「Normal + 心情回应一起下发,已拍板放宽 $in」),故超级群回应**能**
离线拉到,响应回填 eventType=2(=落库 msgType)+ parentMsgId。回应不进未读会话(test_09 的
session 端点看不到它),但游标消息端点能拉。需:A、B 均为 IM_CHANNEL_ID 成员;B 当前不在线。
"""

import time
import uuid

import pytest
import requests

from im_test.client import NON_ERR

CHNN_EVENT_REACTION = 2  # ChnnChat.eventType:0=普通 2=心情回应


@pytest.fixture
def channel_id(im_config):
    cid = im_config.get("channel_id")
    if not cid:
        pytest.skip("未配置 IM_CHANNEL_ID,跳过超级群回应离线用例")
    return int(cid)


def _pull_until(http_b, chnn_id, msg_id, timeout=45):
    """轮询到出现目标 msg_id。返回 (命中行 or None, 最后一次的全量行) —— 第二个返回值
    用于失败时报清楚「到底拉到了什么」:拉到 0 行 / 只拉到普通消息 / 拉到回应但 id 不匹配,
    这三种情况的根因完全不同(成员或游标 / 版本门过滤 / 落库或时序)。"""
    deadline = time.time() + timeout
    last = []
    while time.time() < deadline:
        try:
            code, rows = http_b.channel_offline_messages(chnn_id, count=100, direction=1)
        except requests.exceptions.RequestException:
            continue
        assert code == 200, f"超级群离线拉取 HTTP {code}(鉴权/域名?)"
        last = rows
        hit = next((r for r in rows if r["msg_id"] == msg_id), None)
        if hit:
            return hit, rows
        time.sleep(0.6)
    return None, last


@pytest.mark.write
def test_channel_reaction_offline_pull(logged_in_client, offline_http_b, channel_id):
    a = logged_in_client
    parent = uuid.uuid4().hex
    r = a.send_channel_reaction(channel_id, parent_msg_id=parent)
    assert r["errcode"] == NON_ERR, f"超级群回应上行未被接受 errcode=0x{r['errcode']:04x}"

    hit, rows = _pull_until(offline_http_b, channel_id, r["sent_msg_id"])
    if hit is None:
        kinds = {}
        for x in rows:
            kinds[x.get("event_type")] = kinds.get(x.get("event_type"), 0) + 1
        raise AssertionError(
            f"B 未经 /channel/offlineMessages 拉到超级群回应。"
            f"本轮共拉到 {len(rows)} 行,eventType 分布 {kinds}(2=心情回应)。"
            f"判读:0 行→B 非频道成员/游标不对;有行但无 eventType=2→"
            f"回应被版本门过滤(查 B 在 Redis 的 app_version/channel_type)或未落库;"
            f"有 eventType=2 但 msgId 对不上→落库时序,可加大 timeout。"
            f"目标 msgId={r['sent_msg_id']}")
    assert hit["event_type"] == CHNN_EVENT_REACTION, f"超级群回应离线行 eventType 应为 2,实际 {hit['event_type']}"
    assert hit["parent_msg_id"] == parent, "超级群回应离线行 parentMsgId 应为被回应消息 id"
