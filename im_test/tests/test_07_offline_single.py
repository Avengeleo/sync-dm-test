"""单聊离线拉取(收方视角,HTTP):A(Web 在线)发 sToId=self;App 端(本测试从不建 WS
连接 = 天然离线)通过 /offline/v1/chat 拉到该消息。验证「收方离线 → 落库 → 拉取」链路。

前提:测试账号的 App 端(clientType=0)当前无真机在线,否则消息走在线推、离线拉不到。
离线是 msg-job 经 Kafka 异步落库,故轮询到出现为止;每次拉取会 MarkPulled(测试账号可接受)。
回应 BPush=false 只落库不发厂商推,但 HTTP 离线仍应拉到——这条正是验证点。
"""

import time
import uuid

import pytest
import requests

from im_test import proto_min
from im_test.client import NON_ERR, SINGLE_DELIVER, SINGLE_REACTION_DELIVER

OFFLINE_CLIENT_TYPE = 0  # App 端作为"离线端":本套用例从不为它建 WS 连接


def _pull_until(offline_http, msg_id, timeout=45):
    """轮询离线拉取直到出现目标 msg_id。单次 HTTP 冷调用可能偏慢/超时,吞掉重试到 deadline。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            code, rows = offline_http.offline_chat(client_type=OFFLINE_CLIENT_TYPE, limit=100)
        except requests.exceptions.RequestException:
            continue  # 冷调用超时/瞬断:重试到 deadline(服务端不长轮询,超时属偶发)
        assert code == 200, f"离线拉取 HTTP {code}(鉴权 Authorization / 域名 IM_HTTP_BASE_URL?)"
        hit = next((r for r in rows if r["msg_id"] == msg_id), None)
        if hit:
            return hit
        time.sleep(0.6)
    return None


@pytest.mark.write
def test_single_normal_offline_pull(logged_in_client, offline_http):
    a = logged_in_client
    r = a.send_chat(to_id=a.user_id, content="[selftest] offline-single-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == NON_ERR, f"单聊上行未被接受 errcode=0x{r['errcode']:04x}"

    hit = _pull_until(offline_http, r["sent_msg_id"])
    assert hit is not None, "离线拉取未拿到刚发的单聊消息(App 端是否真离线?msg-job 落库?)"
    assert hit["cmd_id"] == SINGLE_DELIVER, f"离线行 cmdId 应为 0x1004,实际 0x{hit['cmd_id']:04x}"
    # 用内层 sMsgData(序列化 MESChat)校验发送者/内容——顶层 OfflineChatMsg 字段未必填全
    inner = proto_min.parse_single_deliver(hit["data"])
    assert inner["from_id"] == a.user_id, "内层 MESChat.sFromId 应为发送者"


@pytest.mark.write
def test_single_reaction_offline_pull(logged_in_client, offline_http):
    a = logged_in_client
    parent = uuid.uuid4().hex
    r = a.send_reaction(to_id=a.user_id, parent_msg_id=parent, emoji="👍", action=0)
    assert r["errcode"] == NON_ERR, f"回应上行未被接受 errcode=0x{r['errcode']:04x}"

    hit = _pull_until(offline_http, r["sent_msg_id"])
    assert hit is not None, "离线拉取未拿到心情回应(回应 BPush=false 只落库不发厂商推,但 HTTP 应拉到)"
    assert hit["cmd_id"] == SINGLE_REACTION_DELIVER, f"回应离线行 cmdId 应为 0x122d,实际 0x{hit['cmd_id']:04x}"
    # parentMsgId:收方离线行的顶层字段不填,真值在内层 sMsgData(序列化的 MESChat,field12)
    inner = proto_min.parse_single_deliver(hit["data"])
    assert inner["parent_msg_id"] == parent, (
        f"回应离线行内层 MESChat.parentMsgId 应为被回应消息 id;顶层={hit['parent_msg_id']!r} 内层={inner['parent_msg_id']!r}"
    )
