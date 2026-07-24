"""群离线拉取(第二账号 B 作离线收方):A(在线,群成员)发群消息 → B(群成员,不上线)
通过 /offline/v1/group/session 在「有未读会话」里拉到该消息。

为什么用 B:群会话端点只返回未读,而发送者自己发的消息对自己已读、不进自己的未读会话,
故需一个真离线收方 B(不能像单聊那样自发自收)。
需:A、B 均为 IM_GROUP_ID 成员;B 的 IM_USER_ID2/IM_TOKEN2;B 当前不在线(本用例不连 B 的 WS)。
超级群/群心情回应不计未读(不进会话),故这里只测普通消息。
"""

import time
import uuid

import pytest
import requests

from im_test import proto_min
from im_test.client import NON_ERR, GROUP_DELIVER


@pytest.fixture
def group_id(im_config):
    gid = im_config.get("group_id")
    if not gid:
        pytest.skip("未配置 IM_GROUP_ID,跳过群离线用例")
    return int(gid)


def _pull_group_until(http_b, msg_id, timeout=45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            code, rows = http_b.group_session(client_type="0", size=100)
        except requests.exceptions.RequestException:
            continue
        assert code == 200, f"群离线会话 HTTP {code}(鉴权/域名?)"
        hit = next((r for r in rows if r["msg_id"] == msg_id), None)
        if hit:
            return hit
        time.sleep(0.6)
    return None


@pytest.mark.write
def test_group_normal_offline_pull(logged_in_client, offline_http_b, group_id):
    a = logged_in_client
    r = a.send_group_chat(group_id, content="[selftest] offline-group-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == NON_ERR, f"群上行未被接受 errcode=0x{r['errcode']:04x}"

    hit = _pull_group_until(offline_http_b, r["sent_msg_id"])
    assert hit is not None, "B 未在群未读会话拉到该消息(B 是否群成员/当前是否离线?msg-job 落库?)"
    assert hit["group_id"] == group_id, "离线行所属群应为目标群"
    assert hit["cmd_id"] == GROUP_DELIVER, f"群离线行 cmdId 应为 0x2004,实际 0x{hit['cmd_id']:04x}"
    # 发送者用内层 sMsgData(MESGrpChat)校验,顶层字段未必填全
    inner = proto_min.parse_group_deliver(hit["data"])
    assert inner["from_id"] == a.user_id, "内层 MESGrpChat.sFromId 应为发送者 A"
