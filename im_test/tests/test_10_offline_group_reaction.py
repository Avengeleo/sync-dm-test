"""群心情回应 离线拉取(游标端点 /offline/v1/group/pull;第二账号 B 作离线收方)。

群回应不进「未读会话」(isRead=1,故 test_08 的 session 端点看不到它),但按 clientType 的
Pulled 标志存离线、可经 /group/pull 拉到(该端点默认不排除回应,dao 仅在 ExcludeReaction 时才滤)。
需:A、B 均为 IM_GROUP_ID 成员;B 的 IM_USER_ID2/IM_TOKEN2;B 当前不在线。
"""

import time
import uuid

import pytest
import requests

from im_test import proto_min
from im_test.client import NON_ERR, GROUP_REACTION_DELIVER


@pytest.fixture
def group_id(im_config):
    gid = im_config.get("group_id")
    if not gid:
        pytest.skip("未配置 IM_GROUP_ID,跳过群回应离线用例")
    return int(gid)


def _pull_until(http_b, group_id, msg_id, timeout=45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            code, rows = http_b.group_pull(group_id, client_type="0", limit=100, direct=-1)
        except requests.exceptions.RequestException:
            continue
        assert code == 200, f"群离线拉取 HTTP {code}(鉴权/域名?)"
        hit = next((r for r in rows if r["msg_id"] == msg_id), None)
        if hit:
            return hit
        time.sleep(0.6)
    return None


@pytest.mark.write
def test_group_reaction_offline_pull(logged_in_client, offline_http_b, group_id):
    a = logged_in_client
    parent = uuid.uuid4().hex
    r = a.send_group_reaction(group_id, parent_msg_id=parent)
    assert r["errcode"] == NON_ERR, f"群回应上行未被接受 errcode=0x{r['errcode']:04x}"

    hit = _pull_until(offline_http_b, group_id, r["sent_msg_id"])
    assert hit is not None, "B 未经 /group/pull 拉到该群回应(回应是否落离线?B 是否群成员/离线?)"
    assert hit["cmd_id"] == GROUP_REACTION_DELIVER, f"群回应离线行 cmdId 应为 0x2314,实际 0x{hit['cmd_id']:04x}"
    # parentMsgId 顶层未必填,读内层 sMsgData(MESGrpChat, field13)
    inner = proto_min.parse_group_deliver(hit["data"])
    assert inner["parent_msg_id"] == parent, (
        f"群回应离线内层 MESGrpChat.parentMsgId 应为被回应消息 id;内层={inner['parent_msg_id']!r}"
    )
