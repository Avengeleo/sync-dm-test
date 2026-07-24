"""超级群离线(第二账号 B 作离线收方):A 发频道消息 → B(频道成员,不上线)
通过 /channel/v1/sessions 在会话的 last(最新一条)/uUnread 里看到该消息。

需:A、B 均为 IM_CHANNEL_ID 成员;B 的 IM_USER_ID2/IM_TOKEN2;B 当前不在线。
超级群普通消息进会话(eventType=0);心情回应 eventType=2 不进会话/不计未读,故这里只测普通消息。
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
        pytest.skip("未配置 IM_CHANNEL_ID,跳过超级群离线用例")
    return int(cid)


def _sessions_until(http_b, chnn_id, msg_id, timeout=45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            code, rows = http_b.channel_sessions(chnn_id)
        except requests.exceptions.RequestException:
            continue
        assert code == 200, f"超级群会话 HTTP {code}(鉴权/域名?)"
        s = next((x for x in rows if x["chnn_id"] == chnn_id), None)
        if s and s["last_msg_id"] == msg_id:
            return s
        time.sleep(0.6)
    return None


@pytest.mark.write
def test_channel_normal_offline_session(logged_in_client, offline_http_b, channel_id):
    a = logged_in_client
    r = a.send_channel_chat(channel_id, content="[selftest] offline-channel-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == NON_ERR, f"超级群上行未被接受 errcode=0x{r['errcode']:04x}"

    s = _sessions_until(offline_http_b, channel_id, r["sent_msg_id"])
    assert s is not None, "B 的超级群会话未把该消息作为 last(B 是否频道成员/当前是否离线?)"
    assert s["unread"] >= 1, "该频道会话应有未读"
    assert s["last_event"] == 0, f"普通消息 eventType 应为 0,实际 {s['last_event']}"
