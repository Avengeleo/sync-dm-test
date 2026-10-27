"""纯本地协议回归，不读取配置、不连接真实 HTTP/IM/数据库。"""

import pytest
import requests

from im_test import proto_min
from im_test.security_channel import (
    ChannelMessage,
    ChannelReply,
    ChannelRequestError,
    ChannelSession,
    SecurityChannelClient,
    parse_channel_reply,
)


def _message(channel_id=11, msg_id="unit-message", index="507f1f77bcf86cd799439011"):
    return (
        proto_min._fv(1, 7) + proto_min._fv(2, channel_id)
        + proto_min._fs(3, msg_id) + proto_min._fb(6, b"unit-body")
        + proto_min._fs(8, index)
    )


def _response(status=200, body=b"", content_type="application/x-protobuf"):
    response = requests.Response()
    response.status_code = status
    response._content = body
    response.headers["Content-Type"] = content_type
    return response


def _client(response, calls=None):
    def post(url, **kwargs):
        if calls is not None:
            calls.append((url, kwargs))
        return response
    return SecurityChannelClient("https://unit.invalid", "synthetic-unit-token", 8, post=post)


def test_channel_decoding_preserves_nested_messages_and_errcode():
    reply = parse_channel_reply(proto_min._fb(2, _message()), "offline").require_success()
    assert reply.errcode == 0 and len(reply.messages) == 1
    assert reply.messages[0].channel_id == 11
    assert reply.messages[0].msg_id == "unit-message"
    assert reply.messages[0].content == b"unit-body"
    assert reply.messages[0].index == "507f1f77bcf86cd799439011"
    session = proto_min._fv(1, 11) + proto_min._fb(4, _message())
    sessions = parse_channel_reply(proto_min._fb(2, session), "sessions").require_success()
    assert sessions.sessions[0].last.msg_id == "unit-message"


@pytest.mark.parametrize("code", (1, 200, 403, 500, 32768))
def test_protobuf_business_failure_is_not_successful_empty_list(code):
    reply = parse_channel_reply(proto_min._fv(1, code), "offline")
    assert reply.errcode == code
    with pytest.raises(ChannelRequestError):
        reply.require_success()


def test_member_denial_requires_matching_http_and_protobuf_status():
    response = _response(status=403, body=proto_min._fv(1, 403))
    reply = _client(response).by_id(11, ["unit-message"]).require_member_denial()
    assert reply.http_status == 403 and reply.errcode == 403
    for status, body in ((403, b""), (200, proto_min._fv(1, 403))):
        with pytest.raises(ChannelRequestError):
            _client(_response(status=status, body=body)).by_id(11, ["unit-message"]).require_member_denial()


def test_member_denial_must_not_contain_message_or_missing_status():
    for field in (proto_min._fb(2, _message()), proto_min._fs(3, "unit-message")):
        reply = parse_channel_reply(proto_min._fv(1, 403) + field, "by_id", 403)
        with pytest.raises(ChannelRequestError):
            reply.require_member_denial()


@pytest.mark.parametrize("status", (301, 302, 400, 401, 404, 429, 500, 502, 503))
@pytest.mark.parametrize("endpoint", ("sessions", "offline", "by_id"))
def test_http_failures_never_become_empty_channel_success(status, endpoint):
    client = _client(_response(status=status))
    with pytest.raises(ChannelRequestError):
        if endpoint == "sessions":
            client.sessions([11])
        elif endpoint == "offline":
            client.offline([11])
        else:
            client.by_id(11, ["unit-message"])


@pytest.mark.parametrize("content_type,body", (
    ("text/html", b""),
    ("text/html", b"<html>gateway error</html>"),
    ("application/json", b"{}"),
    ("", b""),
))
def test_non_protobuf_response_cannot_pass_health_check(content_type, body):
    with pytest.raises(ChannelRequestError):
        _client(_response(body=body, content_type=content_type)).health()


def test_empty_default_protobuf_response_is_valid_only_with_success_metadata():
    reply = _client(_response()).health()
    assert reply.http_status == 200 and reply.errcode == 0 and not reply.sessions
    with pytest.raises(ChannelRequestError):
        _client(_response(status=403)).by_id(11, ["unit-message"]).require_member_denial()


@pytest.mark.parametrize("body", (
    b"\x08\x80",                        # 截断 varint
    b"\x12\x04\x08",                  # 长度字段越界
    b"\x00",                            # field number 0
    b"\x0a\x00",                       # errcode 应为 varint
    b"\x1a\x00",                       # offline 不存在字段 3
    b"\x08\x00\x08\x00",             # errcode 单值重复
    b"\x08" + b"\xff" * 10,           # 溢出 varint
    b"<html>fake protobuf</html>",
    proto_min._fb(2, b""),                # 空消息不能冒充有效正文
    proto_min._fb(2, b"\x08\x80"),      # 嵌套消息截断
))
def test_malformed_protobuf_never_decodes_to_empty_success(body):
    with pytest.raises(ChannelRequestError):
        _client(_response(body=body)).offline([11]).require_success()


def test_invalid_utf8_message_id_is_a_protocol_failure():
    body = proto_min._fb(2, proto_min._fv(2, 11) + proto_min._fb(3, b"\xff"))
    with pytest.raises(ChannelRequestError):
        parse_channel_reply(body, "offline")


def test_wrong_session_channel_is_a_protocol_failure():
    session = proto_min._fv(1, 22) + proto_min._fb(4, _message(channel_id=11))
    with pytest.raises(ChannelRequestError):
        parse_channel_reply(proto_min._fb(2, session), "sessions")


def test_requests_keep_authenticated_uid_distinct_from_forged_body_uid():
    calls = []
    client = _client(_response(), calls)
    client.sessions([11, 22], version="v2", body_user_id=7)
    client.offline([11], version="v1", count=1000, body_user_id=7, base_index="unit-index", is_contain=1)
    client.by_id(11, ["unit-message"], version="v2", body_user_id=7)
    assert [url.rsplit("/channel/", 1)[1] for url, _ in calls] == [
        "v2/sessions", "v1/offlineMessages", "v2/msg/by_id"
    ]
    for _, kwargs in calls:
        assert kwargs["headers"]["Authorization"] == "synthetic-unit-token:8"
        assert kwargs["allow_redirects"] is False
        assert proto_min.decode_all(kwargs["data"])[1] == [7]
    session_fields = proto_min.decode_all(calls[0][1]["data"])
    assert [proto_min.decode(raw)[1] for raw in session_fields[2]] == [11, 22]
    offline = proto_min.decode(proto_min.decode_all(calls[1][1]["data"])[2][0])
    assert offline[2] == b"unit-index" and offline[3] == 1 and offline[4] == 1000 and offline[5] == 1


def test_transport_errors_hide_exception_detail_and_credentials():
    def post(*args, **kwargs):
        raise requests.ConnectionError("synthetic-unit-token and sensitive response")
    client = SecurityChannelClient("https://unit.invalid", "synthetic-unit-token", 8, post=post)
    with pytest.raises(ChannelRequestError) as failure:
        client.health()
    assert "synthetic-unit-token" not in str(failure.value)
    assert "sensitive response" not in str(failure.value)


def _broadcast_config():
    return {
        "user_id": 7, "user_id2": 8, "channel_id": 11,
        "channel_message_id": "fixed-broadcast", "broadcast_confirmed": True,
    }


class _BroadcastChannelFake:
    def __init__(self, message):
        self.message = message
        self.by_id_reply = ChannelReply(200, 0, messages=(message,))
        self.offline_calls = []

    def sessions(self, channel_ids=(), version="v1"):
        rows = (ChannelSession(11, "", self.message),) if channel_ids else ()
        return ChannelReply(200, 0, sessions=rows)

    def by_id(self, channel_id, msg_ids, version="v1"):
        return self.by_id_reply

    def offline(self, channel_ids, version="v1", **kwargs):
        self.offline_calls.append((channel_ids, version, kwargs))
        return ChannelReply(200, 0, messages=(self.message,))


def _fixed_broadcast():
    return ChannelMessage(11, "fixed-broadcast", b"synthetic-broadcast", "507f1f77bcf86cd799439011")


@pytest.mark.parametrize("missing", ("channel_message_id", "broadcast_confirmed"))
def test_missing_broadcast_evidence_skips_before_any_request(monkeypatch, missing):
    from im_test.tests.security import test_channel_access as access

    config = _broadcast_config()
    config.pop(missing)

    def unexpected_client(*args, **kwargs):
        pytest.fail("缺少广播证据时不应创建或调用环境客户端")

    monkeypatch.setattr(access, "_client", unexpected_client)
    with pytest.raises(pytest.skip.Exception):
        access._prepare_channel_baseline(config, "v1", lambda *args: None)


def test_fixed_broadcast_not_found_is_failure_instead_of_skip(monkeypatch):
    from im_test.tests.security import test_channel_access as access

    fake = _BroadcastChannelFake(_fixed_broadcast())
    fake.by_id_reply = ChannelReply(200, 0, missing=("fixed-broadcast",))
    monkeypatch.setattr(access, "_client", lambda *args, **kwargs: fake)
    with pytest.raises(AssertionError, match="正控消息"):
        access._prepare_channel_baseline(_broadcast_config(), "v1", lambda *args: None)


def test_broadcast_baseline_anchors_same_message_and_records_manual_evidence(monkeypatch):
    from im_test.tests.security import test_channel_access as access

    fixed = _fixed_broadcast()
    fake = _BroadcastChannelFake(fixed)
    properties = []
    monkeypatch.setattr(access, "_client", lambda *args, **kwargs: fake)
    _, _, sample = access._prepare_channel_baseline(
        _broadcast_config(), "v2", lambda name, value: properties.append((name, value))
    )
    assert sample == fixed
    assert fake.offline_calls == [([11], "v2", {
        "count": 1, "base_index": fixed.index, "is_contain": 1,
    })]
    assert ("vuln22_broadcast_fixture_confirmed", "true") in properties
    assert ("vuln22_broadcast_evidence", "operator_confirmed_prior_B_read_or_trusted_broadcast_record") in properties


def test_reaction_cannot_substitute_for_session_broadcast_positive_control(monkeypatch):
    from im_test.tests.security import test_channel_access as access

    reaction = ChannelMessage(11, "fixed-broadcast", b"synthetic-reaction", "507f1f77bcf86cd799439011", event_type=2)
    fake = _BroadcastChannelFake(reaction)
    monkeypatch.setattr(access, "_client", lambda *args, **kwargs: fake)
    with pytest.raises(AssertionError, match="普通消息"):
        access._prepare_channel_baseline(_broadcast_config(), "v1", lambda *args: None)


def test_nonmember_leak_at_same_broadcast_anchor_fails_the_real_case():
    from im_test.tests.security import test_channel_access as access

    fixed = _fixed_broadcast()
    leaking_outsider = _BroadcastChannelFake(fixed)
    with pytest.raises(AssertionError, match="非成员读取到了"):
        access.test_nonmember_cannot_read_private_channel(
            _broadcast_config(), "v2", (None, leaking_outsider, fixed), "offline", True
        )
    assert leaking_outsider.offline_calls == [([11], "v2", {
        "body_user_id": 7, "count": 1, "base_index": fixed.index, "is_contain": 1,
    })]
