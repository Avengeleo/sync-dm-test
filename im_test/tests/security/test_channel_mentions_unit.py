"""定向 @ 夹具发送层的纯本地协议与失败门禁测试，不读取环境凭证。"""

import socket
import struct
import traceback

import pytest

from im_test import frame, proto_min, security_channel_mentions as mentions


UID_A, UID_B, CHANNEL = 17, 29, 3781906774783802013
MSG_ID = "a" * 32
INDEX = "6a1b2c3d" + "0" * 16
DEVICE = "security-at-unit-" + "b" * 32


def _login(uid=UID_A, code=mentions.NON_ERR, seq=1, body=None):
    if body is None:
        body = proto_min._fv(1, uid) + proto_min._fv(2, code)
    return frame.build_frame(mentions.CM_LOGIN_ACK, body, seq)


def _radio(uid=UID_A, channel=CHANNEL, msg_id=MSG_ID, code=mentions.NON_ERR,
           seq=2, index="", body=None):
    if body is None:
        body = (proto_min._fv(1, uid) + proto_min._fv(2, channel)
                + proto_min._fs(3, msg_id) + proto_min._fv(4, 1793589198000)
                + proto_min._fv(5, code))
        if index:
            body += proto_min._fs(6, index)
    return frame.build_frame(mentions.RADIO_CHAT_ACK, body, seq)


class _WS:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.sent = []
        self.closed = False

    def getstatus(self):
        return 101

    def settimeout(self, timeout):
        assert timeout > 0

    def send_binary(self, data):
        self.sent.append(data)

    def recv(self):
        response = next(self.replies)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        self.closed = True


def _send(ws, **kwargs):
    options = dict(device_token=DEVICE, msg_id=MSG_ID, connect=lambda *a, **k: ws)
    options.update(kwargs)
    return mentions.send_directed_mention(
        "wss://dev.invalid/ws", UID_A, "unit-private-token", CHANNEL, UID_B,
        "unit-private-content", **options,
    )


def test_builder_writes_single_packed_target_and_no_forged_sender_or_at_all():
    body = mentions.build_radio_mention(CHANNEL, MSG_ID, UID_B, "hello @B")
    fields = proto_min.decode_all(body)
    assert set(fields) == {2, 3, 6, 10, 11}
    assert fields[2] == [CHANNEL] and fields[3] == [MSG_ID.encode()]
    assert fields[6] == [b"hello @B"] and fields[10] == [1]
    assert fields[11] == [proto_min._enc_varint(UID_B)]


@pytest.mark.parametrize("value", [0, -1, 1 << 63, True, "17", None, 1.2])
@pytest.mark.parametrize("field", ["channel_id", "target_uid"])
def test_builder_rejects_nonpositive_or_nonint64_identifiers(field, value):
    args = dict(channel_id=CHANNEL, msg_id=MSG_ID, target_uid=UID_B, content=b"hi")
    args[field] = value
    with pytest.raises(mentions.MentionSendError):
        mentions.build_radio_mention(**args)


@pytest.mark.parametrize("value", ["", "A" * 32, "a" * 31, "a" * 33, "g" * 32, None, 17])
def test_builder_rejects_invalid_message_id(value):
    with pytest.raises(mentions.MentionSendError):
        mentions.build_radio_mention(CHANNEL, value, UID_B, b"hi")


@pytest.mark.parametrize("content", ["", b"", None, 1, bytearray(b"hi"), b"x" * 16385, "\ud800"])
def test_builder_rejects_empty_oversized_or_invalid_content(content):
    with pytest.raises(mentions.MentionSendError):
        mentions.build_radio_mention(CHANNEL, MSG_ID, UID_B, content)


@pytest.mark.parametrize("index", ["", INDEX])
def test_sender_only_logs_in_and_sends_once_then_closes(index):
    ws = _WS([_login(), _radio(index=index)])
    result = _send(ws)
    assert result == mentions.MentionSendResult(MSG_ID, index, CHANNEL, UID_A, UID_B)
    assert ws.closed and len(ws.sent) == 2
    command, body, seq, _, _ = mentions._parse_wire_frame(ws.sent[0])
    fields = proto_min.decode(body)
    assert command == mentions.CM_LOGIN and seq == 1
    assert fields[1] == UID_A and fields[2] == b"unit-private-token"
    assert fields[3] == DEVICE.encode() and fields[8] == 2
    assert fields[6] == b"9.9.9" and set(fields) == {1, 2, 3, 6, 8}
    command, body, seq, _, _ = mentions._parse_wire_frame(ws.sent[1])
    assert command == mentions.RADIO_CHAT and seq == 2
    assert body == mentions.build_radio_mention(CHANNEL, MSG_ID, UID_B, "unit-private-content")
    assert "unit-private" not in repr(result) and DEVICE not in repr(result)


def test_factory_does_not_follow_redirects_or_disable_tls_verification():
    ws = _WS([_login(), _radio()])
    calls = []

    def connect(*args, **kwargs):
        calls.append((args, kwargs))
        return ws

    _send(ws, connect=connect)
    assert calls[0][1]["redirect_limit"] == 0
    assert "sslopt" not in calls[0][1]


@pytest.mark.parametrize("status", [302, 401, 200, None, "101"])
def test_nonupgraded_http_connection_never_receives_login_credentials(status):
    ws = _WS([_login(), _radio()])
    ws.getstatus = lambda: status
    with pytest.raises(mentions.MentionSendError, match="101"):
        _send(ws)
    assert ws.closed and not ws.sent


@pytest.mark.parametrize("mode", ["missing", "raises"])
def test_unverifiable_handshake_never_receives_login_credentials(mode):
    ws = _WS([_login(), _radio()])
    if mode == "missing":
        ws.getstatus = None
    else:
        def fail():
            raise RuntimeError("private-handshake-response")
        ws.getstatus = fail
    with pytest.raises(mentions.MentionSendError, match="不可验证") as error:
        _send(ws)
    assert ws.closed and not ws.sent
    assert "private-handshake-response" not in str(error.value)
    assert error.value.__suppress_context__


@pytest.mark.parametrize("phase", ["login", "message"])
def test_kick_notification_immediately_stops_without_relogin_or_resend(phase):
    kick = frame.build_frame(mentions.CM_KICKOUT_NOTIFICATION, b"private-kick-body", 99)
    replies = [kick, _login()] if phase == "login" else [_login(), kick, _radio()]
    ws = _WS(replies)
    with pytest.raises(mentions.MentionSendError, match="踢下线") as error:
        _send(ws)
    assert ws.closed and len(ws.sent) == (1 if phase == "login" else 2)
    assert "private-kick-body" not in str(error.value)


@pytest.mark.parametrize("reply", [
    _login(uid=UID_B), _login(code=0), _login(code=0x8101), _login(seq=2),
    _login(body=b""), _login(body=proto_min._fv(2, mentions.NON_ERR)),
    _login(body=proto_min._fv(1, UID_A)),
    _login(body=proto_min._fv(1, UID_A) + proto_min._fv(2, mentions.NON_ERR) + proto_min._fv(2, mentions.NON_ERR)),
    _login(body=b"\x10\x81"), _login(body=b"\x12\x01\x00"),
    _login(body=b"\x10" + b"\x80" * 10 + b"\x00"),
    _login(body=b"\x10" + b"\x80" * 9 + b"\x02"),
    b"", "private-text-response", socket.timeout("private-timeout"),
])
def test_bad_login_never_sends_a_business_message(reply):
    ws = _WS([reply])
    with pytest.raises(mentions.MentionSendError):
        _send(ws)
    assert ws.closed and len(ws.sent) == 1


@pytest.mark.parametrize("reply", [
    _radio(uid=UID_B), _radio(channel=CHANNEL + 1), _radio(msg_id="b" * 32),
    _radio(code=0), _radio(code=0x8503), _radio(seq=1),
    _radio(index="not-an-index"), _radio(index="A" * 24),
    _radio(body=b""), _radio(body=b"\x1a\x10a"),
    _radio(body=b"\x1a\x01\xff"),
    b"", "private-content", socket.timeout("private-timeout"),
])
def test_bad_radio_ack_fails_without_retry_or_additional_commands(reply):
    ws = _WS([_login(), reply])
    with pytest.raises(mentions.MentionSendError):
        _send(ws)
    assert ws.closed and len(ws.sent) == 2


@pytest.mark.parametrize("missing_field", [1, 2, 3, 4, 5])
def test_radio_ack_cannot_omit_any_required_success_or_correlation_field(missing_field):
    rows = {1: proto_min._fv(1, UID_A), 2: proto_min._fv(2, CHANNEL),
            3: proto_min._fs(3, MSG_ID), 4: proto_min._fv(4, 1793589198000),
            5: proto_min._fv(5, mentions.NON_ERR)}
    body = b"".join(value for field, value in rows.items() if field != missing_field)
    ws = _WS([_login(), _radio(body=body)])
    with pytest.raises(mentions.MentionSendError):
        _send(ws)
    assert ws.closed and len(ws.sent) == 2


@pytest.mark.parametrize("duplicate", [proto_min._fv(1, UID_A), proto_min._fv(2, CHANNEL),
                                      proto_min._fs(3, MSG_ID), proto_min._fv(4, 1),
                                      proto_min._fv(5, mentions.NON_ERR)])
def test_radio_ack_rejects_duplicate_single_value_fields(duplicate):
    _, body, _, _, _ = mentions._parse_wire_frame(_radio())
    ws = _WS([_login(), _radio(body=body + duplicate)])
    with pytest.raises(mentions.MentionSendError):
        _send(ws)
    assert ws.closed


def test_message_id_can_be_generated_without_widening_result_or_request(monkeypatch):
    class UUID:
        hex = MSG_ID

    monkeypatch.setattr(mentions.uuid, "uuid4", lambda: UUID())
    ws = _WS([_login(), _radio()])
    result = _send(ws, msg_id=None)
    assert result.msg_id == MSG_ID and len(ws.sent) == 2


@pytest.mark.parametrize("response", [
    _radio()[4:], _radio()[:-1], b"\x00\x00\x00\x01" + _radio()[4:],
    _radio()[:8] + struct.pack(">I", 999) + _radio()[12:],
    _radio()[:4] + b"\x13" + _radio()[5:],
    _radio()[:5] + b"\x12" + _radio()[6:],
    struct.pack(">I", 1024 * 1024 + 1) + _radio()[4:],
    frame.build_frame(mentions.RADIO_CHAT_ACK, b"x" * 65537, 2),
])
def test_malformed_headers_and_oversized_payloads_are_rejected(response):
    ws = _WS([_login(), response])
    with pytest.raises(mentions.MentionSendError):
        _send(ws)
    assert ws.closed


def test_unrelated_valid_frames_are_skipped_without_acknowledging_them():
    ignored = frame.build_frame(0x3004, b"unrelated-private-message", 99)
    ws = _WS([ignored, _login(), ignored, _radio()])
    assert _send(ws).msg_id == MSG_ID
    assert len(ws.sent) == 2 and ws.closed


def test_unrelated_frames_are_bounded():
    ignored = frame.build_frame(0x3004, b"message", 99)
    ws = _WS([ignored] * mentions._MAX_IGNORED_FRAMES + [_login()])
    with pytest.raises(mentions.MentionSendError, match="过多"):
        _send(ws)
    assert len(ws.sent) == 1 and ws.closed


def test_total_deadline_prevents_sending_after_login():
    ws = _WS([_login(), _radio()])
    clock = iter([0, 0, 0, 0, 11])
    with pytest.raises(mentions.MentionSendError, match="超时"):
        _send(ws, timeout=10, monotonic=lambda: next(clock))
    assert len(ws.sent) == 1 and ws.closed


@pytest.mark.parametrize("kwargs", [
    {"timeout": 0}, {"timeout": -1}, {"timeout": 121}, {"timeout": True},
    {"timeout": float("inf")}, {"timeout": float("nan")},
    {"device_token": ""}, {"device_token": "web"}, {"device_token": "a" * 257},
    {"device_token": "long-device-token\n"}, {"app_version": ""}, {"app_version": None},
])
def test_invalid_connection_options_fail_before_opening_socket(kwargs):
    calls = []
    with pytest.raises(mentions.MentionSendError):
        _send(None, connect=lambda *a, **k: calls.append(1), **kwargs)
    assert not calls


@pytest.mark.parametrize("url", ["https://dev.invalid/ws", "wss://", "wss://u:p@dev.invalid/", "wss://dev.invalid:bad/", "wss://dev.invalid/#private"])
def test_invalid_urls_fail_without_echoing_them(url):
    with pytest.raises(mentions.MentionSendError) as error:
        mentions.send_directed_mention(url, UID_A, "secret", CHANNEL, UID_B, "hi", device_token=DEVICE)
    assert url not in str(error.value)


def test_transport_exception_is_suppressed_and_does_not_expose_secrets():
    def fail(*args, **kwargs):
        raise RuntimeError("private-token private-content private-url")

    with pytest.raises(mentions.MentionSendError) as error:
        _send(None, connect=fail)
    rendered = "".join(traceback.format_exception(type(error.value), error.value, error.value.__traceback__))
    assert "private-token" not in rendered
    assert "private-content" not in rendered
    assert "private-url" not in rendered
    assert error.value.__suppress_context__


def test_send_failure_closes_and_does_not_resend():
    ws = _WS([_login()])

    def send(data):
        ws.sent.append(data)
        if len(ws.sent) == 2:
            raise RuntimeError("private-payload")

    ws.send_binary = send
    with pytest.raises(mentions.MentionSendError):
        _send(ws)
    assert ws.closed and len(ws.sent) == 2


def test_close_error_does_not_replace_success():
    ws = _WS([_login(), _radio()])

    def close():
        raise RuntimeError("private-close")

    ws.close = close
    assert _send(ws).msg_id == MSG_ID
