"""Vuln45 fake-only 回归：旧漏洞、假正控、超时和旧队列保护均不得误通过。"""

from dataclasses import replace
from types import SimpleNamespace

import pytest
import requests

from im_test import proto_min as p
from im_test.security_key_identity import (
    APP_OFFLINE, CHAT_FORBIDDEN, FORBIDDEN, NON_ERR, PRIVATE_COMMANDS,
    KEY_DELIVER, KEY_NOTIFY, KEY_NOTIFY_ACK, KEY_REQUEST, KEY_REQUEST_ACK, KEY_RESPONSE,
    ExchangeRecord, KeyIdentityBlocked, KeyIdentityError, SecurityKeyIdentityClient,
    check_group_key_identity, check_group_nonmember_identity, check_private_key_forgery,
    check_private_key_positive, parse_exchange_reply, private_body,
)
from im_test.security_wire import SecurityWireError, WireEvent, fields, one, text


CONFIG = {"http_base": "https://unit.invalid", "ws_url": "wss://unit.invalid/ws", "timeout": 0.5,
          "user_id": 41, "user_id2": 42, "token": "PRIVATE_A_TOKEN", "token2": "PRIVATE_B_TOKEN",
          "key_group_id": 301, "key_nonmember_uid": 43, "client_type": 2}


class FakeClock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now

    def sleep(self, duration):
        self.now += duration


class Device:
    def __init__(self, user_id, slots=()):
        self.user_id, self.slots = user_id, slots

    def device_list(self):
        return SimpleNamespace(require_success=lambda owner: SimpleNamespace(
            devices=tuple(SimpleNamespace(client_type=slot) for slot in self.slots)))


class Backend:
    def __init__(self, vulnerable=None):
        self.vulnerable = vulnerable
        self.rows = {41: [], 42: []}
        self.events = {41: [], 42: []}
        self.sent, self.reads = [], []
        self.number = 0
        self.request_code = None
        self.no_insert = False
        self.no_consume = False
        self.no_notification = False
        self.no_private_downlink = False
        self.no_private_ack = False
        self.no_group_ack = False
        self.legal_group_code = NON_ERR
        self.explicit_private_rejection = False
        self.wrong_ack_id = False
        self.wrong_notify_marker = False

    def clients(self):
        backend = self

        class Client:
            def __init__(self, owner):
                self.user_id = owner

            def exchange_records(self):
                backend.reads.append(self.user_id)
                if len(backend.rows[self.user_id]) >= 500:
                    raise KeyIdentityBlocked("交换队列达到单页上限，无法精确观察；不清理旧记录")
                return tuple(backend.rows[self.user_id])

        return tuple(Client(owner) for owner in (41, 42))

    def devices(self, slots=()):
        return tuple(Device(owner, slots) for owner in (41, 42))

    def session(self, url, owner, token, **kwargs):
        return Session(self, owner)

    def append(self, owner, command, message_id, sender, body):
        self.rows[owner].append(ExchangeRecord(command, message_id, sender, 301, body))

    def remove(self, owner, message_id):
        if not self.no_consume:
            self.rows[owner] = [row for row in self.rows[owner] if row.msg_id != message_id]

    def kwargs(self):
        clock = FakeClock()
        return {"clients": self.clients(), "devices": self.devices(), "session_factory": self.session,
                "clock": clock, "sleep": clock.sleep}


class Session:
    def __init__(self, backend, owner):
        self.backend, self.owner, self.seq = backend, owner, 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def request(self, command, body, response_command):
        seq = self.send(command, body)
        event = self.wait(response_command, seq=seq)
        if event is None:
            raise SecurityWireError("fake 没有匹配响应")
        return event

    def send(self, command, body):
        self.seq += 1
        self.backend.sent.append((self.owner, command, body))
        backend = self.backend
        f = p.decode_all(body)
        if command == KEY_REQUEST:
            sender, group, msg_id = f[1][0], f[3][0], f[4][0].decode()
            key = p.decode_all(f[12][0])
            recipient, marker = key[1][0], key[2][0]
            code = (FORBIDDEN if sender != self.owner and backend.vulnerable != command
                    else CHAT_FORBIDDEN if recipient not in (41, 42) else backend.legal_group_code)
            code = backend.request_code if backend.request_code is not None else code
            ack = (p._fv(1, self.owner) + p._fv(2, group) + p._fs(3, "wrong" if backend.wrong_ack_id else msg_id)
                   + p._fv(4, 1234567) + p._fv(5, code))
            if not backend.no_group_ack:
                backend.events[self.owner].append(WireEvent(KEY_REQUEST_ACK, ack, self.seq))
            if code == NON_ERR and not backend.no_insert:
                delivered = (p._fv(1, sender) + p._fv(2, recipient) + p._fv(3, group)
                             + p._fs(4, msg_id) + p._fb(6, marker))
                backend.append(recipient, KEY_DELIVER, msg_id, sender, delivered)
        elif command == KEY_RESPONSE:
            sender, recipient, group, msg_id = f[1][0], f[2][0], f[3][0], f[4][0].decode()
            if sender != self.owner and backend.vulnerable not in (command, "forward_only_2303"):
                return self.seq
            backend.remove(sender if backend.vulnerable == command else self.owner, msg_id)
            if not backend.no_notification:
                backend.number += 1
                message_id = "server-notify-%d" % backend.number
                if backend.wrong_notify_marker:
                    body = body.replace(f[5][0], b"x" * len(f[5][0]))
                backend.append(recipient, KEY_NOTIFY, message_id, sender, body)
        elif command == KEY_NOTIFY_ACK:
            owner, msg_id = f[1][0], f[2][0].decode()
            if owner == self.owner or backend.vulnerable == command:
                backend.remove(owner if backend.vulnerable == command else self.owner, msg_id)
        elif command in PRIVATE_COMMANDS:
            claimed = f[1][0]
            forged = claimed != self.owner or (command in (101, 104) and f[2][0] != self.owner)
            if forged and backend.vulnerable != "private":
                if backend.explicit_private_rejection:
                    backend.events[self.owner].append(WireEvent(102 if command == 101 else 105,
                                                                p._fv(4, FORBIDDEN), self.seq))
                return self.seq
            if not backend.no_private_ack:
                code = APP_OFFLINE if command == 101 else NON_ERR
                backend.events[self.owner].append(WireEvent(102 if command == 101 else 105,
                                                            p._fv(4, code), self.seq))
            if command != 101 and not backend.no_private_downlink:
                backend.events[claimed].append(WireEvent(command, body, 0))
        return self.seq

    def wait(self, command, seq=None, timeout=None, predicate=None):
        for index, event in enumerate(self.backend.events[self.owner]):
            if event.command == command and (seq is None or event.seq == seq) and (predicate is None or predicate(event)):
                return self.backend.events[self.owner].pop(index)
        return None


def test_group_three_opcodes_use_observable_owned_records_and_consume_only_fixture():
    backend = Backend()
    old = ExchangeRecord(KEY_DELIVER, "old-record", 42, 999, b"NEVER_PARSE_OR_ACK_REAL_OLD_CONTENT")
    backend.rows[41].append(old)
    report = {}
    check_group_key_identity(CONFIG, report=report, **backend.kwargs())
    assert report["verification_status"] == "passed"
    assert report["commands"] == "0x2301,0x2303,0x2305"
    assert backend.rows == {41: [old], 42: []}
    assert not any(b"old-record" in body for _, _, body in backend.sent)
    # 2305 确认的是 server 生成的外层 UUID，而非原始 F。
    notifications = [p.decode_all(body)[2][0] for _, cmd, body in backend.sent if cmd == KEY_NOTIFY_ACK]
    assert notifications == [b"server-notify-1", b"server-notify-1"]


@pytest.mark.parametrize("command", (KEY_REQUEST, KEY_RESPONSE, KEY_NOTIFY_ACK))
def test_each_old_group_identity_vulnerability_is_detected(command):
    backend = Backend(vulnerable=command)
    with pytest.raises(KeyIdentityError):
        check_group_key_identity(CONFIG, **backend.kwargs())


def test_forged_2303_forwarding_is_detected_even_if_victim_record_remains():
    backend = Backend(vulnerable="forward_only_2303")
    with pytest.raises(KeyIdentityError, match="触发了本轮通知"):
        check_group_key_identity(CONFIG, **backend.kwargs())
    assert len(backend.rows[42]) == 1


@pytest.mark.parametrize("setting", ("no_insert", "no_consume", "no_notification"))
def test_missing_group_positive_control_is_blocked_never_passed(setting):
    backend = Backend()
    setattr(backend, setting, True)
    with pytest.raises(KeyIdentityBlocked):
        check_group_key_identity(CONFIG, **backend.kwargs())


@pytest.mark.parametrize("setting", ("wrong_ack_id", "wrong_notify_marker"))
def test_incorrect_group_correlations_fail(setting):
    backend = Backend()
    setattr(backend, setting, True)
    with pytest.raises(KeyIdentityError):
        check_group_key_identity(CONFIG, **backend.kwargs())


@pytest.mark.parametrize("slot", (0, 1))
def test_group_marker_never_reaches_an_existing_real_client(slot):
    backend = Backend()
    kwargs = backend.kwargs()
    kwargs["devices"] = backend.devices((slot,))
    with pytest.raises(KeyIdentityBlocked):
        check_group_key_identity(CONFIG, **kwargs)
    assert backend.sent == []


def test_group_full_queue_stops_before_sending_or_cleaning():
    backend = Backend()
    backend.rows[41] = [ExchangeRecord(KEY_DELIVER, "old-%d" % i, 42, 999, b"old") for i in range(500)]
    with pytest.raises(KeyIdentityBlocked):
        check_group_key_identity(CONFIG, **backend.kwargs())
    assert len(backend.rows[41]) == 500
    assert backend.sent == []


def test_group_missing_ack_is_blocked_without_resend():
    backend = Backend()
    backend.no_group_ack = True
    with pytest.raises(KeyIdentityBlocked):
        check_group_key_identity(CONFIG, **backend.kwargs())
    assert len(backend.sent) == 1


def test_group_environment_denial_on_legal_control_is_blocked():
    backend = Backend()
    backend.legal_group_code = CHAT_FORBIDDEN
    with pytest.raises(KeyIdentityBlocked):
        check_group_key_identity(CONFIG, **backend.kwargs())


def test_nonmember_negative_has_independent_legal_exchange_positive_control():
    backend = Backend()
    kwargs = backend.kwargs()
    kwargs.pop("clock")
    kwargs.pop("sleep")
    check_group_nonmember_identity(CONFIG, **kwargs)
    assert any(command == KEY_RESPONSE for _, command, _ in backend.sent)


def test_nonmember_missing_config_is_blocked_without_network():
    backend = Backend()
    with pytest.raises(KeyIdentityBlocked):
        check_group_nonmember_identity({**CONFIG, "key_nonmember_uid": None},
                                        clients=backend.clients(), devices=backend.devices(), session_factory=backend.session)
    assert backend.sent == []


def test_nonmember_independent_control_keeps_fixture_ids_on_incomplete_preparation():
    backend = Backend()
    backend.no_insert = True
    report = {}
    with pytest.raises(KeyIdentityBlocked):
        check_group_nonmember_identity(CONFIG, clients=backend.clients(), devices=backend.devices(),
                                        session_factory=backend.session, report=report)
    assert report["positive_control_fixture_message_id"]
    assert report["positive_control_rejected_message_id"]
    assert report["positive_control_attempt_id"]


@pytest.mark.parametrize("command", (104, 103, 106))
def test_private_web_same_owner_marker_route_is_a_real_positive(command):
    backend = Backend()
    check_private_key_positive(CONFIG, command, session_factory=backend.session)


@pytest.mark.parametrize("command", (104, 103, 106))
def test_private_success_ack_without_marker_route_is_blocked(command):
    backend = Backend()
    backend.no_private_downlink = True
    with pytest.raises(KeyIdentityBlocked):
        check_private_key_positive(CONFIG, command, session_factory=backend.session)


@pytest.mark.parametrize("command", PRIVATE_COMMANDS)
def test_private_negative_silence_never_means_rejection(command):
    backend = Backend()
    report = {}
    with pytest.raises(KeyIdentityBlocked):
        check_private_key_forgery(CONFIG, command, devices=backend.devices(), session_factory=backend.session,
                                  report=report)
    assert report["verification_status"] == "blocked"
    assert report["request_sequence"] == 1
    assert report["attempt_id"] and report["sent_at"]


@pytest.mark.parametrize("command", (104, 103, 106))
def test_private_cross_owner_marker_forwarding_fails(command):
    backend = Backend(vulnerable="private")
    with pytest.raises(KeyIdentityError):
        check_private_key_forgery(CONFIG, command, session_factory=backend.session)


@pytest.mark.parametrize("command", (104, 103, 106))
def test_private_explicit_rejection_still_requires_same_owner_positive(command):
    backend = Backend()
    backend.explicit_private_rejection = True
    backend.no_private_downlink = True
    with pytest.raises(KeyIdentityBlocked):
        check_private_key_forgery(CONFIG, command, session_factory=backend.session)


def test_101_without_app_can_only_be_entry_control_not_full_sync_pass():
    backend = Backend()
    with pytest.raises(KeyIdentityBlocked, match="App 离线 ACK"):
        check_private_key_positive(CONFIG, 101, devices=backend.devices(), session_factory=backend.session)


def test_101_never_sent_if_a_real_app_is_online():
    backend = Backend()
    with pytest.raises(KeyIdentityBlocked):
        check_private_key_positive(CONFIG, 101, devices=backend.devices((0,)), session_factory=backend.session)
    assert backend.sent == []


def test_private_builder_never_adds_keys_or_random_crypto_material():
    marker = b"opaque-test-marker"
    for command in PRIVATE_COMMANDS:
        parsed = p.decode_all(private_body(command, 41, 42, marker))
        assert parsed[5 if command in (101, 104) else 3] == [marker]
    with pytest.raises(KeyIdentityError):
        private_body(107, 41, 42, marker)


def _offline_reply(owner, correlation, rows=()):
    result = p._fv(1, owner) + p._fs(2, correlation)
    for row in rows:
        inner = (p._fv(1, row.command) + p._fb(2, row.body) + p._fs(3, row.msg_id)
                 + p._fv(4, row.from_id) + p._fv(5, row.group_id))
        result += p._fb(3, inner)
    return result


def test_exchange_http_read_never_carries_ack_and_hides_credentials():
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        parsed = fields(kwargs["data"], {1: 0, 2: 2, 4: 0, 5: 0})
        assert one(parsed, 4) == 500 and one(parsed, 5) == 2
        return SimpleNamespace(status_code=200, headers={"Content-Type": "application/x-protobuf"},
                               content=_offline_reply(41, text(parsed, 2)))

    client = SecurityKeyIdentityClient("https://unit.invalid", "PRIVATE_TOKEN", 41, post=post)
    assert client.exchange_records() == ()
    assert "PRIVATE_TOKEN" not in repr(client)
    assert calls[0][0].endswith("/offline/v1/exchange_key")
    assert calls[0][1]["allow_redirects"] is False


@pytest.mark.parametrize("failure", ("network", "http", "html", "identity", "correlation", "duplicate", "truncated"))
def test_http_failure_or_malformed_reply_never_becomes_empty_queue(failure):
    secret = "PRIVATE_SECRET_BODY_TOKEN"

    def post(url, **kwargs):
        if failure == "network":
            raise requests.RequestException(secret)
        parsed = p.decode_all(kwargs["data"])
        row = ExchangeRecord(KEY_DELIVER, "old", 42, 301, b"SECRET_REAL_KEY_BODY")
        raw = _offline_reply(42 if failure == "identity" else 41,
                             "wrong" if failure == "correlation" else parsed[2][0].decode(),
                             (row, row) if failure == "duplicate" else ())
        if failure == "truncated":
            raw += b"\x1a\x10short"
        return SimpleNamespace(status_code=503 if failure == "http" else 200,
                               headers={"Content-Type": "text/html" if failure == "html" else "application/x-protobuf"},
                               content=raw)

    client = SecurityKeyIdentityClient("https://unit.invalid", secret, 41, post=post)
    with pytest.raises((KeyIdentityError, SecurityWireError)) as exc:
        client.exchange_records()
    assert secret not in str(exc.value)
    assert "SECRET_REAL_KEY_BODY" not in str(exc.value)


def test_offline_parser_limit_and_hidden_content():
    row = ExchangeRecord(KEY_DELIVER, "old", 42, 301, b"PRIVATE_REAL_KEY_BODY")
    assert "PRIVATE_REAL_KEY_BODY" not in repr(row)
    rows = tuple(replace(row, msg_id="old-%d" % i) for i in range(500))
    with pytest.raises(KeyIdentityBlocked):
        parse_exchange_reply(_offline_reply(41, "request", rows), 41, "request")


@pytest.mark.parametrize("url", ("https://user:secret@unit.invalid", "https://unit.invalid?token=secret", "file:///private"))
def test_http_constructor_rejects_secret_bearing_or_invalid_urls(url):
    with pytest.raises(KeyIdentityError) as exc:
        SecurityKeyIdentityClient(url, "SECRET_TOKEN", 41)
    assert "secret" not in str(exc.value)


def test_live_wrapper_hides_unclassified_third_party_exception_and_marks_failed():
    from im_test.tests.security.test_key_identity import _run

    def probe(*args, **kwargs):
        raise requests.RequestException("PRIVATE_TOKEN_KEY_CONTENT")

    request = SimpleNamespace(node=SimpleNamespace(user_properties=[]))
    with pytest.raises(pytest.fail.Exception) as exc:
        _run(probe, CONFIG, request)
    assert "PRIVATE_TOKEN_KEY_CONTENT" not in str(exc.value)
    assert ("vuln45_verification_status", "failed") in request.node.user_properties
    assert not any("PRIVATE_" in str(item) for item in request.node.user_properties)


def test_live_wrapper_keeps_no_ack_as_blocked_and_preserves_safe_attempt_metadata():
    from im_test.tests.security.test_key_identity import _run

    def probe(*args, report, **kwargs):
        report["attempt_id"] = "safe-test-attempt"
        raise KeyIdentityBlocked("无明确拒绝 ACK，保持受阻")

    request = SimpleNamespace(node=SimpleNamespace(user_properties=[]))
    with pytest.raises(pytest.skip.Exception):
        _run(probe, CONFIG, request)
    assert ("vuln45_verification_status", "blocked") in request.node.user_properties
    assert ("vuln45_attempt_id", "safe-test-attempt") in request.node.user_properties
