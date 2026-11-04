"""44/45连接层纯本地回归，不打开网络连接。"""

import socket
import struct

import pytest

from im_test import frame, proto_min as p
from im_test.security_wire import SecurityWireError, WireSession, fields, one, text


def packet(command, body, seq, flags=frame.FLAGS, app_id=frame.APPID):
    return struct.pack(">IBBHII", len(body) + 12, flags, app_id, command, len(body), seq) + body


class Connection:
    def __init__(self, incoming):
        self.incoming = list(incoming)
        self.sent = []
        self.closed = False

    def recv(self, *_):
        if not self.incoming:
            raise socket.timeout()
        item = self.incoming.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def settimeout(self, _):
        pass

    def send_binary(self, raw):
        self.sent.append(raw)

    sendall = send_binary

    def close(self):
        self.closed = True


def login():
    return packet(0x0102, p._fv(1, 7) + p._fv(2, 0x8000), 1)


def session(connection, **kwargs):
    return WireSession("wss://unit.invalid", 7, "unit-secret-token",
                       connect=lambda *a, **k: connection, **kwargs)


def test_push_with_its_own_header_is_cached_before_matching_response():
    connection = Connection([login(), packet(0x1004, b"push", 0, flags=0, app_id=0),
                             packet(0x1002, b"ack", 2)])
    with session(connection) as wire:
        event = wire.request(0x1001, b"request", 0x1002)
        assert event.body == b"ack" and event.seq == 2
        push = wire.wait(0x1004, timeout=0.01)
        assert push.body == b"push" and push.flags == 0
    assert len(connection.sent) == 2 and connection.closed


def test_wrong_sequence_is_not_accepted_and_old_response_stays_available():
    connection = Connection([login(), packet(0x1002, b"old", 99), packet(0x1002, b"new", 2)])
    with session(connection) as wire:
        assert wire.request(0x1001, b"request", 0x1002).body == b"new"
        assert wire.wait(0x1002, seq=99).body == b"old"


def test_ack_with_wrong_header_fails_without_automatic_resend():
    connection = Connection([login(), packet(0x1002, b"ack", 2, flags=0)])
    with session(connection) as wire:
        with pytest.raises(SecurityWireError):
            wire.request(0x1001, b"request", 0x1002)
    assert len(connection.sent) == 2


def test_timeout_means_inconclusive_and_does_not_resend_or_ack():
    connection = Connection([login()])
    with session(connection) as wire:
        assert wire.wait(104, timeout=0.01) is None
        with pytest.raises(SecurityWireError, match="不能自动重发"):
            wire.request(104, b"unit-marker", 105)
    assert len(connection.sent) == 2


@pytest.mark.parametrize("bad", [b"", "text", packet(0x0108, b"", 0),
                                 b"\x00\x00\x00\x0c" + b"\x00" * 4])
def test_close_kick_and_broken_frames_are_not_denials(bad):
    connection = Connection([login(), bad])
    with session(connection) as wire:
        with pytest.raises(SecurityWireError):
            wire.wait(104, timeout=0.01)


def test_tcp_partial_frames_and_combined_packets_are_preserved():
    data = login() + packet(0x1002, b"ok", 2)
    connection = Connection([data[:2], data[2:9], data[9:]])
    wire = WireSession("tcp://unit.invalid:9000", 7, "unit-token", transport="tcp",
                       connect=lambda *a, **k: connection)
    with wire:
        assert wire.request(0x1001, b"req", 0x1002).body == b"ok"
    assert len(connection.sent) == 2


def test_failed_login_closes_and_does_not_send_business_command():
    connection = Connection([packet(0x0102, p._fv(1, 7) + p._fv(2, 0x8101), 1)])
    with pytest.raises(SecurityWireError):
        with session(connection):
            pytest.fail("login must not succeed")
    assert connection.closed and len(connection.sent) == 1


@pytest.mark.parametrize("body", [b"\x80", b"\x0a\x04x", b"\x08\x01\x08\x02",
                                  b"\x00\x00", b"\x0d0000", b"\x10\xff" * 10])
def test_strict_protobuf_rejects_malformed_and_duplicate_fields(body):
    with pytest.raises(SecurityWireError):
        fields(body, {1: 0})


def test_protobuf_repeated_and_default_values_are_not_confused():
    parsed = fields(p._fv(1, 0) + p._fs(2, "a") + p._fs(2, "b"), {1: 0, 2: 2}, repeated=(2,))
    assert one(parsed, 1) == 0 and parsed[2] == [b"a", b"b"]
    assert text(parsed, 3, "missing") == "missing"


def test_connection_and_event_repr_do_not_expose_secrets():
    connection = Connection([login(), packet(104, b"unit-private-key", 0)])
    with session(connection) as wire:
        assert "unit-secret-token" not in repr(wire)
        assert "unit-private-key" not in repr(wire.wait(104))


def test_transport_exception_is_sanitized():
    connection = Connection([login(), RuntimeError("unit-secret-token")])
    with session(connection) as wire:
        with pytest.raises(SecurityWireError) as error:
            wire.wait(104)
    assert "unit-secret-token" not in str(error.value)
