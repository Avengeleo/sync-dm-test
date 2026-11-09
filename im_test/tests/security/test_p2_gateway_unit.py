"""V86有界驱动与WS压缩解析的本地替身回归。"""
import socket
import struct
import zlib

import pytest
from im_test import frame
from im_test import security_gateway_p2 as gw
from im_test.security_p2_config import P2Blocked, P2Error
from im_test.tests.security.test_p2_group_unit import config


def cfg(kind="ws"):
    result = config()
    result.update(p2_transport=kind, tcp_url="tcp://unit.invalid:1234", p2_frame_limit=64, p2_rate=2)
    return result


class Connection:
    def __init__(self, config, compressed=False):
        self.config, self.sent, self.packets, self.closed = config, [], [], False
        self.conn = self
    def __enter__(self):
        return self
    def __exit__(self, *_):
        self.closed = True
    def send(self, command, body=b"", **kwargs):
        self.sent.append((command, body, kwargs))
        return len(self.sent)
    def packet(self, raw, **kwargs):
        self.packets.append(raw)
    def wait(self, cmd, seq):
        assert cmd == 2 and seq == 1
        return b""
    def receive(self):
        raise gw.Closed(1009 if self.config["p2_transport"] == "ws" else None)
    def settimeout(self, value):
        assert value > 0


@pytest.mark.parametrize("kind,case", [(k, c) for k in ("ws", "tcp") for c in gw.CASES if k == "ws" or c != "compressed"])
def test_gateway_driver_is_single_connection_and_bounded(kind, case):
    instances = []
    def factory(*args, **kwargs):
        conn = Connection(*args, **kwargs); instances.append(conn); return conn
    result = gw.run_gateway_case(cfg(kind), case, connection_factory=factory, preflight=lambda *_: None)
    assert result["evidence"] and len(instances) == 1 and instances[0].closed
    conn = instances[0]
    assert len(conn.sent) <= 6
    if kind == "tcp" and case == "oversize":
        assert conn.packets == [struct.pack(">I", 65)] and not conn.sent
    if kind == "ws" and case in ("oversize", "fragmented", "compressed"):
        assert len(conn.sent[0][1]) + 12 == 65


@pytest.mark.parametrize("case", ("oversize", "rate"))
def test_gateway_timeout_never_passes(case):
    class Timeout(Connection):
        def receive(self):
            raise socket.timeout()
    with pytest.raises(P2Error):
        gw.run_gateway_case(cfg(), case, connection_factory=Timeout, preflight=lambda *_: None)


def test_unrelated_close_code_does_not_pass_size_check():
    class Policy(Connection):
        def receive(self):
            raise gw.Closed(1008)
    with pytest.raises(P2Error):
        gw.run_gateway_case(cfg(), "oversize", connection_factory=Policy, preflight=lambda *_: None)


@pytest.mark.parametrize("key,case,value", [("p2_frame_limit", "oversize", 0), ("p2_frame_limit", "compressed", 1 << 30), ("p2_rate", "rate", 0), ("p2_rate", "rate", 501)])
def test_missing_actual_limits_block_before_connection(key, case, value):
    config = cfg(); config[key] = value
    with pytest.raises(P2Blocked):
        gw.run_gateway_case(config, case, connection_factory=lambda *a, **k: pytest.fail("must not connect"), preflight=lambda *_: None)


def test_rate_control_stops_if_no_real_burst_was_formed():
    tick = iter([0, 2])
    with pytest.raises(P2Blocked):
        gw.run_gateway_case(cfg(), "rate", connection_factory=Connection, preflight=lambda *_: None, clock=lambda: next(tick))


def test_other_kick_event_cannot_be_misreported_as_rate_limit():
    class Kicked(Connection):
        def receive(self):
            return 0x0108, b"", 0, 0, 0
    with pytest.raises(P2Error):
        gw.run_gateway_case(cfg(), "rate", connection_factory=Kicked, preflight=lambda *_: None)


class Socket:
    def __init__(self, data):
        self.data = data
    def recv(self, count):
        result, self.data = self.data[:count], self.data[count:]
        return result


def ws_packet(data, fin=True, opcode=2, compressed=False):
    size = bytes([len(data)]) if len(data) < 126 else b"\x7e" + struct.pack(">H", len(data))
    return bytes([(128 if fin else 0) | (64 if compressed else 0) | opcode]) + size + data


def test_actual_ws_reader_handles_compression_and_fragmentation():
    raw = frame.build_frame(2, b"test", 7)
    compressor = zlib.compressobj(wbits=-15)
    compressed = (compressor.compress(raw) + compressor.flush(zlib.Z_SYNC_FLUSH))[:-4]
    conn = gw.ProbeConnection(cfg(), compressed=True)
    from types import SimpleNamespace
    conn.conn = SimpleNamespace(sock=Socket(ws_packet(compressed[:3], fin=False, compressed=True) + ws_packet(compressed[3:], opcode=0)))
    assert conn.receive()[:3] == (2, b"test", 7)


def test_actual_ws_reader_rejects_bomb_and_unnegotiated_compression():
    compressor = zlib.compressobj(wbits=-15)
    payload = (compressor.compress(b"x" * (gw.MAX_REPLY + 1)) + compressor.flush(zlib.Z_SYNC_FLUSH))[:-4]
    from types import SimpleNamespace
    for negotiated in (False, True):
        conn = gw.ProbeConnection(cfg(), compressed=negotiated)
        conn.conn = SimpleNamespace(sock=Socket(ws_packet(payload, compressed=True)))
        with pytest.raises(P2Error):
            conn.receive()

@pytest.mark.parametrize("wrong", ("uid", "code", "disconnect"))
def test_actual_tcp_login_failure_is_never_size_or_rate_success(monkeypatch, wrong):
    from im_test import proto_min as p
    body = p._fv(1, 99 if wrong == "uid" else 11) + p._fv(2, 0x8101 if wrong == "code" else 0x8000)
    class TCP(Socket):
        closed = False
        def settimeout(self, _): pass
        def sendall(self, _): pass
        def close(self): self.closed = True
    sock = TCP(b"" if wrong == "disconnect" else frame.build_frame(0x0102, body, 1))
    monkeypatch.setattr(gw, "_open_tcp", lambda *a: sock)
    with pytest.raises(P2Error):
        with gw.ProbeConnection(cfg("tcp")):
            pytest.fail("failed login must not enter the probe")
    assert sock.closed


def test_missing_compression_negotiation_blocks_before_login(monkeypatch):
    class WS:
        closed = False
        def getheaders(self): return {}
        def close(self): self.closed = True
    conn = WS()
    monkeypatch.setattr(gw.websocket, "create_connection", lambda *a, **k: conn)
    with pytest.raises(P2Blocked):
        with gw.ProbeConnection(cfg(), compressed=True):
            pytest.fail("unnegotiated compression must not run")
    assert conn.closed
