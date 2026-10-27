"""Vuln20 探测器纯本地测试：模拟传输，绝不访问真实环境。"""

import socket
import struct
import time

import pytest

from im_test import frame, proto_min, security_login
from im_test.security_login import (
    CM_LOGIN, CM_LOGIN_ACK, ERR_LOGIN_AUTH, NON_ERR, LoginAck, LoginProbeError,
)
from im_test.tests.security import test_login_uid


def _ack(uid=7, code=NON_ERR, seq=1):
    return frame.build_frame(
        CM_LOGIN_ACK, proto_min._fv(1, uid) + proto_min._fv(2, code), seq
    )


class _WebSocket:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        assert timeout > 0

    def send_binary(self, data):
        self.sent.append(data)

    def recv(self):
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        self.closed = True


class _Socket:
    def __init__(self, response):
        self.response = bytearray(response)
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        assert timeout > 0

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, count):
        # 每次至多返回两个字节，验证 TCP 拆包不会被误判成鉴权拒绝。
        chunk = bytes(self.response[:min(count, 2)])
        del self.response[:len(chunk)]
        return chunk

    def close(self):
        self.closed = True


def test_ws_uses_actual_login_wire_and_server_identity(monkeypatch):
    ws = _WebSocket([_ack()])
    monkeypatch.setattr(security_login.websocket, "create_connection", lambda *a, **k: ws)
    result = security_login.login_once("wss://dev.invalid/", 7, "unit-token", app_version="1.2.3")
    assert result == LoginAck(user_id=7, error_code=NON_ERR)
    command, body, seq, _, _ = security_login._parse_wire_frame(ws.sent[0])
    fields = proto_min.decode(body)
    assert command == CM_LOGIN and seq == 1
    assert fields[1] == 7 and fields[2] == b"unit-token"
    assert fields[3].startswith(b"security-login-")
    assert fields[6] == b"1.2.3" and fields[8] == 2
    assert ws.closed


def test_ws_explicit_business_rejection_is_returned(monkeypatch):
    ws = _WebSocket([_ack(uid=8, code=ERR_LOGIN_AUTH)])
    monkeypatch.setattr(security_login.websocket, "create_connection", lambda *a, **k: ws)
    result = security_login.login_once("ws://dev.invalid/", 8, "unit-token")
    assert result.error_code == ERR_LOGIN_AUTH
    assert ws.closed


@pytest.mark.parametrize("response", [b"", "not-binary", socket.timeout("private-response")])
def test_ws_close_text_and_timeout_are_failures(monkeypatch, response):
    ws = _WebSocket([response])
    monkeypatch.setattr(security_login.websocket, "create_connection", lambda *a, **k: ws)
    with pytest.raises(LoginProbeError):
        security_login.login_once("wss://dev.invalid/", 7, "unit-token")
    assert ws.closed


def test_handshake_error_cannot_leak_credentials_or_count_as_pass(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("HTTP 401 private-token private-response")

    monkeypatch.setattr(security_login.websocket, "create_connection", fail)
    with pytest.raises(LoginProbeError) as error:
        security_login.login_once("wss://dev.invalid/", 7, "private-token")
    assert "private-token" not in str(error.value)
    assert "private-response" not in str(error.value)
    assert error.value.__suppress_context__


def test_tcp_receives_partial_packets_using_length_prefix(monkeypatch):
    connection = _Socket(_ack())
    targets = []

    def connect(target, timeout):
        targets.append(target)
        return connection

    monkeypatch.setattr(security_login.socket, "create_connection", connect)
    result = security_login.login_once("tcp://dev.invalid:9000", 7, "unit-token", transport="tcp")
    assert result == LoginAck(user_id=7, error_code=NON_ERR)
    assert targets == [("dev.invalid", 9000)]
    assert security_login._parse_wire_frame(connection.sent[0])[0] == CM_LOGIN
    assert connection.closed


def test_tcp_close_before_complete_ack_is_failure(monkeypatch):
    connection = _Socket(_ack()[:-1])
    monkeypatch.setattr(security_login.socket, "create_connection", lambda *a, **k: connection)
    with pytest.raises(LoginProbeError):
        security_login.login_once("tcp://dev.invalid:9000", 7, "unit-token", transport="tcp")
    assert connection.closed


def test_tls_uses_default_certificate_verification(monkeypatch):
    connection = _Socket(_ack())
    wrapped = []

    class Context:
        def wrap_socket(self, raw, server_hostname):
            wrapped.append((raw, server_hostname))
            return raw

    monkeypatch.setattr(security_login.socket, "create_connection", lambda *a, **k: connection)
    monkeypatch.setattr(security_login.ssl, "create_default_context", Context)
    result = security_login.login_once("tls://dev.invalid:9443", 7, "unit-token", transport="tcp")
    assert result.error_code == NON_ERR
    assert wrapped == [(connection, "dev.invalid")]
    assert connection.closed


def test_unrelated_valid_frames_do_not_replace_login_ack(monkeypatch):
    ws = _WebSocket([frame.build_frame(0x0002, b"", 0), _ack()])
    monkeypatch.setattr(security_login.websocket, "create_connection", lambda *a, **k: ws)
    assert security_login.login_once("ws://dev.invalid/", 7, "unit-token").error_code == NON_ERR


@pytest.mark.parametrize("data", [
    _ack()[4:],
    b"\x00\x00\x00\x01" + _ack()[4:],
    _ack()[:-1],
    _ack()[:8] + struct.pack(">I", 999) + _ack()[12:],
    _ack(seq=2),
    frame.build_frame(CM_LOGIN_ACK, b"", 1),
    frame.build_frame(CM_LOGIN_ACK, proto_min._fv(2, NON_ERR), 1),
    frame.build_frame(CM_LOGIN_ACK, b"\x10\x81", 1),
    frame.build_frame(CM_LOGIN_ACK, b"\x12\x01\x01", 1),
    frame.build_frame(CM_LOGIN_ACK, b"\x10" + b"\x80" * 10 + b"\x00", 1),
])
def test_malformed_or_uncorrelated_ack_cannot_pass(data):
    with pytest.raises(LoginProbeError):
        security_login._ack_from_frame(data, 1)


def test_tcp_rejects_large_frame_before_reading_body():
    connection = _Socket(struct.pack(">I", security_login._MAX_FRAME_SIZE + 1))
    with pytest.raises(LoginProbeError):
        security_login._recv_tcp_frame(connection, time.monotonic() + 1)


def _config():
    return {
        "ws_url": "wss://dev.invalid/", "tcp_url": "", "user_id": 7,
        "token": "unit-a", "user_id2": 8, "token2": "unit-b",
        "client_type": 2, "timeout": 1, "app_version": "9.9.9",
    }


@pytest.mark.parametrize("results", [
    [LoginAck(7, ERR_LOGIN_AUTH)],  # 无效 A token 不能作为正控。
    [LoginAck(8, NON_ERR)],  # 成功码但身份错误。
    [LoginAck(7, NON_ERR), LoginAck(8, ERR_LOGIN_AUTH)],
    [LoginAck(7, NON_ERR), LoginAck(8, NON_ERR), LoginAck(8, NON_ERR)],
    [LoginAck(7, NON_ERR), LoginAck(8, NON_ERR), LoginAck(8, 0x8102)],
    [LoginAck(7, NON_ERR), LoginAck(8, NON_ERR), LoginAck(8, ERR_LOGIN_AUTH), LoginAck(7, ERR_LOGIN_AUTH)],
])
def test_real_case_never_passes_bad_controls_or_wrong_rejection(monkeypatch, results):
    sequence = iter(results)
    monkeypatch.setattr(test_login_uid, "_login", lambda *a, **k: next(sequence))
    with pytest.raises(AssertionError):
        test_login_uid.test_login_token_cannot_impersonate_other_uid(None, _config(), "ws")


def test_real_case_checks_token_before_and_after_impersonation(monkeypatch):
    results = iter([LoginAck(7, NON_ERR), LoginAck(8, NON_ERR),
                    LoginAck(8, ERR_LOGIN_AUTH), LoginAck(7, NON_ERR)])
    requests = []

    def login(config, transport, endpoint, uid, token):
        requests.append((uid, token))
        return next(results)

    monkeypatch.setattr(test_login_uid, "_login", login)
    test_login_uid.test_login_token_cannot_impersonate_other_uid(None, _config(), "ws")
    assert requests == [(7, "unit-a"), (8, "unit-b"), (8, "unit-a"), (7, "unit-a")]


def test_real_case_transport_failure_is_not_a_skip(monkeypatch):
    def fail(*args, **kwargs):
        raise LoginProbeError("模拟连接失败")

    monkeypatch.setattr(test_login_uid, "_login", fail)
    with pytest.raises(LoginProbeError):
        test_login_uid.test_login_token_cannot_impersonate_other_uid(None, _config(), "ws")
