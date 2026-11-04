"""44/45 专用有界连接层：只显式发包，不自动 ACK、重登或重发。

回应帧按请求序号匹配；异步下行使用自己的协议头，缓存后交给调用方。
超时只返回未观察到事件，不能作为安全拒绝已经通过的证据。
"""

from dataclasses import dataclass, field
import math
import socket
import struct
import time
from urllib.parse import urlsplit
import uuid

import websocket

from im_test import frame, proto_min
from im_test.security_login import _open_tcp, _parse_wire_frame, CM_LOGIN, CM_LOGIN_ACK, NON_ERR


MAX_BODY = 1024 * 1024
MAX_EVENTS = 256


class SecurityWireError(RuntimeError):
    """固定诊断信息，不回显 URL、凭证、正文、密钥或原始异常。"""


def uid(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < (1 << 63)


def _varint(data, offset):
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise SecurityWireError("44/45 protobuf 数值字段被截断")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise SecurityWireError("44/45 protobuf 数值超出协议边界")
        value |= (byte & 127) << (index * 7)
        if not byte & 128:
            return value, offset
    raise SecurityWireError("44/45 protobuf 数值字段过长")


def fields(raw, schema, repeated=()):
    """严格的最小 protobuf 解码；所有值保留为列表，不丢失重复字段。"""
    if not isinstance(raw, bytes) or len(raw) > MAX_BODY:
        raise SecurityWireError("44/45 protobuf 类型或大小不合法")
    result, offset = {}, 0
    while offset < len(raw):
        tag, offset = _varint(raw, offset)
        number, wire = tag >> 3, tag & 7
        if not number or number > (1 << 29) - 1 or schema.get(number) != wire:
            raise SecurityWireError("44/45 protobuf 字段或类型不符合协议")
        if number in result and number not in repeated:
            raise SecurityWireError("44/45 protobuf 含重复单值字段")
        if wire == 0:
            value, offset = _varint(raw, offset)
        elif wire == 2:
            size, offset = _varint(raw, offset)
            if size > len(raw) - offset:
                raise SecurityWireError("44/45 protobuf 长度字段被截断")
            value = raw[offset:offset + size]
            offset += size
        else:
            raise SecurityWireError("44/45 protobuf 字段类型不受支持")
        result.setdefault(number, []).append(value)
    return result


def one(parsed, number, default=None):
    values = parsed.get(number, ())
    return values[0] if values else default


def text(parsed, number, default=""):
    value = one(parsed, number)
    if value is None:
        return default
    try:
        return value.decode("utf-8")
    except (AttributeError, UnicodeError):
        raise SecurityWireError("44/45 protobuf 文本不是有效 UTF-8") from None


@dataclass(frozen=True)
class WireEvent:
    command: int
    body: bytes = field(repr=False)
    seq: int = 0
    flags: int = 0
    app_id: int = 0


class WireSession:
    """一个专用账号的显式连接；退出只关闭连接，不发 logout。"""

    def __init__(self, url, user_id, token, *, transport="ws", client_type=2,
                 timeout=10, app_version="9.9.9", connect=None, monotonic=None):
        try:
            token_ok = isinstance(token, str) and bool(token) and len(token.encode("utf-8")) <= 16384
        except UnicodeError:
            token_ok = False
        if (not uid(user_id) or not isinstance(token, str) or not token
                or not token_ok
                or transport not in ("ws", "tcp") or client_type not in (0, 1, 2)
                or isinstance(client_type, bool) or isinstance(timeout, bool)
                or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 120 or not isinstance(app_version, str)
                or not app_version or len(app_version) > 64):
            raise SecurityWireError("44/45 连接身份、端类型或超时配置不合法")
        try:
            parsed = urlsplit(url)
            parsed.port
            schemes = ("ws", "wss") if transport == "ws" else ("tcp", "tls")
            valid = (parsed.scheme in schemes and parsed.hostname and parsed.username is None
                     and parsed.password is None and not parsed.fragment)
            if transport == "tcp":
                valid = valid and parsed.port and parsed.path in ("", "/") and not parsed.query
            if not valid:
                raise ValueError
        except Exception:
            raise SecurityWireError("44/45 连接地址格式不合法") from None
        self.user_id, self.client_type, self.timeout = user_id, client_type, timeout
        self._url, self._token, self._transport = url, token, transport
        self._version, self._connect = app_version, connect
        self._clock = monotonic or time.monotonic
        self._connection, self._seq = None, 0
        self._pending, self._buffer = [], b""

    def __repr__(self):
        return "WireSession(<专用连接配置已隐藏>)"

    def __enter__(self):
        if self._connection is not None:
            raise SecurityWireError("44/45 连接不能重复打开")
        try:
            if self._connect:
                self._connection = self._connect(self._url, timeout=self.timeout)
            elif self._transport == "ws":
                self._connection = websocket.create_connection(self._url, timeout=self.timeout)
            else:
                self._connection = _open_tcp(self._url, self.timeout)
            body = proto_min.cm_login(self.user_id, self._token, self.client_type,
                                      device_token="security-44-45-" + uuid.uuid4().hex,
                                      app_version=self._version)
            event = self.request(CM_LOGIN, body, CM_LOGIN_ACK)
            parsed = fields(event.body, {1: 0, 2: 0, 3: 0})
            if one(parsed, 1) != self.user_id or one(parsed, 2) != NON_ERR:
                raise SecurityWireError("44/45 专用账号登录未返回本人成功 ACK；停止且不重登")
            return self
        except SecurityWireError:
            self.close()
            raise
        except Exception:
            self.close()
            raise SecurityWireError("44/45 连接或登录失败；停止且不重试") from None

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
        self._connection = None

    def send(self, command, body):
        if (self._connection is None or not isinstance(body, bytes) or len(body) > MAX_BODY
                or not isinstance(command, int) or isinstance(command, bool)
                or not 0 < command <= 0xFFFF or self._seq >= 0xFFFFFFFF):
            raise SecurityWireError("44/45 发包前置或协议参数不合法")
        self._seq += 1
        packet = frame.build_frame(command, body, self._seq)
        try:
            self._connection.settimeout(self.timeout)
            if self._transport == "ws":
                self._connection.send_binary(packet)
            else:
                self._connection.sendall(packet)
        except Exception:
            raise SecurityWireError("44/45 发包结果不确定；停止，不自动重发") from None
        return self._seq

    def _read(self, timeout):
        deadline = self._clock() + timeout
        try:
            if self._transport == "ws":
                self._connection.settimeout(timeout)
                raw = self._connection.recv()
            else:
                while True:
                    if len(self._buffer) >= 4:
                        length = struct.unpack(">I", self._buffer[:4])[0]
                        if not 12 <= length <= MAX_BODY + 12:
                            raise SecurityWireError("44/45 TCP 帧长度超出协议边界")
                        if len(self._buffer) >= length + 4:
                            raw, self._buffer = self._buffer[:length + 4], self._buffer[length + 4:]
                            break
                    remaining = deadline - self._clock()
                    if remaining <= 0:
                        return None
                    self._connection.settimeout(remaining)
                    chunk = self._connection.recv(min(65536, MAX_BODY + 16 - len(self._buffer)))
                    if not chunk:
                        raise SecurityWireError("44/45 TCP 连接已关闭；不能当作安全拒绝")
                    self._buffer += chunk
            if not raw:
                raise SecurityWireError("44/45 连接已关闭；不能当作安全拒绝")
            command, body, seq, flags, app_id = _parse_wire_frame(raw)
            if command == 0x0108:
                raise SecurityWireError("44/45 会话收到踢线通知；停止且不重登")
            return WireEvent(command, body, seq, flags, app_id)
        except (socket.timeout, TimeoutError, websocket.WebSocketTimeoutException):
            return None
        except SecurityWireError:
            raise
        except Exception:
            raise SecurityWireError("44/45 收包或帧解析失败；不能当作安全拒绝") from None

    def wait(self, command, seq=None, timeout=None, predicate=None):
        if self._connection is None:
            raise SecurityWireError("44/45 连接尚未打开")
        duration = self.timeout if timeout is None else timeout
        if (isinstance(duration, bool) or not isinstance(duration, (int, float))
                or not math.isfinite(duration) or not 0 < duration <= 120):
            raise SecurityWireError("44/45 等待时限不合法")
        deadline = self._clock() + duration

        def match(event):
            if event.command != command or (seq is not None and event.seq != seq):
                return False
            if seq is not None and (event.flags != frame.FLAGS or event.app_id != frame.APPID):
                raise SecurityWireError("44/45 回应协议头与请求不一致")
            return predicate is None or predicate(event)

        for index, event in enumerate(self._pending):
            if match(event):
                return self._pending.pop(index)
        while True:
            remaining = deadline - self._clock()
            if remaining <= 0:
                return None
            event = self._read(remaining)
            if event is None:
                return None
            if match(event):
                return event
            if len(self._pending) >= MAX_EVENTS:
                raise SecurityWireError("44/45 无关下行超出有界缓存；停止且不自动 ACK")
            self._pending.append(event)

    def request(self, command, body, response_command):
        seq = self.send(command, body)
        event = self.wait(response_command, seq=seq)
        if event is None:
            raise SecurityWireError("44/45 未收到匹配业务 ACK；结果不确定，不能自动重发")
        return event
