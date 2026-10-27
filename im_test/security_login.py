"""Vuln20 登录探测：读取明确的业务 ACK，不把断连或超时视为鉴权成功。

与 im-gateway/server/im_protocol.go、server/new_websocket/im_message.go 对照：
TCP 与 WS 二进制消息均包含 4 字节长度前缀和 12 字节消息头。
本模块只登录并断开，不发消息、不回传推送 ACK；登录仍会改在线状态及踢线。
"""

from dataclasses import dataclass
import math
import socket
import ssl
import struct
import time
from urllib.parse import urlsplit
import uuid

import websocket

from im_test import frame, proto_min


CM_LOGIN = 0x0101
CM_LOGIN_ACK = 0x0102
NON_ERR = 0x8000
ERR_LOGIN_AUTH = 0x8101
_MAX_FRAME_SIZE = 1024 * 1024
_MAX_IGNORED_FRAMES = 128


class LoginProbeError(RuntimeError):
    """只包含固定诊断文本，避免网络异常带出 URL、响应或凭证。"""


@dataclass(frozen=True)
class LoginAck:
    user_id: int
    error_code: int


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LoginProbeError("等待登录 ACK 超时；此次探测失败")
    return remaining


def _parse_wire_frame(data):
    """严格校验完整的服务端帧，之后复用已有帧解析器。"""
    if not isinstance(data, bytes) or len(data) < 16:
        raise LoginProbeError("登录响应不是完整的二进制 IM 帧")
    length = struct.unpack(">I", data[:4])[0]
    if length < 12 or length > _MAX_FRAME_SIZE or length != len(data) - 4:
        raise LoginProbeError("登录响应长度前缀不合法")
    flags, app_id, command, body_len, seq = struct.unpack(">BBHII", data[4:16])
    if body_len != length - 12:
        raise LoginProbeError("登录响应 BodyLen 与帧长度不一致")
    parsed_command, body = frame.parse_frame(data)
    if parsed_command != command or len(body) != body_len:
        raise LoginProbeError("登录响应帧解析不一致")
    return command, body, seq, flags, app_id


def _validate_ack_varints(body):
    # CMLoginAck 的三个字段均为 varint。先检查边界，避免极简解码器将
    # 截断、非法 wire type 或超长 varint 当成一个可用的业务拒绝。
    offset = 0
    while offset < len(body):
        values = []
        for _ in range(2):
            value = 0
            for index in range(10):
                if offset >= len(body):
                    raise LoginProbeError("登录 ACK protobuf 已截断")
                byte = body[offset]
                offset += 1
                if index == 9 and byte > 1:
                    raise LoginProbeError("登录 ACK protobuf varint 溢出")
                value |= (byte & 0x7F) << (index * 7)
                if not byte & 0x80:
                    break
            else:
                raise LoginProbeError("登录 ACK protobuf varint 过长")
            values.append(value)
            if len(values) == 1 and (value >> 3 == 0 or value & 7 != 0):
                raise LoginProbeError("登录 ACK protobuf 字段类型不合法")


def _decode_login_ack(body):
    _validate_ack_varints(body)
    try:
        fields = proto_min.decode(body)
    except Exception:
        raise LoginProbeError("登录 ACK protobuf 解析失败") from None
    code = fields.get(2)
    uid = fields.get(1, 0)
    if not isinstance(code, int) or not isinstance(uid, int):
        raise LoginProbeError("登录 ACK 缺少数值错误码或身份字段")
    if uid >= 1 << 63 or code > 0x7FFFFFFF:
        raise LoginProbeError("登录 ACK 数值字段超出协议范围")
    if code == NON_ERR and uid <= 0:
        raise LoginProbeError("登录成功 ACK 未包含有效用户身份")
    return LoginAck(user_id=uid, error_code=code)


def _ack_from_frame(data, expected_seq):
    command, body, seq, flags, app_id = _parse_wire_frame(data)
    if command != CM_LOGIN_ACK:
        return None
    if seq != expected_seq or flags != frame.FLAGS or app_id != frame.APPID:
        raise LoginProbeError("登录 ACK 序号或协议头与本次请求不一致")
    return _decode_login_ack(body)


def _recv_exact(connection, count, deadline):
    chunks = []
    remaining = count
    while remaining:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(remaining)
        if not chunk:
            raise LoginProbeError("收到登录 ACK 前连接已关闭；此次探测失败")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_tcp_frame(connection, deadline):
    prefix = _recv_exact(connection, 4, deadline)
    length = struct.unpack(">I", prefix)[0]
    if length < 12 or length > _MAX_FRAME_SIZE:
        raise LoginProbeError("TCP 登录响应长度超出协议边界")
    return prefix + _recv_exact(connection, length, deadline)


def _open_tcp(url, timeout):
    try:
        target = urlsplit(url)
        port = target.port
        if (target.scheme not in ("tcp", "tls") or not target.hostname or not port
                or target.username or target.password or target.path not in ("", "/")
                or target.query or target.fragment):
            raise ValueError
    except Exception:
        raise LoginProbeError("TCP 入口配置应为 tcp://host:port 或 tls://host:port") from None
    connection = socket.create_connection((target.hostname, port), timeout=timeout)
    if target.scheme == "tls":
        try:
            connection = ssl.create_default_context().wrap_socket(
                connection, server_hostname=target.hostname
            )
        except Exception:
            connection.close()
            raise
    return connection


def login_once(url, user_id, token, *, transport="ws", client_type=2,
               timeout=10, app_version="9.9.9"):
    """发一次 CM_LOGIN，返回脱敏的 UID/错误码；任何传输异常均为失败。

    调用者必须先通过 dev 专用账号与写操作许可 fixture。每次新建连接，
    随机设备标识，退出时关闭连接；不会恢复或接管测试前的真实会话。
    """
    if transport not in ("ws", "tcp"):
        raise LoginProbeError("不支持的登录传输类型")
    if (not isinstance(user_id, int) or user_id <= 0 or not isinstance(token, str)
            or not token or not isinstance(client_type, int) or client_type not in (0, 1, 2)
            or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0):
        raise LoginProbeError("登录探测账号、端类型或超时配置不合法")
    if not isinstance(url, str) or not url:
        raise LoginProbeError("登录入口未配置")
    if transport == "ws":
        try:
            target = urlsplit(url)
            if (target.scheme not in ("ws", "wss") or not target.hostname
                    or target.username or target.password or target.fragment):
                raise ValueError
        except Exception:
            raise LoginProbeError("WS 入口配置应为无内嵌凭证的 ws:// 或 wss:// URL") from None

    connection = None
    deadline = time.monotonic() + timeout
    seq = 1
    request = frame.build_frame(CM_LOGIN, proto_min.cm_login(
        user_id, token, client_type,
        device_token="security-login-" + uuid.uuid4().hex,
        app_version=app_version,
    ), seq)
    try:
        if transport == "ws":
            connection = websocket.create_connection(url, timeout=_remaining(deadline))
            connection.settimeout(_remaining(deadline))
            connection.send_binary(request)
        else:
            connection = _open_tcp(url, _remaining(deadline))
            connection.settimeout(_remaining(deadline))
            connection.sendall(request)
        for _ in range(_MAX_IGNORED_FRAMES):
            if transport == "ws":
                connection.settimeout(_remaining(deadline))
                data = connection.recv()
                if not data:
                    raise LoginProbeError("收到登录 ACK 前 WS 已关闭；此次探测失败")
            else:
                data = _recv_tcp_frame(connection, deadline)
            ack = _ack_from_frame(data, seq)
            if ack is not None:
                return ack
        raise LoginProbeError("收到过多非登录帧，未获得本次登录 ACK")
    except LoginProbeError:
        raise
    except Exception:
        # 原始异常可能含带凭证的 URL、HTTP 401 响应或二进制消息，不回显。
        raise LoginProbeError("登录连接、传输或握手失败；未获得有效业务 ACK") from None
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
