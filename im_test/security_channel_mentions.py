"""Vuln42 专用频道定向 @ 夹具的最小 WS 发送层。

只发送 Web 登录和一条普通频道消息，不发 logout、推送 token、下行 ACK
或已读同步。正常 Web 登录仍可能顶掉同槽会话，调用者必须先确认专用账号
没有在线 Web，并提供本次唯一设备标识。关闭连接只断线，不撤销登录凭证。

普通消息 ACK 先于 channel-job 异步落库，合法 ACK 可能没有 Mongo index。
发送成功不是夹具完成；调用者还必须通过可信 by_id 读取取得索引并检查 @。
此模块不重试、不自动重发，不保存或打印 token、正文和原始响应。
"""

from dataclasses import dataclass
import math
import re
import time
from urllib.parse import urlsplit
import uuid

import websocket

from im_test import frame, proto_min
from im_test.security_login import CM_LOGIN, CM_LOGIN_ACK, NON_ERR, _parse_wire_frame


RADIO_CHAT = 0x3001
RADIO_CHAT_ACK = 0x3002
CM_KICKOUT_NOTIFICATION = 0x0108
_MAX_IGNORED_FRAMES = 128
_MAX_CONTENT_BYTES = 16384
_MAX_TOKEN_BYTES = 16384
_MAX_ACK_BODY = 65536


class MentionSendError(RuntimeError):
    """固定诊断信息，不包含凭证、设备标识、URL、正文或原始异常。"""


@dataclass(frozen=True)
class MentionSendResult:
    msg_id: str
    index: str
    channel_id: int
    sender_uid: int
    target_uid: int


def _uid(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < (1 << 63)


def _msg_id(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def build_radio_mention(channel_id, msg_id, target_uid, content):
    """只构造一人定向 @；发送身份由登录网关注入，不提供伪造身份字段。"""
    if not _uid(channel_id) or not _uid(target_uid) or not _msg_id(msg_id):
        raise MentionSendError("定向 @ 的频道、目标身份或消息 ID 不合法")
    if isinstance(content, str):
        try:
            content = content.encode("utf-8")
        except UnicodeError:
            raise MentionSendError("定向 @ 正文不是合法 UTF-8") from None
    if not isinstance(content, bytes) or not content or len(content) > _MAX_CONTENT_BYTES:
        raise MentionSendError("定向 @ 正文为空、类型不合法或超出大小边界")
    return (
        proto_min._fv(2, channel_id)
        + proto_min._fs(3, msg_id)
        + proto_min._fb(6, content)
        + proto_min._fv(10, 1)
        + proto_min._fb(11, proto_min._enc_varint(target_uid))
    )


def _varint(data, offset):
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise MentionSendError("夹具 ACK protobuf 被截断")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise MentionSendError("夹具 ACK protobuf 数值溢出")
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, offset
    raise MentionSendError("夹具 ACK protobuf 数值过长")


def _fields(data, schema):
    if not isinstance(data, bytes) or len(data) > _MAX_ACK_BODY:
        raise MentionSendError("夹具 ACK protobuf 类型或大小不合法")
    offset, fields = 0, {}
    while offset < len(data):
        tag, offset = _varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number not in schema or wire != schema[number] or number in fields:
            raise MentionSendError("夹具 ACK protobuf 字段、类型或重复值不合法")
        if wire == 0:
            value, offset = _varint(data, offset)
        else:
            size, offset = _varint(data, offset)
            if size > len(data) - offset:
                raise MentionSendError("夹具 ACK protobuf 长度字段被截断")
            value = data[offset:offset + size]
            offset += size
        fields[number] = value
    return fields


def _string(fields, number):
    try:
        return fields.get(number, b"").decode("utf-8")
    except UnicodeError:
        raise MentionSendError("夹具 ACK 字符串不是合法 UTF-8") from None


def _remaining(deadline, monotonic):
    remaining = deadline - monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise MentionSendError("等待夹具业务 ACK 超时，发送状态需人工核对")
    return remaining


def _recv_ack(connection, expected_cmd, expected_seq, deadline, monotonic):
    for _ in range(_MAX_IGNORED_FRAMES):
        connection.settimeout(_remaining(deadline, monotonic))
        data = connection.recv()
        if not data:
            raise MentionSendError("收到夹具业务 ACK 前连接已关闭，发送状态需人工核对")
        try:
            command, body, seq, flags, app_id = _parse_wire_frame(data)
        except Exception:
            raise MentionSendError("夹具响应不是合法的有界二进制 IM 帧") from None
        if flags != frame.FLAGS or app_id != frame.APPID:
            raise MentionSendError("夹具响应协议头与本次请求不一致")
        if command == CM_KICKOUT_NOTIFICATION:
            raise MentionSendError("夹具会话收到踢下线通知，立即停止；不要自动重登或重发")
        if command != expected_cmd:
            continue
        if seq != expected_seq:
            raise MentionSendError("夹具业务 ACK 序号与本次请求不一致")
        return body
    raise MentionSendError("收到过多无关帧，未获得本次夹具业务 ACK")


def _login_ack(body, user_id):
    fields = _fields(body, {1: 0, 2: 0, 3: 0})
    if fields.get(1) != user_id or fields.get(2) != NON_ERR:
        raise MentionSendError("夹具登录未返回当前账号的明确成功 ACK")


def _radio_ack(body, user_id, channel_id, msg_id):
    fields = _fields(body, {1: 0, 2: 0, 3: 2, 4: 0, 5: 0, 6: 2, 7: 0})
    if (fields.get(1) != user_id or fields.get(2) != channel_id
            or _string(fields, 3) != msg_id or fields.get(5) != NON_ERR
            or not isinstance(fields.get(4), int) or fields[4] <= 0):
        raise MentionSendError("定向 @ 消息未返回匹配身份、频道和消息的明确成功 ACK")
    index = _string(fields, 6)
    if index and re.fullmatch(r"[0-9a-f]{24}", index) is None:
        raise MentionSendError("定向 @ 消息 ACK 返回了非法 Mongo 索引")
    return index


def _validate_connection(ws_url, user_id, token, target_uid, app_version, timeout, device_token):
    try:
        parsed = urlsplit(ws_url)
        # 显式读取 port，同样拒绝无法解析的端口配置。
        parsed.port
        valid_url = (parsed.scheme in ("ws", "wss") and parsed.hostname
                     and parsed.username is None and parsed.password is None
                     and not parsed.fragment)
    except Exception:
        valid_url = False
    if not valid_url:
        raise MentionSendError("夹具 WS 地址不合法或包含内嵌凭证")
    if (not _uid(user_id) or not _uid(target_uid) or user_id == target_uid
            or not isinstance(token, str) or not token):
        raise MentionSendError("夹具必须使用不同的专用账号及有效登录凭证")
    try:
        valid_token = len(token.encode("utf-8")) <= _MAX_TOKEN_BYTES
    except UnicodeError:
        valid_token = False
    if not valid_token:
        raise MentionSendError("夹具登录凭证编码或长度不合法")
    if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
            or not math.isfinite(timeout) or not 0 < timeout <= 120):
        raise MentionSendError("夹具连接超时必须在有效边界内")
    if (not isinstance(app_version, str) or not app_version or len(app_version) > 64
            or any(ord(c) < 32 or ord(c) > 126 for c in app_version)):
        raise MentionSendError("夹具客户端版本不合法")
    if (not isinstance(device_token, str) or not 12 <= len(device_token) <= 256
            or any(ord(c) < 33 or ord(c) > 126 for c in device_token)
            or device_token.lower() in ("web", "app", "pc")):
        raise MentionSendError("夹具必须显式提供本次唯一的专用设备标识")


def send_directed_mention(ws_url, user_id, token, channel_id, target_uid, content, *,
                          device_token, app_version="9.9.9", timeout=10,
                          msg_id=None, connect=None, monotonic=None):
    """一次连接、一次登录、最多发送一条定向 @；不自动重试和恢复会话。

    device_token 必须由调用者为本次登录生成唯一值。正常登录可能使同槽
    在线设备被顶下线；调用者须预先检查没有在线 Web。无论结果如何均断开，
    不发 logout。ACK 无索引时 index 为空，必须由调用者再从 by_id 确认落库。
    """
    _validate_connection(ws_url, user_id, token, target_uid, app_version, timeout, device_token)
    if msg_id is None:
        msg_id = uuid.uuid4().hex
    message = build_radio_mention(channel_id, msg_id, target_uid, content)
    connect = websocket.create_connection if connect is None else connect
    monotonic = time.monotonic if monotonic is None else monotonic
    connection = None
    try:
        deadline = monotonic() + timeout
        connection = connect(ws_url, timeout=_remaining(deadline, monotonic), redirect_limit=0)
        # websocket-client 在 redirect_limit=0 时仍可能返回未完成升级的对象。
        # 必须确认 HTTP 101，禁止向重定向或鉴权错误连接发送登录凭证。
        try:
            upgraded = connection.getstatus() == 101
        except Exception:
            raise MentionSendError("夹具 WS 握手状态不可验证，未发送登录凭证") from None
        if not upgraded:
            raise MentionSendError("夹具 WS 未完成 HTTP 101 升级，未发送登录凭证")
        connection.settimeout(_remaining(deadline, monotonic))
        connection.send_binary(frame.build_frame(CM_LOGIN, proto_min.cm_login(
            user_id, token, 2, device_token=device_token, app_version=app_version,
        ), 1))
        _login_ack(_recv_ack(connection, CM_LOGIN_ACK, 1, deadline, monotonic), user_id)
        # 登录成功前不发送任何业务消息；单一命令不会消耗离线/已读 ACK。
        connection.settimeout(_remaining(deadline, monotonic))
        connection.send_binary(frame.build_frame(RADIO_CHAT, message, 2))
        index = _radio_ack(
            _recv_ack(connection, RADIO_CHAT_ACK, 2, deadline, monotonic),
            user_id, channel_id, msg_id,
        )
        return MentionSendResult(msg_id, index, channel_id, user_id, target_uid)
    except MentionSendError:
        raise
    except Exception:
        raise MentionSendError("夹具连接、传输或握手失败，发送状态需人工核对；不要自动重发") from None
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
