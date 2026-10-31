"""Vuln43 设备接口的严格 protobuf 客户端；对象和异常不展示设备凭证。

字段对照 loginsrv.proto 与 im.login.proto。HTTP 列表成功码为 NON_ERR
(0x8000)，HTTP kick 成功码由网关覆盖为 200，不能混用。
PushTokenSync 仅提供 wire 编解码：没有执行真实写入、持久化观察或恢复。
"""

from dataclasses import dataclass, field
import hashlib
import math
import struct
from typing import Tuple
from urllib.parse import urlsplit

import requests

from im_test import frame, proto_min


NON_ERR = 0x8000
ERR_TRANSMISSION_FORBIDDEN = 0x8107
CM_PUSHTOKENSYNC = 0x0105
CM_PUSHTOKENSYNC_ACK = 0x0106
_MAX_BODY = 1024 * 1024


class DeviceRequestError(RuntimeError):
    """仅含固定诊断文本，禁止拼入 URL、token、设备标识或响应正文。"""


@dataclass(frozen=True)
class DeviceInfo:
    user_id: int
    client_type: int
    device_token: str = field(repr=False)
    device_name: str = field(repr=False)
    last_login_time: int = field(repr=False)
    device_info: str = field(repr=False)
    app_version: str = field(repr=False)

    def fingerprint(self):
        """比较实际设备内容，不能只比较可被服务器重写的 userId。"""
        content = (
            proto_min._fv(7, self.client_type)
            + proto_min._fs(2, self.device_token)
            + proto_min._fs(3, self.device_name)
            + proto_min._fv(5, self.last_login_time)
            + proto_min._fs(6, self.device_info)
            + proto_min._fs(8, self.app_version)
        )
        return hashlib.sha256(content).digest()


@dataclass(frozen=True)
class DeviceListReply:
    http_status: int
    code: int
    devices: Tuple[DeviceInfo, ...] = field(repr=False)

    def require_success(self, user_id=None, nonempty=False):
        if self.http_status != 200 or self.code != NON_ERR:
            raise DeviceRequestError("设备列表未返回有效业务成功码")
        if nonempty and not self.devices:
            raise DeviceRequestError("设备列表本人非空正控未命中；不能验证设备隔离")
        if user_id is not None and any(d.user_id != user_id for d in self.devices):
            raise DeviceRequestError("设备列表出现其他账号的设备身份")
        return self

    def fingerprints(self):
        return frozenset(d.fingerprint() for d in self.devices)


@dataclass(frozen=True)
class DeviceKickReply:
    http_status: int
    code: int

    def require_success(self):
        if self.http_status != 200 or self.code != 200:
            raise DeviceRequestError("踢设备未返回有效网关业务成功码")
        return self


@dataclass(frozen=True)
class PushTokenSyncAck:
    user_id: int
    error_code: int

    def require_success(self, connected_uid):
        if self.user_id != connected_uid or self.error_code != NON_ERR:
            raise DeviceRequestError("推送同步未返回当前账号的成功 ACK")
        return self

    def require_uid_denial(self, connected_uid):
        if self.user_id != connected_uid or self.error_code != ERR_TRANSMISSION_FORBIDDEN:
            raise DeviceRequestError("推送同步未明确拒绝伪造 UID")
        return self


def _varint(data, offset):
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise DeviceRequestError("设备 protobuf varint 被截断")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise DeviceRequestError("设备 protobuf varint 溢出")
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, offset
    raise DeviceRequestError("设备 protobuf varint 过长")


def _fields(data, schema, repeated=()):
    if not isinstance(data, bytes) or len(data) > _MAX_BODY:
        raise DeviceRequestError("设备 protobuf 响应类型或长度异常")
    offset = 0
    seen = set()
    while offset < len(data):
        tag, offset = _varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not number or schema.get(number) != wire:
            raise DeviceRequestError("设备 protobuf 字段或 wire type 不合法")
        if number in seen and number not in repeated:
            raise DeviceRequestError("设备 protobuf 单值字段重复")
        seen.add(number)
        if wire == 0:
            _, offset = _varint(data, offset)
        elif wire == 2:
            size, offset = _varint(data, offset)
            if size > len(data) - offset:
                raise DeviceRequestError("设备 protobuf 长度字段被截断")
            offset += size
        else:
            raise DeviceRequestError("设备 protobuf wire type 不受支持")
    return proto_min.decode_all(data)


def _one(fields, number, default=None):
    values = fields.get(number, ())
    return values[0] if values else default


def _text(fields, number):
    try:
        return _one(fields, number, b"").decode("utf-8")
    except UnicodeError:
        raise DeviceRequestError("设备 protobuf 字符串不是 UTF-8") from None


def _uid(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < (1 << 63)


def _device(raw):
    f = _fields(raw, {1: 0, 2: 2, 3: 2, 5: 0, 6: 2, 7: 0, 8: 2})
    uid, client_type = _one(f, 1), _one(f, 7, 0)
    token, login_time = _text(f, 2), _one(f, 5, 0)
    if not _uid(uid) or client_type not in (0, 1, 2) or not token or login_time >= (1 << 63):
        raise DeviceRequestError("设备记录缺少有效身份、设备标识或端类型")
    return DeviceInfo(uid, client_type, token, _text(f, 3), login_time, _text(f, 6), _text(f, 8))


def parse_device_list(body, http_status=200):
    fields = _fields(body, {1: 0, 2: 2}, repeated=(2,))
    code = _one(fields, 1)
    if code is None or code > 0x7FFFFFFF:
        raise DeviceRequestError("设备列表缺少有效 int32 业务码")
    rows = tuple(_device(raw) for raw in fields.get(2, ()))
    if len(rows) > 3 or len({d.client_type for d in rows}) != len(rows):
        raise DeviceRequestError("设备列表含重复或超出协议边界的客户端槽位")
    return DeviceListReply(http_status, code, rows)


def parse_device_kick(body, http_status=200):
    fields = _fields(body, {1: 0})
    code = _one(fields, 1)
    if code is None or code > 0x7FFFFFFF:
        raise DeviceRequestError("踢设备响应缺少有效 int32 业务码")
    return DeviceKickReply(http_status, code)


class SecurityDeviceClient:
    def __init__(self, base_url, token, user_id, timeout=10, post=None):
        try:
            parsed = urlsplit(base_url)
            valid = (parsed.scheme in ("http", "https") and parsed.hostname
                     and parsed.username is None and parsed.password is None
                     and not parsed.query and not parsed.fragment)
        except Exception:
            valid = False
        if (not valid or not _uid(user_id) or not isinstance(token, str) or not token
                or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or timeout <= 0 or timeout > 120):
            raise DeviceRequestError("设备接口地址、账号、凭证或超时配置不合法")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self.user_id = user_id
        self.timeout = timeout
        self._post = post or requests.post

    def _request(self, version, endpoint, body, parse):
        if version not in ("v1", "v2"):
            raise DeviceRequestError("设备接口仅支持 v1 / v2")
        try:
            response = self._post(
                self._base_url + "/login/" + version + "/" + endpoint,
                data=body,
                headers={"Authorization": "%s:%d" % (self._token, self.user_id),
                         "Content-Type": "application/octet-stream", "Accept": "application/x-protobuf"},
                timeout=self.timeout, allow_redirects=False,
            )
        except Exception:
            raise DeviceRequestError("设备接口传输失败；未获得有效业务响应") from None
        if response.status_code != 200:
            raise DeviceRequestError("设备接口 HTTP 非 200；不能作为鉴权隔离通过")
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in ("application/x-protobuf", "application/protobuf"):
            raise DeviceRequestError("设备接口未返回 protobuf Content-Type")
        return parse(response.content, response.status_code)

    def device_list(self, body_user_id=None, version="v1"):
        uid = self.user_id if body_user_id is None else body_user_id
        if not _uid(uid):
            raise DeviceRequestError("设备列表请求 UID 不合法")
        return self._request(version, "user/online_device_list", proto_min._fv(1, uid), parse_device_list)

    def kick(self, device_token, *, body_user_id=None, client_type=2, version="v1", confirm=False):
        if confirm is not True:
            raise DeviceRequestError("踢设备是写操作，必须显式确认专用目标设备")
        uid = self.user_id if body_user_id is None else body_user_id
        if not _uid(uid) or client_type not in (0, 1, 2) or not isinstance(device_token, str) or not device_token:
            raise DeviceRequestError("踢设备请求参数不合法")
        body = proto_min._fv(1, uid) + proto_min._fv(2, client_type) + proto_min._fs(3, device_token)
        return self._request(version, "kick/user_device", body, parse_device_kick)


def build_push_sync_frame(user_id, push_type, token, token_type=0, seq=1):
    """仅编码；不登录、不建立连接、不写真实 token。"""
    if (not _uid(user_id) or not isinstance(push_type, int) or not 0 < push_type <= 0xFFFFFFFF
            or not isinstance(token, str) or not token or token_type not in (0, 1)
            or not isinstance(seq, int) or not 0 < seq <= 0xFFFFFFFF):
        raise DeviceRequestError("推送同步协议参数不合法")
    body = (proto_min._fv(1, user_id) + proto_min._fv(2, push_type)
            + proto_min._fs(3, token) + proto_min._fv(4, token_type))
    return frame.build_frame(CM_PUSHTOKENSYNC, body, seq)


def parse_push_sync_ack(data, expected_seq):
    if not isinstance(data, bytes) or not 16 <= len(data) <= _MAX_BODY + 16:
        raise DeviceRequestError("推送同步 ACK 不是完整二进制帧")
    length, flags, app_id, command, body_len, seq = struct.unpack(">IBBHII", data[:16])
    if (length != len(data) - 4 or body_len != len(data) - 16
            or flags != frame.FLAGS or app_id != frame.APPID
            or command != CM_PUSHTOKENSYNC_ACK or seq != expected_seq):
        raise DeviceRequestError("推送同步 ACK 帧头、命令或请求序号不一致")
    fields = _fields(data[16:], {1: 0, 2: 0})
    uid, code = _one(fields, 1), _one(fields, 2)
    if not _uid(uid) or code is None or code > 0x7FFFFFFF:
        raise DeviceRequestError("推送同步 ACK 缺少有效账号或错误码")
    return PushTokenSyncAck(uid, code)
