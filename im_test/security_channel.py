"""Vuln22 的只读 HTTP 客户端；严格区分无消息、成员拒绝和请求失败。

字段号以 im-common/proto/channelpull/pull_arg.proto 为准。仅调用 sessions、
offlineMessages、msg/by_id，不发送消息、不回带 ACK，也不修改成员关系。
"""

from dataclasses import dataclass, field

import requests

from im_test import proto_min


class ChannelRequestError(AssertionError):
    """已配置环境中的传输/协议失败；错误文本不包含凭证、响应正文。"""


@dataclass(frozen=True)
class ChannelMessage:
    channel_id: int
    msg_id: str = field(repr=False)
    content: bytes = field(repr=False)
    index: str = field(repr=False)
    event_type: int = 0


@dataclass(frozen=True)
class ChannelSession:
    channel_id: int
    read_index: str = field(repr=False)
    last: object = field(default=None, repr=False)


@dataclass(frozen=True)
class ChannelReply:
    http_status: int
    errcode: int
    messages: tuple = field(default=(), repr=False)
    sessions: tuple = field(default=(), repr=False)
    missing: tuple = field(default=(), repr=False)

    def require_success(self):
        if self.http_status != 200 or self.errcode != 0:
            raise ChannelRequestError(
                f"频道请求未成功：HTTP={self.http_status}, protobuf errcode={self.errcode}"
            )
        return self

    def require_member_denial(self):
        if self.http_status != 403 or self.errcode != 403:
            raise ChannelRequestError(
                f"未收到明确的成员拒绝：HTTP={self.http_status}, protobuf errcode={self.errcode}"
            )
        if self.messages or self.sessions or self.missing:
            raise ChannelRequestError("成员拒绝响应不应附带消息、会话或消息状态")
        return self


def _read_varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ChannelRequestError("protobuf varint 被截断")
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise ChannelRequestError("protobuf varint 溢出")
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
    raise ChannelRequestError("protobuf varint 过长")


def _fields(data, schema):
    """在调用既有最小解码器前校验完整 wire，防止其容错把截断响应当成空数据。"""
    if not isinstance(data, bytes):
        raise ChannelRequestError("protobuf 响应类型异常")
    offset = 0
    while offset < len(data):
        tag, offset = _read_varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number <= 0 or number > 536870911 or schema.get(number) != wire:
            raise ChannelRequestError("protobuf 字段或 wire type 不符合频道响应协议")
        if wire == 0:
            _, offset = _read_varint(data, offset)
        elif wire == 2:
            length, offset = _read_varint(data, offset)
            if length > len(data) - offset:
                raise ChannelRequestError("protobuf 长度字段被截断")
            offset += length
        else:
            raise ChannelRequestError("频道响应含不支持的 protobuf wire type")
    return proto_min.decode_all(data)


def _one(fields, number, default):
    values = fields.get(number, [])
    if len(values) > 1:
        raise ChannelRequestError("protobuf 单值字段重复")
    return values[0] if values else default


def _string(value):
    try:
        return value.decode("utf-8")
    except UnicodeError:
        raise ChannelRequestError("protobuf 字符串不是合法 UTF-8") from None


_MESSAGE_SCHEMA = {
    1: 0, 2: 0, 3: 2, 4: 0, 5: 0, 6: 2, 7: 2, 8: 2, 9: 0,
    10: 2, 11: 0, 12: 0, 13: 2, 14: 2, 15: 0, 16: 2, 17: 0,
}


def _message(raw):
    fields = _fields(raw, _MESSAGE_SCHEMA)
    # 所有 ChnnChat 字段均为单值，不能通过重复字段藏第二份正文。
    for values in fields.values():
        if len(values) != 1:
            raise ChannelRequestError("频道消息含重复单值字段")
    for number in (3, 7, 8, 10, 13, 14, 16):
        if number in fields:
            _string(fields[number][0])
    message = ChannelMessage(
        channel_id=_one(fields, 2, 0),
        msg_id=_string(_one(fields, 3, b"")),
        content=_one(fields, 6, b""),
        index=_string(_one(fields, 8, b"")),
        event_type=_one(fields, 17, 0),
    )
    if message.channel_id <= 0 or not message.msg_id:
        raise ChannelRequestError("频道消息缺少有效频道或消息 ID")
    return message


def _session(raw):
    fields = _fields(raw, {1: 0, 2: 2, 3: 0, 4: 2, 5: 0, 6: 0})
    for values in fields.values():
        if len(values) != 1:
            raise ChannelRequestError("频道会话含重复单值字段")
    channel_id = _one(fields, 1, 0)
    last_raw = _one(fields, 4, None)
    last = _message(last_raw) if last_raw is not None else None
    if channel_id <= 0 or (last is not None and last.channel_id != channel_id):
        raise ChannelRequestError("会话频道 ID 无效或与最后消息不一致")
    return ChannelSession(channel_id, _string(_one(fields, 2, b"")), last)


def parse_channel_reply(body, kind, http_status=200):
    if kind not in ("sessions", "offline", "by_id"):
        raise ValueError("未知频道响应类型")
    schema = {1: 0, 2: 2}
    if kind == "by_id":
        schema[3] = 2
    fields = _fields(body, schema)
    errcode = _one(fields, 1, 0)
    if errcode > 4294967295:
        raise ChannelRequestError("频道 protobuf errcode 超过 uint32")
    rows = fields.get(2, [])
    return ChannelReply(
        http_status=http_status,
        errcode=errcode,
        messages=tuple(_message(row) for row in rows) if kind != "sessions" else (),
        sessions=tuple(_session(row) for row in rows) if kind == "sessions" else (),
        missing=tuple(_string(row) for row in fields.get(3, [])),
    )


class SecurityChannelClient:
    def __init__(self, base_url, token, user_id, timeout=10, client_type=2, post=None):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.user_id = int(user_id)
        self.timeout = float(timeout)
        self.client_type = int(client_type)
        self._post = post or requests.post

    def _request(self, version, endpoint, body, kind):
        if version not in ("v1", "v2"):
            raise ValueError("仅支持 channel/v1 与 channel/v2")
        path = f"/channel/{version}/{endpoint}"
        try:
            response = self._post(
                self.base_url + path,
                data=body,
                headers={
                    "Authorization": f"{self._token}:{self.user_id}",
                    "Content-Type": "application/octet-stream",
                    "Accept": "application/x-protobuf",
                },
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise ChannelRequestError(f"{path} 请求失败（{type(exc).__name__}）") from None
        allowed = (200, 403) if kind == "by_id" else (200,)
        if response.status_code not in allowed:
            raise ChannelRequestError(f"{path} HTTP={response.status_code}，不能视为无消息")
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in ("application/x-protobuf", "application/protobuf"):
            raise ChannelRequestError(f"{path} 未返回 protobuf Content-Type")
        # 空字节在成功 protobuf 响应中是合法的全零默认消息；空 HTML 不满足上面的类型校验。
        return parse_channel_reply(response.content, kind, response.status_code)

    def sessions(self, channel_ids=(), version="v1", body_user_id=None):
        uid = self.user_id if body_user_id is None else int(body_user_id)
        body = proto_min._fv(1, uid)
        for channel_id in channel_ids:
            body += proto_min._fb(2, proto_min._fv(1, int(channel_id)))
        body += proto_min._fv(3, self.client_type)
        return self._request(version, "sessions", body, "sessions")

    def health(self, version="v1"):
        reply = self.sessions(version=version).require_success()
        if reply.sessions:
            raise ChannelRequestError("空频道鉴权正控不应返回会话")
        return reply

    def offline(self, channel_ids, version="v1", count=10, body_user_id=None, base_index="", is_contain=0):
        uid = self.user_id if body_user_id is None else int(body_user_id)
        body = proto_min._fv(1, uid)
        for channel_id in channel_ids:
            info = proto_min._fv(1, int(channel_id))
            if base_index:
                info += proto_min._fs(2, base_index)
            info += proto_min._fv(3, 1) + proto_min._fv(4, count) + proto_min._fv(5, int(is_contain))
            body += proto_min._fb(2, info)
        body += proto_min._fv(3, self.client_type)
        return self._request(version, "offlineMessages", body, "offline")

    def by_id(self, channel_id, msg_ids, version="v1", body_user_id=None):
        uid = self.user_id if body_user_id is None else int(body_user_id)
        body = proto_min._fv(1, uid) + proto_min.chnn_msg_by_id_req(
            channel_id, msg_ids, client_type=self.client_type
        )
        return self._request(version, "msg/by_id", body, "by_id")
