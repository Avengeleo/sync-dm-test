"""Vuln42 六条频道路由的 protobuf 客户端与身份对照探测。

字段号来自 channelpull/pull_arg.proto。操作记录读取可能惰性写 oper_index，
因此 operations / operation_one 也必须由调用方取得状态改动许可。仅 read_indexes
和 at_messages 为只读；本模块不登录、不发送消息、不自动修改成员关系。
"""

from dataclasses import dataclass, field
import re

import requests

from im_test import proto_min
from im_test.security_channel import (
    ChannelRequestError, SecurityChannelClient, _fields, _message, _one, _string,
)


class IdentityFixtureUnavailable(Exception):
    """夹具没有可区分的前后状态：调用方必须报告 SKIP，不能算通过。"""


@dataclass(frozen=True)
class IdentityIndex:
    channel_id: int
    index: str = field(repr=False)


@dataclass(frozen=True)
class IdentityAtIndexes:
    channel_id: int
    indexes: tuple = field(repr=False)


@dataclass(frozen=True)
class ChannelIdentityReply:
    http_status: int
    errcode: int
    indexes: tuple = field(default=(), repr=False)
    operations: tuple = field(default=(), repr=False)
    at_indexes: tuple = field(default=(), repr=False)

    def require_success(self):
        if self.http_status != 200 or self.errcode != 0:
            raise ChannelRequestError(
                f"频道身份请求未成功：HTTP={self.http_status}, protobuf errcode={self.errcode}"
            )
        return self


def _single_channel(fields):
    channel_id = _one(fields, 1, 0)
    if channel_id <= 0 or channel_id >= 1 << 63:
        raise ChannelRequestError("频道身份响应缺少合法频道 ID")
    return channel_id


def parse_identity_reply(body, kind, http_status=200):
    if kind not in ("read_indexes", "operations", "at_indexes", "ack"):
        raise ValueError("未知频道身份响应类型")
    fields = _fields(body, {1: 0} if kind == "ack" else {1: 0, 2: 2})
    errcode = _one(fields, 1, 0)
    if errcode > 4294967295:
        raise ChannelRequestError("频道身份响应 errcode 超过 uint32")
    indexes, operations, at_indexes = [], [], []
    for raw in fields.get(2, []):
        if kind == "operations":
            operations.append(_message(raw))
        elif kind == "read_indexes":
            row = _fields(raw, {1: 0, 2: 2})
            indexes.append(IdentityIndex(_single_channel(row), _string(_one(row, 2, b""))))
        elif kind == "at_indexes":
            row = _fields(raw, {1: 0, 2: 2})
            at_indexes.append(IdentityAtIndexes(_single_channel(row), tuple(_string(v) for v in row.get(2, []))))
    return ChannelIdentityReply(http_status, errcode, tuple(indexes), tuple(operations), tuple(at_indexes))


class SecurityChannelIdentityClient(SecurityChannelClient):
    def _identity_request(self, version, endpoint, body, kind):
        if version not in ("v1", "v2"):
            raise ValueError("仅支持 channel/v1 与 channel/v2")
        path = f"/channel/{version}/{endpoint}"
        try:
            response = self._post(
                self.base_url + path, data=body,
                headers={"Authorization": f"{self._token}:{self.user_id}",
                         "Content-Type": "application/octet-stream", "Accept": "application/x-protobuf"},
                timeout=self.timeout, allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise ChannelRequestError(f"{path} 请求失败（{type(exc).__name__}）") from None
        if response.status_code != 200:
            raise ChannelRequestError(f"{path} HTTP={response.status_code}，不能视为身份隔离通过")
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in ("application/x-protobuf", "application/protobuf"):
            raise ChannelRequestError(f"{path} 未返回 protobuf Content-Type")
        return parse_identity_reply(response.content, kind, response.status_code).require_success()

    def _uid(self, body_user_id):
        return self.user_id if body_user_id is None else int(body_user_id)

    def read_indexes(self, channel_id, version="v1", body_user_id=None):
        # proto3 repeated int64 lsChnnId=2 使用 packed 编码。
        body = proto_min._fv(1, self._uid(body_user_id))
        body += proto_min._fb(2, proto_min._enc_varint(int(channel_id)))
        return self._identity_request(version, "readIndexes", body, "read_indexes")

    def update_read_index(self, channel_id, index, version="v1", body_user_id=None):
        row = proto_min._fv(1, int(channel_id)) + proto_min._fs(2, index)
        body = proto_min._fv(1, self._uid(body_user_id)) + proto_min._fb(2, row)
        return self._identity_request(version, "readIndexes/edit", body, "ack")

    def operation_one(self, channel_id, version="v1", body_user_id=None):
        body = proto_min._fv(1, self._uid(body_user_id)) + proto_min._fv(2, int(channel_id))
        body += proto_min._fv(3, self.client_type)
        return self._identity_request(version, "oprMessage", body, "operations")

    def operations(self, version="v1", body_user_id=None):
        body = proto_min._fv(1, self._uid(body_user_id)) + proto_min._fv(2, self.client_type)
        return self._identity_request(version, "oprMessages", body, "operations")

    def verify_operations(self, channel_id, index, version="v1", body_user_id=None):
        row = proto_min._fv(1, int(channel_id)) + proto_min._fs(2, index)
        body = proto_min._fv(1, self._uid(body_user_id)) + proto_min._fb(2, row)
        return self._identity_request(version, "oprMessages/verify", body, "ack")

    def at_messages(self, channel_id, version="v1", body_user_id=None):
        row = proto_min._fv(1, int(channel_id))
        body = proto_min._fv(1, self._uid(body_user_id)) + proto_min._fb(2, row)
        return self._identity_request(version, "atMessages", body, "at_indexes")


def _client(config, second=False):
    return SecurityChannelIdentityClient(
        config["http_base"], config["token2" if second else "token"],
        config["user_id2" if second else "user_id"],
        timeout=config["timeout"], client_type=config["client_type"],
    )


def _valid_index(index):
    return bool(re.fullmatch(r"[0-9a-f]{24}", index))


def _members(config, version, clients=None):
    """双方用自己的凭证读取同一固定普通广播，避免非成员门掩盖 UID 漏洞。"""
    a, b = clients or (_client(config), _client(config, True))
    if a.user_id == b.user_id:
        raise ChannelRequestError("频道身份回归要求不同 A/B 账号")
    channel_id, message_id = config["identity_channel_id"], config["identity_message_id"]
    samples = []
    for client in (a, b):
        reply = client.by_id(channel_id, [message_id], version).require_success()
        if reply.missing or len(reply.messages) != 1:
            raise ChannelRequestError("双方成员正控必须命中同一固定广播，空数据不能作正控")
        sample = reply.messages[0]
        if (sample.channel_id != channel_id or sample.msg_id != message_id or
                not sample.content or sample.event_type != 0 or not _valid_index(sample.index)):
            raise ChannelRequestError("固定广播成员正控的数据不符合预置要求")
        samples.append(sample)
    if samples[0] != samples[1]:
        raise ChannelRequestError("双方固定广播正控不一致，无法进行身份对照")
    return a, b, samples[0]


def _read(client, channel_id, version):
    reply = client.read_indexes(channel_id, version).require_success()
    if len(reply.indexes) != 1 or reply.indexes[0].channel_id != channel_id:
        raise ChannelRequestError("已读正控必须返回指定频道的唯一索引，空数据不能作正控")
    index = reply.indexes[0].index
    if not _valid_index(index):
        raise ChannelRequestError("已读正控缺少合法预置游标")
    return index


def _different(a, b, label):
    if a == b:
        raise IdentityFixtureUnavailable(f"A/B {label}相同，无法识别是否信任伪造 UID；需重新预置不同状态")


def check_read_indexes_identity(config, version, clients=None):
    a, b, _ = _members(config, version, clients)
    channel_id = config["identity_channel_id"]
    before_a, before_b = _read(a, channel_id, version), _read(b, channel_id, version)
    _different(before_a, before_b, "已读游标")
    forged = a.read_indexes(channel_id, version, body_user_id=b.user_id).require_success()
    if len(forged.indexes) != 1 or forged.indexes[0].channel_id != channel_id or forged.indexes[0].index != before_a:
        raise ChannelRequestError("readIndexes 未以认证 A 身份读取，或伪造 UID 返回了其他账号状态")
    if _read(a, channel_id, version) != before_a or _read(b, channel_id, version) != before_b:
        raise ChannelRequestError("已读对照期间状态变化，请关闭测试客户端并重新预置")


def _at_view(reply, channel_id, fixture=False):
    reply.require_success()
    if len(reply.at_indexes) != 1 or reply.at_indexes[0].channel_id != channel_id:
        raise ChannelRequestError("@消息正控必须返回指定频道唯一行，空响应不能作正控")
    indexes = reply.at_indexes[0].indexes
    if not indexes:
        if fixture:
            raise IdentityFixtureUnavailable("缺少非空的定向 @ 索引正控，atMessages 身份隔离未验证")
        raise ChannelRequestError("已有非空 @ 正控后返回空数据，不能视为身份隔离通过")
    if any(not _valid_index(index) for index in indexes):
        raise ChannelRequestError("@消息响应存在非法游标")
    return tuple(sorted(set(indexes)))


def check_at_messages_identity(config, version, clients=None):
    a, b, _ = _members(config, version, clients)
    channel_id = config["identity_channel_id"]
    before_a = _at_view(a.at_messages(channel_id, version), channel_id, fixture=True)
    before_b = _at_view(b.at_messages(channel_id, version), channel_id, fixture=True)
    _different(before_a, before_b, "定向 @ 索引")
    forged = _at_view(a.at_messages(channel_id, version, body_user_id=b.user_id), channel_id)
    if forged != before_a:
        raise ChannelRequestError("atMessages 伪造 UID 改变了读取所属账号")
    if (_at_view(a.at_messages(channel_id, version), channel_id) != before_a or
            _at_view(b.at_messages(channel_id, version), channel_id) != before_b):
        raise ChannelRequestError("@消息对照期间状态变化，请重新预置")


def _operation_view(reply, channel_id, require_nonempty=True, fixture=False):
    reply.require_success()
    rows = reply.operations
    if not rows and require_nonempty:
        if fixture:
            raise IdentityFixtureUnavailable("缺少非空待处理操作正控或已被 ACK 消耗，操作身份路径未验证；需重新预置")
        raise ChannelRequestError("已有非空操作正控后返回空数据，不能视为身份隔离通过")
    if any(row.channel_id != channel_id or not row.content or not _valid_index(row.index) for row in rows):
        raise ChannelRequestError("操作正控超出专用频道或缺少正文/合法游标")
    # 不受服务端跨频道 goroutine 返回顺序影响；内容仅在内存比较，不进入失败文本。
    return tuple(sorted((row.channel_id, row.msg_id, row.index, row.content) for row in rows))


def check_operations_identity(config, version, all_channels=False, clients=None):
    a, b, _ = _members(config, version, clients)
    channel_id = config["identity_channel_id"]
    def fetch(client, uid=None, fixture=False):
        reply = (client.operations(version, body_user_id=uid) if all_channels else
                 client.operation_one(channel_id, version, body_user_id=uid))
        return _operation_view(reply, channel_id, fixture=fixture)
    before_a, before_b = fetch(a, fixture=True), fetch(b, fixture=True)
    _different(before_a, before_b, "待处理操作")
    if fetch(a, b.user_id) != before_a:
        raise ChannelRequestError("操作记录请求信任了伪造 UID，未保持认证 A 的游标范围")
    if fetch(a) != before_a or fetch(b) != before_b:
        raise ChannelRequestError("操作对照期间被其他客户端 ACK 或状态变化，请重新预置")


def check_update_read_index_identity(config, version, clients=None):
    """不可回退：推进 A read_index，并可能删除 A 对应范围的 @ 索引。"""
    a, b, sample = _members(config, version, clients)
    channel_id = config["identity_channel_id"]
    before_a, before_b = _read(a, channel_id, version), _read(b, channel_id, version)
    _different(before_a, before_b, "已读游标")
    if sample.index <= max(before_a, before_b):
        raise IdentityFixtureUnavailable("固定广播不比双方已读游标更新，写探测不可判定或夹具已消耗；每个版本需重新预置")
    # 本人合法请求正控使用相同游标，不额外推进状态。
    a.update_read_index(channel_id, before_a, version).require_success()
    if _read(a, channel_id, version) != before_a or _read(b, channel_id, version) != before_b:
        raise ChannelRequestError("本人更新正控改变了非预期状态")
    a.update_read_index(channel_id, sample.index, version, body_user_id=b.user_id).require_success()
    after_a, after_b = _read(a, channel_id, version), _read(b, channel_id, version)
    if after_a != sample.index or after_b != before_b:
        raise ChannelRequestError("伪造 UID 更新未只推进认证 A，或改动了 B 的 read_index")


def check_verify_operations_identity(config, version, clients=None):
    """不可自动恢复：先 ACK A 正控，再伪造 B，B 的待处理列表必须原样保留。"""
    a, b, _ = _members(config, version, clients)
    channel_id = config["identity_channel_id"]
    before_a = _operation_view(a.operation_one(channel_id, version), channel_id, fixture=True)
    before_b = _operation_view(b.operation_one(channel_id, version), channel_id, fixture=True)
    _different(before_a, before_b, "待处理操作")
    target = max(row[2] for row in before_a)
    if target != max(row[2] for row in before_b):
        raise IdentityFixtureUnavailable("双方待处理操作缺少相同末条锚点，不能证明伪造 ACK 会影响 B")
    a.verify_operations(channel_id, target, version).require_success()
    if _operation_view(a.operation_one(channel_id, version), channel_id, False):
        raise ChannelRequestError("本人 ACK 正控未消耗 A 的待处理操作")
    if _operation_view(b.operation_one(channel_id, version), channel_id) != before_b:
        raise ChannelRequestError("本人 ACK 正控意外改变了 B 的待处理操作")
    a.verify_operations(channel_id, target, version, body_user_id=b.user_id).require_success()
    if (_operation_view(a.operation_one(channel_id, version), channel_id, False) or
            _operation_view(b.operation_one(channel_id, version), channel_id) != before_b):
        raise ChannelRequestError("伪造 UID 的 ACK 改动了 B 的待处理操作，或 A 状态发生异常变化")
