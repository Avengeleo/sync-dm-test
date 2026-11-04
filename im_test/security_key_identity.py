"""Vuln45 专用 marker 探测；不读取、生成、持久化或替换客户端真实私钥。

群 ACK 用本人未确认交换记录的精确前后快照及本人消费正控验证。
私钥非法包目前没有明确拒绝 ACK，静默和超时均只能记为受阻。
"""

from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import time
from urllib.parse import urlsplit
import uuid

import requests

from im_test import proto_min as p
from im_test.security_device import SecurityDeviceClient
from im_test.security_wire import SecurityWireError, WireSession, fields, one, text, uid


NON_ERR = 0x8000
FORBIDDEN = 0x8107
CHAT_FORBIDDEN = 0x8201
APP_OFFLINE = 0x8402
KEY_REQUEST, KEY_REQUEST_ACK = 0x2301, 0x2302
KEY_RESPONSE, KEY_DELIVER, KEY_NOTIFY_ACK, KEY_NOTIFY = 0x2303, 0x2304, 0x2305, 0x2306
PRIVATE_COMMANDS = (101, 104, 103, 106)
_REQUEST_SCHEMA = {1: 0, 2: 0, 3: 2, 4: 0, 5: 2, 6: 0, 7: 0}
_PRIVATE_ACK_SCHEMA = {1: 0, 2: 0, 3: 2}
_DELIVER_SCHEMA = {1: 0, 2: 0, 3: 0, 4: 2, 5: 0, 6: 2, 7: 0, 8: 2, 9: 0, 10: 2}
_RESPONSE_SCHEMA = {1: 0, 2: 0, 3: 0, 4: 2, 5: 2, 6: 0, 7: 0, 8: 0, 9: 2}
_MARKER_PREFIX = b"im-security-v45-opaque-marker:"
_MAX_QUEUE = 500


class KeyIdentityError(AssertionError):
    """固定错误，不回显密钥、token、URL、响应体或下层异常。"""


class KeyIdentityBlocked(RuntimeError):
    """缺夹具、正控或拒绝证据时跳过，不能记为通过。"""


def _require(condition, message):
    if not condition:
        raise KeyIdentityError(message)


@dataclass(frozen=True)
class ExchangeRecord:
    command: int
    msg_id: str
    from_id: int
    group_id: int
    body: bytes = field(repr=False)


def parse_exchange_reply(raw, expected_uid, correlation):
    parsed = fields(raw, {1: 0, 2: 2, 3: 2}, repeated=(3,))
    _require(one(parsed, 1) == expected_uid and text(parsed, 2) == correlation,
             "交换记录响应身份或请求关联 ID 不匹配")
    rows = []
    for raw_row in parsed.get(3, ()):
        row = fields(raw_row, {1: 0, 2: 2, 3: 2, 4: 0, 5: 0, 6: 0})
        record = ExchangeRecord(one(row, 1), text(row, 3), one(row, 4), one(row, 5), one(row, 2, b""))
        _require(record.command in (KEY_DELIVER, KEY_NOTIFY) and uid(record.from_id)
                 and uid(record.group_id) and 0 < len(record.msg_id) <= 128 and record.body,
                 "交换记录缺少有效的命令、身份或消息 ID")
        rows.append(record)
    _require(len({row.msg_id for row in rows}) == len(rows), "交换记录出现重复消息 ID")
    if len(rows) >= _MAX_QUEUE:
        raise KeyIdentityBlocked("交换队列达到单页上限，无法精确观察；不清理旧记录")
    return tuple(rows)


class SecurityKeyIdentityClient:
    """只读交换队列；deliveredMsgIds 始终省略，不借读取隐式 ACK。"""

    def __init__(self, base_url, token, user_id, timeout=10, post=None):
        try:
            parsed = urlsplit(base_url)
            valid = (parsed.scheme in ("http", "https") and parsed.hostname
                     and parsed.username is None and parsed.password is None
                     and not parsed.query and not parsed.fragment)
            parsed.port
        except Exception:
            valid = False
        if (not valid or not uid(user_id) or not isinstance(token, str) or not token
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 120):
            raise KeyIdentityError("Vuln45 交换队列地址、身份或超时配置不合法")
        self.user_id, self.timeout = user_id, timeout
        self._base, self._token, self._post = base_url.rstrip("/"), token, post or requests.post

    def __repr__(self):
        return "SecurityKeyIdentityClient(<凭证已隐藏>)"

    def exchange_records(self):
        correlation = uuid.uuid4().hex
        body = (p._fv(1, self.user_id) + p._fs(2, correlation)
                + p._fv(4, _MAX_QUEUE) + p._fv(5, 2))
        try:
            response = self._post(
                self._base + "/offline/v1/exchange_key", data=body,
                headers={"Authorization": "%s:%d" % (self._token, self.user_id),
                         "Content-Type": "application/octet-stream", "Accept": "application/x-protobuf"},
                timeout=self.timeout, allow_redirects=False,
            )
        except Exception:
            raise KeyIdentityError("交换记录读取失败；不能把请求失败当作空队列") from None
        _require(response.status_code == 200, "交换记录 HTTP 非 200；不能当作空队列")
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        _require(content_type in ("application/x-protobuf", "application/protobuf"),
                 "交换记录未返回 protobuf Content-Type")
        return parse_exchange_reply(response.content, self.user_id, correlation)


def _config(config):
    a, b, group = config.get("user_id"), config.get("user_id2"), config.get("key_group_id")
    if not uid(a) or not uid(b) or a == b or not uid(group) or config.get("client_type", 2) != 2:
        raise KeyIdentityBlocked("Vuln45 需要两个不同专用账号、专用密钥群及 Web 槽位")
    return a, b, group


def _clients(config):
    return tuple(SecurityKeyIdentityClient(config["http_base"], config[key], config[who],
                                          config.get("timeout", 10))
                 for who, key in (("user_id", "token"), ("user_id2", "token2")))


def _device_clients(config):
    return tuple(SecurityDeviceClient(config["http_base"], config[key], config[who],
                                     config.get("timeout", 10))
                 for who, key in (("user_id", "token"), ("user_id2", "token2")))


def _isolated_slots(config, *, devices=None, app_only=False):
    """群 marker 会到所有在线端；必须先确认不会交给真实 App/PC 消费。"""
    devices = devices or _device_clients(config)
    try:
        for client in devices:
            reply = client.device_list().require_success(client.user_id)
            if any(row.client_type == 0 or (not app_only and row.client_type == 1)
                   for row in reply.devices):
                raise KeyIdentityBlocked("Vuln45 marker 隔离前置未满足：账号仍有 App/PC 在线")
    except KeyIdentityBlocked:
        raise
    except Exception:
        raise KeyIdentityBlocked("无法只读确认 Vuln45 marker 不会送到真实客户端") from None


def _open(stack, config, factory):
    result = []
    for who, key in (("user_id", "token"), ("user_id2", "token2")):
        result.append(stack.enter_context(factory(
            config["ws_url"], config[who], config[key], transport="ws", client_type=2,
            timeout=config.get("timeout", 10), app_version=config.get("app_version", "9.9.9"))))
    return tuple(result)


def _note(report, **values):
    if report is not None:
        report.update(values)


def _attempt(report, command):
    attempt = uuid.uuid4().hex
    _note(report, attempt_id=attempt, command="0x%04x" % command,
          sent_at=datetime.now(timezone.utc).isoformat(), verification_status="running")
    return attempt


def exchange_request(sender, group, message_id, recipient, marker):
    return (p._fv(1, sender) + p._fv(3, group) + p._fs(4, message_id)
            + p._fv(8, int(time.time() * 1000))
            + p._fb(12, p._fv(1, recipient) + p._fb(2, marker)))


def exchange_response(sender, recipient, group, message_id, marker):
    return (p._fv(1, sender) + p._fv(2, recipient) + p._fv(3, group) + p._fs(4, message_id)
            + p._fb(5, marker) + p._fv(7, NON_ERR) + p._fv(8, int(time.time() * 1000)))


def _group_ack(event, expected_uid, group, message_id):
    # 实际 group-srv packageAck 使用 GroupChatAck；errcode 是 5，不是旧 proto 的 4。
    ack = fields(event.body, {1: 0, 2: 0, 3: 2, 4: 0, 5: 0})
    _require(one(ack, 1) == expected_uid and one(ack, 2) == group and text(ack, 3) == message_id,
             "群密钥 ACK 身份、群或消息 ID 不匹配")
    _require(one(ack, 5) is not None, "群密钥 ACK 缺少明确业务码")
    return one(ack, 5)


def _group_request(session, body):
    seq = session.send(KEY_REQUEST, body)
    event = session.wait(KEY_REQUEST_ACK, seq=seq)
    if event is None:
        raise KeyIdentityBlocked("群密钥请求没有匹配 ACK；超时不能当作身份拒绝或成功正控")
    return event


def _record(rows, message_id):
    return next((row for row in rows if row.msg_id == message_id), None)


def _poll(client, predicate, timeout, clock, sleep):
    deadline = clock() + timeout
    while True:
        rows = client.exchange_records()
        value = predicate(rows)
        if value:
            return value
        if clock() >= deadline:
            raise KeyIdentityBlocked("本轮精确交换记录未完成落库或本人消费正控；不重发、不清理旧记录")
        sleep(min(0.25, max(0, deadline - clock())))


def _unchanged(client, expected, timeout, clock, sleep):
    # 不以没有下行作判定：这里每次读取同一条可精确匹配的持久化未 ACK 记录。
    deadline = clock() + min(timeout, 2)
    while True:
        observed = _record(client.exchange_records(), expected.msg_id)
        _require(observed == expected, "伪造身份 ACK 消耗或改变了另一账号的本轮交换记录")
        if clock() >= deadline:
            return
        sleep(min(0.25, max(0, deadline - clock())))


def _deliver(row, sender, recipient, group, message_id, marker):
    parsed = fields(row.body, _DELIVER_SCHEMA)
    _require(row.command == KEY_DELIVER and row.group_id == group and row.from_id == sender
             and one(parsed, 1) == sender and one(parsed, 2) == recipient
             and one(parsed, 3) == group and text(parsed, 4) == message_id and one(parsed, 6) == marker,
             "群密钥本人正控未命中本轮精确 marker")
    return row


def _notification(rows, sender, recipient, group, original_id, marker, previous_ids):
    matches = []
    for row in rows:
        if row.msg_id in previous_ids or row.command != KEY_NOTIFY or row.group_id != group:
            continue
        parsed = fields(row.body, _RESPONSE_SCHEMA)
        if text(parsed, 4) != original_id:
            continue
        _require(row.from_id == sender and one(parsed, 1) == sender and one(parsed, 2) == recipient
                 and one(parsed, 3) == group and one(parsed, 5) == marker
                 and one(parsed, 7) == NON_ERR, "群密钥通知未命中本人响应的完整 marker")
        matches.append(row)
    _require(len(matches) <= 1, "本轮群密钥响应产生了重复通知")
    return matches[0] if matches else None


def check_group_key_identity(config, *, clients=None, devices=None, session_factory=WireSession,
                             report=None, clock=time.monotonic, sleep=time.sleep):
    """一个全新的 F→N 链路验证 2301、2303、2305；仅本人 ACK 本轮记录。"""
    a, b, group = _config(config)
    _isolated_slots(config, devices=devices)
    clients = clients or _clients(config)
    old_a, old_b = (client.exchange_records() for client in clients)
    message_id = uuid.uuid4().hex
    marker = _MARKER_PREFIX + message_id.encode("ascii")
    denied_id = uuid.uuid4().hex
    _note(report, fixture_message_id=message_id, rejected_message_id=denied_id)
    timeout = config.get("timeout", 10)
    with ExitStack() as stack:
        sa, sb = _open(stack, config, session_factory)
        _attempt(report, KEY_REQUEST)
        denied = _group_request(sa, exchange_request(b, group, denied_id, a, marker))
        _require(_group_ack(denied, a, group, denied_id) == FORBIDDEN,
                 "群密钥伪造发送者未收到明确身份拒绝 ACK")
        _require(all(_record(client.exchange_records(), denied_id) is None for client in clients),
                 "已拒绝的群密钥请求仍产生了本轮交换记录")
        event = _group_request(sa, exchange_request(a, group, message_id, b, marker))
        if _group_ack(event, a, group, message_id) != NON_ERR:
            raise KeyIdentityBlocked("合法群密钥请求未返回成功 ACK，缺少可达正控")
        fixture = _poll(clients[1], lambda rows: _record(rows, message_id), timeout, clock, sleep)
        _deliver(fixture, a, b, group, message_id, marker)
        _require(message_id not in {row.msg_id for row in old_a + old_b}, "本轮消息 ID 与旧记录冲突")

        _attempt(report, KEY_RESPONSE)
        forged_marker = marker + b":forged-response"
        response_marker = marker + b":own-response"
        sa.send(KEY_RESPONSE, exchange_response(b, a, group, message_id, forged_marker))
        _unchanged(clients[1], fixture, timeout, clock, sleep)
        before_notify = {row.msg_id for row in clients[0].exchange_records()}
        unexpected = _notification(clients[0].exchange_records(), b, a, group, message_id, forged_marker,
                                   {row.msg_id for row in old_a})
        _require(unexpected is None, "伪造群密钥回应仍触发了本轮通知")
        sb.send(KEY_RESPONSE, exchange_response(b, a, group, message_id, response_marker))
        _poll(clients[1], lambda rows: _record(rows, message_id) is None, timeout, clock, sleep)
        notification = _poll(clients[0], lambda rows: _notification(
            rows, b, a, group, message_id, response_marker, before_notify), timeout, clock, sleep)
        _note(report, notification_message_id=notification.msg_id)

        _attempt(report, KEY_NOTIFY_ACK)
        sb.send(KEY_NOTIFY_ACK, p._fv(1, a) + p._fs(2, notification.msg_id))
        _unchanged(clients[0], notification, timeout, clock, sleep)
        sa.send(KEY_NOTIFY_ACK, p._fv(1, a) + p._fs(2, notification.msg_id))
        _poll(clients[0], lambda rows: _record(rows, notification.msg_id) is None,
              timeout, clock, sleep)
    # 对旧记录只比较、不解析正文、不 ACK；并发变化会使夹具不可用于正式通过。
    for client, old in zip(clients, (old_a, old_b)):
        now = {row.msg_id: row for row in client.exchange_records()}
        _require(all(now.get(row.msg_id) == row for row in old), "旧交换记录发生变化，专用测试隔离失效")
    _require(_notification(clients[0].exchange_records(), b, a, group, message_id,
                           forged_marker, {row.msg_id for row in old_a}) is None,
             "伪造群密钥回应触发了延迟的本轮通知")
    _note(report, verification_status="passed", commands="0x2301,0x2303,0x2305",
          cleanup="only_current_fixture_web_acks_consumed")


def check_group_nonmember_identity(config, *, clients=None, devices=None,
                                   session_factory=WireSession, report=None):
    a, b, group = _config(config)
    outsider = config.get("key_nonmember_uid")
    if not uid(outsider) or outsider in (a, b):
        raise KeyIdentityBlocked("未配置已确认不在专用密钥群内的测试账号；不探测其他用户")
    # 独立选取此项时仍须证明 A/B 在目标群且合法交换确实可达，不能把群不存在误判为拒绝。
    control_report = {}
    try:
        check_group_key_identity(config, clients=clients, devices=devices,
                                 session_factory=session_factory, report=control_report)
    finally:
        _note(report, **{"positive_control_" + key: value for key, value in control_report.items()})
    _isolated_slots(config, devices=devices)
    clients = clients or _clients(config)
    # 本用例仅验证明确的成员拒绝，不读取第三账号队列、不改成员关系。
    message_id = _attempt(report, KEY_REQUEST)
    marker = _MARKER_PREFIX + message_id.encode("ascii")
    with ExitStack() as stack:
        sa, _ = _open(stack, config, session_factory)
        event = _group_request(sa, exchange_request(a, group, message_id, outsider, marker))
        _require(_group_ack(event, a, group, message_id) == CHAT_FORBIDDEN,
                 "非成员密钥接收者未收到明确成员拒绝 ACK")
    _note(report, verification_status="passed", coverage="nonmember_target_explicit_ack")


def private_body(command, owner, other, marker, *, forged=False):
    if command not in PRIVATE_COMMANDS:
        raise KeyIdentityError("Vuln45 私钥 opcode 不在本次修复范围")
    if command in (101, 104):
        return (p._fv(1, other if forged else owner) + p._fv(2, other if forged else owner)
                + p._fs(3, uuid.uuid4().hex) + p._fb(5, marker) + p._fv(7, 2))
    return p._fv(1, other if forged else owner) + p._fv(2, 2) + p._fb(3, marker)


def _private_marker(event, command, owner, marker):
    parsed = fields(event.body, _REQUEST_SCHEMA if command in (101, 104) else _PRIVATE_ACK_SCHEMA)
    if command in (101, 104):
        return (one(parsed, 1) == owner and one(parsed, 2) == owner
                and one(parsed, 5) == marker and one(parsed, 7, 0) == 2)
    return one(parsed, 1) == owner and one(parsed, 3) == marker and one(parsed, 2, 0) == 2


def _private_positive(session, command, owner, marker):
    body = private_body(command, owner, owner, marker)
    seq = session.send(command, body)
    event = session.wait(102 if command == 101 else 105, seq=seq)
    if event is None:
        raise KeyIdentityBlocked("私钥本人正控没有匹配 ACK；超时不能当作拒绝")
    parsed = fields(event.body, {1: 0, 2: 2, 3: 0, 4: 0})
    code = one(parsed, 4)
    if command == 101:
        _require(code == APP_OFFLINE, "无 App 的私钥请求未返回明确 App 离线 ACK")
        raise KeyIdentityBlocked("101 仅观察到 App 离线 ACK，未做真实 App 私钥同步；不计完整正控通过")
    if code != NON_ERR:
        raise KeyIdentityBlocked("私钥本人 Web 回环未返回成功 ACK，缺少实际可达正控")
    delivered = session.wait(command, predicate=lambda e: _private_marker(e, command, owner, marker))
    if delivered is None:
        raise KeyIdentityBlocked("私钥本人 Web 回环没有匹配 marker 下行；ACK 不能代替实际转发")


def check_private_key_positive(config, command, *, devices=None, session_factory=WireSession, report=None):
    a, _, _ = _config(config)
    if command == 101:
        _isolated_slots(config, devices=devices, app_only=True)
    marker = _MARKER_PREFIX + _attempt(report, command).encode("ascii")
    with ExitStack() as stack:
        sa, _ = _open(stack, config, session_factory)
        _private_positive(sa, command, a, marker)
    _note(report, verification_status="passed", coverage="same_account_web_marker_route_only")


def check_private_key_forgery(config, command, *, devices=None, session_factory=WireSession, report=None):
    a, b, _ = _config(config)
    if command == 101:
        _isolated_slots(config, devices=devices, app_only=True)
    marker = _MARKER_PREFIX + _attempt(report, command).encode("ascii")
    with ExitStack() as stack:
        sa, sb = _open(stack, config, session_factory)
        seq = sa.send(command, private_body(command, a, b, marker, forged=True))
        _note(report, request_sequence=seq)
        event = sa.wait(102 if command == 101 else 105, seq=seq)
        leaked = sb.wait(command, predicate=lambda e: _private_marker(e, command, b, marker))
        _require(leaked is None, "伪造身份私钥 marker 被转发到另一账号")
        if event is not None:
            parsed = fields(event.body, {1: 0, 2: 2, 3: 0, 4: 0})
            _require(one(parsed, 4) == FORBIDDEN, "伪造私钥请求没有返回明确身份拒绝业务码")
            if command == 101:
                raise KeyIdentityBlocked("101 缺少完整 App 同步正控；明确拒绝不单独计正式通过")
            _private_positive(sa, command, a, marker + b":positive-control")
            _note(report, verification_status="passed", coverage="explicit_rejection_and_same_owner_route")
            return
        _note(report, verification_status="blocked", observation="no_explicit_rejection_ack_not_proof")
        raise KeyIdentityBlocked("私钥非法包无明确拒绝 ACK，未见转发不能证明拒绝；后端身份单测与线上验收分开")
