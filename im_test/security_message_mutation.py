"""Vuln44：仅变更本轮创建的普通单聊消息，不读取历史列表、不自动重发。

原消息通过 0x1001 建立收件副本，再通过正常 0x1011 建立本人发件副本。
所有判断使用按新 msgId 回源的落库结果；ACK 本身不能作为修复通过依据。
"""

from contextlib import ExitStack
from dataclasses import dataclass, field
import math
import time
import uuid

import requests

from im_test.security_wire import SecurityWireError, WireSession, fields, one, text, uid


CHAT = 0x1001
CHAT_ACK = 0x1002
CHAT_DELIVER = 0x1004
CHAT_CANCEL = 0x100B
CHAT_CANCEL_ACK = 0x100C
CHAT_OPPOSITE = 0x1011
CHAT_EDIT = 0x1224
CHAT_EDIT_OPPOSITE = 0x1225
CHAT_EDIT_ACK = 0x1226
NON_ERR = 0x8000
ERR_CHAT_FORBIDDEN = 0x8201
MAX_BODY = 1024 * 1024
STABLE_SECONDS = 2.0
POLL_SECONDS = 0.25

CASES = (
    "forged_sender_edit", "forged_sender_cancel", "forged_sender_opposite",
    "own_edit", "own_cancel", "own_opposite",
    "nested_identity_edit", "nested_identity_opposite",
)

_CHAT_SCHEMA = {1: 0, 2: 0, 3: 2, 4: 0, 5: 0, 6: 0, 7: 2,
                10: 2, 11: 2, 12: 2}
_OFFLINE_SCHEMA = {1: 0, 2: 2, 3: 2, 4: 0, 5: 0, 6: 0,
                   7: 0, 8: 2, 9: 0, 10: 0}


class MessageMutationError(AssertionError):
    """仅包含固定诊断，不包含凭证、响应正文或原始异常。"""


def _vi(value):
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << 64):
        raise MessageMutationError("Vuln44 编码数值超出协议范围")
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _fv(number, value):
    return _vi(number << 3) + _vi(value)


def _fb(number, value):
    if not isinstance(value, bytes) or len(value) > MAX_BODY:
        raise MessageMutationError("Vuln44 编码内容类型或大小不合法")
    return _vi((number << 3) | 2) + _vi(len(value)) + value


def _fs(number, value):
    if not isinstance(value, str) or len(value) > 256:
        raise MessageMutationError("Vuln44 编码标识类型或大小不合法")
    return _fb(number, value.encode("utf-8"))


def chat_body(sender, receiver, msg_id, content):
    if not uid(sender) or not uid(receiver) or not content:
        raise MessageMutationError("Vuln44 普通消息缺少有效身份或内容")
    return (_fv(1, receiver) + _fv(2, sender) + _fs(3, msg_id)
            + _fv(4, 1) + _fb(7, content))


def edit_body(user_id, receiver, msg_id, nested):
    if not uid(user_id) or not uid(receiver):
        raise MessageMutationError("Vuln44 编辑请求身份不合法")
    return _fv(1, user_id) + _fv(2, receiver) + _fs(3, msg_id) + _fb(4, nested)


def cancel_body(sender, receiver, msg_id):
    if not uid(sender) or not uid(receiver):
        raise MessageMutationError("Vuln44 撤回请求身份不合法")
    return _fv(1, receiver) + _fv(2, sender) + _fs(5, msg_id)


@dataclass(frozen=True)
class ChatBody:
    from_id: int
    to_id: int
    msg_id: str = field(repr=False)
    msg_type: int = 1
    encrypt: int = 0
    content: bytes = field(default=b"", repr=False)
    raw: bytes = field(default=b"", repr=False)


@dataclass(frozen=True)
class ChatSnapshot:
    # owner_id 来自读取请求的鉴权账号，HTTP 协议不返回数据库 owerId 字段。
    owner_id: int
    command: int
    msg_id: str = field(repr=False)
    from_id: int
    to_id: int
    msg_time: int
    is_cancel: int
    is_edit: int
    is_read: int
    parent_msg_id: str = field(repr=False)
    body: ChatBody = field(repr=False)

    @property
    def record_identity(self):
        return (self.owner_id, self.command, self.msg_id, self.from_id,
                self.to_id, self.msg_time, self.parent_msg_id)


@dataclass(frozen=True)
class MutationResult:
    case: str
    version: str
    msg_id: str
    sender_id: int
    receiver_id: int
    acknowledgement: int
    evidence: str = "persisted_both_owner_views_and_stable_reread"


def _parse_chat(raw):
    parsed = fields(raw, _CHAT_SCHEMA)
    result = ChatBody(one(parsed, 2, 0), one(parsed, 1, 0), text(parsed, 3),
                      one(parsed, 4, 0), one(parsed, 6, 0), one(parsed, 7, b""), raw)
    # 其余 string 字段也必须是合法 UTF-8，不能藏入未解析的畸形数据。
    for number in (10, 11, 12):
        text(parsed, number)
    if (not uid(result.from_id) or not uid(result.to_id) or not result.msg_id
            or len(result.msg_id) > 128 or result.msg_type != 1 or result.encrypt != 0
            or not result.content):
        raise MessageMutationError("Vuln44 回源不是有效的普通未加密单聊消息")
    return result


def parse_chat_reply(raw, owner_id, msg_id, status=200):
    """只接受被请求的唯一记录或明确 missing；空响应不能作落库正控。"""
    if not uid(owner_id) or not isinstance(msg_id, str) or not msg_id:
        raise MessageMutationError("Vuln44 回源账号或消息标识不合法")
    parsed = fields(raw, {1: 0, 2: 2, 3: 2}, repeated=(2, 3))
    if status != 200 or one(parsed, 1, 0) != 200:
        raise MessageMutationError("Vuln44 单聊回源未明确成功")
    rows, missing = parsed.get(2, ()), parsed.get(3, ())
    if not rows:
        if len(missing) == 1 and text({3: list(missing)}, 3) == msg_id:
            return None
        raise MessageMutationError("Vuln44 回源既无唯一记录也无明确缺失状态")
    if len(rows) != 1 or missing:
        raise MessageMutationError("Vuln44 单消息回源返回重复或冲突结果")
    row = fields(rows[0], _OFFLINE_SCHEMA)
    snapshot = ChatSnapshot(
        owner_id, one(row, 1, 0), text(row, 3), one(row, 4, 0), one(row, 5, 0),
        one(row, 6, 0), one(row, 7, 0), one(row, 10, 0), one(row, 9, 0),
        text(row, 8), _parse_chat(one(row, 2, b"")),
    )
    if (snapshot.msg_id != msg_id or snapshot.command not in (CHAT, CHAT_DELIVER)
            or not uid(snapshot.from_id) or not uid(snapshot.to_id) or snapshot.msg_time <= 0
            or any(value not in (0, 1) for value in
                   (snapshot.is_cancel, snapshot.is_edit, snapshot.is_read))
            or snapshot.body.msg_id != msg_id or snapshot.body.from_id != snapshot.from_id
            or snapshot.body.to_id != snapshot.to_id):
        raise MessageMutationError("Vuln44 回源记录及内层消息身份不一致")
    return snapshot


class MutationHttpClient:
    def __init__(self, base_url, token, user_id, timeout=10, transport=None):
        self._base = base_url.rstrip("/")
        self._token = token
        self.user_id = user_id
        self._timeout = timeout
        self._transport = transport or requests

    def read(self, msg_id, version):
        if version not in ("v1", "v2"):
            raise MessageMutationError("Vuln44 HTTP 版本不合法")
        body = _fv(1, self.user_id) + _fs(2, msg_id) + _fv(3, 2)
        try:
            response = self._transport.post(
                self._base + "/offline/" + version + "/chat/msg/by_id",
                data=body, headers={"Authorization": f"{self._token}:{self.user_id}",
                                    "Content-Type": "application/octet-stream"},
                timeout=self._timeout, allow_redirects=False,
            )
        except Exception:
            raise MessageMutationError("Vuln44 单聊回源传输失败，未回显原始异常") from None
        if (response.status_code != 200
                or response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                not in ("application/x-protobuf", "application/octet-stream", "application/protobuf")):
            raise MessageMutationError("Vuln44 单聊回源 HTTP 状态或内容类型不合法")
        try:
            return parse_chat_reply(response.content, self.user_id, msg_id, response.status_code)
        except SecurityWireError:
            raise MessageMutationError("Vuln44 单聊回源 protobuf 不符合协议") from None


def require_ack(event, user_id, msg_id, command, expected):
    if event is None or event.command != command:
        raise MessageMutationError("Vuln44 未收到匹配的明确操作 ACK")
    schema = {1: 0, 2: 2, 3: 0, 4: 0} if command == CHAT_ACK else {1: 0, 2: 2, 3: 0}
    parsed = fields(event.body, schema)
    code = one(parsed, 4 if command == CHAT_ACK else 3, 0)
    if one(parsed, 1, 0) != user_id or text(parsed, 2) != msg_id:
        raise MessageMutationError("Vuln44 ACK 的账号或原消息标识不匹配")
    if code != expected:
        if expected == ERR_CHAT_FORBIDDEN:
            raise MessageMutationError("Vuln44 越权操作未返回明确 ERR_CHAT_FORBIDDEN")
        raise MessageMutationError("Vuln44 本人操作或夹具发送未明确成功")
    return code


def _read_pair(stores, msg_id, version):
    return tuple(store.read(msg_id, version) for store in stores)


def _poll(read, ready, timeout, clock, sleep, failure):
    deadline = clock() + timeout
    while True:
        result = read()
        if ready(result):
            return result
        if clock() >= deadline:
            raise MessageMutationError(failure)
        sleep(min(POLL_SECONDS, max(0, deadline - clock())))


def _stable(read, expected, clock, sleep):
    deadline = clock() + STABLE_SECONDS
    while True:
        if read() != expected:
            raise MessageMutationError("Vuln44 操作后的原记录、内容或归属未保持预期稳定状态")
        if clock() >= deadline:
            return
        sleep(min(POLL_SECONDS, max(0, deadline - clock())))


def _fresh_pair(pair, sender, receiver, msg_id, content):
    if any(row is None for row in pair):
        return False
    for row in pair:
        if (row.from_id != sender or row.to_id != receiver or row.msg_id != msg_id
                or row.body.content != content or row.is_cancel or row.is_edit or row.is_read
                or row.parent_msg_id):
            raise MessageMutationError("Vuln44 新消息双副本不是预期的独立未消费夹具")
    if {row.owner_id for row in pair} != {sender, receiver}:
        raise MessageMutationError("Vuln44 新消息缺少两个鉴权账号的独立副本")
    return True


def _edited_pair(pair, before, target_owner, content):
    if any(row is None for row in pair):
        return False
    complete = True
    for row, original in zip(pair, before):
        if row.record_identity != original.record_identity or row.is_read != original.is_read:
            raise MessageMutationError("Vuln44 编辑改变了原记录归属、身份或其他状态")
        if row.owner_id != target_owner:
            if row != original:
                raise MessageMutationError("Vuln44 编辑影响了不应修改的另一份副本")
        elif row.is_cancel:
            raise MessageMutationError("Vuln44 编辑意外撤回了消息")
        elif row.is_edit != 1 or row.body.content != content:
            complete = False
    return complete


def _canceled_pair(pair, before):
    if any(row is None for row in pair):
        return False
    for row, original in zip(pair, before):
        if (row.record_identity != original.record_identity or row.body != original.body
                or row.is_edit != original.is_edit or row.is_read != original.is_read):
            raise MessageMutationError("Vuln44 撤回意外改变了原记录内容、归属或其他状态")
    return all(row.is_cancel == 1 for row in pair)


def run_message_mutation(config, version, case, *, on_message=None,
                         session_factory=None, http_factory=None, clock=None, sleep=None):
    """每 case 创建一条新消息，协议阶段各发送一次；任何超时都停止而不重发。"""
    if case not in CASES or version not in ("v1", "v2"):
        raise MessageMutationError("Vuln44 用例或 HTTP 版本不合法")
    a, b = config.get("user_id"), config.get("user_id2")
    timeout = config.get("timeout", 10)
    if (not uid(a) or not uid(b) or a == b or config.get("client_type", 2) != 2
            or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 120):
        raise MessageMutationError("Vuln44 专用账号、端类型或超时配置不合法")
    session_factory = session_factory or WireSession
    http_factory = http_factory or MutationHttpClient
    clock, sleep = clock or time.monotonic, sleep or time.sleep
    msg_id = uuid.uuid4().hex
    if on_message is not None:
        on_message(msg_id)
    denied = case.startswith("forged_sender_")
    sender, receiver = (b, a) if denied else (a, b)
    original_content = ("IM_V44_" + msg_id + "_original").encode("ascii")
    new_content = ("IM_V44_" + msg_id + "_edited").encode("ascii")
    stores = (http_factory(config["http_base"], config["token"], a, timeout),
              http_factory(config["http_base"], config["token2"], b, timeout))
    read = lambda: _read_pair(stores, msg_id, version)
    try:
        with ExitStack() as stack:
            sessions = {}
            for owner, token in ((a, config["token"]), (b, config["token2"])):
                sessions[owner] = stack.enter_context(session_factory(
                    config["ws_url"], owner, token, transport="ws", client_type=2,
                    timeout=timeout, app_version=config.get("app_version", "9.9.9"),
                ))
            source = sessions[sender]
            body = chat_body(sender, receiver, msg_id, original_content)
            # 先证实收件副本落库，再建立发件副本；不是对失败消息重试。
            require_ack(source.request(CHAT, body, CHAT_ACK), sender, msg_id, CHAT_ACK, NON_ERR)
            recipient_store = stores[0] if receiver == a else stores[1]
            _poll(lambda: recipient_store.read(msg_id, version), lambda row: row is not None,
                  timeout, clock, sleep, "Vuln44 收件副本未在期限内落库，停止且未重发")
            require_ack(source.request(CHAT_OPPOSITE, body, CHAT_ACK), sender, msg_id, CHAT_ACK, NON_ERR)
            before = _poll(read, lambda pair: _fresh_pair(pair, sender, receiver, msg_id, original_content),
                           timeout, clock, sleep, "Vuln44 双副本夹具未在期限内落库，停止且未重发")
            _stable(read, before, clock, sleep)

            actor = sessions[a]
            opposite = case.endswith("opposite")
            cancel = case.endswith("cancel")
            if cancel:
                command, response = CHAT_CANCEL, CHAT_CANCEL_ACK
                body = cancel_body(b if denied else a, receiver, msg_id)
            else:
                command, response = (CHAT_EDIT_OPPOSITE if opposite else CHAT_EDIT), CHAT_EDIT_ACK
                forged_nested = case.startswith("nested_identity_")
                nested = chat_body(
                    b if forged_nested else sender, a if forged_nested else receiver,
                    uuid.uuid4().hex if forged_nested else msg_id, new_content,
                )
                body = edit_body(b if denied or forged_nested else a,
                                 a if opposite and not denied else receiver, msg_id, nested)
            expected = ERR_CHAT_FORBIDDEN if denied else NON_ERR
            code = require_ack(actor.request(command, body, response), a, msg_id, response, expected)
            if denied:
                _stable(read, before, clock, sleep)
            else:
                ready = ((lambda pair: _canceled_pair(pair, before)) if cancel else
                         (lambda pair: _edited_pair(pair, before, a if opposite else b, new_content)))
                after = _poll(read, ready, timeout, clock, sleep,
                              "Vuln44 仅收到 ACK，预期的本人修改未在期限内实际落库")
                _stable(read, after, clock, sleep)
            return MutationResult(case, version, msg_id, sender, receiver, code)
    except SecurityWireError:
        raise MessageMutationError("Vuln44 连接或 protobuf 协议校验失败，未重发操作") from None
