"""V85：本轮新普通群消息的身份隔离；不自动 ACK 旧消息或改成员。"""
from contextlib import ExitStack
from dataclasses import dataclass, field
import time
import uuid

import requests

from im_test import proto_min as p
from im_test.security_p2_config import P2Blocked, P2Error, require, require_live, idle_accounts
from im_test.security_wire import WireSession, fields, one, text

CHAT, CHAT_ACK, DELIVER = 0x2001, 0x2002, 0x2004
CANCEL, CANCEL_ACK, READ, READ_ACK = 0x2005, 0x2006, 0x2307, 0x2308
NON_ERR, FORBIDDEN = 0x8000, 0x8201
ACKS = {"ack_chat": 0x2003, "ack_join_notice": 0x2103,
        "ack_group_notice": 0x2203, "ack_cancel_notice": 0x2007}
CASES = ("forged_sender_cancel", "cross_group_cancel", "own_cancel", "owner_cancel", *ACKS, "read_sync")


@dataclass(frozen=True)
class GroupRow:
    command: int
    msg_id: str
    sender: int
    group: int
    is_read: int
    raw: bytes = field(repr=False)


def parse_queue(raw, owner, correlation):
    parsed = fields(raw, {1: 0, 2: 2, 3: 2}, repeated=(3,))
    require(one(parsed, 1) == owner and text(parsed, 2) == correlation, "群离线读取身份或关联 ID 不匹配")
    rows = []
    for value in parsed.get(3, ()):
        row = fields(value, {1: 0, 2: 2, 3: 2, 4: 0, 5: 0, 6: 0, 7: 0, 8: 2, 9: 0, 10: 2, 11: 0})
        result = GroupRow(one(row, 1, 0), text(row, 3), one(row, 4, 0), one(row, 5, 0), one(row, 9, 0), value)
        require(bool(result.msg_id) and result.group > 0 and result.is_read in (0, 1), "群离线记录结构无效")
        rows.append(result)
    if len(rows) >= 500:
        raise P2Blocked("群队列达到单页上限，无法观察新记录；不清理旧队列")
    require(len({(r.msg_id, r.command) for r in rows}) == len(rows), "群队列记录重复，无法唯一观察")
    return tuple(rows)


class GroupStore:
    def __init__(self, config, suffix, post=None):
        self.uid = config["user_id" + suffix]
        self._token, self._base = config["token" + suffix], config["http_base"]
        self.version, self.timeout = config["p2_version"], config["timeout"]
        self._post = post or requests.post

    def __repr__(self):
        return "GroupStore(<凭证已隐藏>)"

    def queue(self):
        correlation = uuid.uuid4().hex
        # deliveredMsgIds(3) 始终省略，读取不标记 pulled/read。
        body = p._fv(1, self.uid) + p._fs(2, correlation) + p._fv(4, 500) + p._fv(5, 2)
        try:
            r = self._post(self._base + "/offline/" + self.version + "/group", data=body,
                           headers={"Authorization": f"{self._token}:{self.uid}", "Content-Type": "application/octet-stream"},
                           timeout=self.timeout, allow_redirects=False)
            require(r.status_code == 200 and r.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                    in ("application/x-protobuf", "application/protobuf", "application/octet-stream"), "群读取 HTTP 未明确成功")
            return parse_queue(r.content, self.uid, correlation)
        except (P2Error, P2Blocked):
            raise
        except Exception:
            raise P2Error("群只读快照失败；不能当作空队列") from None


def chat_body(sender, group, msg_id):
    return p._fv(1, group) + p._fv(2, sender) + p._fs(5, msg_id) + p._fb(8, b"im-security-v85-fixture") + p._fv(10, 5)


def group_ack(event, actor, group, msg_id, code):
    require(event is not None, "未收到明确群操作 ACK；不重发")
    parsed = fields(event.body, {1: 0, 2: 0, 3: 2, 4: 0, 5: 0})
    require(one(parsed, 1) == actor and one(parsed, 2) == group and text(parsed, 3) == msg_id,
            "群操作 ACK 账号、群或消息 ID 不匹配")
    require(one(parsed, 5) == code, "群操作未返回预期明确业务码")


def poll(read, ready, config, clock, sleep):
    end = clock() + config["timeout"]
    while True:
        value = read()
        if ready(value):
            return value
        if clock() >= end:
            raise P2Blocked("新夹具未落库或状态不可区分；已停止，不自动重发")
        sleep(min(.25, max(0, end - clock())))


def stable(read, expected, clock, sleep):
    end = clock() + 2
    while True:
        require(read() == expected, "越权包改变了另一账号的新消息记录")
        if clock() >= end:
            return
        sleep(min(.25, max(0, end - clock())))


def run_group_case(config, case, *, session_factory=WireSession, store_factory=GroupStore,
                   preflight=idle_accounts, clock=time.monotonic, sleep=time.sleep, record=lambda *a: None):
    require_live(config, "85")
    require(case in CASES, "未知 V85 阶段")
    if case == "cross_group_cancel" and not config["p2_other_group"]:
        raise P2Blocked("缺少已授权的第二普通群；不自动建群或加群")
    preflight(config, "85")
    stores = [store_factory(config, suffix) for suffix in ("", "2")]
    for store in stores:
        if len(store.queue()) > 490:
            raise P2Blocked("队列余量不足；不消费任何旧记录")
    group, a, b = config["p2_group"], config["user_id"], config["user_id2"]
    with ExitStack() as stack:
        sessions = [stack.enter_context(session_factory(config["ws_url"], config["user_id" + suffix], config["token" + suffix],
                      client_type=2, timeout=config["timeout"], app_version=config["app_version"])) for suffix in ("", "2")]
        def row(index, message):
            matches = [r for r in stores[index].queue() if r.msg_id == message and r.command == DELIVER]
            require(len(matches) <= 1, "新消息出现重复普通行")
            return matches[0] if matches else None
        def send(index, target=group):
            message = uuid.uuid4().hex
            record("new_message_id", message)  # 发送之前先留下 ID，未知结果不能重发。
            sender = a if index == 0 else b
            event = sessions[index].request(CHAT, chat_body(sender, target, message), CHAT_ACK)
            group_ack(event, sender, target, message, NON_ERR)
            received = poll(lambda: row(1-index, message), bool, config, clock, sleep)
            require(received.sender == sender and received.group == target and received.is_read == 0, "普通群夹具身份或未读状态不符合前置")
            stable(lambda: row(1-index, message), received, clock, sleep)
            return message
        if case in ("forged_sender_cancel", "cross_group_cancel", "own_cancel", "owner_cancel"):
            original = send(1 if case == "owner_cancel" else 0)
            observer = 0 if case == "owner_cancel" else 1
            before = row(observer, original)
            other_control = send(0, config["p2_other_group"]) if case == "cross_group_cancel" else None
            other_before = row(1, other_control) if other_control else None
            actor = 1 if case == "forged_sender_cancel" else 0
            target_group = config["p2_other_group"] if case == "cross_group_cancel" else group
            # B伪造A；其余为本人/群主正控，跨群必须是另一个获准测试群。
            body = p._fv(1, target_group) + p._fv(2, a) + p._fs(3, original)
            event = sessions[actor].request(CANCEL, body, CANCEL_ACK)
            denied = case in ("forged_sender_cancel", "cross_group_cancel")
            group_ack(event, b if actor else a, target_group, original, FORBIDDEN if denied else NON_ERR)
            if denied:
                stable(lambda: row(observer, original), before, clock, sleep)
                if other_control:
                    stable(lambda: row(1, other_control), other_before, clock, sleep)
            else:
                poll(lambda: row(observer, original), lambda r: r is None, config, clock, sleep)
                stable(lambda: row(observer, original), None, clock, sleep)
            return
        # 交叉发送两条：A自发M1中B未读/未ACK，B自发M2中A未读/未ACK。
        # 不要求第三账号，也不依赖发送者自己的副本处于未读状态。
        m1, m2 = send(0), send(1)
        b_before, a_before = row(1, m1), row(0, m2)
        if case in ACKS:
            command = ACKS[case]
            def ack(session, claimed, message):
                session.send(command, p._fv(1, claimed) + p._fv(2, group) + p._fs(3, message))
            ack(sessions[0], b, m1)
            stable(lambda: row(1, m1), b_before, clock, sleep)
            ack(sessions[0], b, m2)
            poll(lambda: row(0, m2), lambda r: r is None, config, clock, sleep)
            stable(lambda: row(1, m1), b_before, clock, sleep)
            ack(sessions[1], b, m1)
            poll(lambda: row(1, m1), lambda r: r is None, config, clock, sleep)
        else:
            def read(message):
                ev = sessions[0].request(READ, p._fv(1, b) + p._fs(2, message) + p._fv(3, group), READ_ACK)
                require(one(fields(ev.body, {1: 0}), 1) == NON_ERR, "已读同步未明确成功")
            read(m1)
            stable(lambda: row(1, m1), b_before, clock, sleep)
            read(m2)
            changed = poll(lambda: row(0, m2), lambda r: r is not None and r.is_read == 1, config, clock, sleep)
            require(changed.sender == a_before.sender and changed.msg_id == a_before.msg_id, "已读更新改变了原消息身份")
            stable(lambda: row(1, m1), b_before, clock, sleep)
