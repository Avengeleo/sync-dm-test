"""Vuln44 有界协议与落库证据的本地 fake 回归，不连接真实环境。"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from im_test import security_message_mutation as m
from im_test.security_wire import SecurityWireError, WireEvent, fields, one, text


CONFIG = {"http_base": "https://im.invalid", "ws_url": "wss://im.invalid/ws",
          "user_id": 101, "user_id2": 202, "token": "fake-a-secret", "token2": "fake-b-secret",
          "timeout": 1, "client_type": 2, "app_version": "9.9.9"}


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _ack(command, owner, msg_id, code):
    code_field = 4 if command == m.CHAT_ACK else 3
    return WireEvent(command, m._fv(1, owner) + m._fs(2, msg_id) + m._fv(code_field, code), 7)


def _row_bytes(row):
    return (m._fv(1, row.command) + m._fb(2, row.body.raw) + m._fs(3, row.msg_id)
            + m._fv(4, row.from_id) + m._fv(5, row.to_id) + m._fv(6, row.msg_time)
            + m._fv(7, row.is_cancel) + m._fs(8, row.parent_msg_id)
            + m._fv(9, row.is_read) + m._fv(10, row.is_edit))


def _reply(row=None, missing=""):
    result = m._fv(1, 200)
    if row is not None:
        result += m._fb(2, _row_bytes(row))
    if missing:
        result += m._fs(3, missing)
    return result


def _snapshot(owner=202, sender=101, receiver=202, msg_id="new-message", content=b"fake body"):
    body = m._parse_chat(m.chat_body(sender, receiver, msg_id, content))
    return m.ChatSnapshot(owner, m.CHAT_DELIVER, msg_id, sender, receiver, 123456,
                          0, 0, 0, "", body)


class FakeNetwork:
    def __init__(self, mode="patched"):
        self.mode = mode
        self.rows = {}
        self.sent = []
        self.reads = []
        self.closed = []

    def session(self, url, owner, token, **kwargs):
        network = self
        assert kwargs["transport"] == "ws" and kwargs["client_type"] == 2

        class Session:
            user_id = owner

            def __enter__(self):
                return self

            def __exit__(self, *unused):
                network.closed.append(owner)

            def request(self, command, body, response_command):
                network.sent.append((owner, command, body, response_command))
                if network.mode == "send_timeout":
                    raise SecurityWireError("secret credential should not escape")
                if command in (m.CHAT, m.CHAT_OPPOSITE):
                    chat = m._parse_chat(body)
                    target_owner = chat.to_id if command == m.CHAT else owner
                    if command == m.CHAT_OPPOSITE and network.mode == "missing_owner_copy":
                        return _ack(response_command, owner, chat.msg_id, m.NON_ERR)
                    network.rows[(target_owner, chat.msg_id)] = m.ChatSnapshot(
                        target_owner, m.CHAT_DELIVER, chat.msg_id, owner, chat.to_id,
                        123456, 0, 0, 0, "", chat,
                    )
                    return _ack(response_command, owner, chat.msg_id, m.NON_ERR)
                if command == m.CHAT_CANCEL:
                    parsed = fields(body, {1: 0, 2: 0, 5: 2})
                    receiver, msg_id = one(parsed, 1), text(parsed, 5)
                    key = (receiver, msg_id)
                else:
                    parsed = fields(body, {1: 0, 2: 0, 3: 2, 4: 2})
                    receiver, msg_id = one(parsed, 2), text(parsed, 3)
                    key = (owner if command == m.CHAT_EDIT_OPPOSITE else receiver, msg_id)
                original = network.rows.get(key)
                permitted = original is not None and original.from_id == owner
                code = m.NON_ERR if permitted else m.ERR_CHAT_FORBIDDEN
                if network.mode == "wrong_ack_owner":
                    return _ack(response_command, 999, msg_id, code)
                if network.mode == "ack_only":
                    return _ack(response_command, owner, msg_id, code)
                if permitted or network.mode == "deny_mutates":
                    if command == m.CHAT_CANCEL:
                        for record_key, row in tuple(network.rows.items()):
                            if row.msg_id == msg_id:
                                network.rows[record_key] = replace(row, is_cancel=1)
                    else:
                        nested = m._parse_chat(one(parsed, 4))
                        if network.mode != "untrusted_nested":
                            nested = m._parse_chat(m.chat_body(
                                original.from_id, original.to_id, msg_id, nested.content,
                            ))
                        if original is not None:
                            network.rows[key] = replace(original, body=nested, is_edit=1)
                        if command == m.CHAT_EDIT_OPPOSITE and network.mode == "both_copies_edit":
                            for record_key, row in tuple(network.rows.items()):
                                if row.msg_id == msg_id:
                                    network.rows[record_key] = replace(row, body=nested, is_edit=1)
                return _ack(response_command, owner, msg_id, code)

        return Session()

    def http(self, base_url, token, owner, timeout):
        network = self

        class Http:
            user_id = owner

            def read(self, msg_id, version):
                network.reads.append((owner, msg_id, version))
                row = network.rows.get((owner, msg_id))
                # 与真实 HTTP 一样重新走完整严格解码，不能跳过内层身份断言。
                return m.parse_chat_reply(_reply(row, "" if row else msg_id), owner, msg_id)

        return Http()


def _run(case, version="v1", mode="patched"):
    network, clock, ids = FakeNetwork(mode), Clock(), []
    result = m.run_message_mutation(
        CONFIG, version, case, on_message=ids.append,
        session_factory=network.session, http_factory=network.http,
        clock=clock, sleep=clock.sleep,
    )
    return result, network, ids


@pytest.mark.parametrize("version", ("v1", "v2"))
@pytest.mark.parametrize("case", m.CASES)
def test_every_mutation_case_requires_real_owner_views_and_expected_storage(case, version):
    result, network, ids = _run(case, version)
    assert ids == [result.msg_id]
    assert len(result.msg_id) == 32
    assert [entry[1] for entry in network.sent[:2]] == [m.CHAT, m.CHAT_OPPOSITE]
    assert len(network.sent) == 3  # 两个建副本阶段及一次待测变更，绝不重发。
    assert len(network.closed) == 2
    assert {entry[0] for entry in network.reads} == {101, 202}
    assert {entry[2] for entry in network.reads} == {version}
    for owner in (101, 202):
        assert (owner, result.msg_id) in network.rows
    assert result.acknowledgement == (m.ERR_CHAT_FORBIDDEN if case.startswith("forged_") else m.NON_ERR)


@pytest.mark.parametrize("case", ("own_edit", "own_opposite", "own_cancel"))
def test_success_ack_without_persisted_change_never_passes(case):
    with pytest.raises(m.MessageMutationError, match="仅收到 ACK"):
        _run(case, mode="ack_only")


@pytest.mark.parametrize("case", ("forged_sender_edit", "forged_sender_cancel"))
def test_forbidden_ack_with_original_record_changed_never_passes(case):
    with pytest.raises(m.MessageMutationError, match="稳定状态"):
        _run(case, mode="deny_mutates")


@pytest.mark.parametrize("case", ("nested_identity_edit", "nested_identity_opposite"))
def test_nested_identity_must_be_normalized_in_persisted_record(case):
    with pytest.raises(m.MessageMutationError, match="内层消息身份不一致"):
        _run(case, mode="untrusted_nested")


def test_opposite_end_must_not_change_recipient_copy():
    with pytest.raises(m.MessageMutationError, match="另一份副本"):
        _run("own_opposite", mode="both_copies_edit")


def test_missing_sender_copy_stops_before_mutation_and_keeps_new_id():
    network, clock, ids = FakeNetwork("missing_owner_copy"), Clock(), []
    with pytest.raises(m.MessageMutationError, match="双副本夹具"):
        m.run_message_mutation(CONFIG, "v1", "own_opposite", on_message=ids.append,
                              session_factory=network.session, http_factory=network.http,
                              clock=clock, sleep=clock.sleep)
    assert len(ids) == 1
    assert [entry[1] for entry in network.sent] == [m.CHAT, m.CHAT_OPPOSITE]
    assert len(network.closed) == 2


def test_timeout_stops_without_resend_and_does_not_include_raw_error():
    network, clock, ids = FakeNetwork("send_timeout"), Clock(), []
    with pytest.raises(m.MessageMutationError) as caught:
        m.run_message_mutation(CONFIG, "v1", "own_edit", on_message=ids.append,
                              session_factory=network.session, http_factory=network.http,
                              clock=clock, sleep=clock.sleep)
    assert len(network.sent) == 1 and len(ids) == 1
    assert "secret" not in str(caught.value)


def test_forged_sender_fixture_really_is_b_to_a_with_both_copies():
    result, network, _ = _run("forged_sender_edit")
    assert result.sender_id == 202 and result.receiver_id == 101
    for owner in (101, 202):
        row = network.rows[(owner, result.msg_id)]
        assert (row.from_id, row.to_id, row.body.from_id, row.body.to_id) == (202, 101, 202, 101)
    actor, command, raw, _ = network.sent[-1]
    request = fields(raw, {1: 0, 2: 0, 3: 2, 4: 2})
    assert actor == 101 and command == m.CHAT_EDIT and one(request, 1) == 202


def test_nested_identity_payload_is_forged_but_stored_original_identity():
    result, network, _ = _run("nested_identity_edit")
    parsed = fields(network.sent[-1][2], {1: 0, 2: 0, 3: 2, 4: 2})
    nested = m._parse_chat(one(parsed, 4))
    assert one(parsed, 1) == 202
    assert (nested.from_id, nested.to_id) == (202, 101)
    assert nested.msg_id != result.msg_id
    persisted = network.rows[(202, result.msg_id)]
    assert (persisted.from_id, persisted.to_id, persisted.body.from_id, persisted.body.to_id) == (101, 202, 101, 202)
    assert persisted.body.msg_id == result.msg_id


@pytest.mark.parametrize("raw", (
    b"", m._fv(1, 200), m._fv(1, 0), m._fv(1, 200) + m._fv(1, 200),
    m._fv(1, 200) + m._fs(3, "another-id"), m._fv(1, 200) + b"\x12\x05x",
    m._fv(1, 200) + m._fs(3, "new-message") + m._fs(3, "new-message"),
))
def test_missing_empty_duplicate_or_truncated_http_reply_never_proves_storage(raw):
    with pytest.raises((m.MessageMutationError, SecurityWireError)):
        m.parse_chat_reply(raw, 202, "new-message")


def test_explicit_missing_is_only_pollable_not_a_positive_record():
    assert m.parse_chat_reply(_reply(missing="new-message"), 202, "new-message") is None


def test_owner_view_and_inner_identity_are_checked():
    row = _snapshot()
    parsed = m.parse_chat_reply(_reply(row), 202, row.msg_id)
    assert parsed.owner_id == 202 and parsed.body.content == b"fake body"
    tampered = replace(row, body=m._parse_chat(m.chat_body(202, 101, row.msg_id, b"fake body")))
    with pytest.raises(m.MessageMutationError, match="内层消息身份不一致"):
        m.parse_chat_reply(_reply(tampered), 202, row.msg_id)


@pytest.mark.parametrize("command", (m.CHAT_ACK, m.CHAT_EDIT_ACK, m.CHAT_CANCEL_ACK))
def test_ack_requires_exact_actor_message_and_success_code(command):
    assert m.require_ack(_ack(command, 101, "fresh", m.NON_ERR), 101, "fresh", command, m.NON_ERR) == m.NON_ERR
    for event in (None, _ack(command, 202, "fresh", m.NON_ERR),
                  _ack(command, 101, "wrong", m.NON_ERR),
                  _ack(command, 101, "fresh", 0)):
        with pytest.raises(m.MessageMutationError):
            m.require_ack(event, 101, "fresh", command, m.NON_ERR)


def test_denial_must_be_explicit_forbidden_not_timeout_or_generic_failure():
    for code in (m.NON_ERR, 0, 0x8107, 0x8301):
        with pytest.raises(m.MessageMutationError, match="ERR_CHAT_FORBIDDEN"):
            m.require_ack(_ack(m.CHAT_EDIT_ACK, 101, "fresh", code),
                          101, "fresh", m.CHAT_EDIT_ACK, m.ERR_CHAT_FORBIDDEN)


@pytest.mark.parametrize("version", ("v1", "v2"))
def test_http_request_reads_only_fresh_id_without_delivered_ack(version):
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return SimpleNamespace(status_code=200, content=_reply(_snapshot()),
                               headers={"Content-Type": "application/x-protobuf"})

    client = m.MutationHttpClient("https://im.invalid/", "fake-credential", 202,
                                  transport=SimpleNamespace(post=post))
    result = client.read("new-message", version)
    url, args = calls[0]
    assert url == "https://im.invalid/offline/" + version + "/chat/msg/by_id"
    assert args["allow_redirects"] is False
    parsed = fields(args["data"], {1: 0, 2: 2, 3: 0})
    assert one(parsed, 1) == 202 and text(parsed, 2) == "new-message" and one(parsed, 3) == 2
    assert result.owner_id == 202


def test_http_transport_error_does_not_expose_credential_or_response():
    def post(*unused, **kwargs):
        raise RuntimeError("fake-credential and fake body")

    client = m.MutationHttpClient("https://im.invalid", "fake-credential", 202,
                                  transport=SimpleNamespace(post=post))
    with pytest.raises(m.MessageMutationError) as caught:
        client.read("new-message", "v1")
    assert "fake-credential" not in str(caught.value) and "fake body" not in str(caught.value)


def test_message_and_body_reprs_do_not_print_content_or_message_id():
    row = _snapshot(msg_id="private-fixture-id", content=b"hidden marker body")
    assert "private-fixture-id" not in repr(row)
    assert "hidden marker body" not in repr(row) + repr(row.body)


@pytest.mark.parametrize("updates", ({"user_id": 0}, {"user_id2": 101},
                                     {"client_type": 0}, {"timeout": float("nan")}))
def test_invalid_identity_or_transport_configuration_stops_before_send(updates):
    network = FakeNetwork()
    with pytest.raises(m.MessageMutationError):
        m.run_message_mutation(dict(CONFIG, **updates), "v1", "own_edit",
                              session_factory=network.session, http_factory=network.http)
    assert not network.sent
