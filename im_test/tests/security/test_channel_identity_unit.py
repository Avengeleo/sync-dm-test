"""Vuln42 纯本地 wire/误判回归；所有 HTTP 都是 fake，不读取配置或凭证。"""

from types import SimpleNamespace

import pytest
import requests

from im_test import proto_min as p
from im_test.security_channel import ChannelRequestError
from im_test.security_channel_identity import (
    ChannelIdentityReply, IdentityAtIndexes, IdentityFixtureUnavailable, IdentityIndex,
    SecurityChannelIdentityClient, check_at_messages_identity, check_operations_identity,
    check_read_indexes_identity, check_update_read_index_identity, check_verify_operations_identity,
    parse_identity_reply,
)


CHANNEL = 301
CONFIG = {"identity_channel_id": CHANNEL, "identity_message_id": "fixed-broadcast"}


def index(number):
    return f"{number:024x}"


def message(number, content=b"PRIVATE_MESSAGE_SENTINEL"):
    return (p._fv(2, CHANNEL) + p._fs(3, f"message-{number}") + p._fb(6, content)
            + p._fs(8, index(number)))


class IdentityBackend:
    """可独立恢复每条旧漏洞：仅指定路由重新信任 body uid。"""
    def __init__(self, vulnerable=None):
        self.vulnerable = vulnerable
        self.read = {41: index(1), 42: index(2)}
        self.at = {41: [index(11)], 42: [index(12)]}
        self.ops = {41: [10, 20], 42: [20]}
        self.calls = []
        self.status = 200
        self.errcode = 0
        self.content_type = "application/x-protobuf"
        self.empty_membership = False
        self.extra_channel = False

    def post(self, url, **kwargs):
        path = url.split("/channel/", 1)[1]
        version, endpoint = path.split("/", 1)
        self.calls.append((version, endpoint, kwargs))
        auth_uid = int(kwargs["headers"]["Authorization"].rsplit(":", 1)[1])
        fields = p.decode_all(kwargs["data"])
        uid = fields[1][0] if self.vulnerable == endpoint else auth_uid
        if endpoint == "msg/by_id":
            body = b"" if self.empty_membership else p._fb(2, message(50))
            # 固定消息 ID 必须与配置相同。
            if body:
                body = p._fb(2, p._fv(2, CHANNEL) + p._fs(3, CONFIG["identity_message_id"])
                             + p._fb(6, b"PRIVATE_BROADCAST_SENTINEL") + p._fs(8, index(50)))
        elif endpoint == "readIndexes":
            body = p._fb(2, p._fv(1, CHANNEL) + p._fs(2, self.read[uid]))
        elif endpoint == "atMessages":
            row = p._fv(1, CHANNEL) + b"".join(p._fs(2, value) for value in self.at[uid])
            body = p._fb(2, row)
        elif endpoint in ("oprMessage", "oprMessages"):
            body = b"".join(p._fb(2, message(value)) for value in self.ops[uid])
            if self.extra_channel:
                body += p._fb(2, p._fv(2, 999) + p._fs(3, "outside") + p._fb(6, b"outside") + p._fs(8, index(30)))
        elif endpoint == "readIndexes/edit":
            row = p.decode_all(fields[2][0])
            self.read[uid] = max(self.read[uid], row[2][0].decode())
            body = b""
        elif endpoint == "oprMessages/verify":
            row = p.decode_all(fields[2][0])
            target = row[2][0].decode()
            self.ops[uid] = [value for value in self.ops[uid] if index(value) > target]
            body = b""
        else:
            raise AssertionError("未知 fake 端点")
        if self.errcode:
            body = p._fv(1, self.errcode)
        return SimpleNamespace(status_code=self.status, content=body,
                               headers={"Content-Type": self.content_type})

    def clients(self):
        return tuple(SecurityChannelIdentityClient(
            "https://unit.invalid", f"PRIVATE_FAKE_TOKEN_{uid}", uid,
            timeout=1, client_type=2, post=self.post,
        ) for uid in (41, 42))


PROBES = (
    ("readIndexes", check_read_indexes_identity, {}),
    ("atMessages", check_at_messages_identity, {}),
    ("oprMessage", check_operations_identity, {}),
    ("oprMessages", check_operations_identity, {"all_channels": True}),
    ("readIndexes/edit", check_update_read_index_identity, {}),
    ("oprMessages/verify", check_verify_operations_identity, {}),
)


@pytest.mark.parametrize("version", ("v1", "v2"))
@pytest.mark.parametrize("endpoint,probe,kwargs", PROBES, ids=[row[0] for row in PROBES])
def test_all_six_routes_accept_patched_binding(version, endpoint, probe, kwargs):
    backend = IdentityBackend()
    probe(CONFIG, version, clients=backend.clients(), **kwargs)
    if endpoint == "readIndexes/edit":
        assert backend.read == {41: index(50), 42: index(2)}
    if endpoint == "oprMessages/verify":
        assert backend.ops == {41: [], 42: [20]}


@pytest.mark.parametrize("version", ("v1", "v2"))
@pytest.mark.parametrize("endpoint,probe,kwargs", PROBES, ids=[row[0] for row in PROBES])
def test_each_original_uid_vulnerability_is_detected(version, endpoint, probe, kwargs):
    backend = IdentityBackend(vulnerable=endpoint)
    with pytest.raises(ChannelRequestError):
        probe(CONFIG, version, clients=backend.clients(), **kwargs)


@pytest.mark.parametrize("endpoint,probe,kwargs", PROBES, ids=[row[0] for row in PROBES])
@pytest.mark.parametrize("status", (301, 401, 403, 500, 503))
def test_http_failure_is_not_pass_or_fixture_skip(endpoint, probe, kwargs, status):
    backend = IdentityBackend()
    backend.status = status
    with pytest.raises(ChannelRequestError):
        probe(CONFIG, "v1", clients=backend.clients(), **kwargs)


@pytest.mark.parametrize("endpoint,probe,kwargs", PROBES, ids=[row[0] for row in PROBES])
def test_empty_member_positive_control_fails(endpoint, probe, kwargs):
    backend = IdentityBackend()
    backend.empty_membership = True
    with pytest.raises(ChannelRequestError, match="空数据"):
        probe(CONFIG, "v1", clients=backend.clients(), **kwargs)


@pytest.mark.parametrize("endpoint,probe,kwargs", PROBES, ids=[row[0] for row in PROBES])
def test_equal_account_states_never_count_as_pass(endpoint, probe, kwargs):
    backend = IdentityBackend()
    backend.read[42] = backend.read[41]
    backend.at[42] = backend.at[41][:]
    backend.ops[42] = backend.ops[41][:]
    with pytest.raises(IdentityFixtureUnavailable):
        probe(CONFIG, "v1", clients=backend.clients(), **kwargs)


def test_consumed_write_fixture_does_not_pass_again():
    backend = IdentityBackend()
    check_update_read_index_identity(CONFIG, "v1", clients=backend.clients())
    with pytest.raises(IdentityFixtureUnavailable, match="重新预置"):
        check_update_read_index_identity(CONFIG, "v2", clients=backend.clients())
    backend = IdentityBackend()
    check_verify_operations_identity(CONFIG, "v1", clients=backend.clients())
    with pytest.raises(IdentityFixtureUnavailable, match="重新预置"):
        check_verify_operations_identity(CONFIG, "v2", clients=backend.clients())


@pytest.mark.parametrize("all_channels", (False, True))
def test_operation_read_requires_nonempty_and_bounded_fixture(all_channels):
    backend = IdentityBackend()
    backend.ops = {41: [], 42: []}
    with pytest.raises(IdentityFixtureUnavailable):
        check_operations_identity(CONFIG, "v1", all_channels, backend.clients())
    backend = IdentityBackend()
    backend.extra_channel = True
    with pytest.raises(ChannelRequestError, match="超出专用频道"):
        check_operations_identity(CONFIG, "v1", all_channels, backend.clients())


def test_empty_at_fixture_is_unverified():
    backend = IdentityBackend()
    backend.at[41] = []
    with pytest.raises(IdentityFixtureUnavailable):
        check_at_messages_identity(CONFIG, "v1", clients=backend.clients())


def test_empty_read_response_cannot_be_positive_control():
    backend = IdentityBackend()
    a, b = backend.clients()
    a.read_indexes = lambda *args, **kwargs: ChannelIdentityReply(200, 0)
    with pytest.raises(ChannelRequestError, match="空数据"):
        check_read_indexes_identity(CONFIG, "v1", clients=(a, b))


@pytest.mark.parametrize("endpoint,probe,kwargs", PROBES, ids=[row[0] for row in PROBES])
@pytest.mark.parametrize("status", (401, 503))
def test_identity_endpoint_failure_after_membership_positive_control(endpoint, probe, kwargs, status):
    backend = IdentityBackend()
    def fake_post(url, **request):
        response = backend.post(url, **request)
        if url.endswith("/" + endpoint):
            response.status_code = status
        return response
    clients = tuple(SecurityChannelIdentityClient(
        "https://unit.invalid", "fake-local-token", uid, post=fake_post,
    ) for uid in (41, 42))
    with pytest.raises(ChannelRequestError):
        probe(CONFIG, "v1", clients=clients, **kwargs)


@pytest.mark.parametrize("endpoint,probe,kwargs", PROBES[:4], ids=[row[0] for row in PROBES[:4]])
def test_forged_empty_response_after_nonempty_positive_control_is_failure(endpoint, probe, kwargs):
    backend = IdentityBackend()
    def fake_post(url, **request):
        response = backend.post(url, **request)
        uid = p.decode_all(request["data"])[1][0]
        auth_uid = int(request["headers"]["Authorization"].rsplit(":", 1)[1])
        if url.endswith("/" + endpoint) and uid != auth_uid:
            if endpoint == "atMessages":
                response.content = p._fb(2, p._fv(1, CHANNEL))
            else:
                response.content = b""
        return response
    clients = tuple(SecurityChannelIdentityClient(
        "https://unit.invalid", "fake-local-token", uid, post=fake_post,
    ) for uid in (41, 42))
    with pytest.raises(ChannelRequestError):
        probe(CONFIG, "v1", clients=clients, **kwargs)


@pytest.mark.parametrize("kind,body", (
    ("read_indexes", b"\x12\x05\x08"),
    ("read_indexes", p._fb(2, p._fv(1, CHANNEL) + p._fs(2, index(1)) + p._fs(2, index(2)))),
    ("at_indexes", p._fb(2, p._fv(1, CHANNEL) + p._fb(2, b"\xff"))),
    ("operations", p._fb(2, p._fv(2, CHANNEL))),
    ("ack", p._fv(1, 0) + p._fv(1, 0)),
    ("ack", p._fb(2, b"unexpected")),
    ("ack", p._fv(1, 1 << 32)),
))
def test_malformed_proto_is_failure(kind, body):
    with pytest.raises(ChannelRequestError):
        parse_identity_reply(body, kind)


@pytest.mark.parametrize("status,body,content_type", (
    (200, b"<html>PRIVATE_RESPONSE_SENTINEL</html>", "text/html"),
    (200, p._fv(1, 403), "application/x-protobuf"),
    (200, b"\x12\xff", "application/x-protobuf"),
))
def test_identity_transport_rejects_bad_content_without_response_dump(status, body, content_type):
    def fake(*args, **kwargs):
        return SimpleNamespace(status_code=status, content=body, headers={"Content-Type": content_type})
    client = SecurityChannelIdentityClient("https://unit.invalid", "PRIVATE_TOKEN_SENTINEL", 41, post=fake)
    with pytest.raises(ChannelRequestError) as result:
        client.read_indexes(CHANNEL)
    assert "PRIVATE" not in str(result.value)


def test_timeout_is_failure_without_credentials():
    def timeout(*args, **kwargs):
        raise requests.Timeout("PRIVATE_TOKEN_SENTINEL PRIVATE_RESPONSE_SENTINEL")
    client = SecurityChannelIdentityClient("https://unit.invalid", "PRIVATE_TOKEN_SENTINEL", 41, post=timeout)
    with pytest.raises(ChannelRequestError) as result:
        client.at_messages(CHANNEL)
    assert "PRIVATE" not in str(result.value)


@pytest.mark.parametrize("version", ("v1", "v2"))
def test_request_wire_contract_and_forged_uid(version):
    backend = IdentityBackend()
    client, _ = backend.clients()
    client.read_indexes(CHANNEL, version, body_user_id=42)
    client.update_read_index(CHANNEL, index(5), version, body_user_id=42)
    client.operation_one(CHANNEL, version, body_user_id=42)
    client.operations(version, body_user_id=42)
    client.verify_operations(CHANNEL, index(5), version, body_user_id=42)
    client.at_messages(CHANNEL, version, body_user_id=42)
    by_endpoint = {endpoint: kwargs for _, endpoint, kwargs in backend.calls}
    for endpoint, kwargs in by_endpoint.items():
        fields = p.decode_all(kwargs["data"])
        assert fields[1] == [42]
        assert kwargs["headers"]["Authorization"] == "PRIVATE_FAKE_TOKEN_41:41"
        assert kwargs["allow_redirects"] is False
        if endpoint == "readIndexes":
            assert fields[2] == [p._enc_varint(CHANNEL)]
        elif endpoint in ("readIndexes/edit", "oprMessages/verify"):
            assert p.decode_all(fields[2][0]) == {1: [CHANNEL], 2: [index(5).encode()]}
        elif endpoint == "oprMessage":
            assert fields == {1: [42], 2: [CHANNEL], 3: [2]}
        elif endpoint == "oprMessages":
            assert fields == {1: [42], 2: [2]}
        elif endpoint == "atMessages":
            assert p.decode_all(fields[2][0]) == {1: [CHANNEL]}


def test_reply_reprs_hide_message_ids_content_and_indexes():
    reply = parse_identity_reply(p._fb(2, message(10)), "operations")
    at_reply = ChannelIdentityReply(200, 0, at_indexes=(IdentityAtIndexes(CHANNEL, ("PRIVATE_AT",)),))
    read_reply = ChannelIdentityReply(200, 0, indexes=(IdentityIndex(CHANNEL, "PRIVATE_INDEX"),))
    for value in (reply, at_reply, read_reply):
        assert "PRIVATE" not in repr(value)
        assert "message-10" not in repr(value)
