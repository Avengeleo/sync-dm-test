"""V85真实驱动的内存反向回归，不访问dev。"""
from dataclasses import replace

import pytest
from im_test import proto_min as p
from im_test import security_group_p2 as g
from im_test.security_p2_config import P2Error, P2Blocked, load_p2_config
from im_test.security_wire import WireEvent


def config():
    return load_p2_config({"IM_SECURITY_ENV": "dev", "IM_SECURITY_DEPLOYMENT": "f434b82",
        "IM_SECURITY_HTTP_BASE_URL": "https://unit.invalid", "IM_SECURITY_WS_URL": "wss://unit.invalid",
        "IM_SECURITY_USER_ID": "11", "IM_SECURITY_USER_ID2": "22", "IM_SECURITY_TOKEN": "secret-a",
        "IM_SECURITY_TOKEN2": "secret-b", "IM_SECURITY_P2_GROUP_ID": "33", "IM_SECURITY_P2_OTHER_GROUP_ID": "44",
        "IM_SECURITY_P2_GROUP_OWNER_UID": "11", "IM_SECURITY_P2_HTTP_VERSION": "v1",
        "IM_SECURITY_P2_ALLOW_WRITE": "1", "IM_SECURITY_P2_FIXTURE_CONFIRMED": "1", "IM_SECURITY_TIMEOUT": "1"})


class Clock:
    now = 0
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class Network:
    def __init__(self, mode="fixed"):
        self.rows, self.sources, self.sent, self.closed = {}, {}, [], []
        self.mode = mode
    def store(self, cfg, suffix):
        network, owner = self, cfg["user_id" + suffix]
        class Store:
            def queue(self):
                return tuple(row for (who, _), row in network.rows.items() if who == owner)
        return Store()
    def session(self, url, owner, token, **kwargs):
        network = self
        class Session:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                network.closed.append(owner)
            def send(self, command, body):
                network.sent.append(command)
                packet = p.decode(body)
                if command in g.ACKS.values():
                    actor = packet[1] if network.mode == "body_uid" else owner
                    if network.mode != "reject_all":
                        network.rows.pop((actor, packet[3].decode()), None)
                return 1
            def request(self, command, body, response):
                network.sent.append(command)
                packet = p.decode(body)
                if command == g.CHAT:
                    message, group = packet[5].decode(), packet[1]
                    network.sources[message] = (owner, group)
                    target = 22 if owner == 11 else 11
                    network.rows[target, message] = g.GroupRow(g.DELIVER, message, owner, group, 0, b"unread-row")
                    code = g.NON_ERR
                elif command == g.CANCEL:
                    message, group = packet[3].decode(), packet[1]
                    author, source_group = network.sources[message]
                    actor = packet[2] if network.mode == "body_uid" else owner
                    allowed = actor in (author, 11) and (group == source_group or network.mode == "cross_group")
                    if allowed or network.mode == "denied_but_changed":
                        for key in list(network.rows):
                            if key[1] == message:
                                del network.rows[key]
                    code = g.NON_ERR if allowed else g.FORBIDDEN
                elif command == g.READ:
                    actor = packet[1] if network.mode == "body_uid" else owner
                    key = actor, packet[2].decode()
                    if key in network.rows and network.mode != "reject_all":
                        network.rows[key] = replace(network.rows[key], is_read=1, raw=b"read-row")
                    return WireEvent(response, p._fv(1, g.NON_ERR))
                else:
                    raise AssertionError("unexpected command")
                return WireEvent(response, p._fv(1, owner) + p._fv(2, group) + p._fs(3, message) + p._fv(5, code))
        return Session()


def run(case, network=None, cfg=None):
    net, clock, ids = network or Network(), Clock(), []
    g.run_group_case(cfg or config(), case, session_factory=net.session, store_factory=net.store,
                     preflight=lambda *_: None, clock=clock, sleep=clock.sleep,
                     record=lambda key, value: ids.append(value))
    return net, ids


@pytest.mark.parametrize("case", g.CASES)
def test_group_driver_preserves_legal_paths_and_uses_new_messages(case):
    net, ids = run(case)
    assert ids and len(ids) == len(set(ids))
    assert set(net.sources) == set(ids)
    assert net.closed == [22, 11]
    assert all(ident not in ("old", "historic") for ident in ids)


@pytest.mark.parametrize("case", ("forged_sender_cancel", *g.ACKS, "read_sync"))
def test_group_driver_catches_original_body_uid_vulnerability(case):
    with pytest.raises((P2Error, P2Blocked)):
        run(case, Network("body_uid"))


def test_cross_group_requires_positive_control_in_both_groups():
    with pytest.raises(P2Error):
        run("cross_group_cancel", Network("cross_group"))
    net, ids = run("cross_group_cancel")
    assert {group for _, group in net.sources.values()} == {33, 44} and len(ids) == 2


@pytest.mark.parametrize("case", ("ack_chat", "read_sync"))
def test_rejecting_every_request_is_not_a_pass(case):
    with pytest.raises(P2Blocked):
        run(case, Network("reject_all"))


def test_rejected_ack_without_preserved_storage_is_not_a_pass():
    with pytest.raises(P2Error):
        run("forged_sender_cancel", Network("denied_but_changed"))


def test_missing_other_group_stops_before_any_connection():
    cfg = config(); cfg["p2_other_group"] = 0
    net = Network()
    with pytest.raises(P2Blocked):
        run("cross_group_cancel", net, cfg)
    assert not net.sent


def test_group_queue_decoding_is_read_only_and_strict():
    raw_row = p._fv(1, g.DELIVER) + p._fb(2, b"body") + p._fs(3, "id") + p._fv(4, 11) + p._fv(5, 33)
    reply = p._fv(1, 22) + p._fs(2, "correlation") + p._fb(3, raw_row)
    assert g.parse_queue(reply, 22, "correlation")[0].is_read == 0
    with pytest.raises(P2Error):
        g.parse_queue(reply, 11, "correlation")
    with pytest.raises(P2Error):
        g.parse_queue(reply, 22, "wrong-correlation")


def test_queue_client_omits_delivered_ids_and_hides_credentials():
    captured = []
    def post(url, **kwargs):
        captured.append(kwargs)
        packet = p.decode(kwargs["data"])
        assert 3 not in packet
        from types import SimpleNamespace
        return SimpleNamespace(status_code=200, headers={"Content-Type": "application/x-protobuf"},
                               content=p._fv(1, 11) + p._fb(2, packet[2]))
    store = g.GroupStore(config(), "", post=post)
    assert store.queue() == () and captured[0]["allow_redirects"] is False
    assert "secret-a" not in repr(store)
