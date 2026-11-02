"""定向 @ 夹具编排的纯本地回归；所有配置、网络、时钟和子进程均为 fake。"""

from copy import deepcopy
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest

from im_test import prepare_v42_mentions as prep
from im_test.security_channel import ChannelMessage, ChannelReply, ChannelRequestError
from im_test.security_channel_identity import ChannelIdentityReply, IdentityAtIndexes, IdentityIndex
from im_test.security_channel_mentions import MentionSendError, MentionSendResult
from im_test.security_device import DeviceInfo, DeviceListReply, NON_ERR


CHANNEL = 301
FIXED_MESSAGE = "a" * 32


def index(number):
    return "%024x" % number


@pytest.fixture
def config():
    # 不调用 load_config/load_security_config，避免读取用户环境或配置文件。
    return {
        "target_env": "dev", "deployment": "unit-build", "http_base": "https://unit.invalid",
        "ws_url": "wss://unit.invalid/ws", "user_id": 41, "token": "FAKE_TEST_TOKEN_A",
        "user_id2": 42, "token2": "FAKE_TEST_TOKEN_B", "identity_channel_id": CHANNEL,
        "channel_id": 302, "identity_message_id": FIXED_MESSAGE,
        "identity_fixture_confirmed": True, "identity_allow_write": False,
        "identity_state_confirmed": False, "allow_device_kick": False,
        "timeout": 2.0, "app_version": "unit-version", "client_type": 2,
    }


class Backend:
    """只暴露获准的读取和两次明确发送；未知操作直接使测试失败。"""

    def __init__(self, ready=False, delay=0):
        self.at = {41: [index(11)] if ready else [], 42: [index(12)] if ready else []}
        self.read = {41: index(1), 42: index(2)}
        self.calls = []
        self.sends = []
        self.messages = {}
        self.delay = delay
        self.active_web = set()
        self.fail_second = False
        self.never_stored = False
        self.bad_result = None
        self.member_failure = None
        self.seconds = 0.0
        self.saved = []

    def client_factory(self, config, second=False):
        backend = self
        uid = config["user_id2" if second else "user_id"]

        class Client:
            user_id = uid

            def by_id(self, channel_id, message_ids, version):
                backend.calls.append(("by_id", uid, channel_id, tuple(message_ids), version))
                assert channel_id == CHANNEL and len(message_ids) == 1
                msg_id = message_ids[0]
                if msg_id == FIXED_MESSAGE:
                    if backend.member_failure == (uid, version):
                        return ChannelReply(403, 403)
                    row = ChannelMessage(CHANNEL, msg_id, b"ordinary fixed broadcast", index(50))
                    return ChannelReply(200, 0, messages=(row,))
                pending = backend.messages[msg_id]
                if backend.never_stored or pending["remaining"]:
                    pending["remaining"] = max(0, pending["remaining"] - 1)
                    return ChannelReply(200, 0, missing=(msg_id,))
                if pending["index"] not in backend.at[pending["target"]]:
                    backend.at[pending["target"]].append(pending["index"])
                row = ChannelMessage(CHANNEL, msg_id, b"directed mention", pending["index"])
                return ChannelReply(200, 0, messages=(row,))

            def read_indexes(self, channel_id, version):
                backend.calls.append(("read_indexes", uid, channel_id, version))
                return ChannelIdentityReply(200, 0, indexes=(IdentityIndex(CHANNEL, backend.read[uid]),))

            def at_messages(self, channel_id, version):
                backend.calls.append(("at_messages", uid, channel_id, version))
                return ChannelIdentityReply(200, 0, at_indexes=(IdentityAtIndexes(CHANNEL, tuple(backend.at[uid])),))

        return Client()

    def device_factory(self, base, token, uid, *, timeout):
        assert base == "https://unit.invalid" and timeout == 2.0
        assert token == {41: "FAKE_TEST_TOKEN_A", 42: "FAKE_TEST_TOKEN_B"}[uid]
        backend = self

        class DeviceClient:
            def device_list(self, *, version):
                backend.calls.append(("device_list", uid, version))
                rows = ()
                if uid in backend.active_web:
                    rows = (DeviceInfo(uid, 2, "existing-device", "name", 1, "info", "1"),)
                return DeviceListReply(200, NON_ERR, rows)

        return DeviceClient()

    def send(self, url, uid, token, channel_id, target, content, **kwargs):
        assert url == "wss://unit.invalid/ws" and channel_id == CHANNEL
        assert token == {41: "FAKE_TEST_TOKEN_A", 42: "FAKE_TEST_TOKEN_B"}[uid]
        assert kwargs["app_version"] == "unit-version" and kwargs["timeout"] == 2.0
        assert kwargs["device_token"].startswith("v42-at-")
        assert len(kwargs["msg_id"]) == 32
        self.sends.append((uid, target, kwargs["msg_id"], kwargs["device_token"]))
        if self.fail_second and len(self.sends) == 2:
            raise MentionSendError("本地 fake 第二条发送失败")
        msg_id = kwargs["msg_id"]
        stored = index(100 + len(self.sends))
        self.messages[msg_id] = {"remaining": self.delay, "target": target, "index": stored}
        # 正常广播本就推进发送者游标；准备与只读测试必须分别取基线。
        self.read[uid] = stored
        result = MentionSendResult(msg_id, "", CHANNEL, uid, target)
        return self.bad_result(result) if self.bad_result else result

    def wait(self, seconds):
        self.seconds += seconds

    def persist(self, record):
        self.saved.append(deepcopy(record))

    def prepare(self, config, **kwargs):
        return prep.prepare_fixture(
            config, CHANNEL, client_factory=self.client_factory, device_factory=self.device_factory,
            send=self.send, wait=self.wait, clock=lambda: self.seconds, persist=self.persist, **kwargs,
        )


@pytest.mark.parametrize("field,value", [
    ("target_env", ""), ("target_env", "prod"), ("deployment", ""),
    ("deployment", "unspecified"), ("http_base", ""), ("ws_url", ""),
    ("token", ""), ("token2", ""), ("token2", "FAKE_TEST_TOKEN_A"),
    ("user_id", 0), ("user_id", -1), ("user_id", 1 << 63), ("user_id2", 41),
    ("identity_channel_id", 999), ("channel_id", CHANNEL),
    ("identity_fixture_confirmed", False), ("identity_message_id", "not-a-message-id"),
    ("identity_message_id", "A" * 32), ("identity_allow_write", True),
    ("identity_state_confirmed", True), ("allow_device_kick", True),
])
def test_unsafe_configuration_fails_before_any_network(config, field, value):
    config[field] = value
    backend = Backend()
    with pytest.raises(prep.FixtureError):
        backend.prepare(config, allow_prepare=True)
    assert backend.calls == [] and backend.sends == []


@pytest.mark.parametrize("channel_id", [True, False, "301", 0, -1, 1 << 63, 999])
def test_explicit_channel_is_required_and_cannot_be_coerced(config, channel_id):
    with pytest.raises(prep.FixtureError):
        prep.validate_config(config, channel_id)


def test_default_cli_is_offline_preview(config, monkeypatch, capsys):
    monkeypatch.setattr(prep, "load_config", lambda path: config)

    def forbidden(*args, **kwargs):
        pytest.fail("默认预览禁止创建客户端、发送、执行子进程或写报告")

    for name in ("prepare_fixture", "run_at_tests", "_output_path", "_save"):
        monkeypatch.setattr(prep, name, forbidden)
    assert prep.main(["--env-file", "synthetic-config", "--channel-id", str(CHANNEL)]) == 0
    assert "未连接服务" in capsys.readouterr().out


def _synthetic_env_text(include_environment=True):
    return ("IM_SECURITY_ENV=dev\n" if include_environment else "") + "\n".join([
        "IM_SECURITY_DEPLOYMENT=unit-file-build",
        "IM_SECURITY_HTTP_BASE_URL=https://file-unit.invalid",
        "IM_WS_URL=wss://file-unit.invalid/ws",
        "IM_USER_ID=71", "IM_TOKEN=FAKE_FILE_LEGACY_A",
        "IM_USER_ID2=72", "IM_TOKEN2=FAKE_FILE_LEGACY_B",
        "IM_SECURITY_IDENTITY_CHANNEL_ID=301", "IM_SECURITY_CHANNEL_ID=302",
        "IM_SECURITY_IDENTITY_MESSAGE_ID=" + FIXED_MESSAGE,
        "IM_SECURITY_IDENTITY_FIXTURE_CONFIRMED=1",
    ]) + "\n"


def test_explicit_file_legacy_accounts_override_stale_security_aliases(config, tmp_path, monkeypatch, capsys):
    parent = {
        "IM_SECURITY_ENV": "prod", "IM_SECURITY_DEPLOYMENT": "old-parent-build",
        "IM_SECURITY_USER_ID": "991", "IM_SECURITY_TOKEN": "FAKE_STALE_PARENT_A",
        "IM_SECURITY_USER_ID2": "992", "IM_SECURITY_TOKEN2": "FAKE_STALE_PARENT_B",
        "IM_SECURITY_HTTP_BASE_URL": "https://stale-parent.invalid",
        "IM_SECURITY_WS_URL": "wss://stale-parent.invalid/ws",
        "IM_SECURITY_IDENTITY_ALLOW_WRITE": "1", "IM_SECURITY_ALLOW_DEVICE_KICK": "1",
    }
    original_parent = dict(parent)
    monkeypatch.setattr(prep.os, "environ", parent)
    path = tmp_path / "synthetic-explicit-config"
    path.write_text(_synthetic_env_text(), encoding="utf-8")
    original_file = path.read_bytes()
    loaded = prep.load_config(path)
    prep.validate_config(loaded, CHANNEL)
    assert loaded["target_env"] == "dev" and loaded["deployment"] == "unit-file-build"
    assert (loaded["user_id"], loaded["token"], loaded["user_id2"], loaded["token2"]) == (
        71, "FAKE_FILE_LEGACY_A", 72, "FAKE_FILE_LEGACY_B")
    assert loaded["http_base"] == "https://file-unit.invalid"
    assert loaded["ws_url"] == "wss://file-unit.invalid/ws"
    assert not loaded["identity_allow_write"] and not loaded["allow_device_kick"]
    assert parent == original_parent and path.read_bytes() == original_file
    assert capsys.readouterr() == ("", "")


def test_missing_file_fields_do_not_inherit_any_im_process_values(tmp_path, monkeypatch):
    monkeypatch.setattr(prep.os, "environ", {
        "IM_SECURITY_ENV": "dev", "IM_SECURITY_DEPLOYMENT": "parent-build",
        "IM_SECURITY_TOKEN": "FAKE_STALE_PARENT_A", "IM_TOKEN": "FAKE_PARENT_ALIAS_A",
        "IM_SECURITY_USER_ID": "991", "IM_USER_ID": "991",
        "IM_SECURITY_HTTP_BASE_URL": "https://stale-parent.invalid",
        "IM_SECURITY_WS_URL": "wss://stale-parent.invalid/ws",
        "IM_WS_URL": "wss://stale-alias.invalid/ws",
    })
    path = tmp_path / "synthetic-empty-config"
    path.write_text("# deliberately empty local test input\n", encoding="utf-8")
    loaded = prep.load_config(path)
    assert loaded["target_env"] == "" and loaded["deployment"] == "unspecified"
    assert loaded["user_id"] == 0 and loaded["token"] == ""
    assert loaded["http_base"] == loaded["ws_url"] == ""
    with pytest.raises(prep.FixtureError):
        prep.validate_config(loaded, CHANNEL)


def test_missing_file_environment_cannot_be_approved_by_parent_dev(config, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(prep.os, "environ", {"IM_SECURITY_ENV": "dev"})
    path = tmp_path / "synthetic-no-environment"
    path.write_text(_synthetic_env_text(include_environment=False), encoding="utf-8")
    before = path.read_bytes()

    def forbidden(*args, **kwargs):
        pytest.fail("缺少文件内dev声明时禁止进入网络或报告阶段")

    for name in ("prepare_fixture", "run_at_tests", "_output_path"):
        monkeypatch.setattr(prep, name, forbidden)
    assert prep.main(["--env-file", str(path), "--channel-id", str(CHANNEL), "--prepare"]) == 1
    output = capsys.readouterr()
    assert "IM_SECURITY_ENV=dev" in output.err
    assert "FAKE_FILE_LEGACY" not in output.out + output.err
    assert path.read_bytes() == before


def test_local_file_values_are_not_interpolated_from_process(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(prep.os, "environ", {"SYNTHETIC_SECRET": "DO_NOT_READ_OR_PRINT"})
    path = tmp_path / "synthetic-literal-config"
    text = _synthetic_env_text().replace("FAKE_FILE_LEGACY_A", "literal-${SYNTHETIC_SECRET}")
    path.write_text(text, encoding="utf-8")
    before = path.read_bytes()
    loaded = prep.load_config(path)
    assert loaded["token"] == "literal-${SYNTHETIC_SECRET}"
    assert path.read_bytes() == before
    assert capsys.readouterr() == ("", "")


def test_existing_distinct_nonempty_mentions_reused_without_login_or_send(config):
    backend = Backend(ready=True)
    record = backend.prepare(config, allow_prepare=True)
    assert record["status"] == "ready_reused" and record["sent_count"] == 0
    assert backend.sends == []
    assert not any(call[0] == "device_list" for call in backend.calls)
    positives = {(call[1], call[4]) for call in backend.calls
                 if call[0] == "by_id" and call[3] == (FIXED_MESSAGE,)}
    assert positives == {(41, "v1"), (42, "v1"), (41, "v2"), (42, "v2")}


@pytest.mark.parametrize("uid,version", [(41, "v1"), (42, "v1"), (41, "v2"), (42, "v2")])
def test_membership_positive_control_must_pass_for_both_versions_and_accounts(config, uid, version):
    backend = Backend(ready=True)
    backend.member_failure = (uid, version)
    with pytest.raises(ChannelRequestError):
        backend.prepare(config, allow_prepare=True)
    assert backend.sends == []


def test_missing_fixture_without_prepare_never_checks_devices_or_sends(config):
    backend = Backend()
    with pytest.raises(prep.FixtureError, match="未指定 --prepare"):
        backend.prepare(config)
    assert not any(call[0] == "device_list" for call in backend.calls)
    assert backend.sends == []


@pytest.mark.parametrize("uid", [41, 42])
def test_any_preexisting_online_web_refuses_all_sends(config, uid):
    backend = Backend()
    backend.active_web.add(uid)
    with pytest.raises(prep.FixtureError, match="在线 Web"):
        backend.prepare(config, allow_prepare=True)
    assert backend.sends == []


def test_creates_exactly_two_unique_directed_mentions_and_records_id_before_send(config):
    backend = Backend(delay=2)
    record = backend.prepare(config, allow_prepare=True)
    assert [(row[0], row[1]) for row in backend.sends] == [(41, 42), (42, 41)]
    assert len({row[2] for row in backend.sends}) == len({row[3] for row in backend.sends}) == 2
    assert record["status"] == "ready_created" and record["sent_count"] == 2
    for position, sent in enumerate(backend.sends):
        action = record["messages"][position]
        assert action["msg_id"] == sent[2] and action["status"] == "stored"
        pending = [saved["messages"][position] for saved in backend.saved
                   if len(saved.get("messages", [])) > position]
        assert pending[0]["status"] == "sending" and pending[0]["msg_id"] == sent[2]
        target = "B" if sent[1] == 42 else "A"
        sender = "A" if target == "B" else "B"
        assert action["index"] in record["after"][target]["at_indexes"]
        assert action["index"] not in record["after"][sender]["at_indexes"]
        # ACK 无 index，仍以落库查询取得真实游标；等待期间不得重发。
        assert action["ack_index"] == "" and action["index"]
        by_ids = [call for call in backend.calls if call[0] == "by_id" and call[3] == (sent[2],)]
        assert len(by_ids) >= 4
    assert backend.seconds > 0
    assert {call[0] for call in backend.calls} <= {"by_id", "read_indexes", "at_messages", "device_list"}


def test_timeout_after_ack_preserves_single_message_without_resend(config):
    backend = Backend()
    backend.never_stored = True
    record = {}
    with pytest.raises(prep.FixtureError, match="不自动重试"):
        backend.prepare(config, allow_prepare=True, record=record)
    assert len(backend.sends) == 1 and len(record["messages"]) == 1
    assert record["messages"][0]["status"] == "acked"
    assert record["messages"][0]["msg_id"] == backend.sends[0][2]
    assert backend.saved[-1]["messages"][0]["status"] == "acked"


def test_preparation_waits_for_transient_v1_v2_state_change_without_resending(config):
    backend = Backend()
    original_factory = backend.client_factory
    stale_read_returned = []

    def factory(config, second=False):
        client = original_factory(config, second)
        current_read = client.read_indexes

        def read_indexes(channel_id, version):
            if backend.sends and not second and version == "v1" and not stale_read_returned:
                # 广播后读游标异步写入；同一轮 v1/v2 读到不同时间点。
                stale_read_returned.append(True)
                return ChannelIdentityReply(200, 0, indexes=(IdentityIndex(CHANNEL, index(1)),))
            return current_read(channel_id, version)

        client.read_indexes = read_indexes
        return client

    backend.client_factory = factory
    record = backend.prepare(config, allow_prepare=True)
    assert stale_read_returned == [True] and backend.seconds > 0
    assert record["status"] == "ready_created" and record["sent_count"] == 2
    assert [(row[0], row[1]) for row in backend.sends] == [(41, 42), (42, 41)]
    assert all(action["status"] == "stored" for action in record["messages"])


def test_second_send_failure_preserves_first_stored_and_second_pending_id(config):
    backend = Backend()
    backend.fail_second = True
    record = {}
    with pytest.raises(MentionSendError):
        backend.prepare(config, allow_prepare=True, record=record)
    assert len(backend.sends) == 2
    assert [action["status"] for action in record["messages"]] == ["stored", "sending"]
    assert [action["msg_id"] for action in record["messages"]] == [row[2] for row in backend.sends]
    assert backend.saved[-1]["messages"] == record["messages"]


@pytest.mark.parametrize("field,value", [("msg_id", "b" * 32), ("channel_id", 999),
                                        ("sender_uid", 999), ("target_uid", 999)])
def test_mismatched_send_identity_cannot_be_recorded_as_our_fixture(config, field, value):
    from dataclasses import replace
    backend = Backend()
    backend.bad_result = lambda result: replace(result, **{field: value})
    with pytest.raises(prep.FixtureError):
        backend.prepare(config, allow_prepare=True)
    assert len(backend.sends) == 1


def _xml(path, names=("v1", "v2"), child_tag=None):
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", tests=str(len(names)))
    for version in names:
        case = ET.SubElement(suite, "testcase", name="test_at_messages_uses_session_uid[%s]" % version)
        if child_tag is not None and version == "v2":
            ET.SubElement(case, child_tag)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def test_runner_selects_only_two_at_cases_and_overrides_child_configuration(config, monkeypatch, tmp_path):
    parent = {"PARENT_SENTINEL": "untouched", "IM_SECURITY_ENV": "prod",
              "IM_SECURITY_TOKEN": "UNRELATED_PARENT_FAKE", "IM_SECURITY_IDENTITY_ALLOW_WRITE": "1",
              "IM_SECURITY_ALLOW_DEVICE_KICK": "1", "PYTEST_ADDOPTS": "--old-options"}
    original = dict(parent)
    monkeypatch.setattr(prep.os, "environ", parent)
    captured = {}
    xml = tmp_path / "current.xml"

    def run(command, **kwargs):
        captured.update(command=command, **kwargs)
        _xml(xml)
        return SimpleNamespace(returncode=0)

    prep.run_at_tests(config, xml, run=run)
    nodes = [part for part in captured["command"] if "::" in part]
    assert nodes == ["im_test/tests/security/test_channel_identity.py::test_at_messages_uses_session_uid[v1]",
                     "im_test/tests/security/test_channel_identity.py::test_at_messages_uses_session_uid[v2]"]
    assert captured["command"][:3] == [prep.sys.executable, "-m", "pytest"]
    marker = captured["command"].index("not write")
    assert captured["command"][marker - 1] == "-m"
    assert captured["cwd"] == str(prep.ROOT) and captured["check"] is False
    env = captured["env"]
    assert env is not parent and parent == original
    for name, field in [("ENV", "target_env"), ("DEPLOYMENT", "deployment"),
                        ("HTTP_BASE_URL", "http_base"), ("USER_ID", "user_id"), ("TOKEN", "token"),
                        ("USER_ID2", "user_id2"), ("TOKEN2", "token2"), ("CHANNEL_ID", "channel_id"),
                        ("IDENTITY_CHANNEL_ID", "identity_channel_id"),
                        ("IDENTITY_MESSAGE_ID", "identity_message_id"), ("TIMEOUT", "timeout"),
                        ("CLIENT_TYPE", "client_type")]:
        assert env["IM_SECURITY_" + name] == str(config[field])
    assert env["IM_SECURITY_IDENTITY_FIXTURE_CONFIRMED"] == "1"
    assert all(env[name] == "0" for name in ("IM_SECURITY_IDENTITY_ALLOW_WRITE",
               "IM_SECURITY_IDENTITY_STATE_CONFIRMED", "IM_SECURITY_ALLOW_DEVICE_KICK"))
    assert env["IM_SECURITY_IDENTITY_WRITE_VERSION"] == ""
    assert env["PYTEST_ADDOPTS"] == "" and env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"


@pytest.mark.parametrize("kind", ["skip", "failure", "error", "missing_case", "extra_case",
                                  "duplicate", "wrong_name", "malformed", "no_report", "nonzero"])
def test_runner_rejects_incomplete_skipped_failed_or_unrelated_xml(config, tmp_path, kind):
    xml = tmp_path / "current.xml"

    def run(command, **kwargs):
        if kind == "malformed":
            xml.write_text("<testsuites>", encoding="utf-8")
        elif kind != "no_report":
            names = {"missing_case": ("v1",), "extra_case": ("v1", "v2", "v3"),
                     "duplicate": ("v1", "v1"), "wrong_name": ("v1", "another")}.get(kind, ("v1", "v2"))
            tag = {"skip": "skipped", "failure": "failure", "error": "error"}.get(kind)
            _xml(xml, names, tag)
        return SimpleNamespace(returncode=1 if kind == "nonzero" else 0)

    with pytest.raises(prep.FixtureError):
        prep.run_at_tests(config, xml, run=run)


def test_old_passing_report_is_removed_before_child_run_and_never_reused(config, tmp_path):
    xml = tmp_path / "old.xml"
    _xml(xml)

    def interrupted(command, **kwargs):
        assert not xml.exists()
        return SimpleNamespace(returncode=0)

    with pytest.raises(prep.FixtureError):
        prep.run_at_tests(config, xml, run=interrupted)
    assert not xml.exists()


@pytest.mark.parametrize("failure", ["timeout_after_ack", "second_send"])
def test_cli_writes_partial_failure_report_without_credentials(config, tmp_path, monkeypatch, failure):
    backend = Backend()
    backend.never_stored = failure == "timeout_after_ack"
    backend.fail_second = failure == "second_send"
    monkeypatch.setattr(prep, "ROOT", tmp_path)
    monkeypatch.setattr(prep, "load_config", lambda path: config)
    real_prepare = prep.prepare_fixture

    def prepare(config, channel_id, **kwargs):
        return real_prepare(config, channel_id, client_factory=backend.client_factory,
                            device_factory=backend.device_factory, send=backend.send,
                            wait=backend.wait, clock=lambda: backend.seconds, **kwargs)

    monkeypatch.setattr(prep, "prepare_fixture", prepare)
    assert prep.main(["--channel-id", str(CHANNEL), "--prepare"]) == 1
    report = tmp_path / ".reports/im-security-v42-at-fixture.json"
    import json
    record = json.loads(report.read_text(encoding="utf-8"))
    assert record["status"] == "failed" and record["tests_run"] is False
    assert [row["msg_id"] for row in record["messages"]] == [row[2] for row in backend.sends]
    assert record["write_tests_enabled"] is False and record["device_kick_enabled"] is False
    text = report.read_text(encoding="utf-8")
    assert config["token"] not in text and config["token2"] not in text
    assert config["ws_url"] not in text and config["http_base"] not in text


@pytest.mark.parametrize("change_during_tests", [False, "read_index", "at_indexes"])
def test_cli_uses_post_prepare_baseline_and_requires_stable_readonly_tests(
        config, tmp_path, monkeypatch, change_during_tests):
    backend = Backend()
    monkeypatch.setattr(prep, "ROOT", tmp_path)
    monkeypatch.setattr(prep, "load_config", lambda path: config)
    monkeypatch.setattr(prep, "_client", backend.client_factory)
    real_prepare = prep.prepare_fixture
    runner_called = []

    def prepare(config, channel_id, **kwargs):
        return real_prepare(config, channel_id, client_factory=backend.client_factory,
                            device_factory=backend.device_factory, send=backend.send,
                            wait=backend.wait, clock=lambda: backend.seconds, **kwargs)

    def runner(config, xml_path):
        runner_called.append(str(xml_path))
        _xml(xml_path)
        if change_during_tests == "read_index":
            backend.read[41] = index(999)
        elif change_during_tests == "at_indexes":
            backend.at[42].append(index(999))

    monkeypatch.setattr(prep, "prepare_fixture", prepare)
    monkeypatch.setattr(prep, "run_at_tests", runner)
    status = prep.main(["--channel-id", str(CHANNEL), "--prepare", "--run-tests"])
    import json
    report = tmp_path / ".reports/im-security-v42-at-fixture.json"
    record = json.loads(report.read_text(encoding="utf-8"))
    assert len(runner_called) == 1 and len(backend.sends) == 2
    assert record["before"] != record["before_tests"]
    assert record["after"] == record["before_tests"]
    if change_during_tests:
        assert status == 1 and record["status"] == "failed"
        assert record["tests_run"] is False and "tests_passed" not in record
        assert record["before_tests"] != record["after_tests"]
    else:
        assert status == 0 and record["status"] == "ready_created"
        assert record["before_tests"] == record["after_tests"]
        assert record["tests_run"] is True
        assert record["tests_passed"] == 2 and record["tests_skipped"] == 0


def test_web_becoming_online_before_second_send_stops_without_blind_retry(config):
    backend = Backend()
    real_send = backend.send

    def send(*args, **kwargs):
        result = real_send(*args, **kwargs)
        backend.active_web.add(42)
        return result

    backend.send = send
    record = {}
    with pytest.raises(prep.FixtureError, match="在线 Web"):
        backend.prepare(config, allow_prepare=True, record=record)
    assert len(backend.sends) == len(record["messages"]) == 1
    assert record["messages"][0]["status"] == "stored"
