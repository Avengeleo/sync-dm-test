"""44/45调度与写许可回归；全部使用本地替身。"""

from argparse import Namespace
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from im_test import run_security_44_45 as runner
from im_test.security_config import load_security_config
from im_test.security_device import DeviceRequestError
from im_test.security_write_preflight import require_idle_web_accounts, WritePreflightError
from im_test.tests.security import conftest as gates


def config_file(tmp_path):
    path = tmp_path / "private.env"
    path.write_text("IM_SECURITY_ENV=dev\nIM_SECURITY_DEPLOYMENT=061ec96\nIM_SECURITY_TOKEN=file-token\n"
                    "IM_SECURITY_TOKEN2=file-token-b\nIM_SECURITY_USER_ID=7\nIM_SECURITY_USER_ID2=8\n"
                    "IM_SECURITY_HTTP_BASE_URL=https://unit.invalid\nIM_SECURITY_WS_URL=wss://unit.invalid\n")
    return path


def test_runner_drops_inherited_credentials_and_other_write_switches(tmp_path):
    env = runner.child_environment(config_file(tmp_path), "44", allow_writes=True, fixtures_confirmed=True,
                                    parent_env={"PATH": "/unit", "IM_SECURITY_TOKEN": "inherited-secret",
                                                "DM_TOKEN": "other", "BI_TOKEN": "other",
                                                "PYTEST_ADDOPTS": "im_test/tests", "IM_SECURITY_ALLOW_DEVICE_KICK": "1"})
    assert env["IM_SECURITY_TOKEN"] == "file-token" and env["PATH"] == "/unit"
    assert "DM_TOKEN" not in env and "BI_TOKEN" not in env and "PYTEST_ADDOPTS" not in env
    assert env["IM_SECURITY_ALLOW_DEVICE_KICK"] == "0"
    assert env["IM_SECURITY_IDENTITY_ALLOW_WRITE"] == "0"
    assert env["IM_SECURITY_MUTATION_ALLOW_WRITE"] == "1"
    assert env["IM_SECURITY_KEY_IDENTITY_ALLOW_WRITE"] == "0"
    assert env["IM_SECURITY_ISOLATED_CONFIG"] == "1"


def test_actual_child_root_conftest_cannot_fill_missing_credentials_from_dotenv(tmp_path):
    # 导入真实根conftest，但替换dotenv为内存替身，绝不读取真实.env。
    env = runner.child_environment(config_file(tmp_path), "44", allow_writes=True, fixtures_confirmed=True)
    env.pop("IM_SECURITY_TOKEN")
    script = """
import importlib.util, os, sys, types
fake = types.ModuleType('dotenv')
def load_dotenv(*args, **kwargs):
    os.environ['IM_SECURITY_TOKEN'] = 'wrong-root-account-token'
fake.load_dotenv = load_dotenv
sys.modules['dotenv'] = fake
spec = importlib.util.spec_from_file_location('unit_root_conftest', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert 'IM_SECURITY_TOKEN' not in os.environ
"""
    subprocess.run([sys.executable, "-c", script, str(runner.ROOT / "conftest.py")],
                   env=env, check=True, capture_output=True)


@pytest.mark.parametrize("allow,confirmed", [(False, False), (True, False), (False, True)])
def test_no_writes_without_both_explicit_confirmations(tmp_path, allow, confirmed):
    with pytest.raises(runner.SecurityRunError):
        runner.child_environment(config_file(tmp_path), "44", allow_writes=allow, fixtures_confirmed=confirmed)


def args(tmp_path, suite="both"):
    return Namespace(env_file=config_file(tmp_path), suite=suite, report_dir=tmp_path / "reports",
                     deployment_version=None, allow_test_writes=True, fixtures_confirmed=True)


@pytest.mark.parametrize("tail,expected", [("", True), ("<skipped message='blocked'/>", False),
                                          ("<failure message='failed'/>", False), ("<error/>", False)])
def test_junit_skip_failure_and_error_are_not_passing(tmp_path, tail, expected):
    path = tmp_path / "report.xml"
    path.write_text("<testsuites><testsuite><testcase name='case'>" + tail + "</testcase></testsuite></testsuites>")
    assert runner.summarize_junit(path, 0)["complete"] is expected


def test_no_testcases_or_missing_report_cannot_pass(tmp_path):
    path = tmp_path / "report.xml"
    assert not runner.summarize_junit(path, 0)["complete"]
    path.write_text("<testsuites/>")
    assert not runner.summarize_junit(path, 0)["complete"]


def test_only_two_exact_files_are_dispatched_and_parent_is_not_modified(tmp_path):
    calls = []
    parent = {"IM_SECURITY_ALLOW_DEVICE_KICK": "1", "PYTEST_ADDOPTS": "bad"}

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        xml = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--junitxml=")))
        xml.write_text("<testsuite><testcase name='unit'/></testsuite>")
        return SimpleNamespace(returncode=0)

    assert runner.run(args(tmp_path), execute=execute, parent_env=parent) == 0
    assert [c[0][3] for c in calls] == list(runner.TARGETS.values())
    assert parent["IM_SECURITY_ALLOW_DEVICE_KICK"] == "1"
    assert all("--maxfail=1" in c[0] and "--no-showlocals" in c[0] for c in calls)
    summary = json.loads((tmp_path / "reports/summary.json").read_text())
    assert summary["complete"] and not summary["runtime_version_independently_verified"]
    assert "file-token" not in json.dumps(summary)


def test_failure_stops_before_next_stage_and_preserves_report(tmp_path):
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        xml = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--junitxml=")))
        xml.write_text("<testsuite><testcase name='unit'><failure/></testcase></testsuite>")
        return SimpleNamespace(returncode=1)

    assert runner.run(args(tmp_path), execute=execute) == 1
    assert len(calls) == 1
    summary = json.loads((tmp_path / "reports/summary.json").read_text())
    assert summary["unexecuted"] == ["Vuln45"] and not summary["complete"]


def test_skip_returns_incomplete_and_existing_report_is_never_overwritten(tmp_path):
    run_args = args(tmp_path, "45")

    def execute(command, **kwargs):
        xml = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--junitxml=")))
        xml.write_text("<testsuite><testcase name='unit'><skipped/></testcase></testsuite>")
        return SimpleNamespace(returncode=0)

    assert runner.run(run_args, execute=execute) == 2
    with pytest.raises(runner.SecurityRunError):
        runner.run(run_args, execute=lambda *a, **k: pytest.fail("must not run"))


def test_common_fixture_gates_do_not_open_old_suites(monkeypatch):
    cfg = load_security_config({"IM_SECURITY_ENV": "dev", "IM_SECURITY_DEPLOYMENT": "061ec96",
        "IM_SECURITY_HTTP_BASE_URL": "https://unit.invalid", "IM_SECURITY_WS_URL": "wss://unit.invalid",
        "IM_SECURITY_USER_ID": "7", "IM_SECURITY_TOKEN": "a", "IM_SECURITY_USER_ID2": "8", "IM_SECURITY_TOKEN2": "b"})
    req = SimpleNamespace(node=SimpleNamespace(user_properties=[]))
    with pytest.raises(pytest.skip.Exception):
        gates._security_44_45_write_enabled(cfg, req, "44")
    assert not cfg["allow_device_kick"] and not cfg["identity_allow_write"]


def test_preflight_checks_both_account_tokens_and_never_kicks():
    visited = []

    class Client:
        def __init__(self, base, token, user_id, **kwargs):
            self.user_id = user_id
            visited.append(user_id)

        def device_list(self, **kwargs):
            return SimpleNamespace(require_success=lambda *a, **k: SimpleNamespace(devices=[]))

    require_idle_web_accounts({"http_base": "unit", "token": "a", "token2": "b",
                              "user_id": 7, "user_id2": 8, "timeout": 1}, client_factory=Client)
    assert visited == [7, 8]


@pytest.mark.parametrize("all_slots,client_type", [(False, 2), (True, 0), (True, 1), (True, 2)])
def test_online_devices_block_before_login(all_slots, client_type):
    class Client:
        def __init__(self, base, token, user_id, **kwargs):
            self.user_id = user_id

        def device_list(self, **kwargs):
            return SimpleNamespace(require_success=lambda *a, **k: SimpleNamespace(devices=[SimpleNamespace(client_type=client_type)]))

    with pytest.raises(WritePreflightError):
        require_idle_web_accounts({"http_base": "unit", "token": "a", "token2": "b", "user_id": 7, "user_id2": 8,
                                  "timeout": 1}, all_slots=all_slots, client_factory=Client, settle_seconds=0)


def test_preflight_only_waits_for_normal_close_not_relogging_or_refreshing():
    ticks = [0.0]
    reads = []

    class Client:
        def __init__(self, base, token, user_id, **kwargs):
            self.user_id = user_id

        def device_list(self, **kwargs):
            reads.append(self.user_id)
            devices = [SimpleNamespace(client_type=2)] if len(reads) == 1 else []
            return SimpleNamespace(require_success=lambda *a, **k: SimpleNamespace(devices=devices))

    require_idle_web_accounts({"http_base": "unit", "token": "a", "token2": "b", "user_id": 7, "user_id2": 8,
                              "timeout": 1}, client_factory=Client, clock=lambda: ticks[0],
                              sleep=lambda seconds: ticks.__setitem__(0, ticks[0] + seconds))
    assert reads == [7, 7, 8]


def test_failed_token_is_not_polled_or_retried():
    calls = []

    class Client:
        def __init__(self, base, token, user_id, **kwargs):
            self.user_id = user_id

        def device_list(self, **kwargs):
            calls.append(self.user_id)
            raise DeviceRequestError("fixed error")

    with pytest.raises(WritePreflightError):
        require_idle_web_accounts({"http_base": "unit", "token": "a", "token2": "b", "user_id": 7, "user_id2": 8,
                                  "timeout": 1}, client_factory=Client)
    assert calls == [7]
