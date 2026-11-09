"""P2调度、默认关闭、隔离环境和缺项退出码回归。"""
from argparse import Namespace
import json
from types import SimpleNamespace

import pytest
from im_test import run_security_p2 as r
from im_test.security_p2_config import P2Error, P2Blocked, require_live, idle_accounts, load_p2_config
from im_test.tests.security.test_p2_group_unit import config


def arguments(tmp_path, suite="85"):
    path = tmp_path / "p2.env"
    path.write_text("IM_SECURITY_ENV=dev\nIM_SECURITY_DEPLOYMENT=f434b82\nIM_SECURITY_TOKEN=file-secret\nIM_SECURITY_ALLOW_DEVICE_KICK=1\nIM_SECURITY_MUTATION_ALLOW_WRITE=1\n")
    return Namespace(env_file=path, suite=suite, version="v1" if suite == "85" else None,
                     transport="ws" if suite == "86" else None, case=None,
                     deployment_version=None, allow_test_writes=True, fixtures_confirmed=True,
                     report_dir=tmp_path / "reports")


def test_p2_runner_clears_inherited_accounts_and_old_write_permissions(tmp_path):
    args = arguments(tmp_path)
    env = r.child_environment(args, {"IM_SECURITY_TOKEN": "wrong-secret", "DM_TOKEN": "other", "BI_TOKEN": "other",
                                     "PYTEST_ADDOPTS": "other/test.py", "PATH": "/bin"})
    assert env["IM_SECURITY_TOKEN"] == "file-secret" and env["PATH"] == "/bin"
    assert "DM_TOKEN" not in env and "BI_TOKEN" not in env and "PYTEST_ADDOPTS" not in env
    for key in ("IM_SECURITY_ALLOW_LOGIN", "IM_SECURITY_ALLOW_DEVICE_KICK", "IM_SECURITY_IDENTITY_ALLOW_WRITE",
                "IM_SECURITY_MUTATION_ALLOW_WRITE", "IM_SECURITY_KEY_IDENTITY_ALLOW_WRITE"):
        assert env[key] == "0"
    assert env["IM_SECURITY_P2_ALLOW_WRITE"] == "1" and env["IM_SECURITY_ISOLATED_CONFIG"] == "1"


@pytest.mark.parametrize("switch", ("allow_test_writes", "fixtures_confirmed"))
@pytest.mark.parametrize("suite", ("85", "86"))
def test_live_stages_require_both_explicit_permissions(tmp_path, switch, suite):
    args = arguments(tmp_path, suite); setattr(args, switch, False)
    with pytest.raises(r.SecurityRunError):
        r.run(args, execute=lambda *a, **k: pytest.fail("must not launch tests"), parent_env={})


def test_sql_stage_is_local_only_and_keeps_all_writes_off(tmp_path):
    args = arguments(tmp_path, "92"); args.allow_test_writes = args.fixtures_confirmed = False
    env = r.child_environment(args, {})
    assert env["IM_SECURITY_P2_ALLOW_WRITE"] == "0"


@pytest.mark.parametrize("suite,expected", (("85", 9), ("86", 5), ("92", 1)))
@pytest.mark.parametrize("outcome,code", (("pass", 0), ("skip", 2), ("fail", 1), ("partial", 2)))
def test_runner_collects_only_selected_scope_and_never_retries(tmp_path, suite, expected, outcome, code):
    args = arguments(tmp_path, suite)
    calls = []
    def execute(command, **kwargs):
        calls.append(command)
        assert all("test_channel" not in c and "test_device" not in c and "test_sensitive_logs" not in c for c in command)
        assert kwargs["env"]["IM_SECURITY_ALLOW_DEVICE_KICK"] == "0"
        report = next(c.split("=", 1)[1] for c in command if c.startswith("--junitxml="))
        from pathlib import Path
        count = 1 if outcome == "partial" else expected
        tail = "<skipped/>" if outcome == "skip" else "<failure/>" if outcome == "fail" else ""
        Path(report).write_text("<testsuite>" + "".join("<testcase name='case%d'>%s</testcase>" % (i, tail if i == 0 else "") for i in range(count)) + "</testsuite>")
        return SimpleNamespace(returncode=1 if outcome == "fail" else 0)
    if suite == "92" and outcome == "partial":
        code = 0  # 92本身仅一项，完整的一项才算通过。
    assert r.run(args, execute=execute, parent_env={}) == code
    assert len(calls) == 1
    summary = json.loads((args.report_dir / "summary.json").read_text())
    assert "file-secret" not in json.dumps(summary) and not summary["automatic_retry"]
    assert summary["runtime_version_independently_verified"] is False


def test_tcp_excludes_inapplicable_compression_without_reporting_it_passed(tmp_path):
    args = arguments(tmp_path, "86"); args.transport = "tcp"
    def execute(command, **kwargs):
        assert len([c for c in command if "test_gateway_bounds[" in c]) == 4
        assert not any("[compressed]" in c for c in command)
        from pathlib import Path
        report = next(c.split("=", 1)[1] for c in command if c.startswith("--junitxml="))
        Path(report).write_text("<testsuite>" + "<testcase/>" * 4 + "</testsuite>")
        return SimpleNamespace(returncode=0)
    assert r.run(args, execute=execute, parent_env={}) == 0


@pytest.mark.parametrize("change", ("no_write", "no_confirmation", "wrong_env", "wrong_owner", "same_account", "channel_reuse"))
def test_bad_fixture_stops_before_any_network(change):
    cfg = config()
    if change == "no_write": cfg["p2_allow_write"] = False
    if change == "no_confirmation": cfg["p2_confirmed"] = False
    if change == "wrong_env": cfg["target_env"] = "stg"
    if change == "wrong_owner": cfg["p2_owner"] = 22
    if change == "same_account": cfg["user_id2"] = 11
    if change == "channel_reuse": cfg["identity_channel_id"] = cfg["p2_group"]
    with pytest.raises((P2Blocked, P2Error)):
        require_live(cfg, "85")


def test_online_devices_stop_without_kicking_or_logging_in():
    visited = []
    class Client:
        def __init__(self, base, token, user_id, **kwargs):
            self.user_id = user_id; visited.append(user_id)
        def device_list(self, **kwargs):
            return SimpleNamespace(require_success=lambda *a, **k: SimpleNamespace(devices=[object()]))
    with pytest.raises(P2Blocked):
        idle_accounts({**config(), "timeout": .001}, "85", client_factory=Client, clock=iter([0, 1]).__next__)
    assert visited == [11]


def test_default_no_config_collects_as_blocked_without_any_requests(monkeypatch):
    # 真正调用pytest测试入口的缺配置路径，网络构造器不应触达。
    from im_test.tests.security import test_p2_group, test_p2_gateway
    monkeypatch.setattr(test_p2_group, "load_p2_config", lambda: load_p2_config({}))
    monkeypatch.setattr(test_p2_gateway, "load_p2_config", lambda: load_p2_config({}))
    request = SimpleNamespace(node=SimpleNamespace(user_properties=[]))
    with pytest.raises(pytest.skip.Exception):
        test_p2_group.test_group_identity("own_cancel", request)
    with pytest.raises(pytest.skip.Exception):
        test_p2_gateway.test_gateway_bounds("heartbeat", request)
