"""仅调度V85/86/92；每次选一项，跳过/证据不足均返回2，不自动重试。"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from dotenv import dotenv_values
from im_test.run_security_44_45 import SecurityRunError, _safe_deployment, summarize_junit
from im_test.security_group_p2 import CASES as GROUP_CASES
from im_test.security_gateway_p2 import CASES as GATEWAY_CASES

ROOT = Path(__file__).resolve().parents[1]
FILES = {"85": "im_test/tests/security/test_p2_group.py::test_group_identity",
         "86": "im_test/tests/security/test_p2_gateway.py::test_gateway_bounds",
         "92": "im_test/tests/security/test_p2_robot_sql.py::test_robot_sql_parameters"}


def child_environment(args, parent_env=None):
    path = Path(args.env_file)
    if not path.is_file():
        raise SecurityRunError("P2 专用配置文件不存在；未访问环境")
    try:
        configured = dotenv_values(path, interpolate=False)
    except Exception:
        raise SecurityRunError("P2 配置读取失败；不输出内容") from None
    inherited = os.environ if parent_env is None else parent_env
    child = {k: v for k, v in inherited.items() if not k.startswith(("IM_", "DM_", "BI_", "PYTEST_"))}
    child.update({k: v for k, v in configured.items() if k.startswith("IM_") and isinstance(v, str)})
    if child.get("IM_SECURITY_ENV", "").strip().lower() != "dev":
        raise SecurityRunError("P2 本轮只授权 dev")
    child["IM_SECURITY_DEPLOYMENT"] = _safe_deployment(args.deployment_version or child.get("IM_SECURITY_DEPLOYMENT", ""))
    if args.suite in ("85", "86") and not (args.allow_test_writes and args.fixtures_confirmed):
        raise SecurityRunError("登录/写入需要 --allow-test-writes 与 --fixtures-confirmed 同时明确指定")
    if args.suite == "85" and args.version not in ("v1", "v2"):
        raise SecurityRunError("V85 每次必须选择 --version v1 或 v2，并使用新夹具")
    if args.suite == "86" and args.transport not in ("ws", "tcp"):
        raise SecurityRunError("V86 必须明确选择 --transport ws 或 tcp")
    cases = GROUP_CASES if args.suite == "85" else GATEWAY_CASES if args.suite == "86" else ()
    if args.case and args.case not in cases:
        raise SecurityRunError("所选阶段不属于本次漏洞范围")
    child.update({"IM_SECURITY_ISOLATED_CONFIG": "1", "IM_SECURITY_CLIENT_TYPE": "2",
                  "IM_SECURITY_ALLOW_LOGIN": "0", "IM_SECURITY_ALLOW_DEVICE_KICK": "0",
                  "IM_SECURITY_IDENTITY_ALLOW_WRITE": "0", "IM_SECURITY_IDENTITY_STATE_CONFIRMED": "0",
                  "IM_SECURITY_IDENTITY_WRITE_VERSION": "", "IM_SECURITY_MUTATION_ALLOW_WRITE": "0",
                  "IM_SECURITY_MUTATION_FIXTURE_CONFIRMED": "0", "IM_SECURITY_KEY_IDENTITY_ALLOW_WRITE": "0",
                  "IM_SECURITY_KEY_IDENTITY_FIXTURE_CONFIRMED": "0", "IM_SECURITY_LOG_MANIFEST": "",
                  "IM_SECURITY_P2_ALLOW_WRITE": "1" if args.suite in ("85", "86") else "0",
                  "IM_SECURITY_P2_FIXTURE_CONFIRMED": "1" if args.fixtures_confirmed else "0",
                  "IM_SECURITY_P2_HTTP_VERSION": args.version or "",
                  "IM_SECURITY_P2_TRANSPORT": args.transport or "", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
    return child


def run(args, execute=subprocess.run, parent_env=None):
    env = child_environment(args, parent_env)
    destination = Path(args.report_dir) if args.report_dir else ROOT / ".reports" / ("im-security-p2-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
    if destination.exists():
        raise SecurityRunError("报告目录已存在；不覆盖旧报告，不自动重跑")
    destination.mkdir(parents=True)
    destination = destination.resolve()
    nodes = [FILES[args.suite]]
    if args.case:
        nodes = [nodes[0] + "[" + args.case + "]"]
    elif args.suite == "86" and args.transport == "tcp":
        nodes = [FILES["86"] + "[" + c + "]" for c in GATEWAY_CASES if c != "compressed"]
    xml = destination / ("im-security-v" + args.suite + ".xml")
    command = [sys.executable, "-m", "pytest", *nodes, "-v", "--maxfail=1", "--tb=no", "--no-showlocals",
               "-p", "no:cacheprovider", "-o", "junit_family=xunit1", "--junitxml=" + str(xml)]
    try:
        completed = execute(command, cwd=ROOT, env=env, check=False)
        result = summarize_junit(xml, completed.returncode)
    except (OSError, KeyboardInterrupt):
        result = summarize_junit(xml, 2)
    result.update(scope="Vuln" + args.suite, environment="dev", deployment=env["IM_SECURITY_DEPLOYMENT"],
                  deployment_source="operator_argument" if args.deployment_version else "explicit_config",
                  runtime_version_independently_verified=False, version=args.version, transport=args.transport,
                  mute="pending_not_tested", automatic_retry=False)
    # --maxfail=1、收集过滤和部分JUnit均不能让少量通过冒充所选全部通过。
    expected = 1 if args.case or args.suite == "92" else len(GROUP_CASES) if args.suite == "85" else len(GATEWAY_CASES) - (args.transport == "tcp")
    result["expected_tests"] = expected
    result["complete"] = result["complete"] and result["tests"] == expected
    (destination / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Vuln%s：通过%d 失败%d 错误%d 跳过/受阻%d" % (args.suite, result["passed"], result["failed"], result["errors"], result["skipped"]))
    print("所选阶段全部通过" if result["complete"] else "尚未全部通过；不自动重跑、重发或清理")
    print("报告目录：" + str(destination))
    return 0 if result["complete"] else 1 if result["failed"] or result["errors"] else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("85", "86", "92"), required=True)
    parser.add_argument("--env-file", required=True)
    parser.add_argument("--version", choices=("v1", "v2"))
    parser.add_argument("--transport", choices=("ws", "tcp"))
    parser.add_argument("--case")
    parser.add_argument("--report-dir")
    parser.add_argument("--deployment-version")
    parser.add_argument("--allow-test-writes", action="store_true")
    parser.add_argument("--fixtures-confirmed", action="store_true")
    try:
        return run(parser.parse_args(argv))
    except SecurityRunError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
