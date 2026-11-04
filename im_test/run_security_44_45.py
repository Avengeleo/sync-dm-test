"""只调度 Vuln44/45 的 dev 自测，不收集其他安全或业务测试。

配置仅从指定文件读取，写许可只留在隔离子进程中。退出码：0=所选项
全部通过，1=测试失败，2=缺少前置/存在跳过/报告不完整。不会自动重跑。
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

from dotenv import dotenv_values


ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    "44": "im_test/tests/security/test_message_mutation.py",
    "45": "im_test/tests/security/test_key_identity.py",
}


class SecurityRunError(RuntimeError):
    pass


def _safe_deployment(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", value) is None:
        raise SecurityRunError("部署版本格式不合法；请填写已发布的版本标识，不填写凭证")
    if value.lower() in ("unspecified", "latest", "placeholder"):
        raise SecurityRunError("请填写已确认的实际部署版本，不能使用占位值")
    return value


def child_environment(env_file, suite, *, allow_writes, fixtures_confirmed, deployment=None,
                      parent_env=None):
    """只把指定文件的IM配置传入；清除继承的写许可和pytest附加参数。"""
    if not Path(env_file).is_file():
        raise SecurityRunError("配置文件不存在；不连接dev，不尝试恢复凭证")
    try:
        configured = dotenv_values(env_file, interpolate=False)
    except Exception:
        raise SecurityRunError("配置文件无法读取；不显示路径或配置内容") from None
    inherited = os.environ if parent_env is None else parent_env
    child = {key: value for key, value in inherited.items()
             if not key.startswith(("IM_", "DM_", "BI_", "PYTEST_"))}
    for key, value in configured.items():
        if key.startswith("IM_") and isinstance(value, str):
            child[key] = value
    if child.get("IM_SECURITY_ENV", "").strip().lower() != "dev":
        raise SecurityRunError("44/45只授权dev；配置文件必须明确设置IM_SECURITY_ENV=dev")
    child["IM_SECURITY_DEPLOYMENT"] = _safe_deployment(
        deployment if deployment else child.get("IM_SECURITY_DEPLOYMENT", "")
    )
    if not allow_writes or not fixtures_confirmed:
        raise SecurityRunError("未同时指定写许可和专用夹具确认；不会登录或发包")
    child.update({
        "IM_SECURITY_ISOLATED_CONFIG": "1",
        "IM_SECURITY_CLIENT_TYPE": "2",
        "IM_SECURITY_ALLOW_LOGIN": "0",
        "IM_SECURITY_IDENTITY_ALLOW_WRITE": "0",
        "IM_SECURITY_IDENTITY_STATE_CONFIRMED": "0",
        "IM_SECURITY_IDENTITY_WRITE_VERSION": "",
        "IM_SECURITY_ALLOW_DEVICE_KICK": "0",
        "IM_SECURITY_LOG_MANIFEST": "",
        "IM_SECURITY_MUTATION_ALLOW_WRITE": "1" if suite == "44" else "0",
        "IM_SECURITY_MUTATION_FIXTURE_CONFIRMED": "1" if suite == "44" else "0",
        "IM_SECURITY_KEY_IDENTITY_ALLOW_WRITE": "1" if suite == "45" else "0",
        "IM_SECURITY_KEY_IDENTITY_FIXTURE_CONFIRMED": "1" if suite == "45" else "0",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    })
    return child


def summarize_junit(path, returncode):
    try:
        root = ET.parse(path).getroot()
        cases = list(root.iter("testcase"))
    except (OSError, ET.ParseError):
        return {"tests": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0,
                "complete": False, "report_missing_or_invalid": True, "returncode": returncode}
    counts = {"tests": len(cases), "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for case in cases:
        status = ("errors" if case.find("error") is not None else
                  "failed" if case.find("failure") is not None else
                  "skipped" if case.find("skipped") is not None else "passed")
        counts[status] += 1
    counts.update(complete=bool(cases) and returncode == 0 and counts["passed"] == len(cases),
                  report_missing_or_invalid=False, returncode=returncode)
    return counts


def run(args, *, execute=subprocess.run, parent_env=None):
    suites = ["44", "45"] if args.suite == "both" else [args.suite]
    if args.report_dir:
        destination = Path(args.report_dir).resolve()
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        destination = ROOT / ".reports" / ("im-security-44-45-" + stamp + "-" + uuid.uuid4().hex[:8])
    if destination.exists():
        raise SecurityRunError("报告目录已经存在；请使用新目录，保留旧报告，不自动重跑夹具")
    # 先校验全部所选配置，避免44已发消息后才发现45的公共参数错误。
    environments = {suite: child_environment(args.env_file, suite,
                    allow_writes=args.allow_test_writes, fixtures_confirmed=args.fixtures_confirmed,
                    deployment=args.deployment_version, parent_env=parent_env) for suite in suites}
    destination.mkdir(parents=True)
    summary = {"scope": ["Vuln" + suite for suite in suites], "environment": "dev",
               "deployment": environments[suites[0]]["IM_SECURITY_DEPLOYMENT"],
               "deployment_source": "operator_argument" if args.deployment_version else "local_config",
               "runtime_version_independently_verified": False,
               "complete": False, "stages": [], "unexecuted": []}
    for index, suite in enumerate(suites):
        xml = destination / ("im-security-v" + suite + ".xml")
        command = [sys.executable, "-m", "pytest", TARGETS[suite], "-v", "--maxfail=1",
                   "--tb=short", "--no-showlocals", "-p", "no:cacheprovider",
                   "-o", "junit_family=xunit1", "--junitxml=" + str(xml)]
        try:
            completed = execute(command, cwd=ROOT, env=environments[suite], check=False)
            result = summarize_junit(xml, completed.returncode)
        except (OSError, KeyboardInterrupt):
            result = summarize_junit(xml, 2)
        result["vulnerability"] = "Vuln" + suite
        result["report"] = xml.name
        summary["stages"].append(result)
        if not result["complete"]:
            summary["unexecuted"] = ["Vuln" + s for s in suites[index + 1:]]
            break
    summary["complete"] = (len(summary["stages"]) == len(suites)
                           and all(stage["complete"] for stage in summary["stages"]))
    (destination / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    for stage in summary["stages"]:
        print("%s: 通过%d 失败%d 错误%d 跳过/受阻%d" %
              (stage["vulnerability"], stage["passed"], stage["failed"], stage["errors"], stage["skipped"]))
    print("全部所选项通过" if summary["complete"] else "所选项尚未全部通过；请保留报告，不自动重发夹具")
    if summary["complete"]:
        return 0
    if any(stage["failed"] or stage["errors"] for stage in summary["stages"]):
        return 1
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description="只执行Vuln44/45，登录/消息及测试key包会修改专用夹具")
    parser.add_argument("--env-file", default=".env.dev")
    parser.add_argument("--suite", choices=("44", "45", "both"), default="both")
    parser.add_argument("--report-dir")
    parser.add_argument("--deployment-version", help="由发布记录或负责人确认的实际版本，不代替运行版本核验")
    parser.add_argument("--allow-test-writes", action="store_true")
    parser.add_argument("--fixtures-confirmed", action="store_true")
    try:
        return run(parser.parse_args(argv))
    except SecurityRunError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
