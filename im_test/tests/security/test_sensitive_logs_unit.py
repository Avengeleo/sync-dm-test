"""纯本地日志扫描回归；只使用临时文件和合成值，不读取环境凭证。"""

import base64
import json
import traceback

import pytest

from im_test.security_logs import (
    DEFAULT_SERVICES, REQUIRED_SECRET_TYPES, SecurityLogAuditError, audit_export,
)


DEPLOYMENT = "test-develop-abcdef0"
TIMESTAMP = "2026-10-31T02:01:00Z"


def _export(tmp_path, active=("login-srv",)):
    sentinels = {kind: "V47_UNIT_" + kind + "_PRIVATE_SENTINEL" for kind in REQUIRED_SECRET_TYPES}
    services = {service: {"status": "not_running", "reason": "not enabled in this isolated local fixture"}
                for service in DEFAULT_SERVICES}
    for service in active:
        services[service] = {"status": "running", "file": service + ".ndjson"}
        _write_rows(tmp_path / (service + ".ndjson"), service, ["safe result=ok uid=41"])
    cases = [{
        "scenario": "isolated_success", "outcome": "success",
        "positive_control_succeeded": True, "observed_at": TIMESTAMP,
        "injected_sentinels": list(REQUIRED_SECRET_TYPES),
        "evidence_ref": "manual:local-unit-test-positive-control",
        "diagnostics": {service: "safe result=ok" for service in active},
    }]
    if "crypto-srv" in active:
        cases.append({**cases[0], "scenario": "isolated_expected_error", "outcome": "expected_error",
                      "diagnostics": {"crypto-srv": "safe result=ok"}})
    manifest = {
        "schema_version": 1, "environment": "dev", "deployment": DEPLOYMENT,
        "window": {"start": "2026-10-31T02:00:00Z", "end": "2026-10-31T02:10:00Z"},
        "test_accounts_only": True, "export_complete": True,
        "sentinels": sentinels, "services": services, "cases": cases,
    }
    path = tmp_path / "manifest.json"
    _save(path, manifest)
    return path, manifest


def _save(path, manifest):
    path.write_text(json.dumps(manifest), encoding="utf-8")


def _write_rows(path, service, messages):
    path.write_text("".join(json.dumps({
        "timestamp": TIMESTAMP, "service": service, "deployment": DEPLOYMENT,
        "environment": "dev", "message": message,
    }) + "\n" for message in messages), encoding="utf-8")


def _fails_without_data(path, fragment, secret=""):
    with pytest.raises(SecurityLogAuditError) as caught:
        audit_export(path, DEPLOYMENT)
    text = str(caught.value)
    assert fragment in text
    if secret:
        assert secret not in text
    return text


def test_log_export_checks_all_running_services_and_records_manual_boundary(tmp_path):
    path, _ = _export(tmp_path, DEFAULT_SERVICES)
    report = audit_export(path, DEPLOYMENT)
    assert report.line_count == 13
    assert report.full_service_coverage
    assert report.excluded_services == ()
    assert report.manual_case_count == 2
    assert set(report.covered_secret_types) == set(REQUIRED_SECRET_TYPES)


def test_log_export_reports_explicit_not_running_services_as_unverified(tmp_path):
    path, _ = _export(tmp_path)
    report = audit_export(path, DEPLOYMENT)
    assert report.service_counts == {"login-srv": 1}
    assert not report.full_service_coverage
    assert set(report.excluded_services) == set(DEFAULT_SERVICES) - {"login-srv"}


@pytest.mark.parametrize("kind", REQUIRED_SECRET_TYPES)
@pytest.mark.parametrize("encoding", ["raw", "base64", "urlsafe", "octal", "hex", "decimal", "json_escaped"])
def test_log_export_detects_secret_encodings_without_echoing_value(tmp_path, kind, encoding):
    path, manifest = _export(tmp_path)
    secret = manifest["sentinels"][kind]
    if encoding == "raw":
        value = secret
    elif encoding == "base64":
        value = base64.b64encode(secret.encode()).decode()
    elif encoding == "urlsafe":
        value = base64.urlsafe_b64encode(secret.encode()).decode().rstrip("=")
    elif encoding == "octal":
        value = "".join("\\%03o" % byte for byte in secret.encode())
    elif encoding == "hex":
        value = secret.encode().hex()
    elif encoding == "decimal":
        value = "[" + " ".join(str(byte) for byte in secret.encode()) + "]"
    else:
        value = "".join("\\u%04x" % ord(char) for char in secret)
        # 模拟 JSON 原字段的 Unicode 转义，而非一个包含字面转义的新日志。
        _write_rows(tmp_path / "login-srv.ndjson", "login-srv", ["safe result=ok " + secret])
        source = (tmp_path / "login-srv.ndjson").read_text(encoding="utf-8")
        (tmp_path / "login-srv.ndjson").write_text(source.replace(secret, value), encoding="utf-8")
        _fails_without_data(path, "类别=" + kind, secret)
        return
    _write_rows(tmp_path / "login-srv.ndjson", "login-srv", [{"nested_original": "safe result=ok " + value}])
    message = _fails_without_data(path, "类别=" + kind, secret)
    assert "服务=login-srv 行=1" in message
    assert value not in message


def test_log_export_detects_multiline_pem_and_unknown_private_key_header(tmp_path):
    path, manifest = _export(tmp_path)
    secret = "-----BEGIN PRIVATE KEY-----\nV47_UNIT_SYNTHETIC_KEY_BODY\n-----END PRIVATE KEY-----"
    manifest["sentinels"]["private_key"] = secret
    _save(path, manifest)
    _write_rows(tmp_path / "login-srv.ndjson", "login-srv", ["safe result=ok key=" + secret])
    _fails_without_data(path, "类别=private_key", secret)
    _write_rows(tmp_path / "login-srv.ndjson", "login-srv", ["safe result=ok -----BEGIN RSA PRIVATE KEY-----"])
    _fails_without_data(path, "类别=private_key")


@pytest.mark.parametrize("kind", REQUIRED_SECRET_TYPES)
@pytest.mark.parametrize("prefix_length", [0, 1, 2])
@pytest.mark.parametrize("encoding", ["base64", "urlsafe", "nested"])
def test_log_export_detects_secret_inside_encoded_package_at_all_alignments(tmp_path, kind, prefix_length, encoding):
    path, manifest = _export(tmp_path)
    secret = manifest["sentinels"][kind]
    package = b"x" * prefix_length + secret.encode() + b"\x00\xffprotobuf-suffix"
    if encoding == "urlsafe":
        value = base64.urlsafe_b64encode(package).decode().rstrip("=")
    else:
        value = base64.b64encode(package).decode()
        if encoding == "nested":
            value = base64.b64encode(json.dumps({"protobuf": value}).encode()).decode()
    _write_rows(tmp_path / "login-srv.ndjson", "login-srv", ["safe result=ok", {"body": value}])
    message = _fails_without_data(path, "类别=" + kind, secret)
    assert "行=2" in message
    assert value not in message


@pytest.mark.parametrize("prefix_length", [0, 1, 2])
def test_log_export_encoded_near_match_and_short_common_prefix_are_not_leaks(tmp_path, prefix_length):
    path, manifest = _export(tmp_path)
    value = manifest["sentinels"]["login_token"]
    near_match = value[:-1] + "X"
    package = b"x" * prefix_length + near_match.encode() + b"\x00" + b"V47_UNIT_" + b"\xff"
    encoded = base64.b64encode(package).decode()
    _write_rows(tmp_path / "login-srv.ndjson", "login-srv", ["safe result=ok", encoded])
    assert audit_export(path, DEPLOYMENT).line_count == 2


@pytest.mark.parametrize("kind", REQUIRED_SECRET_TYPES)
@pytest.mark.parametrize("prefix_length", [0, 1, 2])
@pytest.mark.parametrize("encoding", ["go_decimal", "python_decimal", "go_hex"])
def test_log_export_detects_secret_inside_complete_byte_array_packet(tmp_path, kind, prefix_length, encoding):
    path, manifest = _export(tmp_path)
    secret = manifest["sentinels"][kind]
    # 包含二进制头、长度字段、任意前后缀；秘密不是整个切片。
    packet = bytes([10, len(secret)]) + b"x" * prefix_length + secret.encode() + bytes([0, 255, 18, 1, 65])
    if encoding == "go_decimal":
        value = "[" + " ".join(str(byte) for byte in packet) + "]"
    elif encoding == "python_decimal":
        value = str(list(packet))
    else:
        value = "[]uint8{" + ", ".join("0x%x" % byte for byte in packet) + "}"
    _write_rows(tmp_path / "login-srv.ndjson", "login-srv", ["safe result=ok", "packet=" + value])
    message = _fails_without_data(path, "类别=" + kind, secret)
    assert "行=2" in message
    assert value not in message


@pytest.mark.parametrize("invalid", ["256", "99999999999999999999999999999999", "-1", "1.5", "true", '"12"', "1e2"])
@pytest.mark.parametrize("style", ["go_decimal", "python_decimal", "go_hex"])
def test_log_export_does_not_decode_nonbyte_array_substrings(tmp_path, invalid, style):
    path, manifest = _export(tmp_path)
    secret = manifest["sentinels"]["login_token"]
    if style == "go_hex":
        tokens = ["0x%x" % byte for byte in secret.encode()]
        # 非法值使整个切片无效，不能跳过它再拼出一个秘密。
        value = "[]uint8{" + ", ".join([invalid] + tokens + ["0xff"]) + "}"
    else:
        tokens = [str(byte) for byte in secret.encode()]
        separator = " " if style == "go_decimal" else ", "
        value = "[" + separator.join([invalid] + tokens + ["255"]) + "]"
    _write_rows(tmp_path / "login-srv.ndjson", "login-srv", ["safe result=ok", value])
    assert audit_export(path, DEPLOYMENT).line_count == 2


@pytest.mark.parametrize("style", ["go_decimal", "python_decimal", "go_hex", "nonbyte_go_type"])
def test_log_export_byte_array_near_match_and_short_prefix_are_not_leaks(tmp_path, style):
    path, manifest = _export(tmp_path)
    secret = manifest["sentinels"]["login_token"]
    content = (secret[:-1] + "X").encode() + b"\x00V47_UNIT_\xff"
    if style in ("go_hex", "nonbyte_go_type"):
        type_name = "uint8" if style == "go_hex" else "uint16"
        if style == "nonbyte_go_type":
            content = secret.encode() + b"\xff"
        value = "[]" + type_name + "{" + ", ".join("0x%x" % byte for byte in content) + "}"
    else:
        separator = " " if style == "go_decimal" else ", "
        value = "[" + separator.join(str(byte) for byte in content) + "]"
    _write_rows(tmp_path / "login-srv.ndjson", "login-srv", ["safe result=ok", value])
    assert audit_export(path, DEPLOYMENT).line_count == 2


@pytest.mark.parametrize("contents,fragment", [("", "日志为空"), ("\n \n", "日志为空"),
                                                ("{bad-json", "JSONL 日志畸形"), ("[]\n", "元数据不一致")])
def test_log_export_rejects_empty_or_malformed_logs(tmp_path, contents, fragment):
    path, _ = _export(tmp_path)
    (tmp_path / "login-srv.ndjson").write_text(contents, encoding="utf-8")
    _fails_without_data(path, fragment)


@pytest.mark.parametrize("field,value", [("environment", "prod"), ("deployment", "old-version"),
                                         ("service", "another-service"), ("timestamp", "2026-10-30T01:00:00Z"),
                                         ("timestamp", "not-a-time"), ("timestamp", "2026-10-31T02:01:00"),
                                         ("message", "")])
def test_log_export_rejects_wrong_environment_version_window_and_missing_message(tmp_path, field, value):
    path, _ = _export(tmp_path)
    logfile = tmp_path / "login-srv.ndjson"
    row = json.loads(logfile.read_text())
    row[field] = value
    logfile.write_text(json.dumps(row), encoding="utf-8")
    with pytest.raises(SecurityLogAuditError):
        audit_export(path, DEPLOYMENT)


@pytest.mark.parametrize("mutation,fragment", [
    (lambda m: m["services"].pop("signal-job"), "13 个运行制品"),
    (lambda m: m["services"]["login-srv"].update(file="missing.ndjson"), "无法读取完整本地日志"),
    (lambda m: m["services"]["signal-job"].update(reason=""), "必须填写原因"),
    (lambda m: m["sentinels"].pop("login_token"), "login_token"),
    (lambda m: m["sentinels"].update(tea_key=""), "tea_key"),
    (lambda m: m["cases"][0].update(positive_control_succeeded=False), "真实成功正控未确认"),
    (lambda m: m["cases"][0].update(outcome="denied"), "被拒绝的前置"),
    (lambda m: m["cases"][0].update(injected_sentinels=["plaintext"]), "未由成功正控确认"),
    (lambda m: m["cases"][0].update(injected_sentinels=[{}]), "未确认已使用"),
    (lambda m: m["cases"][0].update(evidence_ref=""), "证据引用"),
    (lambda m: m["cases"][0].update(diagnostics={"login-srv": "absent diagnostic"}), "安全诊断未出现"),
    (lambda m: m.update(cases=[]), "缺少真实触发场景"),
    (lambda m: m.update(test_accounts_only=False), "必须人工确认"),
    (lambda m: m.update(export_complete=False), "必须人工确认"),
    (lambda m: m.update(environment="prod"), "dev 验收"),
    (lambda m: m.update(deployment="old-version"), "部署版本与本次配置不一致"),
])
def test_log_export_rejects_missing_coverage_or_unproven_preconditions(tmp_path, mutation, fragment):
    path, manifest = _export(tmp_path)
    mutation(manifest)
    _save(path, manifest)
    _fails_without_data(path, fragment)


def test_log_export_rejects_service_without_success_case_and_crypto_without_error_case(tmp_path):
    path, manifest = _export(tmp_path, ("login-srv", "crypto-srv"))
    manifest["cases"].pop()
    _save(path, manifest)
    _fails_without_data(path, "尚未覆盖受控失败路径")
    manifest["cases"][0]["diagnostics"].pop("crypto-srv")
    _save(path, manifest)
    _fails_without_data(path, "缺少成功操作证据的运行服务")


def test_log_export_does_not_pass_all_not_running(tmp_path):
    path, manifest = _export(tmp_path)
    manifest["services"]["login-srv"] = {"status": "not_running", "reason": "not enabled in this isolated fixture"}
    _save(path, manifest)
    _fails_without_data(path, "没有运行服务")


@pytest.mark.parametrize("contents", ["{invalid-json-secret-canary", "[]", "null"])
def test_log_export_manifest_errors_do_not_echo_contents(tmp_path, contents):
    path = tmp_path / "invalid.json"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(SecurityLogAuditError) as caught:
        audit_export(path, DEPLOYMENT)
    assert contents not in str(caught.value)


def test_log_export_requires_explicit_deployment(tmp_path):
    path, _ = _export(tmp_path)
    with pytest.raises(SecurityLogAuditError, match="必须指定本次 dev 部署版本"):
        audit_export(path, "unspecified")


def test_log_export_traceback_does_not_echo_invalid_timestamp(tmp_path):
    path, manifest = _export(tmp_path)
    secret = manifest["sentinels"]["login_token"]
    manifest["window"]["start"] = secret
    _save(path, manifest)
    with pytest.raises(SecurityLogAuditError) as caught:
        audit_export(path, DEPLOYMENT)
    rendered = "".join(traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__))
    assert secret not in rendered
    assert caught.value.__suppress_context__
