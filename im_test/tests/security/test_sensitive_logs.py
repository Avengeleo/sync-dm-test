"""V47：人工触发 dev 操作并导出日志后的本地验收；不发请求、不接 ELK。"""

import pytest

from im_test.security_logs import SecurityLogAuditError, audit_export


def test_sensitive_logs_manual_export(security_config, record_property):
    config = security_config
    manifest = config.get("log_manifest", "")
    if not manifest:
        pytest.skip("未配置 IM_SECURITY_LOG_MANIFEST；V47 真实运行日志尚未验证")
    if config["target_env"] != "dev":
        pytest.fail("日志验收仅授权 dev；必须配置 IM_SECURITY_ENV=dev", pytrace=False)
    try:
        report = audit_export(manifest, config["deployment"])
    except SecurityLogAuditError as exc:
        pytest.fail(str(exc), pytrace=False)
    record_property("target_environment", "dev")
    record_property("deployment_version", config["deployment"])
    record_property("evidence_source", "manual_operations_and_local_log_export")
    record_property("automatic_live_operations", False)
    record_property("manual_success_evidence_cases", report.manual_case_count)
    record_property("automated_log_lines_checked", report.line_count)
    record_property("runtime_services_checked", ",".join(sorted(report.service_counts)))
    record_property("not_running_services_not_verified", ",".join(report.excluded_services))
    record_property("full_13_service_coverage", report.full_service_coverage)
    record_property("secret_types_checked", ",".join(report.covered_secret_types))
