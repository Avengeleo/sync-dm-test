"""V92扫描正控、反向泄露和证据完整性回归。"""
import base64
import json

import pytest
from im_test.security_p2_config import P2Blocked, P2Error
from im_test.security_robot_sql_p2 import audit_robot_sql


def fixture(tmp_path):
    log = tmp_path / "robot.jsonl"
    rows = [{"environment": "dev", "service": "robot-srv", "timestamp": "2026-11-09T01:01:00Z",
             "message": {"msg": "robot mysql query failed", "error_type": "*mysql.MySQLError", "elapsed_ms": 1}},
            {"environment": "dev", "service": "robot-srv", "timestamp": "2026-11-09T01:02:00Z",
             "message": {"msg": "robot mysql slow query", "elapsed_ms": 11000}}]
    log.write_text("".join(json.dumps(r) + "\n" for r in rows))
    data = {"environment": "dev", "service": "robot-srv", "deployment": "f434b82",
            "version_source": "operator_release_confirmation", "version_evidence": "local-test-release-record",
            "export_complete": True, "export_file": log.name, "expected_line_count": 2,
            "window_start": "2026-11-09T01:00:00Z", "window_end": "2026-11-09T01:05:00Z",
            "parameters": {k: "SQL_SENTINEL_" + k + "_12345678" for k in ("normal", "error", "slow")},
            "cases": [{"kind": k, "completed": True, "parameter_ids": [k], "evidence_ref": "local-test-only",
                       "timestamp": "2026-11-09T01:01:00Z", "diagnostic_line": line}
                      for k, line in (("normal", None), ("error", 1), ("slow", 2))]}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data))
    return path, log, data, rows


def test_sql_audit_accepts_full_evidence_but_does_not_claim_independent_version(tmp_path):
    path, _, _, _ = fixture(tmp_path)
    result = audit_robot_sql(path, "f434b82")
    assert result["line_count"] == 2 and result["cases_checked"] == 3
    assert not result["runtime_version_independently_verified"]
    assert "SQL_SENTINEL" not in repr(result)


@pytest.mark.parametrize("encoding", ("plain", "base64", "hex", "json"))
def test_sql_parameter_leak_is_rejected_without_echoing_value(tmp_path, encoding):
    path, log, data, rows = fixture(tmp_path)
    value = data["parameters"]["error"]
    encoded = {"plain": value, "base64": base64.b64encode(value.encode()).decode(),
               "hex": value.encode().hex(), "json": json.dumps(value)}[encoding]
    rows[0]["message"]["unsafe"] = encoded
    log.write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(P2Error) as exc:
        audit_robot_sql(path, "f434b82")
    assert value not in str(exc.value)


@pytest.mark.parametrize("change", ("no_cases", "no_version_evidence", "filtered"))
def test_missing_evidence_is_blocked_not_passed(tmp_path, change):
    path, _, data, _ = fixture(tmp_path)
    if change == "no_cases":
        data["cases"] = data["cases"][:1]
    elif change == "no_version_evidence":
        data["version_evidence"] = ""
    else:
        data["export_complete"] = False
    path.write_text(json.dumps(data))
    with pytest.raises(P2Blocked):
        audit_robot_sql(path, "f434b82")


@pytest.mark.parametrize("change", ("count", "wrong_service", "wrong_environment", "wrong_time", "no_diagnostic", "unused_parameter", "bad_case_timestamp", "stale_version"))
def test_inconsistent_or_stale_sql_exports_cannot_pass(tmp_path, change):
    path, log, data, rows = fixture(tmp_path)
    if change == "count":
        data["expected_line_count"] = 3
    elif change == "wrong_service":
        rows[0]["service"] = "other-srv"
    elif change == "wrong_environment":
        rows[0]["environment"] = "stg"
    elif change == "wrong_time":
        rows[0]["timestamp"] = "2026-11-01T01:01:00Z"
    elif change == "no_diagnostic":
        rows[0]["message"] = "SQL suppressed"
    elif change == "unused_parameter":
        data["parameters"]["unused"] = "UNUSED_SENTINEL_123456"
    elif change == "bad_case_timestamp":
        data["cases"][0]["timestamp"] = "2026-11-01T01:01:00Z"
    else:
        data["deployment"] = "old-version"
    path.write_text(json.dumps(data)); log.write_text("".join(json.dumps(r) + "\n" for r in rows))
    with pytest.raises(P2Error):
        audit_robot_sql(path, "f434b82")
