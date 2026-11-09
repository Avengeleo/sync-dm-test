"""V92 仅检查 robot-srv 的完整本地 JSONL；不连接数据库/ELK或制造慢SQL。"""
import hashlib
import json
from pathlib import Path

from im_test.security_logs import _leaked_kind, _representations, _text_parts, _timestamp
from im_test.security_p2_config import P2Blocked, P2Error, require


def audit_robot_sql(manifest_path, deployment):
    if not manifest_path:
        raise P2Blocked("缺少 V92 本地 manifest；没有自动连接数据库或日志系统")
    try:
        path = Path(manifest_path)
        require(path.stat().st_size <= 1024 * 1024, "V92 manifest 超出大小预算")
        data = json.loads(path.read_text(encoding="utf-8"))
        require(isinstance(data, dict) and data.get("environment") == "dev" and data.get("service") == "robot-srv", "V92 manifest 环境或服务不符合范围")
        require(data.get("deployment") == deployment and deployment not in ("", "unspecified", "latest", "placeholder"), "V92 部署标记与本次配置不一致")
        if data.get("version_source") not in ("operator_release_confirmation", "runtime_image") or not data.get("version_evidence"):
            raise P2Blocked("缺少 robot-srv 本次版本依据，不能把旧日志当成本次验收")
        if data.get("export_complete") is not True:
            raise P2Blocked("日志导出完整性未确认；不能仅扫描筛选/脱敏后的日志")
        start, end = _timestamp(data.get("window_start")), _timestamp(data.get("window_end"))
        require(start < end, "V92 日志窗口无效")
        params = data.get("parameters")
        require(isinstance(params, dict) and bool(params), "V92 缺少实际用于SQL场景的测试参数")
        require(all(isinstance(k, str) and k and isinstance(v, str) and 16 <= len(v) <= 4096 for k, v in params.items()), "V92 参数必须是有界、可识别的专用测试值")
        scenarios = data.get("cases", [])
        if not isinstance(scenarios, list) or {c.get("kind") for c in scenarios if isinstance(c, dict)} != {"normal", "error", "slow"} or len(scenarios) != 3:
            raise P2Blocked("V92 需正常查询、错误查询、慢查询三项实际场景；不自动触发缺项")
        used = set()
        for case in scenarios:
            refs = case.get("parameter_ids", [])
            require(isinstance(refs, list) and bool(refs) and all(isinstance(k, str) and k in params for k in refs), "V92 场景未关联真实测试参数")
            require(case.get("completed") is True and isinstance(case.get("evidence_ref"), str) and bool(case["evidence_ref"]), "V92 场景没有可追溯执行证据")
            require(start <= _timestamp(case.get("timestamp")) <= end, "V92 场景超出日志窗口")
            used.update(refs)
        require(used == set(params), "V92 含未进入执行场景的参数，不能作为覆盖证据")
        log_path = Path(data.get("export_file", ""))
        if not log_path.is_absolute():
            log_path = path.parent / log_path
        require(log_path.is_file() and log_path.stat().st_size <= 128 * 1024 * 1024, "V92 原始日志缺失或超过本地128MiB预算")
        expected = data.get("expected_line_count")
        require(type(expected) is int and 0 < expected <= 200000, "V92 缺少有效导出计数")
        needles = {key: _representations(value) for key, value in params.items()}
        diagnostics, count, digest = {}, 0, hashlib.sha256()
        with log_path.open("rb") as source:
            while True:
                raw = source.readline(1024 * 1024 + 1)
                if not raw:
                    break
                count += 1
                require(count <= 200000 and len(raw) <= 1024 * 1024 and bool(raw.strip()), "V92 日志行过长、为空或超过总量预算")
                digest.update(raw)
                row = json.loads(raw)
                require(isinstance(row, dict) and row.get("service") == "robot-srv" and row.get("environment") == "dev", "V92 导出夹入其他服务或环境")
                require(start <= _timestamp(row.get("timestamp")) <= end, "V92 导出含窗口外日志")
                require(isinstance(row.get("message"), (str, dict, list)) and bool(row["message"]), "V92 缺少未脱敏原始 message")
                texts = (raw.decode("utf-8"), *tuple(_text_parts(row)))
                if _leaked_kind(texts, needles):
                    raise P2Error("V92 原始日志出现测试SQL参数；不输出命中值或原文")
                flattened = " ".join(texts)
                diagnostics[count] = ("robot mysql query failed" in flattened, "robot mysql slow query" in flattened)
        require(count == expected, "V92 导出行数与权威计数不一致")
        for case in scenarios:
            if case["kind"] == "normal":
                continue  # 正常查询预期不打印SQL，由调用结果提供实际执行证据。
            line = case.get("diagnostic_line")
            require(type(line) is int and line in diagnostics, "V92 错误/慢查询没有精确日志行证据")
            require(diagnostics[line][0 if case["kind"] == "error" else 1], "V92 日志行未匹配本次固定错误/慢查询诊断")
        return {"line_count": count, "sha256": digest.hexdigest(), "scope": "robot-srv SQL parameters only",
                "scenario_evidence_source": "operator_attested_with_error_slow_diagnostic_lines",
                "version_source": data["version_source"], "runtime_version_independently_verified": False,
                "cases_checked": 3}
    except (P2Error, P2Blocked):
        raise
    except Exception:
        raise P2Error("V92 manifest 或原始日志无效；未输出文件内容、路径或参数") from None
