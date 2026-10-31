"""V47 本地导出日志验收；只读文件，不连接日志平台，也不触发业务操作。

JSONL 每行必须保留完整原日志为 message，并带 timestamp/service/deployment/
environment。操作成功、测试输入已注入和导出完整性属于人工证据声明；本模块只
自动校验声明完整性、日志元数据、安全诊断及已知敏感输入是否泄露。
"""

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple


DEFAULT_SERVICES = (
    "http-gateway", "im-gateway-tcp", "im-gateway-ws", "login-srv",
    "crypto-srv", "msg-srv", "msg-job", "notification-srv", "group-job",
    "channel-job", "signal-srv", "signal-job", "call-record-job",
)
REQUIRED_SECRET_TYPES = (
    "login_token", "push_token", "voip_token", "private_key", "tea_key", "plaintext",
)
OPTIONAL_SECRET_TYPES = ("ciphertext", "livekit_token", "public_key")
_PRIVATE_PEM = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
_DECIMAL_ARRAY = re.compile(r"\[([^\[\]]*)\]")
_GO_BYTE_ARRAY = re.compile(r"(?<![A-Za-z0-9_])\[\](?:uint8|byte)\s*\{([^{}]*)\}")
_DECIMAL_BYTE = re.compile(r"[0-9]{1,3}\Z")
_GO_BYTE = re.compile(r"(?:[0-9]{1,3}|0[xX][0-9a-fA-F]{1,2})\Z")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+@-]{0,127}\Z")


class SecurityLogAuditError(ValueError):
    """所有错误只包含固定说明、服务名、行号和类别，禁止嵌入原始数据。"""


@dataclass(frozen=True)
class LogAuditReport:
    line_count: int
    service_counts: Dict[str, int]
    excluded_services: Tuple[str, ...]
    covered_secret_types: Tuple[str, ...]
    manual_case_count: int

    @property
    def full_service_coverage(self):
        return not self.excluded_services


def _fail(message):
    raise SecurityLogAuditError(message) from None


def _timestamp(value):
    if not isinstance(value, str):
        _fail("日志时间必须为带时区的 ISO-8601 字符串")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        _fail("日志时间格式无效（不显示原值）")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("日志时间必须包含时区")
    return parsed


def _read_manifest(path):
    try:
        if path.stat().st_size > 1024 * 1024:
            _fail("manifest 超过 1 MiB，请缩小验收范围")
        with path.open("r", encoding="utf-8") as source:
            data = json.load(source)
    except (OSError, UnicodeError, ValueError):
        _fail("无法读取有效的本地 JSON manifest（不显示路径或内容）")
    if not isinstance(data, dict):
        _fail("manifest 顶层必须为对象")
    return data


def _representations(value):
    raw = value.encode("utf-8")
    quoted = json.dumps(value, ensure_ascii=True)[1:-1]
    protobuf_escaped = "".join(
        {9: "\\t", 10: "\\n", 13: "\\r", 34: '\\"', 92: "\\\\"}.get(
            byte, chr(byte) if 32 <= byte < 127 else "\\%03o" % byte)
        for byte in raw
    )
    return tuple(set((
        value, quoted, json.dumps(quoted)[1:-1],
        protobuf_escaped,
        base64.b64encode(raw).decode("ascii"),
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        raw.hex(), raw.hex().upper(),
        "".join("\\%03o" % byte for byte in raw),
        "".join("\\x%02x" % byte for byte in raw),
        "[" + " ".join(str(byte) for byte in raw) + "]",
        str(list(raw)),
    )))


def _base64_payloads(texts):
    """解开有界候选，覆盖整个 protobuf/JSON 包体中任意字节对齐的秘密。

    不截取短编码片段做匹配；完整候选解码后再找完整敏感值，避免偏移漏检及
    很短公共前缀误报。第二层兼容 base64 包内再次编码的 JSON 字段。
    """
    current, seen = texts, set()
    decoded_size = 0
    for _depth in range(2):
        following = []
        for text in current:
            for match in _BASE64.finditer(text):
                token = match.group(0)
                if token in seen:
                    continue
                seen.add(token)
                if len(seen) > 1024:
                    _fail("日志编码候选过多，无法完整扫描；请缩小单行日志范围")
                try:
                    payload = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
                except (ValueError, base64.binascii.Error):
                    continue
                decoded_size += len(payload)
                if decoded_size > 4 * 1024 * 1024:
                    _fail("日志解码大小超限，无法完整扫描；请缩小单行日志范围")
                yield payload
                # latin-1 保留逐字节边界，不忽略非 UTF-8 字节而把分开的片段拼接。
                following.append(payload.decode("latin-1"))
        current = following


def _byte_array_payloads(texts):
    """解码完整 Go/Python 字节数组；不在更大的数字数组里截取秘密片段。

    支持 fmt %v 的 [10 32 ...]、Python [10, 32, ...] 和 Go %#v 的
    []uint8{0xa, 0x20, ...}。整组必须全部为 0..255 的整数；负数、浮点数、
    字符串、超大整数或其他 Go 类型不是字节数组，不能据其子串判定泄漏。
    """
    seen, decoded_size = set(), 0
    for text in texts:
        for pattern, token_pattern in ((_GO_BYTE_ARRAY, _GO_BYTE), (_DECIMAL_ARRAY, _DECIMAL_BYTE)):
            for match in pattern.finditer(text):
                candidate = match.group(0)
                if candidate in seen:
                    continue
                seen.add(candidate)
                if len(seen) > 1024:
                    _fail("日志字节数组候选过多，无法完整扫描；请缩小单行日志范围")
                body = match.group(1).strip()
                if not body:
                    continue
                if "," in body:
                    tokens = [token.strip() for token in body.split(",")]
                    if not tokens[-1]:
                        tokens.pop()
                else:
                    tokens = body.split()
                # 最短测试输入为 12 字节；只检查完整数组，不匹配短公共片段。
                if len(tokens) < 12 or any(not token_pattern.fullmatch(token) for token in tokens):
                    continue
                if len(tokens) > 262144:
                    _fail("日志字节数组过大，无法完整扫描；请缩小单行日志范围")
                values = [int(token, 16 if token.lower().startswith("0x") else 10) for token in tokens]
                if any(value > 255 for value in values):
                    continue
                payload = bytes(values)
                decoded_size += len(payload)
                if decoded_size > 4 * 1024 * 1024:
                    _fail("日志字节数组解码大小超限，无法完整扫描")
                yield payload


def _leaked_kind(texts, secrets):
    for kind, variants in secrets.items():
        if any(value in text for value in variants for text in texts):
            return kind
    if any(_PRIVATE_PEM.search(text) for text in texts):
        return "private_key"
    for decoder in (_byte_array_payloads, _base64_payloads):
        for payload in decoder(texts):
            for kind, variants in secrets.items():
                if any(value.encode("utf-8") in payload for value in variants):
                    return kind
            if _PRIVATE_PEM.search(payload.decode("latin-1")):
                return "private_key"
    return None


def _text_parts(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _text_parts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _text_parts(child)


def _secrets(data):
    values = data.get("sentinels")
    if not isinstance(values, dict):
        _fail("缺少敏感输入前置：必须配置 sentinels 六类测试输入")
    allowed = REQUIRED_SECRET_TYPES + OPTIONAL_SECRET_TYPES
    if set(values) - set(allowed):
        _fail("sentinels 包含未知类别")
    missing = [kind for kind in REQUIRED_SECRET_TYPES if not values.get(kind)]
    if missing:
        _fail("敏感输入未覆盖：" + ", ".join(missing))
    result = {}
    for kind, value in values.items():
        if not isinstance(value, str) or not 12 <= len(value.encode("utf-8")) <= 32768:
            _fail("敏感输入长度无效；每类需 12 到 32768 字节，类别=" + kind)
        result[kind] = _representations(value)
    return result


def _cases(data, active, secret_types, start, end):
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        _fail("缺少真实触发场景及人工成功证据")
    successful_services, injected = set(), set()
    diagnostics = {service: [] for service in active}
    crypto_error = False
    for number, case in enumerate(cases, 1):
        if not isinstance(case, dict):
            _fail("触发场景必须为对象")
        if not isinstance(case.get("scenario"), str) or not _LABEL.fullmatch(case["scenario"]):
            _fail("触发场景缺少有效名称")
        if case.get("outcome") not in ("success", "expected_error"):
            _fail("场景必须确认 success 或 expected_error；被拒绝的前置不能作为正控")
        if case.get("positive_control_succeeded") is not True:
            _fail("真实成功正控未确认；拒绝、空响应或失败操作不能证明脱敏通过")
        if not isinstance(case.get("evidence_ref"), str) or not case["evidence_ref"].strip():
            _fail("缺少人工操作结果的证据引用")
        observed = _timestamp(case.get("observed_at"))
        if not start <= observed <= end:
            _fail("人工操作时间不在导出窗口内")
        kinds = case.get("injected_sentinels")
        if not isinstance(kinds, list) or not kinds or any(not isinstance(kind, str) or kind not in secret_types for kind in kinds):
            _fail("触发场景未确认已使用哪些敏感测试输入")
        markers = case.get("diagnostics")
        if not isinstance(markers, dict) or not markers or set(markers) - set(active):
            _fail("场景必须引用实际运行且已导出日志的服务")
        for service, marker in markers.items():
            if not isinstance(marker, str) or not 4 <= len(marker) <= 256:
                _fail("安全诊断片段必须为 4 到 256 字符；服务=" + service)
            diagnostics[service].append((number, marker))
        if case["outcome"] == "success":
            successful_services.update(markers)
            injected.update(kinds)
        elif "crypto-srv" in markers:
            crypto_error = True
    if set(active) - successful_services:
        _fail("缺少成功操作证据的运行服务：" + ", ".join(sorted(set(active) - successful_services)))
    if set(secret_types) - injected:
        _fail("敏感输入未由成功正控确认：" + ", ".join(sorted(set(secret_types) - injected)))
    if "crypto-srv" in active and not crypto_error:
        _fail("crypto-srv 尚未覆盖受控失败路径；需成功正控及 expected_error 场景")
    return diagnostics, len(cases)


def audit_export(manifest_path, expected_deployment):
    """校验并扫描本地导出，失败消息与返回报告均不含凭证、正文或原始日志。"""
    if not isinstance(expected_deployment, str) or expected_deployment == "unspecified" or not _LABEL.fullmatch(expected_deployment):
        _fail("必须指定本次 dev 部署版本，不能使用 unspecified")
    path = Path(manifest_path)
    data = _read_manifest(path)
    if data.get("schema_version") != 1 or data.get("environment") != "dev":
        _fail("manifest 必须是 schema_version=1 的 dev 验收")
    if data.get("deployment") != expected_deployment:
        _fail("manifest 部署版本与本次配置不一致")
    if data.get("test_accounts_only") is not True or data.get("export_complete") is not True:
        _fail("必须人工确认专用测试账号及完整未按正文过滤的日志导出")
    window = data.get("window")
    if not isinstance(window, dict):
        _fail("缺少日志导出时间窗口")
    start, end = _timestamp(window.get("start")), _timestamp(window.get("end"))
    if start >= end:
        _fail("日志窗口开始时间必须早于结束时间")
    secrets = _secrets(data)
    services = data.get("services")
    if not isinstance(services, dict) or set(services) != set(DEFAULT_SERVICES):
        _fail("必须逐一声明默认 13 个运行制品；缺日志不能冒充未运行")
    active, excluded = {}, []
    for service, entry in services.items():
        if not isinstance(entry, dict):
            _fail("服务声明格式无效；服务=" + service)
        if entry.get("status") == "not_running":
            if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                _fail("未运行服务必须填写原因；服务=" + service)
            excluded.append(service)
        elif entry.get("status") == "running":
            if not isinstance(entry.get("file"), str) or not entry["file"].strip():
                _fail("运行服务缺少本地导出文件；服务=" + service)
            active[service] = path.parent / entry["file"]
        else:
            _fail("服务状态必须为 running 或 not_running；服务=" + service)
    if not active:
        _fail("没有运行服务；不能用空验收证明日志脱敏通过")
    diagnostics, case_count = _cases(data, active, secrets, start, end)
    found = {service: set() for service in active}
    counts = {}
    for service, filename in active.items():
        count = 0
        try:
            with filename.open("r", encoding="utf-8") as source:
                for line_number, raw in enumerate(source, 1):
                    if not raw.strip():
                        continue
                    if len(raw) > 1024 * 1024:
                        _fail("日志行超过 1 MiB；服务=%s 行=%d" % (service, line_number))
                    try:
                        row = json.loads(raw)
                    except ValueError:
                        _fail("JSONL 日志畸形；服务=%s 行=%d" % (service, line_number))
                    if not isinstance(row, dict) or row.get("service") != service or row.get("environment") != "dev" or row.get("deployment") != expected_deployment:
                        _fail("日志环境/版本/服务元数据不一致；服务=%s 行=%d" % (service, line_number))
                    timestamp = _timestamp(row.get("timestamp"))
                    if not start <= timestamp <= end:
                        _fail("日志超出验收窗口；服务=%s 行=%d" % (service, line_number))
                    if not isinstance(row.get("message"), (str, dict, list)) or not row["message"]:
                        _fail("日志未保留原始 message；服务=%s 行=%d" % (service, line_number))
                    texts = (raw,) + tuple(_text_parts(row))
                    kind = _leaked_kind(texts, secrets)
                    if kind:
                        _fail("发现敏感日志；服务=%s 行=%d 类别=%s" % (service, line_number, kind))
                    for case_number, marker in diagnostics[service]:
                        if any(marker in text for text in _text_parts(row["message"])):
                            found[service].add(case_number)
                    count += 1
        except (OSError, UnicodeError):
            _fail("无法读取完整本地日志；服务=" + service)
        if not count:
            _fail("日志为空；服务=" + service)
        if set(number for number, _ in diagnostics[service]) - found[service]:
            _fail("场景安全诊断未出现在实际日志中；服务=" + service)
        counts[service] = count
    return LogAuditReport(sum(counts.values()), counts, tuple(sorted(excluded)),
                          tuple(sorted(secrets)), case_count)
