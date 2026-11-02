"""为 Vuln42 准备两条定向 @；独立于禁止启用的状态写入/踢设备测试。

默认仅检查本地配置。--prepare 才允许正常 Web 登录和发送至指定专用频道；
--run-tests 仅运行现有 atMessages 的 v1/v2 两项。不会修改任何 .env 文件。
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

from dotenv import dotenv_values

from im_test.security_channel import ChannelRequestError
from im_test.security_channel_identity import _client, _members, _read, _valid_index
from im_test.security_channel_mentions import MentionSendError, send_directed_mention
from im_test.security_config import SecurityConfigurationError, load_security_config
from im_test.security_device import DeviceRequestError, SecurityDeviceClient


ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ("v1", "v2")


class FixtureError(RuntimeError):
    """固定诊断文本；不附带原始请求、响应或账号凭证。"""


class FixtureStateChanging(FixtureError):
    """跨版本读取期间后台正在更新；只允许准备阶段有界等待。"""


def _now():
    return datetime.now(timezone.utc).isoformat()


def load_config(env_file):
    path = Path(env_file)
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise FixtureError("指定的本地配置文件不存在或超过大小限制")
    try:
        # 只读取该文件。继承父进程 IM_SECURITY_TOKEN 会盖过文件里的 IM_TOKEN。
        values = {k: v for k, v in dotenv_values(path, interpolate=False).items() if v is not None}
    except Exception:
        raise FixtureError("读取本地配置失败；不回显文件内容") from None
    values["IM_SECURITY_WS_URL"] = values.get("IM_SECURITY_WS_URL") or values.get("IM_WS_URL", "")
    return load_security_config(values)


def validate_config(config, channel_id):
    if config["target_env"] != "dev":
        raise FixtureError("仅支持明确配置 IM_SECURITY_ENV=dev 的专用测试环境")
    if not config["deployment"] or config["deployment"] == "unspecified":
        raise FixtureError("必须配置 IM_SECURITY_DEPLOYMENT 实际部署版本")
    if any(not config[k] for k in ("http_base", "ws_url", "token", "token2", "user_id", "user_id2")):
        raise FixtureError("缺少 HTTP/WS 地址或 A/B 本人账号凭证")
    if (config["user_id"] == config["user_id2"] or config["token"] == config["token2"]
            or any(not 0 < config[k] < 1 << 63 for k in ("user_id", "user_id2"))):
        raise FixtureError("A/B 必须是不同的合法专用账号，使用各自本人的 token")
    if (not isinstance(channel_id, int) or isinstance(channel_id, bool) or not 0 < channel_id < 1 << 63
            or channel_id != config["identity_channel_id"] or channel_id == config["channel_id"]):
        raise FixtureError("显式频道必须等于配置中的专用频道 R，且不能复用非成员频道 P")
    if not config["identity_fixture_confirmed"] or not re.fullmatch(r"[0-9a-f]{32}", config["identity_message_id"]):
        raise FixtureError("请先确认双方成员及固定普通广播夹具，再配置确认标记和消息 ID")
    if config["identity_allow_write"] or config["identity_state_confirmed"] or config["allow_device_kick"]:
        raise FixtureError("本任务要求频道写测试、状态写入确认和踢设备开关均保持关闭")


def _at_indexes(client, channel_id, version):
    reply = client.at_messages(channel_id, version).require_success()
    if len(reply.at_indexes) != 1 or reply.at_indexes[0].channel_id != channel_id:
        raise FixtureError("@ 索引查询没有返回指定频道的唯一记录")
    indexes = reply.at_indexes[0].indexes
    if any(not _valid_index(index) for index in indexes):
        raise FixtureError("@ 索引查询包含非法游标")
    return sorted(set(indexes))


def snapshot(clients, channel_id):
    by_version = {}
    for version in VERSIONS:
        by_version[version] = {
            label: {"read_index": _read(client, channel_id, version),
                    "at_indexes": _at_indexes(client, channel_id, version)}
            for label, client in zip(("A", "B"), clients)
        }
    if by_version["v1"] != by_version["v2"]:
        raise FixtureStateChanging("v1/v2 状态不一致或被客户端并发消费；请关闭自动读取/ACK 后重试")
    return by_version["v1"]


def fixture_ready(state):
    a, b = state["A"]["at_indexes"], state["B"]["at_indexes"]
    return bool(a and b and a != b)


def _no_online_web(config, label, device_factory):
    second = label == "B"
    uid = config["user_id2" if second else "user_id"]
    client = device_factory(config["http_base"], config["token2" if second else "token"],
                            uid, timeout=config["timeout"])
    # 只读检查，避免普通 Web 登录顶掉尚在线的真实 Web 会话。
    for version in VERSIONS:
        reply = client.device_list(version=version).require_success(uid)
        if any(device.client_type == 2 for device in reply.devices):
            raise FixtureError("专用账号仍有在线 Web 设备；请先在该端正常断开并等待离线，再准备夹具")


def _stored_index(clients, channel_id, msg_id):
    rows = []
    for client in clients:
        reply = client.by_id(channel_id, [msg_id], "v1").require_success()
        if not reply.messages and msg_id in reply.missing:
            return None  # channel-job 异步落库：只轮询读，绝不重发消息。
        if reply.missing or len(reply.messages) != 1:
            raise FixtureError("新 @ 消息的回源正控格式异常")
        row = reply.messages[0]
        if (row.channel_id != channel_id or row.msg_id != msg_id or not row.content
                or row.event_type != 0 or not _valid_index(row.index)):
            raise FixtureError("新 @ 消息没有落为双方可读的非空普通广播")
        rows.append(row)
    if rows[0] != rows[1]:
        raise FixtureError("双方读取的新 @ 消息不一致")
    return rows[0].index


def prepare_fixture(config, channel_id, *, allow_prepare=False, record=None,
                    client_factory=_client, device_factory=SecurityDeviceClient,
                    send=send_directed_mention, wait=time.sleep, clock=time.monotonic,
                    persist=lambda record: None):
    validate_config(config, channel_id)
    clients = (client_factory(config), client_factory(config, True))
    for version in VERSIONS:
        _members(config, version, clients)
    record = record if record is not None else {}
    before = snapshot(clients, channel_id)
    record.update(status="checked", before=before, messages=[])
    persist(record)
    if fixture_ready(before):
        record.update(status="ready_reused", after=before, sent_count=0)
        persist(record)
        return record
    if not allow_prepare:
        raise FixtureError("当前 @ 集合无法区分双方；未指定 --prepare，未登录或发送消息")
    # 两人均先检查；发送每条前再次检查相应槽位。不会调用任何踢设备接口。
    for label in ("A", "B"):
        _no_online_web(config, label, device_factory)
    for label, target in (("A", "B"), ("B", "A")):
        second = label == "B"
        _no_online_web(config, label, device_factory)
        msg_id = uuid.uuid4().hex
        action = {"sender": label, "target": target, "msg_id": msg_id, "status": "sending"}
        record["messages"].append(action)
        record["status"] = "preparing"
        persist(record)  # 先记录 ID；即使 ACK 超时也可按 ID 核对，禁止盲目重发。
        result = send(
            config["ws_url"], config["user_id2" if second else "user_id"],
            config["token2" if second else "token"], channel_id,
            config["user_id" if second else "user_id2"],
            "[selftest][v42-at] %s mentions %s %s" % (label, target, msg_id[:8]),
            app_version=config["app_version"], timeout=config["timeout"],
            device_token="v42-at-" + uuid.uuid4().hex, msg_id=msg_id,
        )
        if (result.msg_id != msg_id or result.channel_id != channel_id
                or result.sender_uid != config["user_id2" if second else "user_id"]
                or result.target_uid != config["user_id" if second else "user_id2"]):
            raise FixtureError("发送结果身份、频道或消息 ID 与预记录夹具不一致")
        action.update(status="acked", ack_index=result.index)
        persist(record)
        # ACK 不保证已经落库，也可能不带 Mongo index；只读轮询确认落库和 @ 索引。
        deadline = clock() + config["timeout"]
        while True:
            index = _stored_index(clients, channel_id, msg_id)
            try:
                state = snapshot(clients, channel_id)
            except FixtureStateChanging:
                state = None  # 异步落库的短暂差异可等待；传输/协议错误仍直接失败。
            if (index and state and index in state[target]["at_indexes"]
                    and state[label]["read_index"] == index):
                if result.index and result.index != index:
                    raise FixtureError("ACK 索引与实际落库索引不一致")
                if index in state[label]["at_indexes"]:
                    raise FixtureError("定向 @ 同时进入发送方索引，不能作为可区分夹具")
                action.update(status="stored", index=index)
                persist(record)
                break
            if clock() >= deadline:
                raise FixtureError("@ 消息未在期限内完成落库及索引准备；已发消息不自动重试或删除")
            wait(0.5)
    after = snapshot(clients, channel_id)
    if not fixture_ready(after):
        raise FixtureError("两条 @ 已发送但双方状态仍不可区分；请检查是否被其他客户端消费")
    for action in record["messages"]:
        if action["index"] not in after[action["target"]]["at_indexes"]:
            raise FixtureError("先前准备的 @ 已被消费；请关闭其他客户端的自动读取/ACK")
    for version in VERSIONS:
        _members(config, version, clients)
    record.update(status="ready_created", after=after, sent_count=len(record["messages"]))
    persist(record)
    return record


def _output_path(value):
    path = (ROOT / value).resolve()
    if (ROOT / ".reports") not in path.parents or path.suffix not in (".json", ".xml"):
        raise FixtureError("输出必须位于本仓库忽略目录 .reports/，使用 JSON 或 XML 文件")
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _save(path, record):
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def run_at_tests(config, xml_path, *, run=subprocess.run):
    child_env = os.environ.copy()
    # 传递此次 --env-file 的解析结果，不让根 conftest 的 .env 选成不同账号/环境。
    for field, name in (
        ("target_env", "ENV"), ("deployment", "DEPLOYMENT"), ("http_base", "HTTP_BASE_URL"),
        ("user_id", "USER_ID"), ("token", "TOKEN"), ("user_id2", "USER_ID2"),
        ("token2", "TOKEN2"), ("channel_id", "CHANNEL_ID"),
        ("identity_channel_id", "IDENTITY_CHANNEL_ID"), ("identity_message_id", "IDENTITY_MESSAGE_ID"),
        ("timeout", "TIMEOUT"), ("client_type", "CLIENT_TYPE"),
    ):
        child_env["IM_SECURITY_" + name] = str(config[field])
    child_env.update(IM_SECURITY_IDENTITY_FIXTURE_CONFIRMED="1", IM_SECURITY_IDENTITY_ALLOW_WRITE="0",
                     IM_SECURITY_IDENTITY_STATE_CONFIRMED="0", IM_SECURITY_ALLOW_DEVICE_KICK="0",
                     IM_SECURITY_IDENTITY_WRITE_VERSION="", PYTEST_ADDOPTS="",
                     PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    nodes = ["im_test/tests/security/test_channel_identity.py::test_at_messages_uses_session_uid[%s]" % v
             for v in VERSIONS]
    # 不复用旧 XML；子进程中途失败不能误读成上一次通过。
    if xml_path.exists():
        xml_path.unlink()
    result = run([sys.executable, "-m", "pytest", *nodes, "-m", "not write", "-q",
                  "-o", "addopts=", "--tb=short", "-o", "junit_family=xunit1",
                  "--junitxml=" + str(xml_path)], cwd=str(ROOT), env=child_env, check=False)
    if result.returncode != 0 or not xml_path.is_file():
        raise FixtureError("atMessages 自测未通过；请查看本轮 XML，不能把未执行或跳过记为通过")
    try:
        cases = list(ET.parse(xml_path).getroot().iter("testcase"))
    except (ET.ParseError, OSError):
        raise FixtureError("本轮 atMessages XML 不完整") from None
    names = {case.get("name") for case in cases}
    if (len(cases) != 2 or names != {"test_at_messages_uses_session_uid[%s]" % v for v in VERSIONS}
            or any(list(case.iter(tag)) for case in cases for tag in ("failure", "error", "skipped"))):
        raise FixtureError("必须是 atMessages v1/v2 两项均通过；跳过、缺项或失败不算通过")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default=".env", help="显式选择云主机配置文件，内容不打印")
    parser.add_argument("--channel-id", required=True, type=int, help="必须与专用频道 R 配置完全一致")
    parser.add_argument("--prepare", action="store_true", help="允许最多两次正常 Web 登录和两条定向 @")
    parser.add_argument("--run-tests", action="store_true", help="只跑 atMessages v1/v2 两个只读测试")
    parser.add_argument("--report", default=".reports/im-security-v42-at-fixture.json")
    parser.add_argument("--junitxml", default=".reports/im-security-v42-at.xml")
    args = parser.parse_args(argv)
    record, report = None, None
    try:
        config = load_config(args.env_file)
        validate_config(config, args.channel_id)
        if not args.prepare and not args.run_tests:
            print("配置检查通过；默认预览未连接服务。使用 --prepare 准备夹具，--run-tests 补跑只读用例。")
            return 0
        report, xml = _output_path(args.report), _output_path(args.junitxml)
        if report == xml or report.suffix != ".json" or xml.suffix != ".xml":
            raise FixtureError("夹具报告须为 JSON，自测报告须为不同的 XML 文件")
        if args.run_tests and xml.exists():
            xml.unlink()  # 准备阶段失败时也不能留下上轮的通过报告冒充本轮。
        record = {"environment": "dev", "deployment": config["deployment"], "channel_id": args.channel_id,
                  "fixed_message_id": config["identity_message_id"], "started_at": _now(),
                  "write_tests_enabled": False, "device_kick_enabled": False,
                  "tests_attempted": False, "tests_run": False}
        persist = lambda value: _save(report, value)
        prepare_fixture(config, args.channel_id, allow_prepare=args.prepare, record=record, persist=persist)
        if args.run_tests:
            record["before_tests"] = snapshot((_client(config), _client(config, True)), args.channel_id)
            record["tests_attempted"] = True
            persist(record)
            run_at_tests(config, xml)
            record["after_tests"] = snapshot((_client(config), _client(config, True)), args.channel_id)
            if record["after_tests"] != record["before_tests"]:
                raise FixtureError("只读自测阶段的已读游标或 @ 集合发生变化；不能计为稳定通过")
            record.update(tests_run=True, tests_passed=2, tests_skipped=0, junitxml=str(xml.relative_to(ROOT)))
        record["finished_at"] = _now()
        persist(record)
        print("夹具已就绪，发送 %d 条消息；写测试、踢设备保持关闭。" % record["sent_count"])
        if args.run_tests:
            print("atMessages：v1、v2 共 2 项通过，0 跳过。")
        print("夹具记录：" + str(report.relative_to(ROOT)))
        return 0
    except (FixtureError, SecurityConfigurationError, ChannelRequestError, DeviceRequestError, MentionSendError) as exc:
        if record is not None and report is not None:
            record.update(status="failed", finished_at=_now(), error=str(exc))
            _save(report, record)
        print("未完成：" + str(exc), file=sys.stderr)
        return 1
    except Exception:
        # 不回显底层网络异常、请求对象或 traceback locals。
        if record is not None and report is not None:
            record.update(status="failed", finished_at=_now(), error="未预期的本地或传输错误，未回显详情")
            _save(report, record)
        print("未完成：本地文件或传输异常；不自动重发，请先核对夹具记录中的消息 ID。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
