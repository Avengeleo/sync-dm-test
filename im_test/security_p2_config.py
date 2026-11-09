"""P2 专项配置与门禁；不读取/恢复凭证，不改其他安全套件许可。"""
import os
import re
import time

from im_test.security_config import load_security_config
from im_test.security_device import SecurityDeviceClient


class P2Error(AssertionError):
    """固定诊断，不携带原始网络异常、凭证或响应正文。"""


class P2Blocked(RuntimeError):
    """缺少夹具、实际参数或证据；不能计作通过。"""


def require(condition, message):
    if not condition:
        raise P2Error(message)


def load_p2_config(environ=None):
    env = os.environ if environ is None else environ
    config = load_security_config(env)
    def integer(key):
        try:
            value = int(env.get(key, "") or "0")
        except (ValueError, TypeError):
            raise P2Error("P2 数值配置格式错误") from None
        require(0 <= value < 1 << 63, "P2 数值配置超出边界")
        return value
    config.update(
        p2_allow_write=env.get("IM_SECURITY_P2_ALLOW_WRITE") == "1",
        p2_confirmed=env.get("IM_SECURITY_P2_FIXTURE_CONFIRMED") == "1",
        p2_group=integer("IM_SECURITY_P2_GROUP_ID"),
        p2_owner=integer("IM_SECURITY_P2_GROUP_OWNER_UID"),
        p2_other_group=integer("IM_SECURITY_P2_OTHER_GROUP_ID"),
        p2_version=env.get("IM_SECURITY_P2_HTTP_VERSION", ""),
        p2_transport=env.get("IM_SECURITY_P2_TRANSPORT", ""),
        p2_frame_limit=integer("IM_SECURITY_P2_MAX_FRAME_BYTES"),
        p2_rate=integer("IM_SECURITY_P2_CMD_LIMIT_RATE"),
        p2_log_manifest=env.get("IM_SECURITY_P2_SQL_MANIFEST", ""),
    )
    return config


def require_live(config, suite):
    if config["target_env"] != "dev":
        raise P2Blocked("P2 真实自测只授权 dev；未连接环境")
    version = config["deployment"]
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", version)
            or version.lower() in ("unspecified", "latest", "placeholder")):
        raise P2Blocked("缺少已确认的实际 P2 部署版本；不沿用旧版标记")
    if not config["p2_allow_write"] or not config["p2_confirmed"]:
        raise P2Blocked("P2 登录/写入许可与专用夹具未同时确认")
    required = ["http_base", "user_id", "token"]
    if suite == "85":
        required += ["ws_url", "user_id2", "token2", "p2_group", "p2_owner"]
    else:
        require(config["p2_transport"] in ("ws", "tcp"), "请明确选择 WS 或 TCP")
        required += [config["p2_transport"] + "_url"]
    if any(not config[k] for k in required):
        raise P2Blocked("缺少 P2 专用账号、地址或普通群配置；不自动准备账号")
    require(config["client_type"] == 2, "P2 仅使用专用 Web 槽位，不模拟真实 App")
    if suite == "85":
        require(config["user_id"] != config["user_id2"] and config["token"] != config["token2"], "A/B 必须是不同专用账号")
        require(config["p2_owner"] == config["user_id"], "85 夹具要求 A 是群主、B 是普通成员")
        require(config["p2_version"] in ("v1", "v2"), "85 一次只运行 v1 或 v2")
        excluded = {config["channel_id"], config["identity_channel_id"], config["other_channel_id"]} - {0}
        require(config["p2_group"] not in excluded and config["p2_other_group"] not in excluded,
                "P2 普通群不能复用既有频道 P/Q/R")
        require(not config["p2_other_group"] or config["p2_other_group"] != config["p2_group"], "跨群夹具必须是另一个已授权普通群")


def idle_accounts(config, suite, client_factory=SecurityDeviceClient, clock=time.monotonic, sleep=time.sleep):
    """有界等待前一脚本断开；不踢设备、不刷新 token。"""
    for suffix in (("", "2") if suite == "85" else ("",)):
        try:
            c = client_factory(config["http_base"], config["token" + suffix], config["user_id" + suffix], timeout=config["timeout"])
            deadline = clock() + min(3, config["timeout"])
            while True:
                reply = c.device_list(version="v1").require_success(c.user_id, nonempty=False)
                if not reply.devices:
                    break
                if clock() >= deadline:
                    raise P2Blocked("P2 专用账号仍有在线设备；请正常断开，不调用踢设备")
                sleep(min(.25, max(0, deadline - clock())))
        except P2Blocked:
            raise
        except Exception:
            raise P2Blocked("P2 设备/鉴权前置不可读；不重试失效 token") from None
