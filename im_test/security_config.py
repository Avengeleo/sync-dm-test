"""安全回归专用配置；配置对象的 repr 不显示地址、账号或凭证。"""

import math
import os
from urllib.parse import urlsplit


class SecurityConfigurationError(ValueError):
    pass


class SecurityConfig(dict):
    def __repr__(self):
        return "SecurityConfig(<配置值已隐藏>)"

    __str__ = __repr__


def load_security_config(environ=None):
    env = os.environ if environ is None else environ

    def value(*names, default=""):
        for name in names:
            text = env.get(name, "").strip()
            if text and not text.startswith("#"):
                return text
        return default

    def integer(name, fallback=None, default=0):
        raw = value(name, *([fallback] if fallback else []), default=str(default))
        try:
            result = int(raw)
        except ValueError:
            raise SecurityConfigurationError(name + " 必须为整数") from None
        if result < 0:
            raise SecurityConfigurationError(name + " 不能为负数")
        return result

    try:
        timeout = float(value("IM_SECURITY_TIMEOUT", "IM_TIMEOUT", default="10"))
    except ValueError:
        raise SecurityConfigurationError("IM_SECURITY_TIMEOUT 必须为正数") from None
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 120:
        raise SecurityConfigurationError("IM_SECURITY_TIMEOUT 必须在 0 到 120 秒之间")

    config = SecurityConfig(
        target_env=value("IM_SECURITY_ENV").lower(),
        deployment=value("IM_SECURITY_DEPLOYMENT", default="unspecified"),
        ws_url=value("IM_SECURITY_WS_URL"),
        tcp_url=value("IM_SECURITY_TCP_URL"),
        http_base=value("IM_SECURITY_HTTP_BASE_URL").rstrip("/"),
        user_id=integer("IM_SECURITY_USER_ID", "IM_USER_ID"),
        token=value("IM_SECURITY_TOKEN", "IM_TOKEN"),
        user_id2=integer("IM_SECURITY_USER_ID2", "IM_USER_ID2"),
        token2=value("IM_SECURITY_TOKEN2", "IM_TOKEN2"),
        channel_id=integer("IM_SECURITY_CHANNEL_ID", "IM_CHANNEL_ID"),
        channel_message_id=value("IM_SECURITY_CHANNEL_MESSAGE_ID"),
        broadcast_confirmed=value("IM_SECURITY_BROADCAST_CONFIRMED") == "1",
        other_channel_id=integer("IM_SECURITY_OTHER_CHANNEL_ID"),
        lifecycle_channel_id=integer("IM_SECURITY_LIFECYCLE_CHANNEL_ID"),
        lifecycle_message_id=value("IM_SECURITY_LIFECYCLE_MESSAGE_ID"),
        membership_phase=value("IM_SECURITY_MEMBERSHIP_PHASE"),
        client_type=integer("IM_SECURITY_CLIENT_TYPE", "IM_CLIENT_TYPE", default=2),
        timeout=timeout,
        app_version=value("IM_SECURITY_APP_VERSION", "IM_NEW_APP_VERSION", default="9.9.9"),
        allow_login=value("IM_SECURITY_ALLOW_LOGIN") == "1",
    )
    for key, schemes in (
        ("ws_url", {"ws", "wss"}),
        ("tcp_url", {"tcp", "tls"}),
        ("http_base", {"http", "https"}),
    ):
        if not config[key]:
            continue
        try:
            parsed = urlsplit(config[key])
            valid = parsed.scheme in schemes and bool(parsed.hostname)
            valid = valid and parsed.username is None and parsed.password is None
            valid = valid and parsed.fragment == ""
            if key == "tcp_url":
                valid = valid and parsed.port is not None and parsed.path in ("", "/") and not parsed.query
        except ValueError:
            valid = False
        if not valid:
            raise SecurityConfigurationError(key + " 地址格式不正确（不显示原值）")
    if config["client_type"] not in (0, 1, 2):
        raise SecurityConfigurationError("IM_SECURITY_CLIENT_TYPE 只能为 0、1、2")
    return config
