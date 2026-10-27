"""Vuln20 真实 dev 回归：需要专用账号，登录会更新会话并可能踢线。"""

import pytest

from im_test.security_login import ERR_LOGIN_AUTH, NON_ERR, login_once


pytestmark = pytest.mark.write


def _login(config, transport, endpoint, uid, token):
    return login_once(
        endpoint, uid, token, transport=transport,
        client_type=config["client_type"], timeout=config["timeout"],
        app_version=config["app_version"],
    )


def _require_success(ack, uid, label):
    assert ack.error_code == NON_ERR, (
        f"{label} 正控登录失败，错误码=0x{ack.error_code:04x}；"
        "无效/过期 token 或服务异常不能作为漏洞已修复的证据"
    )
    assert ack.user_id == uid, f"{label} 成功 ACK 的 UID 与账号不一致"


@pytest.mark.parametrize("transport", ["ws", "tcp"])
def test_login_token_cannot_impersonate_other_uid(
        security_login_enabled, security_config, transport):
    config = security_config
    endpoint = config.get("ws_url" if transport == "ws" else "tcp_url")
    if not endpoint:
        pytest.skip(f"未配置 {transport.upper()} 登录入口")
    if not config.get("user_id") or not config.get("token"):
        pytest.skip("未配置 dev 专用账号 A")
    if not config.get("user_id2") or not config.get("token2"):
        pytest.skip("未配置 dev 专用账号 B")
    uid_a, uid_b = config["user_id"], config["user_id2"]
    assert uid_a != uid_b, "Vuln20 回归必须使用两个不同的 dev 专用账号"

    # 前后都确认 A token 有效，防止过期凭证让负向请求假通过。
    _require_success(_login(config, transport, endpoint, uid_a, config["token"]), uid_a, "账号 A")
    _require_success(_login(config, transport, endpoint, uid_b, config["token2"]), uid_b, "账号 B")
    forged = _login(config, transport, endpoint, uid_b, config["token"])
    assert forged.error_code == ERR_LOGIN_AUTH, (
        f"A token + B UID 必须明确返回 ERR_LOGIN_AUTH(0x8101)，"
        f"实际错误码=0x{forged.error_code:04x}；断连、超时或其他错误码不算通过"
    )
    _require_success(_login(config, transport, endpoint, uid_a, config["token"]), uid_a, "账号 A 复核")
