"""只在显式选择 dev、配置专用账号后运行真实安全回归。"""

import pytest

from im_test.security_config import load_security_config, SecurityConfigurationError


@pytest.fixture(scope="session")
def security_config():
    try:
        return load_security_config()
    except SecurityConfigurationError as exc:
        pytest.fail(str(exc), pytrace=False)


def _require_dev(config, request):
    if not config["target_env"]:
        pytest.skip("未配置 IM_SECURITY_ENV=dev；真实环境未验证")
    if config["target_env"] != "dev":
        pytest.fail("本套件仅授权测试 dev，IM_SECURITY_ENV 必须为 dev", pytrace=False)
    request.node.user_properties.extend([
        ("target_environment", "dev"),
        ("deployment_version", config["deployment"]),
    ])


def _require_accounts(config):
    names = {"user_id": "IM_SECURITY_USER_ID / IM_USER_ID", "token": "IM_SECURITY_TOKEN / IM_TOKEN",
             "user_id2": "IM_SECURITY_USER_ID2 / IM_USER_ID2", "token2": "IM_SECURITY_TOKEN2 / IM_TOKEN2"}
    missing = [label for key, label in names.items() if not config[key]]
    if missing:
        pytest.skip("缺少专用测试配置：" + ", ".join(missing) + "；真实环境未验证")
    if config["user_id"] == config["user_id2"] or config["token"] == config["token2"]:
        pytest.fail("A/B 必须是不同测试账号，并各自使用本人的有效 token", pytrace=False)


@pytest.fixture
def security_login_enabled(security_config, request):
    _require_dev(security_config, request)
    _require_accounts(security_config)
    if not security_config["allow_login"]:
        pytest.skip("登录会修改会话并可能踢线；专用账号准备好后设置 IM_SECURITY_ALLOW_LOGIN=1")
    return security_config


@pytest.fixture
def security_http_enabled(security_config, request):
    _require_dev(security_config, request)
    _require_accounts(security_config)
    if not security_config["http_base"] or not security_config["channel_id"]:
        pytest.skip("缺少 IM_SECURITY_HTTP_BASE_URL / IM_SECURITY_CHANNEL_ID；真实环境未验证")
    return security_config


def pytest_collection_modifyitems(items):
    for item in items:
        if "/im_test/tests/security/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(pytest.mark.im_security)
