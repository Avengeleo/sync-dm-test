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


def _require_deployment(config):
    if config["deployment"] == "unspecified":
        pytest.skip("未配置 IM_SECURITY_DEPLOYMENT 实际部署版本；本轮安全回归未验证")


@pytest.fixture
def security_identity_http_enabled(security_config, request):
    """42/43 共用 HTTP 前置；设备自测不要求 V22 的私密频道。"""
    _require_dev(security_config, request)
    _require_accounts(security_config)
    _require_deployment(security_config)
    if not security_config["http_base"]:
        pytest.skip("缺少 IM_SECURITY_HTTP_BASE_URL；真实环境未验证")
    return security_config


@pytest.fixture
def security_channel_identity_enabled(security_identity_http_enabled, request):
    config = security_identity_http_enabled
    if not config["identity_channel_id"] or not config["identity_message_id"]:
        pytest.skip("缺少 IM_SECURITY_IDENTITY_CHANNEL_ID / IDENTITY_MESSAGE_ID；Vuln42 未验证")
    if config["identity_channel_id"] == config["channel_id"]:
        pytest.fail("Vuln42 双成员专用频道不能复用 Vuln22 非成员频道 P", pytrace=False)
    if not config["identity_fixture_confirmed"]:
        pytest.skip("请先确认 A/B 均为专用频道成员及固定广播夹具，再设置 IM_SECURITY_IDENTITY_FIXTURE_CONFIRMED=1")
    request.node.user_properties.append(("vuln42_fixture_confirmation", "manual_both_members_isolated_channel"))
    return config


@pytest.fixture
def security_channel_identity_write_enabled(security_channel_identity_enabled, request):
    config = security_channel_identity_enabled
    if not config["identity_allow_write"] or not config["identity_state_confirmed"]:
        pytest.skip("Vuln42 状态操作需 IM_SECURITY_IDENTITY_ALLOW_WRITE=1 和 IDENTITY_STATE_CONFIRMED=1；默认不推进游标或确认操作")
    if not config["identity_write_version"]:
        pytest.skip("请选择 IM_SECURITY_IDENTITY_WRITE_VERSION=v1/v2；写用例需分版本重置夹具，不能连续消费同一份状态")
    if config["identity_write_version"] not in ("v1", "v2"):
        pytest.fail("IM_SECURITY_IDENTITY_WRITE_VERSION 必须为 v1 或 v2", pytrace=False)
    request.node.user_properties.append(("vuln42_state_write_confirmation", "manual_isolated_mutable_fixture"))
    return config


@pytest.fixture
def security_device_enabled(security_identity_http_enabled):
    return security_identity_http_enabled


@pytest.fixture
def security_device_kick_enabled(security_device_enabled, request):
    config = security_device_enabled
    if not config["allow_device_kick"]:
        pytest.skip("踢设备会关闭会话并可能使 token 失效；专用设备准备好后设置 IM_SECURITY_ALLOW_DEVICE_KICK=1")
    if not config["device_kick_phase"] or not config["device_kick_version"]:
        pytest.skip("缺少 IM_SECURITY_DEVICE_KICK_PHASE / DEVICE_KICK_VERSION；单次仅选择一个踢设备阶段")
    if config["device_kick_phase"] not in ("forged_uid", "own_uid") or config["device_kick_version"] not in ("v1", "v2"):
        pytest.fail("设备阶段必须为 forged_uid/own_uid，版本必须为 v1/v2", pytrace=False)
    required = ("device_token", "device_token2", "device_observer_token", "device_observer_token2")
    if any(not config[key] for key in required):
        pytest.skip("缺少 IM_SECURITY_DEVICE_TOKEN/TOKEN2 或 DEVICE_OBSERVER_TOKEN/TOKEN2；踢设备未验证")
    if config["device_observer_token"] == config["token"] or config["device_observer_token2"] == config["token2"]:
        pytest.fail("踢设备观察凭证必须与该账号的目标设备登录token不同", pytrace=False)
    request.node.user_properties.append(("vuln43_kick_fixture_confirmation", "manual_isolated_web_devices_and_observers"))
    return config


def pytest_collection_modifyitems(items):
    for item in items:
        if "/im_test/tests/security/" in str(item.fspath).replace("\\", "/"):
            item.add_marker(pytest.mark.im_security)
