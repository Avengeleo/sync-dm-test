"""配置保护与诊断脱敏的本地验证，不连接任何服务。"""

import pytest

from im_test.security_config import load_security_config, SecurityConfigurationError


def test_security_configuration_repr_hides_credentials():
    config = load_security_config({"IM_SECURITY_TOKEN": "private-token-a", "IM_SECURITY_TOKEN2": "private-token-b",
                                   "IM_SECURITY_WS_URL": "wss://localhost/im?key=private-url-token"})
    assert "private" not in repr(config)
    assert "private" not in str(config)
    assert config["token"] == "private-token-a"


@pytest.mark.parametrize("key,value", [("IM_SECURITY_USER_ID", "private-invalid-value"),
                                       ("IM_SECURITY_TIMEOUT", "private-invalid-value"),
                                       ("IM_SECURITY_TCP_URL", "tcp://user:private-invalid-value@localhost:1234")])
def test_invalid_config_diagnostic_does_not_echo_values(key, value):
    with pytest.raises(SecurityConfigurationError) as error:
        load_security_config({key: value})
    assert "private-invalid-value" not in str(error.value)


def test_existing_im_accounts_are_compatible_but_endpoints_require_explicit_config():
    config = load_security_config({"IM_USER_ID": "7", "IM_TOKEN": "test-a", "IM_USER_ID2": "8", "IM_TOKEN2": "test-b",
                                   "IM_HTTP_BASE_URL": "https://localhost/", "IM_CHANNEL_ID": "11"})
    assert config["user_id"] == 7 and config["user_id2"] == 8
    assert config["http_base"] == "" and config["ws_url"] == "" and config["tcp_url"] == ""
    assert config["channel_id"] == 11
    assert not config["target_env"] and not config["allow_login"]


def test_security_endpoints_and_fixed_broadcast_are_explicit():
    config = load_security_config({"IM_SECURITY_WS_URL": "wss://localhost/im",
                                   "IM_SECURITY_TCP_URL": "tcp://localhost:1234",
                                   "IM_SECURITY_HTTP_BASE_URL": "https://localhost/",
                                   "IM_SECURITY_CHANNEL_MESSAGE_ID": "fixed-broadcast",
                                   "IM_SECURITY_BROADCAST_CONFIRMED": "1"})
    assert config["ws_url"] == "wss://localhost/im"
    assert config["tcp_url"] == "tcp://localhost:1234"
    assert config["http_base"] == "https://localhost"
    assert config["channel_message_id"] == "fixed-broadcast" and config["broadcast_confirmed"]
