"""42/43/47 的配置、测试数据隔离和写操作门禁；全部本地验证。"""

from types import SimpleNamespace

import pytest

from im_test.security_config import load_security_config
from im_test.tests.security import conftest as gates


def _config(**extra):
    env = {
        "IM_SECURITY_ENV": "dev", "IM_SECURITY_DEPLOYMENT": "unit-deployment",
        "IM_SECURITY_HTTP_BASE_URL": "https://unit.invalid",
        "IM_SECURITY_USER_ID": "7", "IM_SECURITY_TOKEN": "unit-token-a",
        "IM_SECURITY_USER_ID2": "8", "IM_SECURITY_TOKEN2": "unit-token-b",
    }
    env.update(extra)
    return load_security_config(env)


def _request():
    return SimpleNamespace(node=SimpleNamespace(user_properties=[]))


def test_p1_defaults_do_not_enable_mutation_or_reuse_private_channel():
    config = load_security_config({"IM_CHANNEL_ID": "11"})
    assert config["channel_id"] == 11
    assert config["identity_channel_id"] == 0
    assert not config["identity_allow_write"] and not config["identity_state_confirmed"]
    assert not config["allow_device_kick"] and not config["log_manifest"]


def test_device_read_gate_does_not_need_vuln22_private_channel():
    config = _config()
    enabled = gates.security_identity_http_enabled.__wrapped__(config, _request())
    assert gates.security_device_enabled.__wrapped__(enabled) is config
    assert not config["channel_id"]


@pytest.mark.parametrize("field,value,exception", (
    ("IM_SECURITY_ENV", "", pytest.skip.Exception),
    ("IM_SECURITY_ENV", "production", pytest.fail.Exception),
    ("IM_SECURITY_DEPLOYMENT", "", pytest.skip.Exception),
    ("IM_SECURITY_HTTP_BASE_URL", "", pytest.skip.Exception),
    ("IM_SECURITY_TOKEN2", "", pytest.skip.Exception),
    ("IM_SECURITY_USER_ID2", "7", pytest.fail.Exception),
))
def test_http_p1_gate_requires_dev_accounts_endpoint_and_deployment(field, value, exception):
    with pytest.raises(exception):
        gates.security_identity_http_enabled.__wrapped__(_config(**{field: value}), _request())


def test_v42_cannot_use_vuln22_nonmember_fixture():
    config = _config(IM_SECURITY_CHANNEL_ID="11", IM_SECURITY_IDENTITY_CHANNEL_ID="11",
                     IM_SECURITY_IDENTITY_MESSAGE_ID="unit-broadcast", IM_SECURITY_IDENTITY_FIXTURE_CONFIRMED="1")
    with pytest.raises(pytest.fail.Exception):
        gates.security_channel_identity_enabled.__wrapped__(config, _request())


@pytest.mark.parametrize("allow,state,version", (("0", "0", "v1"), ("1", "0", "v1"),
                                                ("0", "1", "v1"), ("1", "1", "")))
def test_v42_writes_need_both_confirmations_and_selected_version(allow, state, version):
    config = _config(IM_SECURITY_IDENTITY_ALLOW_WRITE=allow, IM_SECURITY_IDENTITY_STATE_CONFIRMED=state,
                     IM_SECURITY_IDENTITY_WRITE_VERSION=version)
    with pytest.raises(pytest.skip.Exception):
        gates.security_channel_identity_write_enabled.__wrapped__(config, _request())


def test_v42_write_version_must_be_explicit_protocol_version():
    config = _config(IM_SECURITY_IDENTITY_ALLOW_WRITE="1", IM_SECURITY_IDENTITY_STATE_CONFIRMED="1",
                     IM_SECURITY_IDENTITY_WRITE_VERSION="unit-sensitive-invalid")
    with pytest.raises(pytest.fail.Exception) as failure:
        gates.security_channel_identity_write_enabled.__wrapped__(config, _request())
    assert "unit-sensitive-invalid" not in str(failure.value)


def _kick_config(**extra):
    env = {
        "IM_SECURITY_ALLOW_DEVICE_KICK": "1", "IM_SECURITY_DEVICE_KICK_PHASE": "forged_uid",
        "IM_SECURITY_DEVICE_KICK_VERSION": "v1", "IM_SECURITY_DEVICE_TOKEN": "unit-device-a",
        "IM_SECURITY_DEVICE_TOKEN2": "unit-device-b", "IM_SECURITY_DEVICE_OBSERVER_TOKEN": "unit-observer-a",
        "IM_SECURITY_DEVICE_OBSERVER_TOKEN2": "unit-observer-b",
    }
    env.update(extra)
    return _config(**env)


@pytest.mark.parametrize("field", ("IM_SECURITY_ALLOW_DEVICE_KICK", "IM_SECURITY_DEVICE_KICK_PHASE",
                                    "IM_SECURITY_DEVICE_KICK_VERSION", "IM_SECURITY_DEVICE_TOKEN",
                                    "IM_SECURITY_DEVICE_TOKEN2", "IM_SECURITY_DEVICE_OBSERVER_TOKEN",
                                    "IM_SECURITY_DEVICE_OBSERVER_TOKEN2"))
def test_kick_never_starts_without_complete_explicit_fixture(field):
    config = _kick_config(**{field: ""})
    with pytest.raises(pytest.skip.Exception):
        gates.security_device_kick_enabled.__wrapped__(config, _request())


@pytest.mark.parametrize("field,value", (("IM_SECURITY_DEVICE_KICK_PHASE", "unit-secret-invalid"),
                                         ("IM_SECURITY_DEVICE_KICK_VERSION", "unit-secret-invalid"),
                                         ("IM_SECURITY_DEVICE_OBSERVER_TOKEN", "unit-token-a"),
                                         ("IM_SECURITY_DEVICE_OBSERVER_TOKEN2", "unit-token-b")))
def test_invalid_kick_fixture_fails_without_echoing_values(field, value):
    with pytest.raises(pytest.fail.Exception) as failure:
        gates.security_device_kick_enabled.__wrapped__(_kick_config(**{field: value}), _request())
    assert value not in str(failure.value)


def test_observer_credentials_and_manifest_path_stay_out_of_repr():
    config = _kick_config(IM_SECURITY_LOG_MANIFEST="/unit/private-log-marker/manifest.json")
    assert "unit-observer" not in repr(config)
    assert "private-log-marker" not in str(config)
    assert gates.security_device_kick_enabled.__wrapped__(config, _request()) is config
