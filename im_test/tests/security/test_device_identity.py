"""Vuln43 dev 回归：默认只读；kick 必须手工分阶段准备专用 Web 设备。"""

import time

import pytest

from im_test.security_device import DeviceRequestError, SecurityDeviceClient


def _invoke(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except DeviceRequestError as exc:
        pytest.fail(str(exc), pytrace=False)


def _check(condition, message):
    if not condition:
        pytest.fail(message, pytrace=False)


def _client(config, second=False, observer=False):
    suffix = "2" if second else ""
    key = "device_observer_token" + suffix if observer else "token" + suffix
    return _invoke(SecurityDeviceClient, config["http_base"], config[key],
                   config["user_id" + suffix], timeout=config["timeout"])


def _owned_devices(client, version, body_uid=None, nonempty=True):
    result = _invoke(client.device_list, body_user_id=body_uid, version=version)
    return _invoke(result.require_success, client.user_id, nonempty=nonempty)


def _binding_case(config, version):
    a, b = _client(config), _client(config, second=True)
    a_before = _owned_devices(a, version).fingerprints()
    b_before = _owned_devices(b, version).fingerprints()
    _check(a_before != b_before, "A/B 设备内容指纹无法区分；需要不同的在线设备夹具")
    a_forged = _owned_devices(a, version, b.user_id).fingerprints()
    b_forged = _owned_devices(b, version, a.user_id).fingerprints()
    a_after = _owned_devices(a, version).fingerprints()
    b_after = _owned_devices(b, version).fingerprints()
    _check(a_before == a_after and b_before == b_after,
           "在线设备夹具在验证期间变化，不能确认身份隔离")
    _check(a_forged == a_before and b_forged == b_before,
           "异 UID 请求未返回当前认证账号的设备内容")


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_device_list_is_bound_to_authenticated_account(security_device_enabled, version, request):
    request.node.user_properties.append(("device_case", "read_only_nonempty_account_binding"))
    _binding_case(security_device_enabled, version)


def _kick_preconditions(config, version, phase):
    if not config.get("allow_device_kick"):
        pytest.skip("踢设备未显式开启；写入隔离未验证")
    if config.get("device_kick_version") not in ("v1", "v2") or config.get("device_kick_phase") not in ("forged_uid", "own_uid"):
        pytest.fail("已开启踢设备，但版本或阶段配置不合法", pytrace=False)
    if config.get("device_kick_version") != version or config.get("device_kick_phase") != phase:
        pytest.skip("手工分阶段 kick：此次未选择该版本和阶段；此项未验证")
    required = ("device_token", "device_token2", "device_observer_token", "device_observer_token2")
    if any(not config.get(key) for key in required):
        pytest.skip("缺少专用 Web 目标设备或独立观察凭证；踢设备未验证")
    _check(config["device_observer_token"] != config["token"]
           and config["device_observer_token2"] != config["token2"],
           "观察凭证必须独立于对应的 Web 目标设备登录凭证")


def _target(reply, token):
    matches = [d for d in reply.devices if d.client_type == 2 and d.device_token == token]
    _check(len(matches) == 1, "配置的专用 Web 目标设备未在线，不能执行踢设备回归")
    return matches[0].fingerprint()


def _kick_case(config, version, phase, request):
    _kick_preconditions(config, version, phase)
    request.node.user_properties.extend([
        ("device_kick_version", version), ("device_kick_phase", phase),
        ("device_kick_target_slot", "Web:2"),
        ("target_token_device_mapping", "operator_confirmed"),
        ("device_observation", "HTTP_device_record_and_target_B_token_health"),
    ])
    a, b = _client(config), _client(config, second=True)
    observe_a = _client(config, observer=True)
    observe_b = _client(config, second=True, observer=True)
    a_before = _owned_devices(a, version)
    b_before = _owned_devices(b, version)
    target_a = _target(a_before, config["device_token"])
    target_b = _target(b_before, config["device_token2"])
    _check(target_a in _owned_devices(observe_a, version).fingerprints()
           and target_b in _owned_devices(observe_b, version).fingerprints(),
           "独立观察凭证未看到同一组专用目标设备")

    forged = phase == "forged_uid"
    result = _invoke(a.kick, config["device_token2"] if forged else config["device_token"],
                     body_user_id=b.user_id if forged else a.user_id, client_type=2,
                     version=version, confirm=True)
    _invoke(result.require_success)

    # 负向也可能按绑定后的 A UID 踢掉 A 自己，因此后续只使用独立 A 观察凭证。
    # 每次 B 观察都同时验证其目标登录 token 仍能通过当前鉴权，不能仅看残留记录。
    observe_until = time.monotonic() + 2
    deadline = time.monotonic() + max(3, min(10, config["timeout"]))
    a_removed = False
    while True:
        b_target_view = _owned_devices(b, version)
        b_observer_view = _owned_devices(observe_b, version)
        _check(target_b in b_target_view.fingerprints() and target_b in b_observer_view.fingerprints(),
               "B 目标凭证或设备未保持存活；发现跨账号踢线或夹具异常")
        current_a = _owned_devices(observe_a, version, nonempty=False)
        a_removed = target_a not in current_a.fingerprints()
        now = time.monotonic()
        if now >= observe_until and (forged or a_removed):
            break
        _check(now < deadline, "A 本人正常踢设备后，独立观察端仍看到目标在线")
        time.sleep(0.25)
    if not forged:
        _check(a_removed, "A 本人正常踢设备没有移除专用目标")


@pytest.mark.write
@pytest.mark.parametrize("version", ["v1", "v2"])
@pytest.mark.parametrize("phase", ["forged_uid", "own_uid"])
def test_device_kick_manual_prepared_phase(security_device_kick_enabled, version, phase, request):
    _kick_case(security_device_kick_enabled, version, phase, request)


@pytest.mark.write
@pytest.mark.parametrize("transport", ["tcp", "ws"])
def test_push_token_sync_real_persistence_requires_manual_verification(transport):
    pytest.skip("%s PushTokenSync 本期仅覆盖协议编解码；真实写入、B 持久化观察和原 token 恢复尚未验证，须按文档人工补验" % transport)
