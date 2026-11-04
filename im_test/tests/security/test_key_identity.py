"""Vuln45 marker 专用写测；不等同于真实密钥交换或加解密验收。"""

import pytest

from im_test.security_key_identity import (
    PRIVATE_COMMANDS, KeyIdentityBlocked, KeyIdentityError, check_group_key_identity,
    check_group_nonmember_identity, check_private_key_forgery, check_private_key_positive,
)
from im_test.security_wire import SecurityWireError, uid


def _run(probe, config, request, *args):
    report = {"scope": "vuln45_identity_only", "transport": "ws", "key_material": "opaque_test_marker_only"}
    for key in ("user_id", "user_id2", "key_group_id"):
        if uid(config.get(key)):
            report[key] = config[key]
    try:
        probe(config, *args, report=report)
    except KeyIdentityBlocked as exc:
        report["verification_status"] = "blocked"
        pytest.skip(str(exc))
    except (KeyIdentityError, SecurityWireError) as exc:
        report["verification_status"] = "failed"
        pytest.fail(str(exc), pytrace=False)
    except Exception:
        report["verification_status"] = "failed"
        pytest.fail("Vuln45 探测异常停止；不展示底层异常、凭证、正文或密钥，不自动重试", pytrace=False)
    finally:
        request.node.user_properties.extend(("vuln45_" + key, value) for key, value in sorted(report.items()))


@pytest.mark.write
def test_group_key_exchange_binds_session_identity(security_key_identity_enabled, request):
    _run(check_group_key_identity, security_key_identity_enabled, request)


@pytest.mark.write
def test_group_key_exchange_rejects_nonmember_target(security_key_identity_enabled, request):
    _run(check_group_nonmember_identity, security_key_identity_enabled, request)


@pytest.mark.write
@pytest.mark.parametrize("command", PRIVATE_COMMANDS, ids=lambda command: "opcode-%d" % command)
def test_private_key_same_account_marker_positive(security_key_identity_enabled, command, request):
    _run(check_private_key_positive, security_key_identity_enabled, request, command)


@pytest.mark.write
@pytest.mark.parametrize("command", PRIVATE_COMMANDS, ids=lambda command: "opcode-%d" % command)
def test_private_key_forgery_requires_explicit_rejection(security_key_identity_enabled, command, request):
    _run(check_private_key_forgery, security_key_identity_enabled, request, command)
