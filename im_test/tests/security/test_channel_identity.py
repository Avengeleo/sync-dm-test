"""Vuln42 真实 dev 差异回归。专用共享频道与 Vuln22 非成员频道分开配置。"""

import pytest

from im_test.security_channel_identity import (
    IdentityFixtureUnavailable, check_at_messages_identity, check_operations_identity,
    check_read_indexes_identity, check_update_read_index_identity, check_verify_operations_identity,
)


@pytest.fixture(params=("v1", "v2"))
def identity_version(request):
    return request.param


def _run(probe, config, version, request, **kwargs):
    request.node.user_properties.extend([
        ("vuln42_channel_fixture", "dedicated_shared_channel_both_members_confirmed"),
        ("vuln42_version", version),
    ])
    try:
        probe(config, version, **kwargs)
    except IdentityFixtureUnavailable as exc:
        pytest.skip(str(exc))


def _write_version(config, version):
    if config.get("identity_write_version") != version:
        pytest.skip("状态探测每次仅运行显式选择的 IM_SECURITY_IDENTITY_WRITE_VERSION；另一版本需重新预置")


def test_read_indexes_uses_session_uid(security_channel_identity_enabled, identity_version, request):
    _run(check_read_indexes_identity, security_channel_identity_enabled, identity_version, request)


def test_at_messages_uses_session_uid(security_channel_identity_enabled, identity_version, request):
    _run(check_at_messages_identity, security_channel_identity_enabled, identity_version, request)


@pytest.mark.write
@pytest.mark.parametrize("all_channels", (False, True), ids=("oprMessage", "oprMessages"))
def test_operation_reads_use_session_uid(
    security_channel_identity_write_enabled, identity_version, all_channels, request,
):
    # 两个读取接口可能初始化 oper_index；不能标为只读。
    _write_version(security_channel_identity_write_enabled, identity_version)
    request.node.user_properties.append(("state_side_effect", "operation_read_may_initialize_cursor"))
    _run(check_operations_identity, security_channel_identity_write_enabled, identity_version, request,
         all_channels=all_channels)


@pytest.mark.write
def test_read_index_update_changes_only_session_owner(
    security_channel_identity_write_enabled, identity_version, request,
):
    _write_version(security_channel_identity_write_enabled, identity_version)
    request.node.user_properties.append(("state_side_effect", "A_read_index_advances_and_mentions_may_be_removed_no_automatic_rollback"))
    _run(check_update_read_index_identity, security_channel_identity_write_enabled, identity_version, request)


@pytest.mark.write
def test_operation_ack_does_not_consume_forged_owner(
    security_channel_identity_write_enabled, identity_version, request,
):
    _write_version(security_channel_identity_write_enabled, identity_version)
    request.node.user_properties.append(("state_side_effect", "A_pending_operations_consumed_no_automatic_rollback_reseed_per_version"))
    _run(check_verify_operations_identity, security_channel_identity_write_enabled, identity_version, request)
