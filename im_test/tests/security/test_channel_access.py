"""Vuln22 真实 dev 只读回归；不得用鉴权/传输失败冒充非成员拒绝。"""

import re

import pytest

from im_test.security_channel import SecurityChannelClient


@pytest.fixture(params=("v1", "v2"))
def channel_version(request):
    return request.param


def _client(config, second=False):
    return SecurityChannelClient(
        config["http_base"], config["token2" if second else "token"],
        config["user_id2" if second else "user_id"],
        timeout=config["timeout"], client_type=config["client_type"],
    )


def _nonempty_messages(reply, channel_id):
    reply.require_success()
    assert reply.messages, "成员账号未读到正控消息，请检查成员配置和频道数据"
    assert all(message.channel_id == channel_id for message in reply.messages), "正控返回了错误频道"
    assert any(message.content for message in reply.messages), "成员正控缺少非空消息正文"
    return reply.messages


def _prepare_channel_baseline(config, version, record_property):
    # A 独自可见的 targetUsers 消息不能证明 B 原本能读，必须提供可信广播前置。
    if not config.get("channel_message_id"):
        pytest.skip("未配置 IM_SECURITY_CHANNEL_MESSAGE_ID 固定普通广播消息，Vuln22 成员隔离未验证")
    if not config.get("broadcast_confirmed"):
        pytest.skip("未人工确认固定消息是全员普通广播（IM_SECURITY_BROADCAST_CONFIRMED=1），Vuln22 成员隔离未验证")
    record_property("vuln22_broadcast_fixture_confirmed", "true")
    record_property("vuln22_broadcast_evidence", "operator_confirmed_prior_B_read_or_trusted_broadcast_record")
    assert config["user_id"] != config["user_id2"], "Vuln22 需要不同的 A/B 账号"
    channel_id = config["channel_id"]
    fixed_msg_id = config["channel_message_id"]
    member, outsider = _client(config), _client(config, second=True)
    # B 必须先以自己的凭证完成独立鉴权正控，过期 token 的 401 不能当成授权修复通过。
    health = outsider.sessions(version=version).require_success()
    assert not health.sessions, "空频道鉴权正控不应返回会话"
    by_id = member.by_id(channel_id, [fixed_msg_id], version)
    hits = _nonempty_messages(by_id, channel_id)
    assert len(hits) == 1 and hits[0].msg_id == fixed_msg_id, "按 ID 正控未命中配置的固定广播消息"
    assert not by_id.missing, "按 ID 正控错误地报告固定广播消息缺失"
    sample = hits[0]
    assert sample.event_type == 0, "固定广播夹具必须是普通消息，回应不能作为会话列表的广播正控"
    assert re.fullmatch(r"[0-9a-fA-F]{24}", sample.index), "固定广播消息缺少合法 Mongo 游标"
    sessions = member.sessions([channel_id], version).require_success()
    assert sessions.sessions, "成员账号未读到会话正控，请检查配置和频道数据"
    assert all(row.channel_id == channel_id for row in sessions.sessions), "会话正控频道错误"
    assert any(row.last is not None and row.last.content for row in sessions.sessions), "会话正控缺少非空最后消息"
    messages = _nonempty_messages(member.offline(
        [channel_id], version, count=1, base_index=sample.index, is_contain=1
    ), channel_id)
    assert len(messages) == 1 and messages[0].msg_id == fixed_msg_id, "离线正控未命中同一条固定广播消息"
    return member, outsider, sample


@pytest.fixture
def channel_baseline(security_http_enabled, security_config, channel_version, request):
    return _prepare_channel_baseline(
        security_config, channel_version,
        lambda name, value: request.node.user_properties.append((name, value)),
    )


@pytest.mark.parametrize("endpoint", ("sessions", "offline", "by_id"))
@pytest.mark.parametrize("forge_body_uid", (False, True), ids=("own-body-uid", "forged-member-body-uid"))
def test_nonmember_cannot_read_private_channel(
    security_config, channel_version, channel_baseline, endpoint, forge_body_uid
):
    """A 三条端点均有非空正控；B 的请求体声明 A 身份也不能读私密频道。"""
    _, outsider, sample = channel_baseline
    channel_id = security_config["channel_id"]
    body_uid = security_config["user_id"] if forge_body_uid else security_config["user_id2"]
    if endpoint == "sessions":
        reply = outsider.sessions([channel_id], channel_version, body_user_id=body_uid).require_success()
        assert not reply.sessions, "非成员读取到了私密频道会话/最后消息"
    elif endpoint == "offline":
        reply = outsider.offline(
            [channel_id], channel_version, body_user_id=body_uid,
            count=1, base_index=sample.index, is_contain=1,
        ).require_success()
        assert not reply.messages, "非成员读取到了私密频道历史消息"
    else:
        outsider.by_id(channel_id, [sample.msg_id], channel_version, body_user_id=body_uid).require_member_denial()


@pytest.mark.parametrize("endpoint", ("sessions", "offline"))
def test_mixed_channel_request_keeps_only_membership(
    security_config, channel_version, channel_baseline, endpoint
):
    """可选 B 自有频道：同一请求保留 B 有权频道、剔除 A 的私密频道。"""
    _, outsider, _ = channel_baseline
    own_channel = security_config.get("other_channel_id")
    if not own_channel:
        pytest.skip("未配置 B 自有/A 非成员的 other_channel_id，混合频道请求未验证")
    private_channel = security_config["channel_id"]
    assert own_channel != private_channel, "混合正控频道必须与私密目标不同"
    if endpoint == "sessions":
        positive = outsider.sessions([own_channel], channel_version).require_success()
        assert positive.sessions and any(row.last is not None and row.last.content for row in positive.sessions), "B 自有频道缺少非空会话正控"
        assert all(row.channel_id == own_channel for row in positive.sessions), "B 会话正控频道错误"
        reply = outsider.sessions([own_channel, private_channel], channel_version).require_success()
        assert reply.sessions, "混合请求错误地丢弃了 B 有权限频道"
        assert all(row.channel_id == own_channel for row in reply.sessions), "混合请求泄漏了非成员频道会话"
    else:
        _nonempty_messages(outsider.offline([own_channel], channel_version), own_channel)
        reply = outsider.offline([own_channel, private_channel], channel_version).require_success()
        assert reply.messages, "混合请求错误地丢弃了 B 有权限频道消息"
        assert all(row.channel_id == own_channel for row in reply.messages), "混合请求泄漏了非成员频道历史"


def test_offline_single_channel_caps_count_at_100(
    security_config, channel_version, channel_baseline
):
    """先用有界分页证明存在至少 101 条，再验证请求 1000 仍最多返回 100。"""
    member, _, _ = channel_baseline
    channel_id = security_config["channel_id"]
    first = member.offline([channel_id], channel_version, count=100).require_success()
    assert all(message.channel_id == channel_id for message in first.messages), "上限正控频道错误"
    assert len(first.messages) <= 100, "请求 100 条却返回了更多消息"
    if len(first.messages) < 100:
        pytest.skip("频道历史不足 101 条，单页 100 条上限未验证；未发送补数消息")
    assert all(re.fullmatch(r"[0-9a-fA-F]{24}", message.index) for message in first.messages), "缺少合法历史游标，无法证明第 101 条数据"
    oldest = min(message.index for message in first.messages)
    older = member.offline([channel_id], channel_version, count=1, base_index=oldest).require_success()
    assert len(older.messages) <= 1, "有界历史探测返回了超量消息"
    if not older.messages:
        pytest.skip("频道仅能证明 100 条历史，单页上限未验证；未发送补数消息")
    assert older.messages[0].channel_id == channel_id, "历史探测频道错误"
    assert older.messages[0].msg_id not in {message.msg_id for message in first.messages}, "历史探测重复返回游标内消息，未证明存在第 101 条"
    oversized = member.offline([channel_id], channel_version, count=1000).require_success()
    assert oversized.messages, "大 pageSize 请求没有返回成员正控消息"
    assert all(message.channel_id == channel_id for message in oversized.messages), "上限请求频道错误"
    assert len(oversized.messages) <= 100, "单频道请求 count=1000 绕过了 100 条上限"
