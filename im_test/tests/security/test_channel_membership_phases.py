"""Vuln22 成员变更的手工阶段回归；本文件只读，不执行退出、重入或消息 ACK。

使用专用频道 C 和同一条正常广播消息，人工按 member_warm → 退出 B →
after_quit → 重新加入 B → rejoined 分别执行。一次执行只证明所选阶段，
缺少其他阶段不等于完整生命周期通过。固定消息须仍为 C 中双方可见的最新消息。
"""

import re

import pytest

from im_test.security_channel import SecurityChannelClient


_PHASES = ("member_warm", "after_quit", "rejoined")


def _require(condition, message):
    # 不让 pytest 的表达式展开或错误报告带出消息正文、完整响应或客户端凭证。
    if not condition:
        pytest.fail(message, pytrace=False)


def _client(config, second=False):
    return SecurityChannelClient(
        config["http_base"], config["token2" if second else "token"],
        config["user_id2" if second else "user_id"],
        timeout=config.get("http_timeout", config.get("timeout", 10)),
        client_type=config.get("client_type", 2),
    )


def _record_reply(record_property, endpoint, reply):
    record_property(endpoint + "_http", reply.http_status)
    record_property(endpoint + "_errcode", reply.errcode)
    record_property(endpoint + "_message_count", len(reply.messages))
    record_property(endpoint + "_session_count", len(reply.sessions))


def _known_message(client, channel_id, message_id, version):
    reply = client.by_id(channel_id, [message_id], version=version).require_success()
    _require(not reply.missing and len(reply.messages) == 1,
             "已知广播消息正控未命中；不能以空频道或不可见消息证明访问控制通过")
    known = reply.messages[0]
    _require(known.channel_id == channel_id and known.msg_id == message_id,
             "已知广播消息正控的频道或消息 ID 不一致")
    _require(bool(known.content), "已知广播消息正文为空，不能作为本次可见性正控")
    _require(known.event_type == 0, "固定广播必须是普通消息，回应不能作为成员会话正控")
    _require(bool(re.fullmatch(r"[0-9a-fA-F]{24}", known.index)),
             "已知广播消息缺少有效游标，无法执行有界离线回归")
    return reply, known


@pytest.mark.parametrize("version", ["v1", "v2"])
@pytest.mark.parametrize("phase", _PHASES)
def test_channel_membership_manual_phase(
        security_http_enabled, security_config, record_property, version, phase):
    config = security_config
    record_property("membership_phase", phase)
    record_property("channel_api_version", version)
    record_property("membership_chain_complete", False)

    selected = config.get("membership_phase", "")
    if not selected:
        pytest.skip("未选择成员变更手工阶段；退群/重入整链尚未验证")
    _require(selected in _PHASES, "成员变更阶段必须为 member_warm、after_quit 或 rejoined")
    if selected != phase:
        pytest.skip("本次未选择此手工阶段；该阶段不计为通过")

    channel_id = config.get("lifecycle_channel_id")
    message_id = config.get("lifecycle_message_id", "")
    if not channel_id or not message_id:
        pytest.skip("缺少专用生命周期频道或固定广播消息；此阶段和整链尚未验证")
    _require(isinstance(channel_id, int) and channel_id > 0,
             "生命周期频道必须为有效正整数")
    _require(channel_id != config.get("channel_id"),
             "生命周期频道 C 必须独立于普通越权测试的私密目标频道")
    _require(config["user_id"] != config["user_id2"],
             "成员变更回归必须使用两个不同的专用账号")
    record_property("lifecycle_channel_id", channel_id)

    owner, member = _client(config), _client(config, second=True)
    # 空频道请求只检查真实 HTTP 鉴权，不改成员或已读状态。失效 token 必须失败。
    owner.health(version=version).require_success()
    member.health(version=version).require_success()
    # 即使 B 已退出，A 也必须仍能读同频道、同消息，避免不存在的数据假通过。
    _owner_reply, known = _known_message(owner, channel_id, message_id, version)

    if phase == "after_quit":
        # 每个入口立即请求一次；不轮询至迟早拒绝，不接受中间泄漏后最终空响应。
        sessions = member.sessions([channel_id], version=version)
        _record_reply(record_property, "sessions", sessions)
        sessions.require_success()
        _require(not sessions.sessions and not sessions.messages and not sessions.missing,
                 "退群后 sessions 仍返回频道 C 的会话或消息")

        offline = member.offline(
            [channel_id], version=version, count=1,
            base_index=known.index, is_contain=1,
        )
        _record_reply(record_property, "offline", offline)
        offline.require_success()
        _require(not offline.messages and not offline.sessions and not offline.missing,
                 "退群后 offlineMessages 仍返回频道 C 的历史消息")

        by_id = member.by_id(channel_id, [message_id], version=version)
        _record_reply(record_property, "by_id", by_id)
        by_id.require_member_denial()
        record_property("membership_assertion", "denied")
    else:
        by_id, visible = _known_message(member, channel_id, message_id, version)
        _record_reply(record_property, "by_id", by_id)
        _require(visible.index == known.index and visible.content == known.content,
                 "A/B 的固定广播消息不一致，请使用双方可见的正常广播消息")

        sessions = member.sessions([channel_id], version=version)
        _record_reply(record_property, "sessions", sessions)
        sessions.require_success()
        _require(len(sessions.sessions) == 1,
                 "成员 sessions 未返回唯一频道 C 的正控会话")
        session = sessions.sessions[0]
        _require(session.channel_id == channel_id and session.last is not None,
                 "成员 sessions 未返回频道 C 的最新消息")
        _require(session.last.msg_id == message_id and session.last.content == known.content,
                 "成员 sessions 最新消息与固定广播消息不一致；请保持专用频道无其他新消息")

        offline = member.offline(
            [channel_id], version=version, count=1,
            base_index=known.index, is_contain=1,
        )
        _record_reply(record_property, "offline", offline)
        offline.require_success()
        _require(len(offline.messages) == 1,
                 "成员 offlineMessages 未返回游标锚定的固定广播消息")
        message = offline.messages[0]
        _require(message.channel_id == channel_id and message.msg_id == message_id
                 and message.content == known.content,
                 "成员 offlineMessages 与固定广播消息不一致")
        record_property("membership_assertion", "allowed")

    record_property("membership_endpoints_checked", 3)
