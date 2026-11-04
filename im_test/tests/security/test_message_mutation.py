"""Vuln44 真实 dev 回归；每项只修改当次正常协议新建的普通单聊消息。"""

import pytest

from im_test.security_message_mutation import CASES, MessageMutationError, run_message_mutation


@pytest.mark.write
@pytest.mark.parametrize("version", ("v1", "v2"))
@pytest.mark.parametrize("case", CASES)
def test_message_mutation_uses_original_sender(
    security_mutation_enabled, version, case, request,
):
    request.node.user_properties.extend([
        ("vuln44_case", case), ("vuln44_http_version", version),
        ("vuln44_scope", "fresh_plain_p2p_message_only_both_owner_views"),
        ("state_side_effect", "one_new_message_two_protocol_copies_no_retry_no_cleanup"),
    ])

    def record_message(msg_id):
        request.node.user_properties.append(("vuln44_new_message_id", msg_id))

    try:
        result = run_message_mutation(security_mutation_enabled, version, case,
                                      on_message=record_message)
    except MessageMutationError as exc:
        pytest.fail(str(exc), pytrace=False)
    except Exception:
        # pytest 的原始 traceback 可能包含 token/正文局部变量，只输出固定诊断。
        pytest.fail("Vuln44 自测发生未分类错误；已停止且未自动重发", pytrace=False)
    request.node.user_properties.extend([
        ("vuln44_acknowledgement", hex(result.acknowledgement)),
        ("vuln44_evidence", result.evidence),
    ])
