"""离线积压清理(drain):拉一批 → 回带 ack → 再拉,直到清空。

为什么需要:离线拉取是 `limit=N` 的窗口查询,只返回最老的 N 条未拉取消息。
测试用例发完消息后轮询拉取,若该账号的离线队列积压已 ≥ limit,
新发的消息永远排在窗口之外 —— 用例会稳定失败在「拉不到刚发的消息」,
且失败原因和落库/门控毫无关系,极具误导性(2026-08-29 排查实录:
积压 100+ 条导致全部离线用例连挂,一度误判为 msg-job 落库故障)。

因此凡是"发消息 → 离线拉取"的用例,跑之前都应先把队列清空。
ack 会把消息标记为已拉取(不可逆),仅限测试账号使用。
"""


def drain_single(http, client_type=0, batch=100, max_rounds=50):
    """清空单聊离线队列,返回被 ack 掉的条数。

    每轮:拉 batch 条 → 把这批原样回带作为 delivered(=ack)→ 下一轮。
    拉到空批次即结束;max_rounds 是防御性上限,避免服务端异常时死循环。
    """
    total = 0
    for _ in range(max_rounds):
        code, rows = http.offline_chat(client_type=client_type, limit=batch)
        if code != 200:
            raise AssertionError(f"drain 拉取失败 HTTP {code}")
        if not rows:
            return total
        delivered = [{"msg_id": r["msg_id"], "msg_time": r["msg_time"], "cmd_id": r["cmd_id"]}
                     for r in rows]
        code, _ = http.offline_chat(client_type=client_type, limit=batch, delivered=delivered)
        if code != 200:
            raise AssertionError(f"drain ack 失败 HTTP {code}")
        total += len(rows)
    raise AssertionError(
        f"drain 超过 {max_rounds} 轮仍未清空(已 ack {total} 条),"
        f"疑似 ack 未生效或有其它来源持续写入")
