"""快捷回应 bar-最常用回应表情(按次数排,top-12;每次心情回应 add 上报 count+1)。

契约(读 handler_sticker.go 核实):
  report {emoji} → count+1;top {limit} → 按 useCount 降序(默认12,上限100)
注意:累计计数、无删除口(产品设计如此),用例用 before/after 增量断言、不依赖清理。
"""

import pytest


def _counts(env):
    data = env.data or {}
    return {x.get("emoji"): x.get("useCount") for x in (data.get("list") or [])}


@pytest.mark.write
def test_report_increments_count(dm_client):
    key = "ZZ_SELFTEST_REACTION"  # 独特 key,不与真实表情冲突
    before = _counts(dm_client.reaction_emoji_top(limit=100).expect_ok()).get(key, 0)
    dm_client.reaction_emoji_report(key).expect_ok()
    dm_client.reaction_emoji_report(key).expect_ok()
    after = _counts(dm_client.reaction_emoji_top(limit=100).expect_ok()).get(key, 0)
    assert after == before + 2, f"两次上报应 +2:{before}→{after}"


def test_top_sorted_and_capped(dm_client):
    lst = (dm_client.reaction_emoji_top(limit=12).expect_ok().data or {}).get("list") or []
    assert len(lst) <= 12, "默认/上限 12"
    counts = [x.get("useCount", 0) for x in lst]
    assert counts == sorted(counts, reverse=True), "应按次数降序"


def test_report_empty_rejected(dm_client):
    dm_client.call("/user/reaction/emoji/report", {}).expect(400)


# ── 真 emoji 存储链路(4 字节 SMP 字符)──
# 上面的用例用 ASCII key,绕开了本接口唯一真实的输入形态。以下用真 emoji:
# 连接 DSN 若是 charset=utf8(=utf8mb3,仅 3 字节)则 4 字节 emoji 会报错/被截断;
# 列 collation 若是 *_general_ci 则不同 emoji 可能比较相等而互相串台。
# 这两种坏法都只有真 emoji 能测出来。
_SMP_EMOJIS = ["\U0001F600", "\U0001F44D", "\U0001F389"]  # 😀 👍 🎉,均 4 字节


@pytest.mark.write
@pytest.mark.parametrize("emoji", _SMP_EMOJIS)
def test_report_real_emoji_persists(dm_client, emoji):
    """真 emoji 应能上报并按**完全相同的字面值**取回(禁止模糊匹配)。"""
    before = _counts(dm_client.reaction_emoji_top(limit=100).expect_ok()).get(emoji, 0)
    dm_client.reaction_emoji_report(emoji).expect_ok()
    got = _counts(dm_client.reaction_emoji_top(limit=100).expect_ok())
    assert emoji in got, (
        f"上报的 emoji {emoji!r}(4字节)在 top 里取不回来。"
        f"典型原因:MySQL 连接 charset=utf8(=utf8mb3)存不下 4 字节字符。"
        f"实际返回的 key:{list(got)[:10]}"
    )
    assert got[emoji] == before + 1, f"计数应 +1:{before}→{got[emoji]}"


@pytest.mark.write
def test_distinct_emojis_do_not_collide(dm_client):
    """不同 emoji 必须是各自独立的行,不能因 collation 归并成同一条
    (general_ci 下多个 SMP 字符可能被判为相等 → 计数串台、bar 显示错表情)。"""
    for e in _SMP_EMOJIS:
        dm_client.reaction_emoji_report(e).expect_ok()
    got = _counts(dm_client.reaction_emoji_top(limit=100).expect_ok())
    present = [e for e in _SMP_EMOJIS if e in got]
    assert len(present) == len(_SMP_EMOJIS), (
        f"三个不同 emoji 应各自成行,实际只找到 {present}。"
        f"缺失说明被 collation 判为相等而合并(计数会互相污染)"
    )


@pytest.mark.write
def test_multi_codepoint_emoji(dm_client):
    """多码位 emoji(ZWJ 组合)应原样存取——客户端表情面板里有这类字符。"""
    family = "\U0001F468‍\U0001F469‍\U0001F467"  # 👨‍👩‍👧(含零宽连接符)
    dm_client.reaction_emoji_report(family).expect_ok()
    got = _counts(dm_client.reaction_emoji_top(limit=100).expect_ok())
    similar = [k for k in got if k and "\U0001F468" in k]
    assert family in got, f"多码位 emoji 未原样存回;实际 keys 中含 👨 的:{similar}"
