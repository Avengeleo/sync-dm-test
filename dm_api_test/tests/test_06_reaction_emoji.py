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
