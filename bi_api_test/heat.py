"""人气热度自测共享字段与取值。数值口径对照 sync-bi-api heat_metric.go。"""

METRIC_KEYS = (
    "base_viewers",
    "base_reserve",
    "base_heat",
    "base_likes",
    "viewers_inc_min",
    "viewers_inc_max",
    "viewers_dec_min",
    "viewers_dec_max",
    "reserve_inc_min",
    "reserve_inc_max",
    "reserve_dec_min",
    "reserve_dec_max",
    "like_inc_min",
    "like_inc_max",
    "coeff_viewers",
    "coeff_comment",
    "coeff_gift",
    "coeff_like",
)

FOLLOW_GLOBAL = 0
CUSTOM = 1

# 写库用例用的可辨识底数,测完必须 restore,避免污染 develop 全局
MARKER = {
    "base_viewers": 987651,
    "base_reserve": 20,
    "base_heat": 500,
    "base_likes": 50,
    "viewers_inc_min": 3,
    "viewers_inc_max": 8,
    "viewers_dec_min": 2,
    "viewers_dec_max": 6,
    "reserve_inc_min": 2,
    "reserve_inc_max": 5,
    "reserve_dec_min": 1,
    "reserve_dec_max": 4,
    "like_inc_min": 1,
    "like_inc_max": 3,
    "coeff_viewers": 2.0,
    "coeff_comment": 1.5,
    "coeff_gift": 0.8,
    "coeff_like": 0.3,
}

TIER_KINDS = ("tier_low", "tier_mid", "tier_high")


def pick_metrics(row):
    out = {}
    for k in METRIC_KEYS:
        assert k in row, f"缺指标字段 {k}: {row!r}"
        v = row[k]
        if k.startswith("coeff_"):
            out[k] = round(float(v), 2)
        else:
            out[k] = int(v)
    return out


def page_list(env):
    env.expect_ok()
    assert isinstance(env.data, dict), f"分页信封应为对象:{env.data!r}"
    assert "list" in env.data and "total" in env.data, f"缺 list/total:{env.data!r}"
    assert isinstance(env.data["list"], list)
    return env.data["list"], env.data["total"]
