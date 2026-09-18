"""C 端展示指标自测共享字段。口径对照 swagger_live_preview_heat.json 与 live-srv 公式。

展示人数 = 基准 + 虚拟 + 真实在线(预告间无真实在线)
展示热度 = round(基础热度 + 人数×coeff_viewers + 弹幕×coeff_comment + 礼物×coeff_gift + 点赞×coeff_like)
预告预约 = max(0, 基础预约 + 展示增量);开播页抽屉仍是表内真实人数
"""

V3_ITEM_KEYS = (
    "item_type",
    "preview_id",
    "live_record_id",
    "room_id",
    "live_type",
    "title",
    "cover",
    "broadcaster_nickname",
    "live_room_heat",
    "scheduled_at",
    "reserve_count",
    "community_sort",
)

PREVIEW_DETAIL_KEYS = (
    "preview_id",
    "title",
    "cover",
    "scheduled_at",
    "reserve_count",
    "is_reserved",
    "display_status",
    "is_fulfilled",
    "popularity",
    "live_room_heat",
)

# 网关未部署 / live-srv 未跟上时常见业务码,整组 skip 而不是红
SKIP_UNDEPLOYED = (404, 500, 501, 502, 503)


def as_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def page_list(env):
    env.expect_ok()
    data = env.data
    assert isinstance(data, dict), f"分页信封应为对象:{data!r}"
    assert "list" in data and "total" in data, f"缺 list/total:{data!r}"
    assert isinstance(data["list"], list)
    return data["list"], as_int(data["total"])


def split_v3(rows):
    lives, previews = [], []
    for row in rows:
        kind = row.get("item_type")
        if kind == "live":
            lives.append(row)
        elif kind == "preview":
            previews.append(row)
        else:
            raise AssertionError(f"item_type 非法:{row!r}")
    return lives, previews


def assert_v3_item(row):
    for k in V3_ITEM_KEYS:
        assert k in row, f"room_list_v3 缺 {k}: {row!r}"
    kind = row.get("item_type")
    heat = as_int(row.get("live_room_heat"))
    reserve = as_int(row.get("reserve_count"))
    assert heat >= 0, f"live_room_heat 不应为负:{row!r}"
    assert reserve >= 0, f"reserve_count 不应为负:{row!r}"
    if kind == "live":
        assert as_int(row.get("preview_id")) == 0
        assert (row.get("room_id") or "") != ""
        assert reserve == 0, f"直播卡 reserve_count 应为 0:{row!r}"
    elif kind == "preview":
        assert as_int(row.get("preview_id")) > 0
        assert heat == 0, f"预告卡 live_room_heat 应为 0:{row!r}"
        assert as_int(row.get("live_record_id") or 0) == 0
        assert not (row.get("room_id") or "")
    return kind


def assert_v2_display(data, where):
    assert isinstance(data, dict), f"{where} data 应为对象:{data!r}"
    assert "popularity" in data, f"{where} 缺 popularity:{data!r}"
    pop = as_int(data.get("popularity"))
    heat = as_int(data.get("live_room_heat"))
    likes = as_int(data.get("likes"))
    online = as_int(data.get("online_count"))
    assert pop >= 0, f"{where} popularity 不应为负:{pop}"
    assert heat >= 0, f"{where} live_room_heat 不应为负:{heat}"
    assert likes >= 0, f"{where} likes 不应为负:{likes}"
    assert online == pop, f"{where} online_count 应等于 popularity: {online} vs {pop}"
    return pop, heat, likes


def assert_old_no_popularity(data, where):
    assert isinstance(data, dict), f"{where} data 应为对象:{data!r}"
    assert "popularity" not in data, f"{where} 旧接口不应带 popularity:{data!r}"
    for k in ("live_room_heat", "likes", "online_count"):
        assert k in data, f"{where} 缺旧字段 {k}"
        assert as_int(data.get(k)) >= 0
