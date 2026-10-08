"""C 端展示指标自测共享字段。口径对照 swagger_live_preview_heat.json 与 live-srv 公式。

展示人数 = 基准 + 虚拟 + 真实在线(预告间无真实在线)
展示热度 = round(基础热度 + 人数×coeff_viewers + 弹幕×coeff_comment + 礼物×coeff_gift + 点赞×coeff_like)
预告预约 = max(0, 基础预约 + 展示增量);开播页抽屉仍是表内真实人数
"""

SEED_COVER = "https://bi-sticker-selftest.invalid/preview_cover.png"
SEED_TITLE_PREFIX = "[pytest-heat]"

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

SHARE_CARD_KEYS = (
    "room_id",
    "status",
    "live_type",
    "title",
    "cover",
    "broadcaster_user_id",
    "broadcaster_nickname",
    "avatar",
    "live_record_id",
    "preview_id",
    "scheduled_at",
    "is_reserved",
    "live_room_heat",
    "liveRoomLikes",
)

SHARE_STATUS_LIVING = 1
SHARE_STATUS_PREVIEW = 2
SHARE_STATUS_ENDED = 3
SHARE_STATUS_INVALID = 4
SHARE_STATUS_PREVIEW_CANCELLED = 5


def as_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def share_list(env):
    env.expect_ok()
    data = env.data
    assert isinstance(data, dict), f"分享卡片信封应为对象:{data!r}"
    assert isinstance(data.get("list"), list), f"缺 list:{data!r}"
    return data["list"]


def assert_share_card(row):
    for k in SHARE_CARD_KEYS:
        assert k in row, f"share_cards 缺 {k}: {row!r}"
    status = as_int(row.get("status"))
    assert status in (
        SHARE_STATUS_LIVING,
        SHARE_STATUS_PREVIEW,
        SHARE_STATUS_ENDED,
        SHARE_STATUS_INVALID,
        SHARE_STATUS_PREVIEW_CANCELLED,
    ), f"status 非法:{row!r}"
    room_id = row.get("room_id") or ""
    preview_id = as_int(row.get("preview_id"))
    if status != SHARE_STATUS_INVALID:
        assert room_id != "", f"room_id 为空:{row!r}"
    assert as_int(row.get("live_room_heat")) >= 0, f"live_room_heat 不应为负:{row!r}"
    assert as_int(row.get("liveRoomLikes")) >= 0, f"liveRoomLikes 不应为负:{row!r}"
    reserved = row.get("is_reserved")
    if status == SHARE_STATUS_LIVING:
        assert as_int(row.get("preview_id")) == 0
        assert reserved in (False, 0, None)
    elif status == SHARE_STATUS_PREVIEW:
        assert as_int(row.get("preview_id")) > 0
        assert as_int(row.get("live_record_id")) == 0
        assert as_int(row.get("scheduled_at")) > 0
    elif status == SHARE_STATUS_ENDED:
        assert as_int(row.get("preview_id")) == 0
        assert reserved in (False, 0, None)
    elif status == SHARE_STATUS_PREVIEW_CANCELLED:
        assert preview_id > 0
        assert as_int(row.get("live_record_id")) == 0
        assert as_int(row.get("liveRoomLikes")) == 0
        assert reserved in (False, 0, None)
    else:
        assert room_id != "" or preview_id > 0, f"无效卡片缺少房间号和预告号:{row!r}"
        if room_id != "":
            assert preview_id == 0
        assert (row.get("title") or "") == ""
        assert as_int(row.get("live_record_id")) == 0
        assert as_int(row.get("liveRoomLikes")) == 0
        assert reserved in (False, 0, None)
    return status


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


def _pick_category_id(client):
    priv = client.check_user_live_privilege()
    data = priv.data if priv.is_ok() and isinstance(priv.data, dict) else {}
    cid = as_int(data.get("default_category_id"))
    if cid:
        return cid, priv
    cats = client.live_category()
    if cats.is_ok() and isinstance(cats.data, list) and cats.data:
        first = cats.data[0] if isinstance(cats.data[0], dict) else {}
        return as_int(first.get("id")), priv
    return 0, priv


def publish_seed_preview(client, cover=""):
    """用当前登录态发一场 pending 预告。不是主播则 (None, privilege_env)。"""
    import time

    cid, priv = _pick_category_id(client)
    if not priv.is_ok():
        return None, priv
    data = priv.data if isinstance(priv.data, dict) else {}
    if not data.get("is_broadcaster"):
        return None, priv
    if not cid:
        return None, priv
    scheduled = int(time.time()) + 20 * 60
    payload = {
        "live_title": f"{SEED_TITLE_PREFIX} {scheduled}",
        "live_cover_img": cover or SEED_COVER,
        "live_category": cid,
        "live_type": 1,
        "scheduled_at": scheduled,
    }
    env = client.preview_publish(**payload)
    if env.code == 70204:
        payload["scheduled_at"] = scheduled + 2 * 3600
        payload["live_title"] = f"{SEED_TITLE_PREFIX} {payload['scheduled_at']}"
        env = client.preview_publish(**payload)
    return env, priv
