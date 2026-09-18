"""C 端混排 + 直播间详情 v2:展示人气/热度;旧 live_room_detail 不加 popularity。"""

import pytest

from dm_api_test.live_display import (
    as_int,
    assert_old_no_popularity,
    assert_v2_display,
    assert_v3_item,
    page_list,
    split_v3,
)


def test_room_list_v3_envelope(dm_client, live_display_ready):
    rows, total = live_display_ready["rows"], live_display_ready["total"]
    assert isinstance(total, int)
    assert len(rows) <= 20
    for row in rows:
        assert_v3_item(row)


def test_room_list_v3_live_then_preview(dm_client, live_display_ready):
    rows, _ = page_list(dm_client.room_list_v3(page=1, page_size=50))
    seen_preview = False
    for row in rows:
        kind = assert_v3_item(row)
        if kind == "preview":
            seen_preview = True
        elif seen_preview:
            raise AssertionError(f"预告后面又出现直播卡,混排顺序应为先 live 再 preview:{row!r}")


def test_room_list_v3_guest_ok(guest_client, live_display_ready):
    rows, _ = page_list(guest_client.room_list_v3(page=1, page_size=10))
    for row in rows:
        assert_v3_item(row)


def test_live_detail_v2_display_fields(dm_client, sample_live_item):
    room_id = sample_live_item["room_id"]
    env = dm_client.live_room_detail_v2(room_id).expect_ok()
    assert_v2_display(env.data, "live_room_detail_v2")
    assert env.data.get("live_room_id") == room_id


def test_old_live_detail_has_no_popularity(dm_client, sample_live_item):
    old = dm_client.live_room_detail(sample_live_item["room_id"]).expect_ok().data
    assert_old_no_popularity(old, "live_room_detail")


def test_v2_popularity_covers_real_online(dm_client, sample_live_item):
    room_id = sample_live_item["room_id"]
    old = dm_client.live_room_detail(room_id).expect_ok().data
    v2 = dm_client.live_room_detail_v2(room_id).expect_ok().data
    pop, _, _ = assert_v2_display(v2, "v2")
    real_online = as_int(old.get("online_count"))
    assert pop >= real_online, (
        f"展示人数应 >= 旧接口真实在线: popularity={pop} online_count={real_online}"
    )


def test_live_detail_v2_missing_room_id(dm_client, live_display_ready):
    dm_client.call("/live/live_room_detail_v2", {}).expect(70120)


def test_voice_detail_v2_if_present(dm_client, live_display_ready):
    lives, _ = split_v3(live_display_ready["rows"])
    voice = [x for x in lives if as_int(x.get("live_type")) == 5]
    if not voice:
        pytest.skip("当前混排无语聊直播卡")
    room_id = voice[0]["room_id"]
    env = dm_client.voice_room_detail_v2(room_id)
    if env.http_status == 404 or env.code in (404, 500) or env.code is None:
        pytest.skip(f"无语聊模块或未部署 detail_v2:{env!r}")
    env.expect_ok()
    assert_v2_display(env.data, "voice_room/detail_v2")
    old = dm_client.voice_room_detail(room_id)
    if old.is_ok():
        assert "popularity" not in (old.data or {})
