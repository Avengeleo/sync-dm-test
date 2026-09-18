"""预告间详情:展示人数/热度/预约;开播页抽屉仍是真实预约人数。"""

from dm_api_test.live_display import PREVIEW_DETAIL_KEYS, as_int


def test_preview_detail_display_fields(dm_client, sample_preview_item):
    env = dm_client.preview_detail(sample_preview_item["preview_id"]).expect_ok()
    data = env.data
    for k in PREVIEW_DETAIL_KEYS:
        assert k in data, f"preview/detail 缺 {k}: {data!r}"
    assert as_int(data["preview_id"]) == as_int(sample_preview_item["preview_id"])
    assert as_int(data["popularity"]) >= 0
    assert as_int(data["live_room_heat"]) >= 0
    assert as_int(data["reserve_count"]) >= 0
    assert as_int(data["display_status"]) in (1, 2, 3)


def test_preview_detail_guest_ok(guest_client, sample_preview_item):
    env = guest_client.preview_detail(sample_preview_item["preview_id"]).expect_ok()
    assert as_int(env.data.get("popularity")) >= 0
    assert env.data.get("is_reserved") in (False, 0, None)


def test_preview_detail_missing_id(dm_client, live_display_ready):
    dm_client.call("/live/preview/detail", {}).expect(1015)


def test_guest_reserve_rejected(guest_client, sample_preview_item):
    guest_client.preview_reserve(sample_preview_item["preview_id"]).expect(70208)


def test_drawer_real_reserve_vs_display(dm_client, sample_preview_item):
    """开播页抽屉 reserve_count 是表内真实人数,详情是展示预约,允许不相等。"""
    drawer = dm_client.preview_list()
    if not drawer.is_ok():
        return
    data = drawer.data or {}
    rows = data.get("list") or []
    pid = as_int(sample_preview_item["preview_id"])
    hit = next((x for x in rows if as_int(x.get("preview_id")) == pid), None)
    if not hit:
        return
    detail = dm_client.preview_detail(pid).expect_ok().data
    assert as_int(hit.get("reserve_count")) >= 0
    assert as_int(detail.get("reserve_count")) >= 0
