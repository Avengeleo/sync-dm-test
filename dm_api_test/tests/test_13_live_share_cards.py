"""直播间分享卡片 POST /live/share_cards。

只读:字段、直播中优先、不存在的房间、去重顺序、参数上限、游客。
写库:主播号造一场预告,断言预告卡和 is_reserved,结束时取消预约并删预告。
"""

import time

import pytest

from dm_api_test.live_display import (
    SHARE_STATUS_INVALID,
    SHARE_STATUS_LIVING,
    SHARE_STATUS_PREVIEW,
    SKIP_UNDEPLOYED,
    as_int,
    assert_share_card,
    share_list,
)

MISSING_ROOM = "pytest-share-missing-room"


def _skip_undeployed(env):
    if env.http_status == 404 or env.code in SKIP_UNDEPLOYED or env.code is None:
        pytest.skip(
            f"/live/share_cards 不可用 http={env.http_status} code={env.code} msg={env.msg!r}。"
            "确认 develop 已部署带 ShareCards 的 api-gateway/h5-gateway 和 live-srv"
        )


@pytest.fixture(scope="module")
def share_cards_ready(dm_client, live_display_ready):
    env = dm_client.share_cards([MISSING_ROOM])
    _skip_undeployed(env)
    rows = share_list(env)
    assert len(rows) == 1
    assert assert_share_card(rows[0]) == SHARE_STATUS_INVALID
    return True


def test_share_cards_missing_room(dm_client, share_cards_ready):
    rows = share_list(dm_client.share_cards([MISSING_ROOM]))
    card = rows[0]
    assert card["room_id"] == MISSING_ROOM
    assert assert_share_card(card) == SHARE_STATUS_INVALID


def test_share_cards_living_room(dm_client, sample_live_item, share_cards_ready):
    room_id = sample_live_item["room_id"]
    rows = share_list(dm_client.share_cards([room_id]))
    assert len(rows) == 1
    card = rows[0]
    assert assert_share_card(card) == SHARE_STATUS_LIVING
    assert card["room_id"] == room_id
    assert card["title"] == sample_live_item.get("title")
    assert as_int(card["live_record_id"]) == as_int(sample_live_item.get("live_record_id"))
    assert as_int(card["preview_id"]) == 0
    assert card.get("is_reserved") in (False, 0, None)


def test_share_cards_batch_order_and_dedupe(dm_client, sample_live_item, share_cards_ready):
    room_id = sample_live_item["room_id"]
    rows = share_list(dm_client.share_cards([f"  {room_id}  ", room_id, MISSING_ROOM]))
    assert [row["room_id"] for row in rows] == [room_id, MISSING_ROOM]
    assert assert_share_card(rows[0]) == SHARE_STATUS_LIVING
    assert assert_share_card(rows[1]) == SHARE_STATUS_INVALID


def test_share_cards_reject_bad_batch(dm_client, share_cards_ready):
    dm_client.call("/live/share_cards", {}).expect(1015)
    dm_client.call("/live/share_cards", {"room_ids": ""}).expect(1015)
    dm_client.call("/live/share_cards", {"room_ids": "[]"}).expect(1015)
    dm_client.call("/live/share_cards", {"room_ids": '[""]'}).expect(1015)
    dm_client.call("/live/share_cards", {"room_ids": ["not-a-string"]}).expect(1015)
    dm_client.share_cards([f"room-{i}" for i in range(21)]).expect(1015)
    dm_client.call("/live/share_cards", {"preview_ids": ""}).expect(1015)
    dm_client.call("/live/share_cards", {"preview_ids": "[]"}).expect(1015)
    dm_client.call("/live/share_cards", {"preview_ids": "[0]"}).expect(1015)
    dm_client.call("/live/share_cards", {"preview_ids": '["0"]'}).expect(1015)
    dm_client.share_cards_by_preview(list(range(1, 22))).expect(1015)


def test_share_cards_missing_preview(dm_client, share_cards_ready):
    missing = 9876543210123
    rows = share_list(dm_client.share_cards_by_preview([missing]))
    assert len(rows) == 1
    card = rows[0]
    assert as_int(card["preview_id"]) == missing
    assert card.get("room_id") in ("", None)
    assert assert_share_card(card) == SHARE_STATUS_INVALID


def test_share_cards_room_ids_ignore_preview_ids(dm_client, share_cards_ready):
    rows = share_list(dm_client.share_cards([MISSING_ROOM], preview_ids='["9876543210123"]'))
    assert len(rows) == 1
    assert rows[0]["room_id"] == MISSING_ROOM
    assert as_int(rows[0]["preview_id"]) == 0
    assert assert_share_card(rows[0]) == SHARE_STATUS_INVALID


def test_share_cards_guest_not_reserved(guest_client, sample_live_item, share_cards_ready):
    room_id = sample_live_item["room_id"]
    env = guest_client.share_cards([room_id, MISSING_ROOM])
    _skip_undeployed(env)
    rows = share_list(env)
    assert [row["room_id"] for row in rows] == [room_id, MISSING_ROOM]
    for row in rows:
        assert_share_card(row)
        assert row.get("is_reserved") in (False, 0, None)


def _card_for(client, room_id):
    rows = share_list(client.share_cards([room_id]))
    assert len(rows) == 1
    return rows[0]


@pytest.mark.write
def test_share_card_preview_reserve_roundtrip(dm_client, seeded_preview, share_cards_ready):
    priv = dm_client.check_user_live_privilege().expect_ok().data or {}
    room_id = priv.get("room_id") or ""
    if not room_id:
        pytest.skip("主播权限未返回 room_id,无法对上预告所在房间")
    pid = as_int(seeded_preview.get("preview_id"))
    # 房间事实缓存 5 秒,刚发的预告可能还没进卡片。
    time.sleep(6)
    card = _card_for(dm_client, room_id)
    status = assert_share_card(card)

    if priv.get("is_living"):
        assert status == SHARE_STATUS_LIVING
        assert as_int(card["preview_id"]) == 0
        dm_client.preview_reserve(pid).expect_ok()
        try:
            again = _card_for(dm_client, room_id)
            assert assert_share_card(again) == SHARE_STATUS_LIVING
            assert again.get("is_reserved") in (False, 0, None)
        finally:
            dm_client.preview_cancel_reserve(pid)
        return

    assert status == SHARE_STATUS_PREVIEW, f"未开播房间应出预告卡:{card!r}"
    shown = as_int(card["preview_id"])
    if shown == pid:
        assert card.get("title") == seeded_preview.get("title")
    assert card.get("is_reserved") in (False, 0, None)

    before = dm_client.preview_detail(shown).expect_ok().data or {}
    was_reserved = bool(before.get("is_reserved"))

    def _restore():
        if was_reserved:
            dm_client.preview_reserve(shown)
        else:
            dm_client.preview_cancel_reserve(shown)

    try:
        if was_reserved:
            dm_client.preview_cancel_reserve(shown).expect_ok()
        else:
            dm_client.preview_reserve(shown).expect_ok()
        mid = _card_for(dm_client, room_id)
        assert assert_share_card(mid) == SHARE_STATUS_PREVIEW
        assert as_int(mid["preview_id"]) == shown
        assert bool(mid.get("is_reserved")) != was_reserved
    finally:
        _restore()
