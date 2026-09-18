"""写库自测:改完必须 restore,避免污染 develop 全局/主播配置。"""

import pytest

from bi_api_test.heat import CUSTOM, FOLLOW_GLOBAL, MARKER, page_list, pick_metrics


def _restore_global(client, snap):
    payload = pick_metrics(snap)
    payload["current_tier"] = int(snap.get("current_tier") or 0)
    payload["update_tier"] = False
    client.heat_global_save(**payload).expect_ok()


def _restore_broadcaster(client, row):
    live_id = row["id"]
    if int(row.get("config_source") or 0) == CUSTOM:
        client.heat_config_update(live_id=live_id, source=CUSTOM, **pick_metrics(row)).expect_ok()
    else:
        client.heat_config_update(live_id=live_id, source=FOLLOW_GLOBAL).expect_ok()


@pytest.mark.write
def test_global_save_follow_rows_update(client, heat_ready):
    snap = client.heat_global_get().expect_ok().data["global"]
    try:
        payload = dict(MARKER)
        payload["current_tier"] = int(snap.get("current_tier") or 0)
        payload["update_tier"] = False
        client.heat_global_save(**payload).expect_ok()

        got = pick_metrics(client.heat_global_get().expect_ok().data["global"])
        assert got == pick_metrics(MARKER)

        rows, _ = page_list(client.broadcaster_list(page=1, size=50, config_source=FOLLOW_GLOBAL))
        for row in rows:
            assert pick_metrics(row) == pick_metrics(MARKER), (
                f"跟随全局行 id={row.get('id')} 未吃到新全局"
            )
    finally:
        _restore_global(client, snap)


@pytest.mark.write
def test_broadcaster_custom_then_follow(client, sample_broadcaster):
    live_id = sample_broadcaster["id"]
    origin = dict(sample_broadcaster)
    try:
        client.heat_config_update(live_id=live_id, source=CUSTOM, **MARKER).expect_ok()
        rows, _ = page_list(client.broadcaster_list(page=1, size=50, config_source=CUSTOM))
        hit = [x for x in rows if x.get("id") == live_id]
        assert hit, f"自定义后未在 config_source=1 列表找到 id={live_id}"
        assert pick_metrics(hit[0]) == pick_metrics(MARKER)

        client.heat_config_update(live_id=live_id, source=FOLLOW_GLOBAL).expect_ok()
        g = pick_metrics(client.heat_global_get().expect_ok().data["global"])
        again, _ = page_list(client.broadcaster_list(page=1, size=20))
        row = next((x for x in again if x.get("id") == live_id), None)
        assert row, f"切回全局后列表找不到 id={live_id}"
        assert row.get("config_source") == FOLLOW_GLOBAL
        assert pick_metrics(row) == g
    finally:
        _restore_broadcaster(client, origin)


@pytest.mark.write
def test_update_tier_does_not_change_global(client, heat_ready):
    before = client.heat_global_get().expect_ok().data
    snap_global = before["global"]
    snap_low = before["tiers"]["tier_low"]
    try:
        payload = dict(MARKER)
        payload["base_viewers"] = 38  # 档位稿改人数区间,基准保持低档量级以免误当全局
        payload["current_tier"] = 1
        payload["update_tier"] = True
        client.heat_global_save(**payload).expect_ok()

        after = client.heat_global_get().expect_ok().data
        assert pick_metrics(after["global"]) == pick_metrics(snap_global), "update_tier 不应改生效全局"
        assert pick_metrics(after["tiers"]["tier_low"]) == pick_metrics(payload)
    finally:
        restore = pick_metrics(snap_low)
        restore["current_tier"] = 1
        restore["update_tier"] = True
        client.heat_global_save(**restore).expect_ok()
        _restore_global(client, snap_global)
