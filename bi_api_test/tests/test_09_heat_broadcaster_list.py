"""主播列表:配置来源 + 生效四项 + 高阶;config_source 筛选。"""

from bi_api_test.heat import CUSTOM, FOLLOW_GLOBAL, page_list, pick_metrics


def test_broadcaster_list_envelope(client, heat_ready):
    rows, total = page_list(client.broadcaster_list(page=1, size=5))
    assert isinstance(total, int)
    assert len(rows) <= 5


def test_broadcaster_list_heat_fields(client, sample_broadcaster, heat_ready):
    pick_metrics(sample_broadcaster)
    assert sample_broadcaster.get("config_source") in (FOLLOW_GLOBAL, CUSTOM)


def test_follow_global_row_matches_global(client, heat_ready):
    rows, _ = page_list(client.broadcaster_list(page=1, size=50, config_source=FOLLOW_GLOBAL))
    if not rows:
        return
    expected = pick_metrics(heat_ready["global"])
    for row in rows:
        assert row.get("config_source") == FOLLOW_GLOBAL
        assert pick_metrics(row) == expected, (
            f"跟随全局行 id={row.get('id')} 生效指标应等于当前全局"
        )


def test_config_source_filter_custom(client, heat_ready):
    rows, _ = page_list(client.broadcaster_list(page=1, size=50, config_source=CUSTOM))
    for row in rows:
        assert row.get("config_source") == CUSTOM, f"自定义筛选混入其他来源:{row!r}"
