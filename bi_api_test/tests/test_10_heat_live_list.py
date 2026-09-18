"""直播列表:session_status 拆行 + 展示人数/热度拆列。虚拟增量依赖 live-srv,允许为 0。"""

from bi_api_test.heat import page_list


DISPLAY_KEYS = (
    "viewers_total",
    "viewers_base",
    "viewers_virtual",
    "viewers_member",
    "viewers_guest",
    "reserve_total",
    "reserve_base",
    "reserve_actual",
    "heat_total",
    "heat_base",
    "heat_actual",
    "likes_total",
    "likes_base",
    "likes_actual",
)


def _assert_display_row(row):
    status = row.get("session_status")
    assert status in ("live", "preview"), f"session_status 非法:{row!r}"
    for k in DISPLAY_KEYS:
        assert k in row, f"缺 {k}: {row!r}"
        assert int(row[k]) >= 0 or k.endswith("_actual"), f"{k} 不应为异常负值:{row[k]}"
    assert int(row["hot"]) == int(row["heat_total"]), "hot 应等于 heat_total"
    viewers_sum = (
        int(row["viewers_base"])
        + int(row["viewers_virtual"])
        + int(row["viewers_member"])
        + int(row["viewers_guest"])
    )
    assert int(row["viewers_total"]) == viewers_sum, (
        f"人数总数应对上基准+虚拟+会员+游客: {row}"
    )
    assert int(row["heat_total"]) == int(row["heat_base"]) + int(row["heat_actual"])
    assert int(row["reserve_total"]) == int(row["reserve_base"]) + int(row["reserve_actual"])
    if status == "live":
        assert int(row.get("preview_id") or 0) == 0
    if status == "preview":
        assert int(row.get("preview_id") or 0) > 0


def test_live_list_envelope(client, heat_ready):
    rows, total = page_list(client.live_list(page=1, size=10))
    assert isinstance(total, int)
    assert len(rows) <= 10
    for row in rows:
        _assert_display_row(row)


def test_live_list_filter_live(client, heat_ready):
    rows, _ = page_list(client.live_list(page=1, size=20, session_status="live"))
    for row in rows:
        assert row.get("session_status") == "live"
        _assert_display_row(row)


def test_live_list_filter_preview(client, heat_ready):
    rows, _ = page_list(client.live_list(page=1, size=20, session_status="preview"))
    for row in rows:
        assert row.get("session_status") == "preview"
        _assert_display_row(row)


def test_live_list_bad_session_status(client, heat_ready):
    # logic 返回 error → handler Fail,业务码 201
    env = client.live_list(session_status="xxx")
    env.expect(201)
