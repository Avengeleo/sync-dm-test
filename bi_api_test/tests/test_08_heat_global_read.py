"""全局配置只读:回显 global + 三档预设。"""

from bi_api_test.heat import TIER_KINDS, pick_metrics


def test_global_get_shape(heat_ready):
    g = heat_ready["global"]
    pick_metrics(g)
    assert g.get("kind") == "global"
    assert g.get("current_tier") in (0, 1, 2, 3), f"档位非法:{g.get('current_tier')}"


def test_global_get_tiers(heat_ready):
    tiers = heat_ready["tiers"]
    assert isinstance(tiers, dict)
    for kind in TIER_KINDS:
        assert kind in tiers, f"缺档位 {kind}: {list(tiers)}"
        row = tiers[kind]
        pick_metrics(row)
        assert row.get("kind") == kind


def test_heat_without_token_forbidden(anon_client):
    env = anon_client.post(
        "/admin/live/broadcaster/heat_config/global/get",
        json={},
        auth=False,
    )
    env.expect(403)


def test_removed_heat_list_not_ok(client, heat_ready):
    # 已并回 broadcaster/list,独立 list 不应再当成功接口用
    env = client.post("/admin/live/broadcaster/heat_config/list", json={"page": 1, "size": 10})
    assert env.code != 200, f"已下线的 heat_config/list 仍返回成功:{env!r}"


def test_removed_heat_display_list_not_ok(client, heat_ready):
    env = client.post("/admin/live/broadcaster/heat_display/list", json={"page": 1, "size": 10})
    assert env.code != 200, f"已下线的 heat_display/list 仍返回成功:{env!r}"
