"""保存校验:非法值应 400 中文提示、不落库。"""

from bi_api_test.heat import MARKER, pick_metrics


def _save(client, **overrides):
    payload = dict(MARKER)
    payload["current_tier"] = 0
    payload["update_tier"] = False
    payload.update(overrides)
    return client.heat_global_save(**payload)


def test_negative_base_rejected(client, heat_ready):
    env = _save(client, base_viewers=-1)
    env.expect(400)
    assert "基准" in (env.msg or "")


def test_range_max_lt_min_rejected(client, heat_ready):
    env = _save(client, viewers_inc_min=8, viewers_inc_max=3)
    env.expect(400)
    assert "范围" in (env.msg or "")


def test_negative_coeff_rejected(client, heat_ready):
    env = _save(client, coeff_like=-0.1)
    env.expect(400)
    assert "系数" in (env.msg or "")


def test_coeff_three_decimals_rejected(client, heat_ready):
    env = _save(client, coeff_viewers=2.123)
    env.expect(400)
    assert "两位小数" in (env.msg or "")


def test_invalid_source_rejected(client, sample_broadcaster, heat_ready):
    env = client.heat_config_update(
        live_id=sample_broadcaster["id"],
        source=9,
        **MARKER,
    )
    env.expect(400)
    assert "配置来源" in (env.msg or "")


def test_update_tier_requires_low_mid_high(client, heat_ready):
    env = _save(client, current_tier=0, update_tier=True)
    env.expect(400)
    assert "档位" in (env.msg or "")


def test_invalid_save_does_not_mutate_global(client, heat_ready):
    before = pick_metrics(client.heat_global_get().expect_ok().data["global"])
    _save(client, base_heat=-8).expect(400)
    after = pick_metrics(client.heat_global_get().expect_ok().data["global"])
    assert after == before, "校验失败不应改全局配置"
