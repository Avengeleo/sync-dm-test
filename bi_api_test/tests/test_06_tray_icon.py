"""托盘图标 96x96 校验(opt-in:需配置 BI_TRAY_ICON_* 才运行)。

校验语义(读 zip_import.go validateTrayIcon 核实):
  网络失败 → fail-open(放行);解码失败或宽高 ≠ 96x96 → 19311。
因此必须用「服务器能拉到」的真实图才能验证拒绝逻辑,故做成 opt-in。
"""

import pytest


@pytest.mark.tray_icon
@pytest.mark.write
def test_tray_icon_ok_96(client, make_pack_payload, config):
    if not config["tray_ok"]:
        pytest.skip("未配置 BI_TRAY_ICON_OK")
    env = client.sticker_create(**make_pack_payload(tray_icon=config["tray_ok"])).expect_ok()
    client.safe_delete(env.data["pack_id"])


@pytest.mark.tray_icon
def test_tray_icon_bad_not_96(client, make_pack_payload, config):
    if not config["tray_bad"]:
        pytest.skip("未配置 BI_TRAY_ICON_BAD")
    # 可访问但非 96x96 → 19311
    client.sticker_create(**make_pack_payload(tray_icon=config["tray_bad"])).expect(19311)
