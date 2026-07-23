"""贴图读接口(数据依赖:读表由 bi 上架后异步同步过来;无数据时优雅跳过)。

契约(读 sticker.go / handler_sticker.go 核实):
  pack_list: {version} → {version, list:[StickerPackInfo]}(list 空时为 null)
  item_list: {pack_id 必填} → 直接数组 [StickerItemInfo](空时 null)
  my_pack/list → {version, list}(本期不启用,但接口在)
"""

import pytest


def test_pack_list_shape(dm_client):
    env = dm_client.sticker_pack_list().expect_ok()
    data = env.data or {}
    assert "version" in data, "pack_list 应含 version"
    assert "list" in data, "pack_list 应含 list"
    # list 可能为 null(无上架包/未同步),不强求非空


def test_item_list_requires_pack_id(dm_client):
    # 缺 pack_id → 400
    dm_client.call("/user/sticker/item_list", {}).expect(400)


def test_item_list_of_first_pack(dm_client):
    packs = (dm_client.sticker_pack_list().expect_ok().data or {}).get("list")
    if not packs:
        pytest.skip("无上架贴图包(bi 未上架或快照未同步到 dm 读表),跳过包内贴图查询")
    pack_id = packs[0]["packId"]
    env = dm_client.sticker_item_list(pack_id).expect_ok()
    # data 为数组或 null;有则校验字段
    if env.data:
        it = env.data[0]
        assert "imgUrl" in it and "width" in it


def test_my_pack_list_shape(dm_client):
    env = dm_client.my_pack_list().expect_ok()
    data = env.data or {}
    assert "list" in data, "my_pack/list 应含 list"
