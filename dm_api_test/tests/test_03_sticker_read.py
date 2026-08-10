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


# ============================================================
# 响应形态陷阱:强类型客户端(iOS/Android)最容易在这里崩
# ============================================================

@pytest.mark.write
def test_item_list_unknown_pack_returns_null_not_404(dm_client):
    """未知 pack_id → code=200 且 data 为 null(不是 404、也不是空数组)。
    客户端若按 404 或 [] 处理会走错分支。"""
    env = dm_client.sticker_item_list("PACK_NOT_EXIST_9999").expect_ok()
    assert env.data is None, f"空包的 data 应为 null,实际 {env.data!r}"


@pytest.mark.write
def test_item_list_is_bare_array_not_wrapped(dm_client):
    """item_list 的 data 是**裸数组**,不是 {list:[...]}——与其它列表接口不一致,
    客户端按统一的 data.list 解析会取空。"""
    packs = (dm_client.sticker_pack_list().expect_ok().data or {}).get("list") or []
    if not packs:
        pytest.skip("无上架贴图包,跳过")
    env = dm_client.sticker_item_list(packs[0]["packId"]).expect_ok()
    if env.data is None:
        pytest.skip("该包内无贴图")
    assert isinstance(env.data, list), (
        f"item_list 的 data 应是裸数组,实际类型 {type(env.data).__name__} → {str(env.data)[:120]}"
    )
    item = env.data[0]
    assert "imgUrl" in item, f"item 应含 imgUrl(camelCase),实际键:{sorted(item)}"


@pytest.mark.write
def test_pack_zero_value_fields_are_omitted(dm_client):
    """proto3 零值字段会整个消失(不是返 0)。
    isPlatformIssued=0 是绝大多数包的常态,强类型端若按"必有该键"解码会直接崩,
    必须按缺省=0 处理。本用例把这一契约钉死。"""
    packs = (dm_client.sticker_pack_list().expect_ok().data or {}).get("list") or []
    if not packs:
        pytest.skip("无上架贴图包,跳过")

    for p in packs:
        # 必有的非零字段
        assert p.get("packId"), f"packId 必须存在且非空:{p}"
        assert p.get("nameZh"), f"nameZh 必须存在且非空:{p}"
        # 零值字段允许缺席,但只要出现就必须是 int
        for k in ("isPlatformIssued", "sortWeight", "stickerCount"):
            if k in p:
                assert isinstance(p[k], int), f"{k} 出现时应为整数,实际 {p[k]!r}"

    non_platform = [p for p in packs if p.get("isPlatformIssued", 0) == 0]
    if non_platform:
        assert "isPlatformIssued" not in non_platform[0], (
            "非平台包的 isPlatformIssued=0 应被 proto3 省略(键不存在);"
            "若这里失败说明序列化行为变了,客户端可以改用必有该键的解码方式"
        )


@pytest.mark.write
def test_pack_list_version_always_returns_full_list(dm_client):
    """version 只是给客户端做本地缓存比对用:传任何值服务端都返**全量**列表,
    不做增量。客户端若期望"传旧 version 只回增量"会解析出错。"""
    base = dm_client.sticker_pack_list(version=0).expect_ok().data or {}
    cur_version = base.get("version")
    n = len(base.get("list") or [])
    assert isinstance(cur_version, int), f"version 应为整数,实际 {cur_version!r}"

    for v in (cur_version, cur_version + 999):
        again = dm_client.sticker_pack_list(version=v).expect_ok().data or {}
        assert len(again.get("list") or []) == n, (
            f"传 version={v} 仍应返回全量 {n} 条,实际 {len(again.get('list') or [])} 条"
        )
        assert again.get("version") == cur_version, "返回的 version 应始终是服务端当前版本"


@pytest.mark.write
def test_pack_list_ordering(dm_client):
    """排序契约:平台发行包在前 → 权重 DESC → id ASC。
    客户端直接按返回顺序渲染托盘,顺序错=小金刚不在首位。"""
    packs = (dm_client.sticker_pack_list().expect_ok().data or {}).get("list") or []
    if len(packs) < 2:
        pytest.skip("上架包不足 2 个,无法验证排序")

    flags = [p.get("isPlatformIssued", 0) for p in packs]
    first_zero = next((i for i, f in enumerate(flags) if f == 0), len(flags))
    assert all(f == 0 for f in flags[first_zero:]), (
        f"平台发行包必须全部排在前面,实际 isPlatformIssued 序列:{flags}"
    )

    weights = [p.get("sortWeight", 0) for p in packs]
    for grp in (weights[:first_zero], weights[first_zero:]):
        assert grp == sorted(grp, reverse=True), f"同组内应按权重降序,实际 {grp}"
