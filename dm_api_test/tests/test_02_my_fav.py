"""我的最爱(单张收藏,贴图/GIF)。

契约(读 handler_sticker.go 核实):
  add: {fav_type(1贴图/2GIF,必填非0), img_url(必填), pack_id(贴图必填/GIF空), ...} → 200;幂等;
       每类满 10 → 40701「我的最爱数量已达上限」(2026-08-10 由 403 改;403 在本项目是鉴权
       语义——见 test_00_smoke 的「403 → token 被冻结」,两者撞码客户端无法区分)
  list: {fav_type(0全部/1/2)} → {list:[{id,favType,packId,imgUrl,...,favTime}]},最新在前
  del: {ids:"id1|id2"} 按行 id 批量删(id 取自 list;网关签名要求扁平串,不能传嵌套数组)
  收藏存快照(不校验贴图是否真存在),故用例可用任意 pack_id+img_url,自成一体。
"""

import pytest

_IMG = "http://dm-selftest.invalid/fav_{}.webp"


def _key(fav):
    return (fav.get("favType"), fav.get("packId"), fav.get("imgUrl"))


@pytest.mark.write
def test_add_list_del_roundtrip(dm_client, fav_cleaner):
    img = _IMG.format("rt1")
    fav_cleaner(1, img, "PACKSELFTEST")
    dm_client.my_fav_add(fav_type=1, img_url=img, pack_id="PACKSELFTEST",
                          file_name="rt1.webp", width=240, height=240).expect_ok()

    data = dm_client.my_fav_list(fav_type=1).expect_ok().data or {}
    rows = data.get("list") or []
    urls = [f.get("imgUrl") for f in rows]
    assert img in urls, "收藏后列表应包含刚加的图"

    # 删除后应消失(按行 id 删)
    fav_id = next(f["id"] for f in rows if f.get("imgUrl") == img)
    dm_client.my_fav_del([fav_id]).expect_ok()
    data = dm_client.my_fav_list(fav_type=1).expect_ok().data or {}
    urls = [f.get("imgUrl") for f in (data.get("list") or [])]
    assert img not in urls, "删除后列表不应再有该图"


@pytest.mark.write
def test_add_idempotent(dm_client, fav_cleaner):
    img = _IMG.format("idem")
    fav_cleaner(1, img, "PACKSELFTEST")
    dm_client.my_fav_add(fav_type=1, img_url=img, pack_id="PACKSELFTEST").expect_ok()
    dm_client.my_fav_add(fav_type=1, img_url=img, pack_id="PACKSELFTEST").expect_ok()  # 重复 200


@pytest.mark.write
def test_fav_type_zero_rejected(dm_client):
    # fav_type=0 触发网关 required(int 零值)→ 400
    dm_client.my_fav_add(fav_type=0, img_url=_IMG.format("z"), pack_id="P").expect(400)


# 我的最爱超上限的业务码(2026-08-10:原 403 → 40701)。
# 403 与网关鉴权拦截码冲突,客户端无法区分"没权限"与"收藏满了";且 403 不在 msgError
# 码表内导致 msg 恒为空。改用语义化码后网关会自动回填 msg。
CODE_FAV_LIMIT = 40701
FAV_LIMIT_PER_TYPE = 10


def _fill_to_limit(dm_client, fav_cleaner, fav_type, pack_id, tag):
    """把某一类收藏塞满到上限,返回已用的 img_url 列表。"""
    used = []
    for i in range(FAV_LIMIT_PER_TYPE):
        img = _IMG.format(f"{tag}{i}")
        fav_cleaner(fav_type, img, pack_id)
        dm_client.my_fav_add(fav_type=fav_type, img_url=img, pack_id=pack_id).expect_ok()
        used.append(img)
    return used


@pytest.mark.write
def test_over_limit_sticker(dm_client, fav_cleaner):
    """贴图类满 10 后第 11 个 → 40701,且 msg 非空(网关按码表回填)。"""
    _fill_to_limit(dm_client, fav_cleaner, 1, "PACKLIMIT", "lim")
    over = _IMG.format("lim_over")
    fav_cleaner(1, over, "PACKLIMIT")
    env = dm_client.my_fav_add(fav_type=1, img_url=over, pack_id="PACKLIMIT")
    assert env.code == CODE_FAV_LIMIT, (
        f"超上限应返 {CODE_FAV_LIMIT},实际 {env.code}。"
        f"若仍为 403 → user-srv 未部署新版本"
    )
    assert env.msg, (
        "msg 不应为空——网关会按 msgError 码表回填「我的最爱数量已达上限」;"
        "为空说明 api-gateway/h5-gateway 未随 api-common 重新编译(这是最易漏的一步)"
    )


@pytest.mark.write
def test_over_limit_gif(dm_client, fav_cleaner):
    """GIF 类满 10 后第 11 个 → 40701(客户端 2026-08-10 实际反馈的场景;GIF pack_id 传空)。"""
    _fill_to_limit(dm_client, fav_cleaner, 2, "", "giflim")
    over = _IMG.format("giflim_over")
    fav_cleaner(2, over, "")
    env = dm_client.my_fav_add(fav_type=2, img_url=over, pack_id="")
    assert env.code == CODE_FAV_LIMIT, f"GIF 超上限应返 {CODE_FAV_LIMIT},实际 {env.code}"
    assert env.msg, "msg 不应为空(网关码表回填)"


@pytest.mark.write
def test_limit_is_per_type_not_global(dm_client, fav_cleaner):
    """分类计数:GIF 满 10 之后,贴图仍可正常收藏(证明上限不是全局共享)。"""
    _fill_to_limit(dm_client, fav_cleaner, 2, "", "isolgif")
    over = _IMG.format("isolgif_over")
    fav_cleaner(2, over, "")
    assert dm_client.my_fav_add(fav_type=2, img_url=over, pack_id="").code == CODE_FAV_LIMIT

    img = _IMG.format("isolsticker")
    fav_cleaner(1, img, "PACKISOL")
    dm_client.my_fav_add(fav_type=1, img_url=img, pack_id="PACKISOL").expect_ok()


@pytest.mark.write
def test_duplicate_add_at_limit_still_ok(dm_client, fav_cleaner):
    """满额时重复收藏"已收藏过的那条"应幂等返 200,不能误报超限
    (代码里 IsMyStickerFav 判重在计数之前,这条守住这个顺序)。"""
    used = _fill_to_limit(dm_client, fav_cleaner, 1, "PACKDUP", "dup")
    dm_client.my_fav_add(fav_type=1, img_url=used[0], pack_id="PACKDUP").expect_ok()


@pytest.mark.write
def test_gif_fav_no_pack_id(dm_client, fav_cleaner):
    # GIF(fav_type=2)pack_id 传空,应可收藏
    img = _IMG.format("gif")
    fav_cleaner(2, img, "")
    dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="").expect_ok()
