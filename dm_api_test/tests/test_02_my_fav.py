"""我的最爱(单张收藏,贴图/GIF)。

契约(读 handler_sticker.go 核实):
  add: {fav_type(1贴图/2GIF,必填非0), img_url(必填), pack_id(贴图必填/GIF空), ...} → 200;幂等;每类>10 → 403
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


@pytest.mark.write
def test_over_limit_returns_403(dm_client, fav_cleaner):
    # 贴图类收藏满 10 后第 11 个 → 403(每类上限 10)
    for i in range(10):
        img = _IMG.format(f"lim{i}")
        fav_cleaner(1, img, "PACKLIMIT")
        dm_client.my_fav_add(fav_type=1, img_url=img, pack_id="PACKLIMIT").expect_ok()
    over = _IMG.format("lim_over")
    fav_cleaner(1, over, "PACKLIMIT")
    dm_client.my_fav_add(fav_type=1, img_url=over, pack_id="PACKLIMIT").expect(403)


@pytest.mark.write
def test_gif_fav_no_pack_id(dm_client, fav_cleaner):
    # GIF(fav_type=2)pack_id 传空,应可收藏
    img = _IMG.format("gif")
    fav_cleaner(2, img, "")
    dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="").expect_ok()
