"""最近使用(贴图/GIF 服务端化;每次发送 upsert use_time、超上限淘汰最旧)。

契约(读 handler_sticker.go/stickerDb.go 核实;emoji=fav_type3,key 存 img_url,上限14):
  report: {fav_type(1贴图/2GIF),img_url,pack_id(贴图必填/GIF空),...} → upsert;贴图上限10/GIF20,超量淘汰最旧
  list:   {fav_type} → {list:[{id,favType,packId,imgUrl,...,useTime}]},最近在前
  del:    {ids:"id1|id2"} 按行 id 批量删(id 取自 list;网关签名要求扁平串,不能传嵌套数组)
注意:用例会写该用户真实"最近使用"(测试环境账号),结束自动清理;超上限用例会挤掉该用户既有最近使用(可接受,本就 ephemeral)。
"""

import pytest

_IMG = "http://dm-selftest.invalid/recent_{}.webp"


def _urls(env):
    data = env.data or {}
    return [x.get("imgUrl") for x in (data.get("list") or [])]


@pytest.mark.write
def test_report_and_list(dm_client, recent_cleaner):
    img = _IMG.format("r1")
    recent_cleaner(1, img, "PACKR")
    dm_client.recent_report(1, img, pack_id="PACKR", file_name="r1.webp", width=240, height=240).expect_ok()
    assert img in _urls(dm_client.recent_list(1).expect_ok()), "上报后列表应含该图"


@pytest.mark.write
def test_report_idempotent(dm_client, recent_cleaner):
    img = _IMG.format("idem")
    recent_cleaner(1, img, "PACKR")
    dm_client.recent_report(1, img, pack_id="PACKR").expect_ok()
    dm_client.recent_report(1, img, pack_id="PACKR").expect_ok()  # 再报一次
    urls = _urls(dm_client.recent_list(1).expect_ok())
    assert urls.count(img) == 1, "同一条重复上报应只留一条(upsert 刷新 use_time)"


@pytest.mark.write
def test_over_cap_evicts_oldest(dm_client, recent_cleaner):
    # 报 11 个(贴图上限 10)→ 最旧被淘汰:列表 ≤10、最新在、我方最旧那条不在
    imgs = [_IMG.format(f"cap{i}") for i in range(11)]
    for im in imgs:
        recent_cleaner(1, im, "PACKCAP")
        dm_client.recent_report(1, im, pack_id="PACKCAP").expect_ok()
    urls = _urls(dm_client.recent_list(1).expect_ok())
    assert len(urls) <= 10, f"贴图最近使用应 ≤10,实际 {len(urls)}"
    assert imgs[0] not in urls, "最旧的一条应被淘汰"
    assert imgs[-1] in urls, "最新的一条应在"


@pytest.mark.write
def test_del(dm_client, recent_cleaner):
    img = _IMG.format("del")
    recent_cleaner(1, img, "PACKR")
    dm_client.recent_report(1, img, pack_id="PACKR").expect_ok()
    rows = (dm_client.recent_list(1).expect_ok().data or {}).get("list") or []
    rid = next(x["id"] for x in rows if x.get("imgUrl") == img)
    dm_client.recent_del([rid]).expect_ok()
    assert img not in _urls(dm_client.recent_list(1).expect_ok()), "删除后列表不应再有"


@pytest.mark.write
def test_gif_recent_no_pack_id(dm_client, recent_cleaner):
    img = _IMG.format("gif")
    recent_cleaner(2, img, "")
    dm_client.recent_report(2, img, pack_id="").expect_ok()
    assert img in _urls(dm_client.recent_list(2).expect_ok()), "GIF 最近使用应含该图"


@pytest.mark.write
def test_emoji_recent(dm_client, recent_cleaner):
    # emoji 最近使用(fav_type=3):无 URL/pack_id,emoji key 放 img_url 位;上限 14
    key = "\U0001F602"  # 😂
    recent_cleaner(3, key, "")
    dm_client.recent_report(3, key, pack_id="").expect_ok()
    urls = _urls(dm_client.recent_list(3).expect_ok())
    assert key in urls, "emoji 最近使用应含该表情 key"


def test_report_fav_type_zero_rejected(dm_client):
    # fav_type=0 触发网关 required → 400
    dm_client.call("/user/sticker/recent/report",
                   {"img_url": _IMG.format("z")}).expect(400)
