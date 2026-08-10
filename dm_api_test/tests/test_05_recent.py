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


# ============================================================
# 三类上限各不相同,且走同一个 switch 分支——GIF/emoji 两条分支此前从未执行过
# ============================================================
CAP_STICKER, CAP_GIF, CAP_EMOJI = 10, 20, 14
CODE_DEL_NOTHING = 40702


def _report_n(dm_client, recent_cleaner, fav_type, n, tag, pack_id=""):
    """按顺序上报 n 条,返回 img_url 列表(顺序=上报先后)。"""
    keys = []
    for i in range(n):
        if fav_type == 3:
            key = f"\U0001F600️{tag}{i}"  # emoji 类:key 放 img_url 位
        else:
            key = _IMG.format(f"{tag}{i}")
        recent_cleaner(fav_type, key, pack_id)
        dm_client.recent_report(fav_type, key, pack_id=pack_id).expect_ok()
        keys.append(key)
    return keys


@pytest.mark.write
def test_gif_cap_20_evicts_oldest(dm_client, recent_cleaner):
    """GIF 上限 20:报 21 条后只剩 20,最旧被淘汰、最新在。"""
    keys = _report_n(dm_client, recent_cleaner, 2, CAP_GIF + 1, "gifcap")
    urls = _urls(dm_client.recent_list(2).expect_ok())
    mine = [u for u in urls if u in keys]
    assert len(mine) == CAP_GIF, f"GIF 最近使用应恰为 {CAP_GIF} 条,实际 {len(mine)}"
    assert keys[0] not in urls, "最旧的一条应被淘汰"
    assert keys[-1] in urls, "最新的一条应保留"


@pytest.mark.write
def test_emoji_cap_14_evicts_oldest(dm_client, recent_cleaner):
    """emoji 上限 14(与贴图 10、GIF 20 都不同)。"""
    keys = _report_n(dm_client, recent_cleaner, 3, CAP_EMOJI + 1, "emocap")
    urls = _urls(dm_client.recent_list(3).expect_ok())
    mine = [u for u in urls if u in keys]
    assert len(mine) == CAP_EMOJI, f"emoji 最近使用应恰为 {CAP_EMOJI} 条,实际 {len(mine)}"
    assert keys[0] not in urls, "最旧的一条应被淘汰"
    assert keys[-1] in urls, "最新的一条应保留"


@pytest.mark.write
def test_eviction_scoped_by_fav_type(dm_client, recent_cleaner):
    """淘汰必须按类型隔离:贴图报满触发淘汰,不能顺带删掉 GIF/emoji 的记录
    (淘汰条件漏 fav_type 会造成无声的数据丢失)。"""
    gif = _IMG.format("scope_gif")
    emo = "\U0001F389️scope"
    recent_cleaner(2, gif, "")
    recent_cleaner(3, emo, "")
    dm_client.recent_report(2, gif, pack_id="").expect_ok()
    dm_client.recent_report(3, emo, pack_id="").expect_ok()

    _report_n(dm_client, recent_cleaner, 1, CAP_STICKER + 1, "scope_stk", pack_id="PACKSCOPE")

    assert gif in _urls(dm_client.recent_list(2).expect_ok()), "贴图淘汰不应影响 GIF"
    assert emo in _urls(dm_client.recent_list(3).expect_ok()), "贴图淘汰不应影响 emoji"


# ============================================================
# recent/del —— 与 my_fav/del 是各自独立的 handler 分支,需单独覆盖
# ============================================================

@pytest.mark.write
def test_del_nonexistent_id_returns_40702(dm_client, recent_cleaner):
    """删不存在的 id → 40702(不能静默返 200),且不影响已有记录。"""
    img = _IMG.format("delnone")
    recent_cleaner(2, img, "")
    dm_client.recent_report(2, img, pack_id="").expect_ok()

    env = dm_client.recent_del([99999999])
    assert env.code == CODE_DEL_NOTHING, (
        f"删除未命中应返 {CODE_DEL_NOTHING},实际 {env.code}(200 说明仍是静默假成功)"
    )
    assert env.msg, "msg 应带「删除失败:记录不存在或不属于当前用户」"
    assert img in _urls(dm_client.recent_list(2).expect_ok()), "删除失败不应影响其它记录"


@pytest.mark.write
def test_del_evicted_id_returns_40702(dm_client, recent_cleaner):
    """删一个"已被淘汰"的 id → 40702。这是 recent 独有场景(my_fav 无淘汰):
    客户端编辑态里拿的是旧列表,期间有新上报把它挤掉了,再点删除就会命中。
    口径:40702 = 该条已不存在,客户端本地移除即可,不应弹故障。"""
    keys = _report_n(dm_client, recent_cleaner, 1, CAP_STICKER, "evict", pack_id="PACKEVICT")
    rows = (dm_client.recent_list(1).expect_ok().data or {}).get("list") or []
    victim = next((r for r in rows if r.get("imgUrl") == keys[0]), None)
    assert victim is not None, "最旧一条此时应还在"

    extra = _IMG.format("evict_push")
    recent_cleaner(1, extra, "PACKEVICT")
    dm_client.recent_report(1, extra, pack_id="PACKEVICT").expect_ok()  # 挤掉 keys[0]

    dm_client.recent_del([victim["id"]]).expect(CODE_DEL_NOTHING)


@pytest.mark.write
def test_del_ids_boundaries(dm_client):
    """ids 边界:空串 400;逗号分隔(客户端最易用错的分隔符)400;超 30 个 400。"""
    dm_client.recent_del("").expect(400)
    dm_client.recent_del("1,2").expect(400)
    dm_client.recent_del(list(range(1, 32))).expect(400)


# ============================================================
# 取值域与 my_fav 相反,极易混
# ============================================================

@pytest.mark.write
def test_recent_list_rejects_fav_type_zero(dm_client):
    """recent/list 不接受 0(没有"全部"),而 my_fav/list 的 0 = 全部。
    两个接口枚举不同,客户端不可复用同一份取值域。"""
    dm_client.recent_list(0).expect(400)
    dm_client.recent_list(99).expect(400)


@pytest.mark.write
def test_report_sticker_without_pack_id_rejected(dm_client):
    """贴图上报必须带 pack_id → 缺失 400(my_fav 侧同规则,recent 侧此前未覆盖)。"""
    dm_client.recent_report(1, _IMG.format("nopack"), pack_id="").expect(400)


@pytest.mark.write
def test_recent_list_field_contract(dm_client, recent_cleaner):
    """字段契约:是 useTime 不是 favTime;id 可用于删除;写入值原样回显。"""
    img = _IMG.format("fields")
    recent_cleaner(2, img, "")
    dm_client.recent_report(2, img, pack_id="", file_name="a.gif", width=320, height=240).expect_ok()

    rows = (dm_client.recent_list(2).expect_ok().data or {}).get("list") or []
    row = next((r for r in rows if r.get("imgUrl") == img), None)
    assert row is not None, "刚上报的应在列表里"
    assert isinstance(row.get("id"), int) and row["id"] > 0, "id 须为正整数(删除用)"
    assert "useTime" in row, f"时间字段名应是 useTime(不是 favTime),实际键:{sorted(row)}"
    assert row.get("fileName") == "a.gif", "fileName 应原样回显"
    assert row.get("width") == 320 and row.get("height") == 240, "宽高应原样回显"
