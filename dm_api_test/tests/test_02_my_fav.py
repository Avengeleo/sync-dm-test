"""我的最爱(单张收藏,贴图/GIF)。

契约(读 handler_sticker.go 核实):
  add: {fav_type(1贴图/2GIF,必填非0), img_url(必填), pack_id(贴图必填/GIF空), ...} → 200;幂等;
       每类满 10 → 40701「我的最爱数量已达上限」(2026-08-10 由 403 改;403 在本项目是鉴权
       语义——见 test_00_smoke 的「403 → token 被冻结」,两者撞码客户端无法区分)
  list: {fav_type(0全部/1/2)} → {list:[{id,favType,packId,imgUrl,...,favTime}]},最新在前
  del: {ids:"id1|id2"} 按行 id 批量删(id 取自 list;网关签名要求扁平串,不能传嵌套数组)
  收藏存快照(不校验贴图是否真存在),故用例可用任意 pack_id+img_url,自成一体。

参数校验(两道:网关 binding + user-srv):
  add  fav_type 必填非0且∈{1,2}(3=emoji 只用于 recent,这里非法) / img_url 必填且≤512
       / file_name ≤128 / 贴图(1)必须带 pack_id、GIF(2)传空 → 违反均 400
  list fav_type ∈{0,1,2},否则 400
  del  ids 必填、解析后 1..30 个,否则 400;脏段(空/非数字)跳过不报错
业务码:40701 数量已达上限 / 40702 删除未命中任何行(id 不存在或不属于本人)
"""

import pytest

_IMG = "http://dm-selftest.invalid/fav_{}.webp"

# 本套件写入的收藏都带这些特征,清理时据此识别(绝不会误伤该账号的真实收藏)
_SELFTEST_MARKS = ("http://dm-selftest.invalid/", "DRIVkLoKs8Gpi8QpXH")


def _purge_selftest_favs(dm_client):
    """删掉本套件遗留的测试收藏。
    每类上限只有 10,任何一条用例残留都会让后续用例误报超限(表现为"时好时坏"),
    因此每条用例开始前强制清场,保证用例之间完全隔离。"""
    for ft in (1, 2):
        try:
            rows = (dm_client.my_fav_list(fav_type=ft).data or {}).get("list") or []
        except Exception:
            continue
        ids = [r["id"] for r in rows
               if any(m in str(r.get("imgUrl", "")) for m in _SELFTEST_MARKS) and r.get("id")]
        for i in range(0, len(ids), 30):  # del 单次上限 30
            try:
                dm_client.my_fav_del(ids[i:i + 30])
            except Exception:
                pass


@pytest.fixture(autouse=True)
def _isolate_favs(dm_client):
    """用例间隔离:开始前清场(结束后由各用例的 fav_cleaner 收尾)。"""
    _purge_selftest_favs(dm_client)
    yield


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


# 删除未命中任何行的业务码(2026-08-10 新增)。原先无论删掉几行都返 200,
# 客户端"移除成功"但库里没减,再收藏就撞 40701——正是本次线上反馈的现象。
CODE_DEL_NOTHING = 40702


@pytest.mark.write
def test_delete_then_add_at_limit(dm_client, fav_cleaner):
    """复现客户端反馈:GIF 满 10 → 删掉 1 个 → 再添加应当成功(不能再返 40701)。"""
    _fill_to_limit(dm_client, fav_cleaner, 2, "", "delre")

    rows = (dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or []
    assert len(rows) >= FAV_LIMIT_PER_TYPE, f"应已满 {FAV_LIMIT_PER_TYPE},实际 {len(rows)}"

    # 用 list 返回的真实行 id 删一条
    dm_client.my_fav_del([rows[0]["id"]]).expect_ok()

    after = (dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or []
    assert len(after) == len(rows) - 1, (
        f"删除后应少一条(删前 {len(rows)}、删后 {len(after)});数量没变说明删除是静默假成功"
    )

    # 腾出位置后再添加,必须成功
    img = _IMG.format("delre_new")
    fav_cleaner(2, img, "")
    dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="").expect_ok()


@pytest.mark.write
def test_delete_bad_id_reports_error(dm_client, fav_cleaner):
    """传不存在的 id → 40702,不能静默返 200
    (静默成功正是"客户端以为删了、其实没删"的根因)。"""
    img = _IMG.format("badid")
    fav_cleaner(2, img, "")
    dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="").expect_ok()

    env = dm_client.my_fav_del([99999999])  # 不存在的行 id
    assert env.code == CODE_DEL_NOTHING, (
        f"删除未命中任何行应返 {CODE_DEL_NOTHING},实际 {env.code}。"
        f"若为 200 → user-srv 未部署本次修复"
    )
    assert env.msg, "msg 应带「删除失败:记录不存在或不属于当前用户」"

    # 该条收藏应仍在(证明确实没误删)
    urls = [x.get("imgUrl") for x in ((dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or [])]
    assert img in urls, "删除失败时不应影响其它收藏"


# ============================================================
# 参数校验(客户端最容易踩;两道校验:网关 binding + user-srv)
# ============================================================

@pytest.mark.write
def test_reject_img_url_too_long(dm_client):
    """img_url 超 512 字符 → 400(与 DB varchar(512) 对齐,避免写入截断)。"""
    long_url = "http://dm-selftest.invalid/" + ("x" * 520) + ".webp"
    dm_client.my_fav_add(fav_type=2, img_url=long_url, pack_id="").expect(400)


@pytest.mark.write
def test_reject_file_name_too_long(dm_client):
    """file_name 超 128 字符 → 400(对齐 DB varchar(128))。"""
    dm_client.my_fav_add(fav_type=2, img_url=_IMG.format("longname"), pack_id="",
                         file_name="n" * 200).expect(400)


@pytest.mark.write
def test_reject_emoji_fav_type(dm_client):
    """fav_type=3(emoji)不属于「我的最爱」→ 400。
    emoji 只在「最近使用」里用 fav_type=3,两个接口的取值域不同,易混。"""
    dm_client.my_fav_add(fav_type=3, img_url="\U0001F602", pack_id="").expect(400)


@pytest.mark.write
def test_reject_unknown_fav_type(dm_client):
    """未知 fav_type(99)→ 400,不能落库成脏数据。"""
    dm_client.my_fav_add(fav_type=99, img_url=_IMG.format("badtype"), pack_id="").expect(400)


@pytest.mark.write
def test_reject_sticker_without_pack_id(dm_client):
    """贴图(fav_type=1)必须带 pack_id → 缺失返 400。"""
    dm_client.my_fav_add(fav_type=1, img_url=_IMG.format("nopack"), pack_id="").expect(400)


@pytest.mark.write
def test_reject_empty_img_url(dm_client):
    """img_url 为空 → 400(网关 binding:required 拦下)。"""
    dm_client.my_fav_add(fav_type=2, img_url="", pack_id="").expect(400)


@pytest.mark.write
def test_list_reject_invalid_fav_type(dm_client):
    """list 的 fav_type 只接受 0/1/2,传 3 → 400。"""
    dm_client.my_fav_list(fav_type=3).expect(400)


# ============================================================
# 响应契约:客户端要靠这些字段做展示与删除
# ============================================================

@pytest.mark.write
def test_response_fields_complete_and_roundtrip(dm_client, fav_cleaner):
    """add 传入的字段应原样回显,且 id/favTime 可用——客户端拿这些渲染和删除。"""
    img = _IMG.format("fields")
    fav_cleaner(2, img, "")
    dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="",
                         file_name="cat_dance.gif", width=480, height=360).expect_ok()

    rows = (dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or []
    row = next((r for r in rows if r.get("imgUrl") == img), None)
    assert row is not None, "刚收藏的应出现在列表里"

    # 字段名用 camelCase(响应侧约定),值应与写入一致
    assert row.get("favType") == 2, f"favType 应为 2,实际 {row.get('favType')}"
    assert row.get("fileName") == "cat_dance.gif", f"fileName 未原样回显:{row.get('fileName')}"
    assert row.get("width") == 480 and row.get("height") == 360, (
        f"宽高未原样回显:{row.get('width')}x{row.get('height')}"
    )
    assert isinstance(row.get("id"), int) and row["id"] > 0, (
        f"id 必须是正整数(删除要用它),实际 {row.get('id')!r}"
    )
    assert isinstance(row.get("favTime"), int) and row["favTime"] > 1_600_000_000, (
        f"favTime 应是 unix 秒,实际 {row.get('favTime')!r}"
    )
    # GIF 的 packId 为空串(proto3 零值可能被省略,两种都接受)
    assert row.get("packId", "") == "", f"GIF 的 packId 应为空,实际 {row.get('packId')!r}"


@pytest.mark.write
def test_list_newest_first_and_ids_unique(dm_client, fav_cleaner):
    """列表按最新在前;id 唯一(客户端按 id 去重/删除)。"""
    imgs = []
    for i in range(3):
        img = _IMG.format(f"order{i}")
        fav_cleaner(2, img, "")
        dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="").expect_ok()
        imgs.append(img)

    rows = (dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or []
    mine = [r for r in rows if r.get("imgUrl") in imgs]
    assert len(mine) == 3, f"应能查到刚加的 3 条,实际 {len(mine)}"

    got_order = [r["imgUrl"] for r in mine]
    assert got_order == list(reversed(imgs)), f"应最新在前,实际顺序 {got_order}"

    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids)), "列表中 id 不应重复"


@pytest.mark.write
def test_list_all_types_mixed(dm_client, fav_cleaner):
    """fav_type=0 返回贴图+GIF 混合(客户端"全部"Tab 用)。"""
    gif = _IMG.format("mixgif")
    stk = _IMG.format("mixstk")
    fav_cleaner(2, gif, "")
    fav_cleaner(1, stk, "PACKMIX")
    dm_client.my_fav_add(fav_type=2, img_url=gif, pack_id="").expect_ok()
    dm_client.my_fav_add(fav_type=1, img_url=stk, pack_id="PACKMIX").expect_ok()

    rows = (dm_client.my_fav_list(fav_type=0).expect_ok().data or {}).get("list") or []
    urls = [r.get("imgUrl") for r in rows]
    assert gif in urls and stk in urls, "fav_type=0 应同时包含贴图与 GIF"
    types = {r.get("favType") for r in rows if r.get("imgUrl") in (gif, stk)}
    assert types == {1, 2}, f"混合列表应含两种 favType,实际 {types}"


# ============================================================
# 真实客户端场景
# ============================================================

@pytest.mark.write
def test_real_giphy_url_with_query_string(dm_client, fav_cleaner):
    """真实 giphy URL 带 ?&= 等 query 参数(客户端实际传的形态),
    须能原样存取——URL 被截断或转义会导致客户端取回后加载不出图。"""
    url = ("https://media4.giphy.com/media/DRIVkLoKs8Gpi8QpXH/giphy.gif"
           "?cid=b1a85744es5ifps0nexeyiex&ep=v1_gifs_trending&rid=giphy.gif&ct=g")
    fav_cleaner(2, url, "")
    dm_client.my_fav_add(fav_type=2, img_url=url, pack_id="",
                         file_name="DRIVkLoKs8Gpi8QpXH", width=480, height=480).expect_ok()

    rows = (dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or []
    got = next((r for r in rows if r.get("imgUrl") == url), None)
    assert got is not None, (
        "带 query string 的真实 GIF URL 应原样存回;"
        f"实际列表中的 URL:{[r.get('imgUrl') for r in rows][:3]}"
    )


# ============================================================
# 删除边界(本次线上问题所在,重点覆盖)
# ============================================================

@pytest.mark.write
def test_delete_multiple_at_once(dm_client, fav_cleaner):
    """一次删多条:全部消失,且未误删其它条目。"""
    imgs = []
    for i in range(3):
        img = _IMG.format(f"multi{i}")
        fav_cleaner(2, img, "")
        dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="").expect_ok()
        imgs.append(img)
    keep = _IMG.format("multi_keep")
    fav_cleaner(2, keep, "")
    dm_client.my_fav_add(fav_type=2, img_url=keep, pack_id="").expect_ok()

    rows = (dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or []
    del_ids = [r["id"] for r in rows if r.get("imgUrl") in imgs]
    assert len(del_ids) == 3
    dm_client.my_fav_del(del_ids).expect_ok()

    after = [r.get("imgUrl") for r in ((dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or [])]
    assert all(i not in after for i in imgs), "三条应全部删除"
    assert keep in after, "未指定的收藏不应被误删"


@pytest.mark.write
def test_delete_partial_match_still_ok(dm_client, fav_cleaner):
    """ids 里混有无效 id:有效的照删、整体返 200(幂等语义),
    只有一条都没命中才返 40702。"""
    img = _IMG.format("partial")
    fav_cleaner(2, img, "")
    dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="").expect_ok()

    rows = (dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or []
    real_id = next(r["id"] for r in rows if r.get("imgUrl") == img)

    dm_client.my_fav_del([real_id, 99999998]).expect_ok()  # 一真一假
    after = [r.get("imgUrl") for r in ((dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or [])]
    assert img not in after, "有效 id 对应的收藏应被删除"


@pytest.mark.write
def test_delete_twice_second_reports_not_matched(dm_client, fav_cleaner):
    """重复删同一个 id:第一次 200,第二次 40702(已不存在)。
    客户端连点两次删除时,第二次的 40702 属预期,不应视为故障。"""
    img = _IMG.format("twice")
    fav_cleaner(2, img, "")
    dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="").expect_ok()

    rows = (dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or []
    fid = next(r["id"] for r in rows if r.get("imgUrl") == img)

    dm_client.my_fav_del([fid]).expect_ok()
    dm_client.my_fav_del([fid]).expect(CODE_DEL_NOTHING)


@pytest.mark.write
def test_delete_rejects_empty_and_oversized_ids(dm_client):
    """ids 为空串 → 400(网关 binding);超过 30 个 → 400(防滥用)。"""
    dm_client.my_fav_del("").expect(400)
    dm_client.my_fav_del(list(range(1, 32))).expect(400)  # 31 个


@pytest.mark.write
def test_delete_ignores_malformed_id_segments(dm_client, fav_cleaner):
    """ids 串里混入空段/非数字("12||abc|13")应被跳过而非整体失败:
    有效 id 仍需删除成功——防止客户端拼串时多个竖线就全军覆没。"""
    img = _IMG.format("dirty")
    fav_cleaner(2, img, "")
    dm_client.my_fav_add(fav_type=2, img_url=img, pack_id="").expect_ok()

    rows = (dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or []
    fid = next(r["id"] for r in rows if r.get("imgUrl") == img)

    dm_client.my_fav_del(f"{fid}||abc| ").expect_ok()
    after = [r.get("imgUrl") for r in ((dm_client.my_fav_list(fav_type=2).expect_ok().data or {}).get("list") or [])]
    assert img not in after, "脏段应被跳过,有效 id 仍要删掉"
