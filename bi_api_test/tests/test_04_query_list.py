"""列表查询:分页信封、按状态/名称筛选。

响应形态:SuccessPage → data = {list: [...], total: N}
"""

import pytest


def test_list_envelope_shape(client):
    env = client.sticker_list(page=1, size=10).expect_ok()
    assert isinstance(env.data, dict)
    assert "list" in env.data and "total" in env.data
    assert isinstance(env.data["list"], list)


def test_list_pagination_size(client):
    env = client.sticker_list(page=1, size=2).expect_ok()
    assert len(env.data["list"]) <= 2, "返回条数不应超过 size"


@pytest.mark.write
def test_list_filter_by_status_and_name(client, make_pack_payload):
    # 造一个可辨识名称的上架包,验证按状态=已上架 + 名称模糊能命中
    payload = make_pack_payload(status=1)
    marker = payload["name_zh"]
    env = client.sticker_create(**payload).expect_ok()
    pack_id = env.data["pack_id"]
    try:
        res = client.sticker_list(page=1, size=50, status=1, name=marker).expect_ok()
        hit = [x for x in res.data["list"] if x.get("pack_id") == pack_id]
        assert hit, f"按 status=1 + name={marker} 未查到刚建的包"
        assert hit[0]["name_zh"] == marker
        assert hit[0]["status"] == 1
    finally:
        client.safe_delete(pack_id)


@pytest.mark.write
def test_list_status_filter_excludes(client, draft_pack):
    # draft_pack 是草稿(status=3);按 status=1(已上架)筛不应包含它
    res = client.sticker_list(page=1, size=100, status=1).expect_ok()
    ids = [x.get("pack_id") for x in res.data["list"]]
    assert draft_pack not in ids, "已上架筛选不应包含草稿包"
