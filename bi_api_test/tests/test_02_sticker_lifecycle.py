"""贴图包全生命周期:创建草稿 → 详情回显 → 编辑整包替换 → 上架 → 调序 → 下架 → 删除。"""

import pytest


@pytest.mark.write
def test_full_lifecycle(client, make_pack_payload):
    # 1) 创建草稿
    payload = make_pack_payload(status=3)
    env = client.sticker_create(**payload).expect_ok()
    pack_id = env.data["pack_id"]

    try:
        # 2) 详情回显:五语言、贴图明细
        detail = client.sticker_detail(pack_id).expect_ok().data
        assert detail["name_zh"] == payload["name_zh"]
        assert detail["name_vi"] == payload["name_vi"]
        assert detail["status"] == 3
        assert len(detail["stickers"]) == 1

        # 3) 编辑:整包替换为 2 张贴图 + 改名
        new_stickers = [
            {"img_url": "http://bi-sticker-selftest.invalid/a.png",
             "file_name": "a.png", "width": 200, "height": 200, "sort": 1},
            {"img_url": "http://bi-sticker-selftest.invalid/b.png",
             "file_name": "b.png", "width": 200, "height": 200, "sort": 2},
        ]
        upd = dict(payload)
        upd.pop("status", None)  # update 无 status 字段
        upd["pack_id"] = pack_id
        upd["name_zh"] = payload["name_zh"] + "改"
        upd["stickers"] = new_stickers
        client.sticker_update(**upd).expect_ok()

        detail = client.sticker_detail(pack_id).expect_ok().data
        assert detail["name_zh"].endswith("改"), "编辑后中文名未更新"
        assert len(detail["stickers"]) == 2, "贴图明细应被整包替换为 2 张"

        # 4) 上架
        client.sticker_update_status(pack_id, 1).expect_ok()
        assert client.sticker_detail(pack_id).expect_ok().data["status"] == 1

        # 5) 调整排序权重
        client.sticker_update_sort(pack_id, 999).expect_ok()
        assert client.sticker_detail(pack_id).expect_ok().data["sort_weight"] == 999

        # 6) 下架
        client.sticker_update_status(pack_id, 2).expect_ok()
        assert client.sticker_detail(pack_id).expect_ok().data["status"] == 2

        # 7) 下架后可删除
        client.sticker_delete(pack_id).expect_ok()
        # 删除后详情应查不到(ErrPackNotFound → 19307)
        client.sticker_detail(pack_id).expect(19307)
        pack_id = None
    finally:
        if pack_id:
            client.safe_delete(pack_id)
