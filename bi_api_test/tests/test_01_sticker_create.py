"""创建接口的参数校验矩阵。

错误码(读 response_type.go 核实):
  19307 参数不完整(五语言/发行者/托盘图标必填、名称超 50、status 非 1/3)
  19308 单包贴图 > 30
"""

import pytest


@pytest.mark.write
def test_create_draft_ok(client, make_pack_payload):
    env = client.sticker_create(**make_pack_payload(status=3)).expect_ok()
    pack_id = env.data["pack_id"]
    assert pack_id.startswith("PACK"), f"包ID 形态应为 PACK+顺序号:{pack_id}"
    client.safe_delete(pack_id)


@pytest.mark.write
def test_create_online_ok(client, make_pack_payload):
    env = client.sticker_create(**make_pack_payload(status=1)).expect_ok()
    pack_id = env.data["pack_id"]
    detail = client.sticker_detail(pack_id).expect_ok()
    assert detail.data["status"] == 1, "立即上架后状态应为已上架(1)"
    client.safe_delete(pack_id)


def test_create_missing_name_zh(client, make_pack_payload):
    client.sticker_create(**make_pack_payload(name_zh="")).expect(19307)


def test_create_name_too_long(client, make_pack_payload):
    client.sticker_create(**make_pack_payload(name_en="x" * 51)).expect(19307)


def test_create_missing_publisher(client, make_pack_payload):
    client.sticker_create(**make_pack_payload(publisher="")).expect(19307)


def test_create_missing_tray_icon(client, make_pack_payload):
    client.sticker_create(**make_pack_payload(tray_icon="")).expect(19307)


def test_create_invalid_status(client, make_pack_payload):
    # status 只能 1(上架)/3(草稿),传 2 应判参数不完整
    client.sticker_create(**make_pack_payload(status=2)).expect(19307)


def test_create_too_many_stickers(client, make_pack_payload):
    stickers = [
        {
            "img_url": f"http://bi-sticker-selftest.invalid/s{i}.png",
            "file_name": f"s{i}.png",
            "width": 240,
            "height": 240,
            "sort": i,
        }
        for i in range(1, 32)  # 31 张 > 30 上限
    ]
    client.sticker_create(**make_pack_payload(stickers=stickers)).expect(19308)
