"""ZIP 批量导入。

错误码(读 zip_import.go 核实,失败用例均在「第一遍预检」返回,不触达 S3):
  19309 ZIP 解析失败(坏 zip 字节 / 解压总量超限)
  19310 ZIP 内含非图片后缀 / 单张超限 / 解码失败 / 空包
  19308 图片条目 > 30

正例会真正上传 S3 并返回 CDN URL,故打 @s3 标记(需测试环境 S3 可用)。
"""

import pytest

from common.assets import zip_of_pngs, make_zip, make_png


@pytest.mark.s3
def test_zip_import_ok(client):
    zip_bytes = zip_of_pngs(3, width=200, height=200)
    env = client.sticker_zip_import(zip_bytes).expect_ok()
    items = env.data["items"]
    assert len(items) == 3, "应解析出 3 张"
    for it in items:
        assert it["width"] == 200 and it["height"] == 200, "宽高应由服务端解码回填"
        assert it["img_url"], "应返回 CDN URL"
        assert it["file_name"].endswith(".png")


def test_zip_bad_bytes(client):
    # 非 zip 字节 → 打不开 → 19309
    client.sticker_zip_import(b"this is not a zip file at all").expect(19309)


def test_zip_non_image_entry(client):
    # 含 .txt 非图片后缀 → 19310
    zip_bytes = make_zip({"readme.txt": b"hello", "a.png": make_png(96, 96)})
    client.sticker_zip_import(zip_bytes).expect(19310)


def test_zip_empty(client):
    # 空 zip(0 图片条目)→ 19310
    client.sticker_zip_import(make_zip({})).expect(19310)


def test_zip_too_many_entries(client):
    # 31 张合法 PNG > 30 上限 → 19308(条目数超限在预检返回,不上传 S3)
    zip_bytes = zip_of_pngs(31, width=32, height=32)
    client.sticker_zip_import(zip_bytes).expect(19308)


def test_zip_ignores_macosx_junk(client):
    # __MACOSX/ 与点开头条目应被静默跳过;若只剩这些则视为空包 → 19310
    zip_bytes = make_zip({
        "__MACOSX/._a.png": b"junk",
        ".DS_Store": b"junk",
    })
    client.sticker_zip_import(zip_bytes).expect(19310)
