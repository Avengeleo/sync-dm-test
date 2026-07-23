"""真实数据回放:客户端(DEV)实际提交的创建载荷,原样打一遍。

来源:2026-07 前端联调时客户端发来的 /admin/sticker/create CURL。
用途:数据库建错库修复后,用真实数据端到端确认 create 通(平台发行包 + 20 张贴图 + 真实 tray_icon)。
注意:tray_icon 是真实 S3 图,服务端会拉取校验 96x96——若该图非 96x96,create 返 19311(与 DB 无关),
     断言失败信息会直接显示 code=19311,据此判断是"托盘图尺寸"而非"表"的问题。
"""

import pytest

# S3 域名(客户端真实上传桶)
_S3 = "https://aws-bucket-9527.s3.ap-northeast-1.amazonaws.com"

CLIENT_PAYLOAD = {
    "name_zh": "测试1-中文",
    "name_en": "测试1-英文",
    "name_th": "测试1-泰文",
    "name_tw": "测试1-繁体",
    "name_vi": "测试1-越南文",
    "publisher": "KK官方",
    "tray_icon": f"{_S3}/n6aSaBCeBpE1JtgSU0.png",
    "sort_weight": 0,
    "is_platform_issued": 1,  # 平台发行(小金刚)
    "status": 1,              # 立即上架
    "stickers": [
        {"img_url": f"{_S3}/teiYLBKKqkVqOnRF75.webp", "file_name": "14_3x.webp", "width": 384, "height": 384, "sort": 1},
        {"img_url": f"{_S3}/516NJf6ZrK0DxXiBUj.webp", "file_name": "09_3x.webp", "width": 384, "height": 384, "sort": 2},
        {"img_url": f"{_S3}/meMdpjgBLmNRiDJ3Pm.webp", "file_name": "19_3x.webp", "width": 384, "height": 384, "sort": 3},
        {"img_url": f"{_S3}/hvkM00vORQDB0aqwX8.webp", "file_name": "17_3x.webp", "width": 384, "height": 384, "sort": 4},
        {"img_url": f"{_S3}/Ehr7YoHojcs7ISXOMJ.webp", "file_name": "20_3x.webp", "width": 384, "height": 384, "sort": 5},
        {"img_url": f"{_S3}/o4yZEBnJB5iVH0Vdnm.webp", "file_name": "13_3x.webp", "width": 384, "height": 384, "sort": 6},
        {"img_url": f"{_S3}/dpnBGK2uzKv76B1IEN.webp", "file_name": "03_3x.webp", "width": 384, "height": 384, "sort": 7},
        {"img_url": f"{_S3}/7Dx58u92ou21zNeerA.webp", "file_name": "02_3x.webp", "width": 384, "height": 384, "sort": 8},
        {"img_url": f"{_S3}/CsJNmu5W8FZhnTygrA.webp", "file_name": "10_3x.webp", "width": 384, "height": 384, "sort": 9},
        {"img_url": f"{_S3}/bbAxHeDp3AIRozGvRi.webp", "file_name": "07_3x.webp", "width": 384, "height": 384, "sort": 10},
        {"img_url": f"{_S3}/uoJO4hNGImnEStlfub.webp", "file_name": "05_3x.webp", "width": 384, "height": 384, "sort": 11},
        {"img_url": f"{_S3}/DncagxggF7pKAB5IIt.webp", "file_name": "16_3x.webp", "width": 384, "height": 384, "sort": 12},
        {"img_url": f"{_S3}/dtbtX6BPmCuTL9jygP.webp", "file_name": "18_3x.webp", "width": 384, "height": 384, "sort": 13},
        {"img_url": f"{_S3}/LUhmwwt9t5aCHmmkAs.webp", "file_name": "08_3x.webp", "width": 384, "height": 384, "sort": 14},
        {"img_url": f"{_S3}/UwCVYkzSlqaiK7iFaR.webp", "file_name": "06_3x.webp", "width": 384, "height": 384, "sort": 15},
        {"img_url": f"{_S3}/VXorI77zYICDOJhS4t.webp", "file_name": "12_3x.webp", "width": 384, "height": 384, "sort": 16},
        {"img_url": f"{_S3}/dcjg19QNGVHMJzxDY3.webp", "file_name": "01_3x.webp", "width": 384, "height": 384, "sort": 17},
        {"img_url": f"{_S3}/DysxXs9mHKfWWFYMJw.webp", "file_name": "15_3x.webp", "width": 384, "height": 384, "sort": 18},
        {"img_url": f"{_S3}/qHCu5uLRjuKxPFmChj.webp", "file_name": "04_3x.webp", "width": 384, "height": 384, "sort": 19},
        {"img_url": f"{_S3}/y9BSgvU8XctP7NyK1S.webp", "file_name": "11_3x.webp", "width": 384, "height": 384, "sort": 20},
    ],
}


@pytest.mark.write
def test_create_from_real_client_payload(client):
    env = client.sticker_create(**CLIENT_PAYLOAD).expect_ok()
    pack_id = env.data["pack_id"]
    try:
        detail = client.sticker_detail(pack_id).expect_ok().data
        assert detail["is_platform_issued"] == 1, "应为平台发行包"
        assert detail["status"] == 1, "应立即上架"
        assert len(detail["stickers"]) == 20, "20 张贴图应全部落库"
        assert detail["name_zh"] == "测试1-中文"
    finally:
        client.safe_delete(pack_id)
