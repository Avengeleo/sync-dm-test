"""bi-admin 套件的 fixtures(配置读 BI_* 环境变量;.env 由根 conftest 加载)。"""

import os

import pytest

from bi_api_test.client import BiAdminClient

# happy-path 托盘图标:.invalid 保留域名永不解析 → 服务端 fetch 失败 → fail-open 放行
TRAY_ICON_FAILOPEN = "http://bi-sticker-selftest.invalid/tray_96.png"


def _cfg():
    return {
        "base_url": os.environ.get("BI_BASE_URL", "http://127.0.0.1:8094"),
        "username": os.environ.get("BI_USERNAME", ""),
        "password": os.environ.get("BI_PASSWORD", ""),
        "tray_ok": os.environ.get("BI_TRAY_ICON_OK", ""),
        "tray_bad": os.environ.get("BI_TRAY_ICON_BAD", ""),
        "timeout": int(os.environ.get("BI_HTTP_TIMEOUT", "15")),
    }


@pytest.fixture(scope="session")
def config():
    c = _cfg()
    if not c["username"] or not c["password"]:
        pytest.skip("未配置 BI_USERNAME / BI_PASSWORD(见根目录 .env.example),跳过 bi 套件")
    return c


@pytest.fixture(scope="session")
def anon_client(config):
    return BiAdminClient(config["base_url"], timeout=config["timeout"])


@pytest.fixture(scope="session")
def client(config):
    c = BiAdminClient(config["base_url"], timeout=config["timeout"])
    try:
        c.login(config["username"], config["password"])
    except Exception as e:
        pytest.skip(f"bi 登录失败,后续用例无法进行:{e}")
    return c


@pytest.fixture
def tray_icon_failopen():
    return TRAY_ICON_FAILOPEN


def _base_pack_payload(tray_icon, suffix):
    return {
        "name_zh": f"自测包{suffix}",
        "name_en": f"selftest{suffix}",
        "name_th": f"th{suffix}",
        "name_tw": f"繁體{suffix}",
        "name_vi": f"vi{suffix}",
        "publisher": "自测机器人",
        "tray_icon": tray_icon,
        "sort_weight": 10,
        "is_platform_issued": 0,
        "status": 3,
        "stickers": [
            {
                "img_url": "http://bi-sticker-selftest.invalid/s1.png",
                "file_name": "s1.png",
                "width": 240,
                "height": 240,
                "sort": 1,
            }
        ],
    }


@pytest.fixture
def make_pack_payload():
    counter = {"n": 0}

    def _factory(**overrides):
        counter["n"] += 1
        payload = _base_pack_payload(TRAY_ICON_FAILOPEN, counter["n"])
        payload.update(overrides)
        return payload

    return _factory


@pytest.fixture
def draft_pack(client, make_pack_payload):
    env = client.sticker_create(**make_pack_payload(status=3)).expect_ok()
    pack_id = env.data["pack_id"]
    yield pack_id
    client.safe_delete(pack_id)
