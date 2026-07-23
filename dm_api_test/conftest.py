"""dm-api 套件 fixtures(读 DM_API_* 环境变量;.env 由根 conftest 加载)。

需要的 .env 值(见根 .env.example 的 dm-api 段):
  DM_API_BASE_URL   dev 网关域名(到 scheme://host,不带 /api 前缀)
  DM_API_PREFIX     版本前缀,默认 /api/v2(APP 网关);H5 用 /api/h5
  DM_API_APP_ID     sys_apps 表里一条 is_enabled=1 的 app_id
  DM_API_APP_SECRET 该 app_id 对应的 app_secrect(库查)
  DM_API_WIPS       Encversion 旁路值(跳过 AES;配置/运维取,或抓真实请求的 Encversion 头)
  DM_API_TOKEN      一个有效用户会话 token(live 抓,如 H5 devtools)
  DM_API_CLIENT_TYPE 可选,部分接口要 Client-type(1=app/2=pc/3=web)
"""

import os

import pytest

from dm_api_test.client import DmApiClient


def _clean(key):
    """读环境值:去首尾空白;若误把行内注释(# 开头)当成了值,视为空。"""
    v = os.environ.get(key, "").strip()
    if v.startswith("#"):
        return ""
    return v


def _cfg():
    return {
        "base_url": _clean("DM_API_BASE_URL"),
        "prefix": _clean("DM_API_PREFIX") or "/api/h5",
        "app_id": _clean("DM_API_APP_ID"),
        "app_secret": _clean("DM_API_APP_SECRET"),
        "wips": _clean("DM_API_WIPS"),
        "token": _clean("DM_API_TOKEN"),
        "client_type": _clean("DM_API_CLIENT_TYPE"),
        "timeout": int(_clean("BI_HTTP_TIMEOUT") or "15"),
    }


@pytest.fixture(scope="session")
def dm_config():
    c = _cfg()
    missing = [k for k in ("base_url", "app_id", "app_secret", "wips", "token") if not c[k]]
    if missing:
        pytest.skip(f"dm-api 未配置:缺 {', '.join('DM_API_' + m.upper() for m in missing)}(见根 .env.example),跳过 dm-api 套件")
    return c


@pytest.fixture(scope="session")
def dm_client(dm_config):
    return DmApiClient(
        base_url=dm_config["base_url"],
        app_id=dm_config["app_id"],
        app_secret=dm_config["app_secret"],
        token=dm_config["token"],
        wips=dm_config["wips"],
        prefix=dm_config["prefix"],
        client_type=dm_config["client_type"],
        timeout=dm_config["timeout"],
    )


@pytest.fixture
def fav_cleaner(dm_client):
    """记录本用例添加的收藏,结束时批量删除,避免污染该用户真实收藏。"""
    added = []  # [{"fav_type","pack_id","img_url"}]

    def _track(fav_type, img_url, pack_id=""):
        added.append({"fav_type": fav_type, "pack_id": pack_id, "img_url": img_url})

    yield _track
    if added:
        try:
            dm_client.my_fav_del(added)
        except Exception:
            pass
