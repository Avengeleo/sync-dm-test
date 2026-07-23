"""IM 套件 fixtures(读 IM_* 环境变量;.env 由根 conftest 加载)。

需要的 .env 值:
  IM_WS_URL    H5 的 WebSocket 地址(devtools → Network → WS 那条,如 wss://imws.ramon2025.com/)
  IM_USER_ID   你的 user_id(库 users 表按手机号查,或 H5 app 里)
  IM_TOKEN     IM 登录 token(login-srv 走 identify-srv 校验;多半就是 DM_API_TOKEN 那个)
  IM_CLIENT_TYPE 可选,默认 2(web/H5)
"""

import os

import pytest

from im_test.client import ImWsClient, NON_ERR


def _clean(key):
    v = os.environ.get(key, "").strip()
    return "" if v.startswith("#") else v


def _cfg():
    return {
        "url": _clean("IM_WS_URL"),
        "user_id": _clean("IM_USER_ID"),
        "token": _clean("IM_TOKEN"),
        "client_type": int(_clean("IM_CLIENT_TYPE") or "2"),
        "timeout": int(_clean("IM_TIMEOUT") or "10"),
    }


_ENV_NAME = {"url": "IM_WS_URL", "user_id": "IM_USER_ID", "token": "IM_TOKEN"}


@pytest.fixture(scope="session")
def im_config():
    c = _cfg()
    missing = [_ENV_NAME[k] for k in ("url", "user_id", "token") if not c[k]]
    if missing:
        pytest.skip(f"IM 未配置:缺 {', '.join(missing)}(见根 .env.example),跳过 IM 套件")
    return c


@pytest.fixture
def im_client(im_config):
    """已连接、未登录(供登录用例自己测 login)。"""
    c = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type"], im_config["timeout"])
    try:
        c.connect()
    except Exception as e:
        pytest.skip(f"IM WebSocket 连接失败:{e}(检查 IM_WS_URL / VPN)")
    yield c
    c.close()


@pytest.fixture
def logged_in_client(im_client):
    """已连接且已登录。"""
    err = im_client.login()
    if err != NON_ERR:
        pytest.skip(f"IM 登录失败 nErr=0x{err:04x}(token 无效/过期?),跳过需登录的用例")
    return im_client
