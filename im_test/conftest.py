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
from im_test.http_offline import OfflineHttpClient
from im_test.offline_drain import drain_single


def _clean(key):
    v = os.environ.get(key, "").strip()
    return "" if v.startswith("#") else v


def _cfg():
    return {
        "url": _clean("IM_WS_URL"),
        "user_id": _clean("IM_USER_ID"),
        "token": _clean("IM_TOKEN"),
        "client_type": int(_clean("IM_CLIENT_TYPE") or "2"),      # 发送端 A 的端类型,默认 2=Web
        "client_type_b": int(_clean("IM_CLIENT_TYPE_B") or "0"),  # 收方端 B 的端类型,默认 0=App(必须≠A)
        "group_id": _clean("IM_GROUP_ID"),      # 你所在的一个群 id(群回应/群投递用,可选)
        "channel_id": _clean("IM_CHANNEL_ID"),  # 你所在的一个超级群/频道 id(超级群回应/投递用,可选)
        "http_base": _clean("IM_HTTP_BASE_URL"),  # http-gateway 域名(离线拉取用,如 https://im-http.ramon2025.com:3801)
        "old_app_version": _clean("IM_OLD_APP_VERSION") or "2.20.0",  # 版本兼容门:模拟老客户端的版本号(须 < 门槛)
        "new_app_version": _clean("IM_NEW_APP_VERSION") or "9.9.9",   # 模拟够版本客户端(须 >= 门槛)
        "user_id2": _clean("IM_USER_ID2"),  # 第二账号 B(群/超级群离线作离线收方)
        "token2": _clean("IM_TOKEN2"),
        "timeout": int(_clean("IM_TIMEOUT") or "10"),
        "http_timeout": int(_clean("IM_HTTP_TIMEOUT") or "15"),  # 离线 HTTP 单次超时(冷调用/mongo 慢可能偏慢)
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
    # 带 new_app_version 登录:代表"当前版本客户端"。不传版本会被版本兼容门按失败关闭判老,
    # 导致 test_04/05/06 的回应用例被门挡住(误报)。
    c = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type"], im_config["timeout"],
                   app_version=im_config["new_app_version"])
    try:
        c.connect()
    except Exception as e:
        pytest.skip(f"IM WebSocket 连接失败:{e}(检查 IM_WS_URL / VPN)")
    yield c
    c.close()


@pytest.fixture
def logged_in_client(im_client):
    """已连接且已登录(发送端 A;clientType=IM_CLIENT_TYPE,默认 2=Web)。"""
    err = im_client.login()
    if err != NON_ERR:
        pytest.skip(f"IM 登录失败 nErr=0x{err:04x}(token 无效/过期?),跳过需登录的用例")
    return im_client


@pytest.fixture
def receiver_client(im_config):
    """收方端 B:同一账号的**第二条连接**,clientType 必须与 A 不同(默认 0=App),
    否则同 clientType 第二次登录会把前一条踢下线(0x0108)。投递测试:A 发、B 收下行。"""
    if im_config["client_type_b"] == im_config["client_type"]:
        pytest.skip("IM_CLIENT_TYPE_B 与 IM_CLIENT_TYPE 相同,双连接会互踢——请设为不同端类型(如 A=2 web / B=0 app)")
    b = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type_b"], im_config["timeout"],
                   app_version=im_config["new_app_version"])  # 够版本端,不应被门拦
    try:
        b.connect()
    except Exception as e:
        pytest.skip(f"收方端 B WebSocket 连接失败:{e}")
    err = b.login()
    if err != NON_ERR:
        b.close()
        pytest.skip(f"收方端 B 登录失败 nErr=0x{err:04x},跳过投递用例")
    yield b
    b.close()


@pytest.fixture
def offline_http(im_config):
    """离线拉取 HTTP 客户端(http-gateway;Authorization={token}:{userId})。未配 IM_HTTP_BASE_URL 则 skip。"""
    base = im_config.get("http_base")
    if not base:
        pytest.skip("未配置 IM_HTTP_BASE_URL,跳过离线拉取用例")
    return OfflineHttpClient(base, im_config["token"], im_config["user_id"], im_config["http_timeout"])


@pytest.fixture
def drained_offline_http(im_config, offline_http):
    """主账号的离线 HTTP 客户端,**先把积压清空**再交给用例。

    离线拉取是 limit 窗口查询:队列积压 ≥ limit 时,用例新发的消息排在窗口外,
    会稳定失败在「拉不到刚发的消息」——原因与被测逻辑无关,极易误判为服务端故障
    (2026-08-29 实录:积压 100+ 导致全部离线用例连挂,一度怀疑 msg-job 落库坏了)。
    故凡「发消息 → 离线拉」的用例都应经此 fixture 取客户端。
    注意:drain 会 ack 掉存量消息(不可逆),仅限测试账号。"""
    n = drain_single(offline_http, client_type=im_config["client_type_b"])
    if n:
        print(f"\n[drain] 清理主账号离线积压 {n} 条(避免积压把新消息挤出 limit 窗口)")
    return offline_http


@pytest.fixture
def offline_http_b(im_config):
    """第二账号 B 的离线 HTTP 客户端(群/超级群离线:A 发、B 作离线收方拉取)。
    未配 IM_HTTP_BASE_URL 或 IM_USER_ID2/IM_TOKEN2 则 skip。"""
    base = im_config.get("http_base")
    if not base:
        pytest.skip("未配置 IM_HTTP_BASE_URL,跳过离线拉取用例")
    uid2, tok2 = im_config.get("user_id2"), im_config.get("token2")
    if not uid2 or not tok2:
        pytest.skip("未配置 IM_USER_ID2 / IM_TOKEN2(第二账号 B),跳过群/超级群离线用例")
    return OfflineHttpClient(base, tok2, uid2, im_config["http_timeout"])


@pytest.fixture
def old_receiver_client(im_config):
    """版本兼容门用:收方端 B 以**低版本**登录(clientType 同 receiver_client,默认 App=0)。
    服务端应拒绝向它下发心情回应(0x122d/0x2314/0x3213),但普通消息照常。"""
    if im_config["client_type_b"] == im_config["client_type"]:
        pytest.skip("IM_CLIENT_TYPE_B 与 IM_CLIENT_TYPE 相同,双连接会互踢")
    b = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type_b"], im_config["timeout"],
                   app_version=im_config["old_app_version"])
    try:
        b.connect()
    except Exception as e:
        pytest.skip(f"低版本收方端连接失败:{e}")
    err = b.login()
    if err != NON_ERR:
        b.close()
        pytest.skip(f"低版本收方端登录失败 nErr=0x{err:04x}")
    yield b
    b.close()


@pytest.fixture
def old_version_offline_http(im_config):
    """低版本身份的离线拉取:先用低版本登录刷新 Redis 里的 app_version,再走 HTTP 拉。
    离线门控读的是 Redis 版本(登录时写入),故必须先建立一次低版本登录。"""
    base = im_config.get("http_base")
    if not base:
        pytest.skip("未配置 IM_HTTP_BASE_URL,跳过离线用例")
    c = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type_b"], im_config["timeout"],
                   app_version=im_config["old_app_version"])
    try:
        c.connect()
    except Exception as e:
        pytest.skip(f"低版本登录连接失败:{e}")
    err = c.login()
    if err != NON_ERR:
        c.close()
        pytest.skip(f"低版本登录失败 nErr=0x{err:04x}")
    c.close()  # 断开=离线,但 Redis 里 app_version 已是低版本
    yield OfflineHttpClient(base, im_config["token"], im_config["user_id"], im_config["http_timeout"])
