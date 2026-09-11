"""PC 扫码登录断言(dev)。模拟 PC 注册二维码会话 + App 授权 + PC 轮询拿 token。

契约(读 api-gateway/router/user.go、user-srv/handler_login.go 核实):
  PC  POST /user/login/scan_code          只验 Sign,Header Client-type=1,TTL=180s
  PC  POST /user/login/get_scan_code      只验 Sign → 1027 等待 / 200+token / 1026 失效
  App POST /user/login/get_scan_code_info  Sign+Token,只读设备信息,不写「已扫码」
  App POST /user/login/allow_code_login    Sign+Token,签发/复用 identify token,TTL 改 60s
  之后 PC 用 token 调 /user/info/get 拿 user_id,再 CMLogin 进 IM。

服务端不生成二维码、不生成 code_key;PC 自己造 key。没有独立「已扫码」态。
Redis 写入是异步的,注册后立刻轮询可能短暂 1026,本文件会重试。

运行(工作区根,已填 .env 的 DM_API_*):

    pytest dm_api_test/tests/test_08_pc_scan_login.py -v
    pytest dm_api_test/tests/test_08_pc_scan_login.py -v -m "not write"   # 只跑只读断言
    pytest dm_api_test/tests/test_08_pc_scan_login.py::test_pc_scan_login_happy_path -v -s

配了 IM_WS_URL / IM_NEW_APP_VERSION 时,happy path 会再用扫到的 token 打一条 PC CMLogin。

⚠️ happy path 标了 write:AppAllowLogin 会跨端踢(豁免 PC+App,踢 Web),
并 Kick 该账号当前在用的 PC 设备 token。请单独跑本文件,不要夹在整包 dm_api
套件中间——若 DM_API_TOKEN 本身是 Web/H5 会话,授权后这个 token 会 501。
建议用 App 端 token,或接受测完要重抓 token。
"""

import os
import time
import uuid

import pytest

from dm_api_test.client import DmApiClient

CODE_WAIT = 1027          # 请等待扫描授权
CODE_EXPIRED = 1026       # 二维码已失效
CODE_MISSING_KEY = 36996  # code_key 必填
CODE_BAD_CLIENT = 36995   # Client-type / client_type 非法
CODE_MISSING_CLIENT = 36994
CODE_MISSING_SYNC = 36997


def _clean(key):
    v = os.environ.get(key, "").strip()
    return "" if v.startswith("#") else v


def _new_session():
    return {
        "code_key": "pytest-pc-" + uuid.uuid4().hex,
        "device_token": "pytest-pc-dev-" + uuid.uuid4().hex,
        "device_name": "pytest PC scan",
        "device_info": "pytest-pc",
    }


def _wait_scan_code(dm_client, code_key, timeout=6.0, interval=0.25):
    """等异步 Redis 落库。返回最后一次 Envelope。"""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = dm_client.get_scan_code(code_key)
        if last.code in (200, CODE_WAIT, CODE_EXPIRED):
            return last
        time.sleep(interval)
    return last


def _wait_until(dm_client, code_key, want, timeout=8.0, interval=0.3):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = dm_client.get_scan_code(code_key)
        if last.code == want:
            return last
        time.sleep(interval)
    return last


def _register_pc(dm_client, sess=None, client_type=None):
    sess = sess or _new_session()
    env = dm_client.login_scan_code(
        sess["code_key"], sess["device_token"],
        device_info=sess["device_info"], device_name=sess["device_name"],
        client_type=client_type,
    )
    env.expect_ok()
    waiting = _wait_scan_code(dm_client, sess["code_key"])
    assert waiting is not None, "轮询无响应"
    assert waiting.code == CODE_WAIT, (
        f"注册后应进入等待授权(1027),实际 code={waiting.code} msg={waiting.msg!r}。"
        f"1026=Redis 异步未落或已过期。"
    )
    return sess


# ── 只读 / 无授权副作用 ──


def test_scan_code_missing_code_key(dm_client):
    dm_client.call("/user/login/scan_code", {
        "device_info": "pytest-pc",
        "device_name": "pytest",
        "device_token": "pytest-dev",
        "app_version": "1.0.0",
        "os_version": "Windows-10",
    }, extra_headers={"client-type": DmApiClient.CLIENT_PC}).expect(CODE_MISSING_KEY)


def test_scan_code_invalid_client_type(dm_client):
    sess = _new_session()
    dm_client.login_scan_code(
        sess["code_key"], sess["device_token"], client_type="9",
    ).expect(CODE_BAD_CLIENT)


def test_poll_unknown_key_is_expired(dm_client):
    dm_client.get_scan_code("pytest-never-" + uuid.uuid4().hex).expect(CODE_EXPIRED)


def test_register_then_poll_waiting(dm_client):
    """PC 注册后轮询只能是 1027;App 读信息也不推进状态(没有「已扫码」)。"""
    sess = _register_pc(dm_client)

    info = dm_client.get_scan_code_info(sess["code_key"]).expect_ok().data or {}
    assert info.get("device_name") == sess["device_name"], info
    assert info.get("device_info") == sess["device_info"], info
    assert int(info.get("client_type")) == int(DmApiClient.CLIENT_PC), info

    dm_client.get_scan_code(sess["code_key"]).expect(CODE_WAIT)


def test_get_scan_code_info_requires_token(dm_client):
    sess = _register_pc(dm_client)
    dm_client.call(
        "/user/login/get_scan_code_info",
        {"code_key": sess["code_key"]},
        token="",
    ).expect(401)


def test_get_scan_code_info_unknown_key(dm_client):
    dm_client.get_scan_code_info("pytest-never-" + uuid.uuid4().hex).expect(CODE_EXPIRED)


def test_allow_missing_fields(dm_client):
    dm_client.call("/user/login/allow_code_login", {
        "client_type": "1",
        "sync_offline_msg_flag": "0",
    }).expect(CODE_MISSING_KEY)
    dm_client.call("/user/login/allow_code_login", {
        "code_key": "x",
        "sync_offline_msg_flag": "0",
    }).expect(CODE_MISSING_CLIENT)
    dm_client.call("/user/login/allow_code_login", {
        "code_key": "x",
        "client_type": "1",
    }).expect(CODE_MISSING_SYNC)


def test_allow_invalid_client_type(dm_client):
    sess = _register_pc(dm_client)
    dm_client.allow_code_login(sess["code_key"], client_type="9").expect(CODE_BAD_CLIENT)


def test_allow_unknown_key_is_expired(dm_client):
    dm_client.allow_code_login("pytest-never-" + uuid.uuid4().hex).expect(CODE_EXPIRED)


# ── 完整授权:有副作用 ──


@pytest.mark.write
def test_pc_scan_login_happy_path(dm_client):
    """PC 注册 → App 授权 → PC 拿到 token → /user/info/get → 可选 IM CMLogin。"""
    sess = _register_pc(dm_client)

    allow = dm_client.allow_code_login(sess["code_key"], sync_offline_msg_flag="0")
    allow.expect_ok()

    polled = _wait_until(dm_client, sess["code_key"], 200)
    assert polled is not None and polled.code == 200, (
        f"授权后轮询应 200+token,实际 code={getattr(polled, 'code', None)} "
        f"msg={getattr(polled, 'msg', None)!r} raw={getattr(polled, 'raw', None)!r}。"
        f"确认后 Redis TTL 只有 60s,异步写入未落也会先 1027。"
    )
    data = polled.data or {}
    token = data.get("token") or ""
    assert token, f"扫码成功必须带回 identify token: {data!r}"
    assert "sync_offline_msg_flag" in data, data
    assert int(data.get("sync_offline_msg_flag") or 0) == 0, data

    pc = dm_client.fork(token=token, client_type=DmApiClient.CLIENT_PC)
    profile = pc.info_get().expect_ok().data or {}
    user_id = int(profile.get("user_id") or 0)
    assert user_id > 0, f"token 应能换到 user_id: {profile!r}"
    assert profile.get("nick_name") is not None, profile

    print("\n[pc-scan] user_id=%s token=%s…%s" % (
        user_id, token[:6], token[-4:] if len(token) > 10 else token))

    ws_url = _clean("IM_WS_URL")
    if not ws_url:
        pytest.skip("未配置 IM_WS_URL,HTTP 链路已通过,跳过 IM CMLogin")

    from im_test.client import ImWsClient, NON_ERR

    im = ImWsClient(
        ws_url, user_id, token, client_type=int(DmApiClient.CLIENT_PC),
        timeout=int(_clean("IM_TIMEOUT") or "10"),
        app_version=_clean("IM_NEW_APP_VERSION") or "9.9.9",
        device_token=sess["device_token"],
    )
    try:
        im.connect()
    except Exception as e:
        pytest.skip(f"IM WebSocket 连不上:{e}(HTTP 链路已通过)")
    try:
        err = im.login()
        assert err == NON_ERR, (
            f"扫码 token 进 IM 失败 nErr=0x{err:04x}(0x8000=成功)。"
            f"HTTP 已拿到 token 且 /user/info/get 成功,问题在 login-srv Check / CMLogin。"
        )
        print("[pc-scan] IM CMLogin ok nErr=0x%04x clientType=PC" % err)
    finally:
        im.close()
