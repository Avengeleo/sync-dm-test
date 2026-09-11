"""PC 扫码登录用例的共享常量/步骤。"""

import os
import time
import uuid

CODE_WAIT = 1027
CODE_EXPIRED = 1026
CODE_MISSING_KEY = 36996
CODE_BAD_CLIENT = 36995
CODE_MISSING_CLIENT = 36994
CODE_MISSING_SYNC = 36997


def env(key):
    v = os.environ.get(key, "").strip()
    return "" if v.startswith("#") else v


def new_session():
    return {
        "code_key": "pytest-pc-" + uuid.uuid4().hex,
        "device_token": "pytest-pc-dev-" + uuid.uuid4().hex,
        "device_name": "pytest PC scan",
        "device_info": "pytest-pc",
    }


def wait_scan_code(dm_client, code_key, timeout=6.0, interval=0.25):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = dm_client.get_scan_code(code_key)
        if last.code in (200, CODE_WAIT, CODE_EXPIRED):
            return last
        time.sleep(interval)
    return last


def wait_until(dm_client, code_key, want, timeout=8.0, interval=0.3):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = dm_client.get_scan_code(code_key)
        if last.code == want:
            return last
        time.sleep(interval)
    return last


def register_pc(dm_client, sess=None, client_type=None):
    sess = sess or new_session()
    dm_client.login_scan_code(
        sess["code_key"], sess["device_token"],
        device_info=sess["device_info"], device_name=sess["device_name"],
        client_type=client_type,
    ).expect_ok()
    waiting = wait_scan_code(dm_client, sess["code_key"])
    assert waiting is not None, "轮询无响应"
    assert waiting.code == CODE_WAIT, (
        f"注册后应进入等待授权(1027),实际 code={waiting.code} msg={waiting.msg!r}。"
        f"1026=Redis 异步未落或已过期。"
    )
    return sess


# users.register_type / login_type:1 手机 2 邮箱 3 账号。扫码授权不读这些字段,
# 只认 token 里的 user_id。type=3 注册时 email/mobile 都空,登录名写在 mid。
REGISTER_PHONE, REGISTER_EMAIL, REGISTER_ACCOUNT = 1, 2, 3


def complete_pc_scan_login(authed_client):
    """PC 注册二维码 → 当前账号授权 → 轮询 token → /user/info/get。"""
    from dm_api_test.client import DmApiClient

    sess = register_pc(authed_client)
    authed_client.allow_code_login(sess["code_key"], sync_offline_msg_flag="0").expect_ok()
    polled = wait_until(authed_client, sess["code_key"], 200)
    assert polled is not None and polled.code == 200, (
        f"授权后轮询应 200+token,实际 code={getattr(polled, 'code', None)} "
        f"msg={getattr(polled, 'msg', None)!r} raw={getattr(polled, 'raw', None)!r}。"
        f"确认后 Redis TTL 只有 60s,异步写入未落也会先 1027。"
    )
    data = polled.data or {}
    token = data.get("token") or ""
    assert token, f"扫码成功必须带回 identify token: {data!r}"
    assert "sync_offline_msg_flag" in data, data

    pc = authed_client.fork(token=token, client_type=DmApiClient.CLIENT_PC)
    profile = pc.info_get().expect_ok().data or {}
    user_id = int(profile.get("user_id") or 0)
    assert user_id > 0, f"token 应能换到 user_id: {profile!r}"
    assert profile.get("nick_name") is not None, profile
    return {"sess": sess, "token": token, "profile": profile, "pc": pc}


def assert_scan_profile(profile, expect_register_type=None):
    """扫码后资料断言。type=2/3 允许 mobile 为空;type=3 还允许 email 为空。"""
    rt = int(profile.get("register_type") or 0)
    if expect_register_type is not None:
        assert rt == expect_register_type, (
            f"期望 register_type={expect_register_type}(1手机/2邮箱/3账号),"
            f"实际={rt} mid={profile.get('mid')!r} "
            f"email={profile.get('email')!r} mobile={profile.get('mobile')!r}"
        )
    if rt == REGISTER_EMAIL:
        assert profile.get("email"), f"邮箱注册账号扫码后应带回 email: {profile!r}"
    elif rt == REGISTER_PHONE:
        assert profile.get("mobile"), f"手机注册账号扫码后应带回 mobile: {profile!r}"
    elif rt == REGISTER_ACCOUNT:
        assert profile.get("mid"), f"账号注册扫码后应带回 mid(登录名): {profile!r}"
    return rt


def maybe_im_login(token, user_id, device_token):
    """配了 IM_WS_URL 则用扫码 token 打 PC CMLogin;未配则 skip。"""
    import pytest
    from dm_api_test.client import DmApiClient

    ws_url = env("IM_WS_URL")
    if not ws_url:
        pytest.skip("未配置 IM_WS_URL,HTTP 链路已通过,跳过 IM CMLogin")

    from im_test.client import ImWsClient, NON_ERR

    im = ImWsClient(
        ws_url, user_id, token, client_type=int(DmApiClient.CLIENT_PC),
        timeout=int(env("IM_TIMEOUT") or "10"),
        app_version=env("IM_NEW_APP_VERSION") or "9.9.9",
        device_token=device_token,
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
