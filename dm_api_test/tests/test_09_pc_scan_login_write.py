"""PC 扫码登录完整授权(write)。

AppAllowLogin 跨端互踢:豁免 PC + App,踢掉 Web。
若 DM_API_TOKEN 是 H5/Web 会话,本用例跑通后该 token 会变成 501「登录重置」,
必须从 H5 重新登录再抓 token。要用 App 端 token 才不会被自己踢掉。

请和 test_08 分开跑,先保证 token 有效:

    pytest dm_api_test/tests/test_00_smoke.py -v
    pytest dm_api_test/tests/test_09_pc_scan_login_write.py -v -s
"""

import pytest

from dm_api_test.client import DmApiClient
from dm_api_test.scan_login import env, register_pc, wait_until


@pytest.mark.write
def test_pc_scan_login_happy_path(authed_client):
    """PC 注册 → App 授权 → PC 拿到 token → /user/info/get → 可选 IM CMLogin。"""
    sess = register_pc(authed_client)

    allow = authed_client.allow_code_login(sess["code_key"], sync_offline_msg_flag="0")
    allow.expect_ok()

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
    assert int(data.get("sync_offline_msg_flag") or 0) == 0, data

    pc = authed_client.fork(token=token, client_type=DmApiClient.CLIENT_PC)
    profile = pc.info_get().expect_ok().data or {}
    user_id = int(profile.get("user_id") or 0)
    assert user_id > 0, f"token 应能换到 user_id: {profile!r}"
    assert profile.get("nick_name") is not None, profile

    print("\n[pc-scan] user_id=%s token=%s…%s" % (
        user_id, token[:6], token[-4:] if len(token) > 10 else token))
    print("[pc-scan] 若 DM_API_TOKEN 来自 H5/Web,现在已被跨端踢掉(501),请重抓后再跑其它需登录用例。")

    ws_url = env("IM_WS_URL")
    if not ws_url:
        pytest.skip("未配置 IM_WS_URL,HTTP 链路已通过,跳过 IM CMLogin")

    from im_test.client import ImWsClient, NON_ERR

    im = ImWsClient(
        ws_url, user_id, token, client_type=int(DmApiClient.CLIENT_PC),
        timeout=int(env("IM_TIMEOUT") or "10"),
        app_version=env("IM_NEW_APP_VERSION") or "9.9.9",
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
