"""PC 扫码登录完整授权(write)。覆盖服务端 HTTP + 可选 IM CMLogin,不测原生 PC 画码。

AppAllowLogin 只认 token→user_id。手机/邮箱/账号密码注册(type=1/2/3)同一条链;
type=3 未绑邮箱手机时 mid=登录名,email/mobile 都可以空。

跨端互踢:豁免 PC+App,踢 Web。H5 token 跑完会 501,需重抓后再跑其它需登录用例。

    pytest dm_api_test/tests/test_00_smoke.py -v
    pytest dm_api_test/tests/test_09_pc_scan_login_write.py -v -s
    # 邮箱账号另配 DM_API_TOKEN_EMAIL 后再跑同一文件(会多一条用例)
"""

import pytest

from dm_api_test.scan_login import (
    REGISTER_EMAIL,
    assert_scan_profile,
    complete_pc_scan_login,
    maybe_im_login,
)


def _run_and_report(authed_client, expect_register_type=None):
    got = complete_pc_scan_login(authed_client)
    profile = got["profile"]
    rt = assert_scan_profile(profile, expect_register_type=expect_register_type)
    print("\n[pc-scan] user_id=%s register_type=%s mid=%r email=%r mobile=%r token=%s…%s" % (
        profile.get("user_id"), rt, profile.get("mid"),
        profile.get("email"), profile.get("mobile"),
        got["token"][:6], got["token"][-4:] if len(got["token"]) > 10 else got["token"]))
    print("[pc-scan] 若当前授权 token 来自 H5/Web,现在已被跨端踢掉(501),请重抓后再跑其它需登录用例。")
    maybe_im_login(got["token"], int(profile["user_id"]), got["sess"]["device_token"])
    return profile


@pytest.mark.write
def test_pc_scan_login_happy_path(authed_client):
    """当前 DM_API_TOKEN 对应账号(手机/邮箱/纯账号都行)走完扫码+可选 IM。"""
    _run_and_report(authed_client)


@pytest.mark.write
def test_pc_scan_login_email_account(email_authed_client):
    """邮箱注册账号:扫码不得因 mobile 为空失败。需 .env 配 DM_API_TOKEN_EMAIL。"""
    profile = _run_and_report(email_authed_client, expect_register_type=REGISTER_EMAIL)
    assert profile.get("email"), profile
