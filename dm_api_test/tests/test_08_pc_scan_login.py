"""PC 扫码登录只读断言:注册会话、轮询等待、参数校验。不调用 allow_code_login。

授权完整链路在 test_09(会跨端踢 Web,把 .env 里的 H5 token 打成 501)。
本文件可反复跑,不需要重抓 token:

    pytest dm_api_test/tests/test_08_pc_scan_login.py -v
"""

import uuid

from dm_api_test.client import DmApiClient
from dm_api_test.scan_login import (
    CODE_BAD_CLIENT,
    CODE_EXPIRED,
    CODE_MISSING_CLIENT,
    CODE_MISSING_KEY,
    CODE_MISSING_SYNC,
    CODE_WAIT,
    new_session,
    register_pc,
)


def _never_key():
    return "pytest-never-" + uuid.uuid4().hex


def test_scan_code_missing_code_key(dm_client):
    dm_client.call("/user/login/scan_code", {
        "device_info": "pytest-pc",
        "device_name": "pytest",
        "device_token": "pytest-dev",
        "app_version": "1.0.0",
        "os_version": "Windows-10",
    }, extra_headers={"client-type": DmApiClient.CLIENT_PC}).expect(CODE_MISSING_KEY)


def test_scan_code_invalid_client_type(dm_client):
    sess = new_session()
    dm_client.login_scan_code(
        sess["code_key"], sess["device_token"], client_type="9",
    ).expect(CODE_BAD_CLIENT)


def test_poll_unknown_key_is_expired(dm_client):
    dm_client.get_scan_code(_never_key()).expect(CODE_EXPIRED)


def test_register_then_poll_waiting(authed_client):
    """PC 注册后轮询只能是 1027;App 读信息也不推进状态(没有「已扫码」)。"""
    sess = register_pc(authed_client)

    info = authed_client.get_scan_code_info(sess["code_key"]).expect_ok().data or {}
    assert info.get("device_name") == sess["device_name"], info
    assert info.get("device_info") == sess["device_info"], info
    assert int(info.get("client_type")) == int(DmApiClient.CLIENT_PC), info

    authed_client.get_scan_code(sess["code_key"]).expect(CODE_WAIT)


def test_get_scan_code_info_requires_token(authed_client):
    sess = register_pc(authed_client)
    authed_client.get_scan_code_info(sess["code_key"]).expect_ok()
    authed_client.call(
        "/user/login/get_scan_code_info",
        {"code_key": sess["code_key"]},
        token="",
    ).expect(401)


def test_get_scan_code_info_unknown_key(authed_client):
    authed_client.get_scan_code_info(_never_key()).expect(CODE_EXPIRED)


def test_allow_missing_fields(authed_client):
    authed_client.call("/user/login/allow_code_login", {
        "client_type": "1",
        "sync_offline_msg_flag": "0",
    }).expect(CODE_MISSING_KEY)
    authed_client.call("/user/login/allow_code_login", {
        "code_key": "x",
        "sync_offline_msg_flag": "0",
    }).expect(CODE_MISSING_CLIENT)
    authed_client.call("/user/login/allow_code_login", {
        "code_key": "x",
        "client_type": "1",
    }).expect(CODE_MISSING_SYNC)


def test_allow_invalid_client_type(authed_client):
    sess = register_pc(authed_client)
    authed_client.allow_code_login(sess["code_key"], client_type="9").expect(CODE_BAD_CLIENT)


def test_allow_unknown_key_is_expired(authed_client):
    authed_client.allow_code_login(_never_key()).expect(CODE_EXPIRED)
