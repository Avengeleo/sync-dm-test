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
