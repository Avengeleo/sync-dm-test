"""dm-api 套件 fixtures 脚手架(读 DM_API_* 环境变量;.env 由根 conftest 加载)。"""

import os

import pytest

from dm_api_test.client import DmApiClient


@pytest.fixture(scope="session")
def dm_config():
    base = os.environ.get("DM_API_BASE_URL", "")
    token = os.environ.get("DM_API_TOKEN", "")
    if not base or not token:
        pytest.skip("未配置 DM_API_BASE_URL / DM_API_TOKEN,跳过 dm-api 套件")
    return {
        "base_url": base,
        "token": token,
        "timeout": int(os.environ.get("BI_HTTP_TIMEOUT", "15")),
    }


@pytest.fixture(scope="session")
def dm_client(dm_config):
    c = DmApiClient(dm_config["base_url"], timeout=dm_config["timeout"])
    c.set_token(dm_config["token"])
    return c
