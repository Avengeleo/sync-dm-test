"""dm-api 套件占位用例:接入前默认 skip(缺 DM_API_* 配置)。

作为模板:配好鉴权 + 确认路径后,把下面的断言改成真实期望即可。
"""

import pytest


@pytest.mark.dm_api
def test_dm_api_reachable(dm_client):
    # 示例:拉贴图上架包列表,信封应为 code=200
    env = dm_client.sticker_pack_list()
    env.expect_ok()
    assert isinstance(env.data, dict) and "list" in env.data
