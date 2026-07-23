"""工作区根 conftest:统一加载 .env、注册 markers、按目录自动打服务标记。

各服务套件(bi_api_test / dm_api_test / ...)的具体 fixtures 在各自的 conftest.py。
"""

import os

# 加载工作区根的 .env(装了 python-dotenv 就用,没装也不报错)
try:
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except Exception:
    pass


# 目录 → 服务标记:pytest -m bi 只跑 bi 套件,-m dm_api 只跑 dm-api 套件
_SUITE_MARKERS = {
    "bi_api_test": "bi",
    "dm_api_test": "dm_api",
    "dm_im_test": "dm_im",
    "im_test": "im",
}


def pytest_configure(config):
    config.addinivalue_line("markers", "write: 会写库/改状态的用例(对测试环境有副作用)")
    config.addinivalue_line("markers", "s3: 依赖测试环境 S3 可用")
    config.addinivalue_line("markers", "tray_icon: 需配置 BI_TRAY_ICON_* 才运行")
    config.addinivalue_line("markers", "im: dm-im 长连接服务套件")
    for mark in _SUITE_MARKERS.values():
        config.addinivalue_line("markers", f"{mark}: {mark} 服务套件")


def pytest_collection_modifyitems(config, items):
    """按用例所在目录自动补服务标记,无需在每个测试上手写装饰器。"""
    for item in items:
        path = str(item.fspath).replace("\\", "/")
        for folder, mark in _SUITE_MARKERS.items():
            if f"/{folder}/" in path:
                item.add_marker(mark)
