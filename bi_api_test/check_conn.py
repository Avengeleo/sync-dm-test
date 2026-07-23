#!/usr/bin/env python3
"""连通性 & 登录自检:填完 .env 后先跑这个,确认能连上、账号能登录,再跑整套 pytest。

用法:
    python check_conn.py
"""

import os
import sys

# 作为脚本单独运行时,把工作区根(本文件上一级)加进 sys.path,保证能 import 到 bi_api_test / common
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
except Exception:
    pass

from bi_api_test.client import BiAdminClient

base = os.environ.get("BI_BASE_URL", "http://127.0.0.1:8094")
user = os.environ.get("BI_USERNAME", "")
pwd = os.environ.get("BI_PASSWORD", "")

print(f"目标: {base}")
if not user or not pwd:
    print("✗ 未配置 BI_USERNAME / BI_PASSWORD(复制 .env.example 为 .env 填写)")
    sys.exit(2)

c = BiAdminClient(base, timeout=int(os.environ.get("BI_HTTP_TIMEOUT", "15")))
try:
    c.login(user, pwd)
except Exception as e:
    print(f"✗ 连接或登录失败: {type(e).__name__}: {e}")
    print("  排查: VPN 是否已连?base_url/端口是否正确?账号密码是否正确?")
    sys.exit(1)

print(f"✓ 登录成功,token 前 12 位: {c.token[:12]}...")

# 顺带打一枪只读接口,确认鉴权头链路通
env = c.sticker_list(page=1, size=1)
if env.code == 200:
    total = env.data.get("total") if isinstance(env.data, dict) else "?"
    print(f"✓ 贴图列表接口可用,当前贴图包总数: {total}")
    print("\n环境就绪,可运行: pytest -m \"not write\"  (先跑只读用例探路)")
    sys.exit(0)
else:
    print(f"✗ 列表接口返回异常: {env!r}")
    sys.exit(1)
