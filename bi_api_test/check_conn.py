#!/usr/bin/env python3
"""连通性 & 登录自检:填完 .env 后先跑这个,确认能连上、账号能登录,再跑整套 pytest。

用法(不要用 pytest 跑本文件):
    python bi_api_test/check_conn.py

develop 开了图形验证时请配 BI_TOKEN(浏览器请求头 X-Chat-admin),不要配账号密码指望脚本过滑块。
"""

import os
import sys


def main():
    # 作为脚本单独运行时,把工作区根(本文件上一级)加进 sys.path
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
    token = os.environ.get("BI_TOKEN", "").strip()
    verify = os.environ.get("BI_DYNAMIC_VERIFY_TOKEN", "").strip()

    print(f"目标: {base}")
    if not token and (not user or not pwd):
        print("✗ 未配置 BI_TOKEN,也未配置 BI_USERNAME / BI_PASSWORD(复制 .env.example 为 .env 填写)")
        return 2

    c = BiAdminClient(base, timeout=int(os.environ.get("BI_HTTP_TIMEOUT", "15")))
    if token:
        c.token = token
        print(f"✓ 使用 .env 的 BI_TOKEN,前 12 位: {c.token[:12]}...")
    else:
        try:
            c.login(user, pwd, dynamic_verify_token=verify or None)
        except Exception as e:
            print(f"✗ 连接或登录失败: {type(e).__name__}: {e}")
            msg = str(e)
            if "50014" in msg or "图形验证" in msg:
                print("  develop 后台登录开了图形验证,脚本过不了滑块。")
                print("  做法:浏览器打开 BI 后台 → 完成图形验证并登录")
                print("  → F12 Network 任意 /admin/* 请求 → 复制请求头 X-Chat-admin")
                print("  → 写进 .env 的 BI_TOKEN=... 再跑本脚本")
            else:
                print("  排查: VPN 是否已连?base_url/端口是否正确?账号密码是否正确?")
            return 1
        print(f"✓ 登录成功,token 前 12 位: {c.token[:12]}...")

    env = c.sticker_list(page=1, size=1)
    if env.code != 200:
        print(f"✗ 列表接口返回异常: {env!r}")
        if env.code == 402:
            print("  BI_TOKEN 已过期,浏览器重新登录后台后再复制 X-Chat-admin")
        return 1
    total = env.data.get("total") if isinstance(env.data, dict) else "?"
    print(f"✓ 贴图列表接口可用,当前贴图包总数: {total}")

    heat = c.heat_global_get()
    if heat.code != 200:
        print(f"✗ 人气热度 global/get 异常: {heat!r}")
        print("  排查: develop 是否已部署 admin、app 库是否执行 20260916_live_display_metrics.sql")
        return 1

    print("✓ 人气热度 global/get 可用")
    print("\n环境就绪:")
    print('  pytest -m "bi and not write"   # 只读(含热度列表)')
    print(
        "  pytest bi_api_test/tests/test_08_heat_global_read.py "
        "bi_api_test/tests/test_09_heat_broadcaster_list.py "
        "bi_api_test/tests/test_10_heat_live_list.py "
        "bi_api_test/tests/test_11_heat_validate.py"
    )
    print("  pytest bi_api_test/tests/test_12_heat_write.py -m write   # 会改配置,用例结束会 restore")
    return 0


if __name__ == "__main__":
    sys.exit(main())
