"""一次性清空测试账号的离线积压(单聊)。

为什么需要:离线拉取是 limit 窗口查询,只返回最老的 N 条未拉取消息。
跑测会不断发消息但多数用例不 ack,积压越滚越大;一旦 ≥ limit,
后续所有「发消息 → 离线拉取」用例都会稳定失败在「拉不到刚发的消息」,
且报错完全指向不到真因(2026-08-29 实录:积压 100+ 让全部离线用例连挂,
一度误判为 msg-job 落库故障,排查了半小时)。

用法:.venv/Scripts/python.exe drain_offline.py
只影响 .env 里配置的测试账号;ack 不可逆,勿对真实用户账号使用。
"""
import os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except Exception:
    pass

from im_test.http_offline import OfflineHttpClient
from im_test.offline_drain import drain_single

base = os.environ.get("IM_HTTP_BASE_URL", "").strip()
if not base:
    sys.exit("缺 IM_HTTP_BASE_URL")

targets = []
for uid_key, tok_key, label in [("IM_USER_ID", "IM_TOKEN", "主账号 A"),
                                ("IM_USER_ID2", "IM_TOKEN2", "第二账号 B")]:
    uid, tok = os.environ.get(uid_key, "").strip(), os.environ.get(tok_key, "").strip()
    if uid and tok:
        targets.append((label, uid, OfflineHttpClient(base, tok, uid, 20)))

if not targets:
    sys.exit("缺 IM_USER_ID/IM_TOKEN")

for label, uid, http in targets:
    print(f"\n{label} ({uid}):")
    for ct, name in [(0, "App(0)"), (1, "PC(1)"), (2, "Web(2)")]:
        try:
            n = drain_single(http, client_type=ct)
            print(f"  {name:10} 已清理 {n} 条")
        except Exception as e:
            print(f"  {name:10} 失败: {e}")

print("\n清理完成。现在跑离线用例应能正常拉到新发的消息。")
