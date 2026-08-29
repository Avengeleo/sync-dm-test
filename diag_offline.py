"""离线链路诊断:不发消息,直接裸拉,看离线库里到底有没有东西。

用法:.venv/Scripts/python.exe diag_offline.py(Windows 反斜杠亦可)
读根 .env 的 IM_* 配置,只做只读拉取(不带 delivered → 不会 ack 标记已拉取)。
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

base = os.environ.get("IM_HTTP_BASE_URL", "").strip()
uid = os.environ.get("IM_USER_ID", "").strip()
tok = os.environ.get("IM_TOKEN", "").strip()
if not (base and uid and tok):
    sys.exit("缺 IM_HTTP_BASE_URL / IM_USER_ID / IM_TOKEN")

c = OfflineHttpClient(base, tok, uid, 20)
print(f"账号 {uid} @ {base}\n")

for ct, name in [(0, "App(clientType=0)"), (1, "PC(1)"), (2, "Web(2)")]:
    try:
        code, rows = c.offline_chat(client_type=ct, limit=100)
    except Exception as e:
        print(f"  {name:22} 异常: {type(e).__name__}: {e}")
        continue
    print(f"  {name:22} HTTP {code}  未拉取消息 {len(rows)} 条")
    for r in rows[:3]:
        print(f"      cmd=0x{r['cmd_id']:04x} msg_id={r['msg_id'][:16]}... time={r.get('msg_time')}")

print("""
判读:
  App 有若干条  → 离线库有数据、拉取链路通。那问题是"新发的消息没进来"
                  (msg-srv 落库 或 Kafka→msg-job 落库环节),看 msg-srv/msg-job 日志。
  App 恒 0 条   → 该账号 App 端离线库是空的。要么消息压根没落库,
                  要么之前的跑测已把它们 ack 掉了(测试会带 delivered 回带)。
  HTTP 非 200   → 鉴权/域名问题,与落库无关。
""")
