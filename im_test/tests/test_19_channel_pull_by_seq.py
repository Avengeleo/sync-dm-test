"""消息漫游 · 按 seq 拉取社群消息 POST /channel/v1/msg/by_seq(feature/msg-roaming 一期)。

先用新架构客户端发消息拿到 ACK 里的 seq,再用 HTTP 按 seq 拉取,核对 seq、msgId、内容和分页。
  direction=1 往更早:base_seq=0 取最新(打开会话)、base_seq=本地最小 seq(往上翻)
  direction=2 往更新:base_seq=本地最大 seq(补缺号)
返回 next_seq(下次同方向的 base_seq)和 has_more。

前置:同 test_18(channel-job、channel-srv 已部署),另需 channel-pull-server、http-gateway 已部署,
配置 IM_HTTP_BASE_URL、IM_CHANNEL_ID。频道里可能有别人同时发言,断言只依赖本用例自己发的消息。

⚠️ 会往频道发若干条 [selftest] 消息和一条回应。
"""

import os
import uuid

import pytest

from im_test.client import ImWsClient, NON_ERR

SEQ_BASE = 100_000_000
ROAMING_APP_VERSION = os.environ.get("IM_ROAMING_APP_VERSION", "").strip() or "99.0.0"
OLDER, NEWER = 1, 2


@pytest.fixture
def channel_id(im_config):
    cid = im_config.get("channel_id")
    if not cid:
        pytest.skip("未配置 IM_CHANNEL_ID,跳过按 seq 拉取用例")
    return int(cid)


@pytest.fixture
def new_client(im_config):
    c = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type"], im_config["timeout"], app_version=ROAMING_APP_VERSION)
    try:
        c.connect()
    except Exception as e:
        pytest.skip(f"新架构客户端连接失败:{e}")
    if (err := c.login()) != NON_ERR:
        c.close()
        pytest.skip(f"新架构客户端登录失败 nErr=0x{err:04x}")
    yield c
    c.close()


def _send(client, channel_id, n=1):
    """发 n 条,返回 [(msg_id, seq, text)],seq 取自 ACK。"""
    out = []
    for _ in range(n):
        text = "[selftest] by-seq-" + uuid.uuid4().hex[:8]
        r = client.send_channel_chat_seq(channel_id, content=text)
        assert r["errcode"] == NON_ERR, f"社群上行未被接受 errcode=0x{r['errcode']:04x}"
        assert r["seq"] >= SEQ_BASE, f"ACK 应带 seq,实际 {r['seq']}(先确认 test_18 通过)"
        out.append((r["sent_msg_id"], r["seq"], text))
    return out


def _pull(offline_http, channel_id, direction, base_seq=0, count=20, client_type=0):
    code, rsp = offline_http.channel_msg_by_seq(channel_id, direction, base_seq, count, client_type)
    assert code == 200, f"按 seq 拉取失败 HTTP {code}(检查 channel-pull-server、http-gateway 是否已部署)"
    seqs = [m["seq"] for m in rsp["msgs"]]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), f"返回应按 seq 升序且不重复:{seqs}"
    assert all(s <= rsp["max_seq"] for s in seqs), f"返回的 seq 不应超过 maxSeq={rsp['max_seq']}:{seqs}"
    return rsp


@pytest.mark.write
def test_pull_newer_matches_ack(new_client, offline_http, channel_id):
    """补缺号:从第一条之前往更新拉,三条都在,seq、msgId、内容与发送时一致。"""
    sent = _send(new_client, channel_id, 3)
    rsp = _pull(offline_http, channel_id, NEWER, base_seq=sent[0][1] - 1, count=50, client_type=0)
    got = {m["msg_id"]: m for m in rsp["msgs"]}
    for msg_id, seq, text in sent:
        assert msg_id in got, f"拉取结果缺少刚发的消息 {msg_id}(seq={seq})"
        assert got[msg_id]["seq"] == seq, f"拉取的 seq 应与 ACK 一致:{got[msg_id]['seq']} vs {seq}"
        assert got[msg_id]["content"] == text.encode(), "App 端应拿到发送的内容"
    assert rsp["max_seq"] >= sent[-1][1]


@pytest.mark.write
def test_pull_latest_then_page_older(new_client, offline_http, channel_id):
    """打开会话取最新,再往上翻:后一页的 seq 都小于前一页,next_seq 衔接。"""
    sent = _send(new_client, channel_id, 3)
    first = _pull(offline_http, channel_id, OLDER, base_seq=0, count=2)
    assert first["msgs"], "最新一页不应为空"
    assert first["msgs"][-1]["seq"] >= sent[-1][1], "最新一页应包含刚发的最后一条或更新的消息"
    assert first["next_seq"] == first["msgs"][0]["seq"] and first["has_more"], \
        f"取满一页时 next_seq 应为本页最小 seq 且还有更多:{first['next_seq']} {first['has_more']}"

    second = _pull(offline_http, channel_id, OLDER, base_seq=first["next_seq"], count=2)
    assert second["msgs"], "往上翻应还有消息(本用例刚发了 3 条)"
    assert second["msgs"][-1]["seq"] < first["msgs"][0]["seq"], "往上翻的消息应都早于上一页"


@pytest.mark.write
def test_pull_newer_up_to_date(new_client, offline_http, channel_id):
    """已是最新:往更新拉为空,next_seq=max_seq,has_more=False。"""
    _send(new_client, channel_id, 1)
    latest = _pull(offline_http, channel_id, OLDER, base_seq=0, count=1)
    rsp = _pull(offline_http, channel_id, NEWER, base_seq=latest["max_seq"])
    assert rsp["msgs"] == [] or all(m["seq"] > latest["max_seq"] for m in rsp["msgs"])
    if not rsp["msgs"]:
        assert rsp["next_seq"] == rsp["max_seq"] and not rsp["has_more"]


@pytest.mark.write
def test_pull_includes_reaction_event(new_client, offline_http, channel_id):
    """心情回应也占 seq,按 seq 拉取能拿到,eventType=2。"""
    (parent_id, parent_seq, _), = _send(new_client, channel_id, 1)
    r = new_client.send_channel_reaction_seq(channel_id, parent_msg_id=parent_id)
    assert r["errcode"] == NON_ERR and r["seq"] > parent_seq
    rsp = _pull(offline_http, channel_id, NEWER, base_seq=parent_seq, count=50)
    got = {m["msg_id"]: m for m in rsp["msgs"]}
    assert r["sent_msg_id"] in got, "按 seq 拉取应包含心情回应"
    assert got[r["sent_msg_id"]]["seq"] == r["seq"] and got[r["sent_msg_id"]]["event_type"] == 2


def test_pull_bad_param(offline_http, channel_id):
    code, _ = offline_http.channel_msg_by_seq(channel_id, direction=3)
    assert code == 400, f"非法 direction 应返回 400,实际 {code}"
    code, _ = offline_http.channel_msg_by_seq(channel_id, direction=NEWER, base_seq=0)
    assert code == 400, f"往更新必须带 base_seq,应返回 400,实际 {code}"
