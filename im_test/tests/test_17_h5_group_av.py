"""H5 群音视频信令自测(M1–M7),打 develop 环境。

被测改动(sync-dm-im signal-srv,已合 develop):
  M1 群通话在线扇出补 Web
  M2 离线队列拆 webPulled,Web/PC/App 互不吞
  M3 Mongo 索引+刷数 —— 运维动作,本套 skip
  M4 补 0x410f / 0x411b / 0x411f DELIVER ACK 路由
  M5 ACK 用网关注入的 FromUserId,不信包体 userId
  M6 音视频 cmd 不进版本门;Web 低版本仍应收到
  M7 仅 Web / App+Web / App+PC+Web 三端都能收到 0x4104

群通话扇出会跳过发起人,所以被叫必须是第二账号:
  IM_USER_ID / IM_TOKEN     = 主叫 A(默认 Web)
  IM_USER_ID2 / IM_TOKEN2   = 被叫 B,且与 A 同在 IM_GROUP_ID
B 的真机请先退出,否则在线推会把离线用例抢走。

跑:
  pytest -m im im_test/tests/test_17_h5_group_av.py
"""

import time
import uuid

import pytest
import requests

from im_test import proto_min
from im_test.client import (
    NON_ERR,
    SIG_P2P_CALL_DELIVER,
    SIG_GROUP_CALL_DELIVER,
    SIG_GROUP_CALL_DELIVER_ACK,
    SIG_GROUP_HANGUP_DELIVER,
    SIG_GROUP_HANGUP_DELIVER_ACK,
    SIG_GROUP_DISCONNECTED_DELIVER,
    SIG_GROUP_DISCONNECTED_DELIVER_ACK,
    SIG_GROUP_BUSY_DELIVER,
    SIG_GROUP_BUSY_DELIVER_ACK,
)

AV_WAIT = 15  # 信令经 Kafka 扇出,比聊天略慢


@pytest.fixture
def group_id(im_config):
    gid = im_config.get("group_id")
    if not gid:
        pytest.skip("未配置 IM_GROUP_ID,跳过群音视频用例")
    return int(gid)


def _finish(a, group_id, call_id):
    if not call_id:
        return
    try:
        a.send_group_call_finish(group_id, call_id)
    except Exception as e:
        print(f"\n[warn] 结束群通话失败 callId={call_id}: {e}")


def _recv_group_call(peer, msg_id, timeout=AV_WAIT):
    d = proto_min.parse_sponsor_group_call(peer.recv_deliver(SIG_GROUP_CALL_DELIVER, timeout=timeout))
    assert d["msg_id"] == msg_id, f"被叫收到的 0x4104 msgId={d['msg_id']} 应为 {msg_id}"
    return d


def _pull_signal_until(http, client_type, msg_id, timeout=45):
    deadline = time.time() + timeout
    last_code = None
    while time.time() < deadline:
        try:
            code, rows = http.offline_signal(client_type=client_type, limit=100)
        except requests.exceptions.RequestException:
            continue
        last_code = code
        assert code == 200, f"/offline/v1/signal HTTP {code}(鉴权/IM_HTTP_BASE_URL?)"
        hit = next((r for r in rows if r["msg_id"] == msg_id), None)
        if hit:
            return hit
        time.sleep(0.6)
    pytest.fail(
        f"clientType={client_type} 在 {timeout}s 内未拉到 msgId={msg_id}"
        f"(最后 HTTP {last_code};B 真机是否在线?signal-srv 是否已发 develop?)"
    )


# ── M1 / M7 在线扇出 ──

@pytest.mark.write
def test_m1_only_web_gets_group_call(logged_in_client, peer_web_client, group_id):
    """M1+M7①:被叫只开 Web,应实时收到 0x4104。旧代码这里是 // web 暂无音视频。"""
    a, b = logged_in_client, peer_web_client
    r = a.send_group_call(group_id, invite_ids=[b.user_id])
    try:
        assert r["errcode"] == NON_ERR, f"群通话上行被拒 errcode=0x{r['errcode']:04x}(A/B 都是群成员?)"
        d = _recv_group_call(b, r["sent_msg_id"])
        assert d["group_id"] == group_id
        assert d["user_id"] == a.user_id
    finally:
        _finish(a, group_id, r.get("call_id"))


@pytest.mark.write
def test_m1_p2p_web_still_ok(logged_in_client, peer_web_client):
    """对照:私聊 0x4004 本来就会投 Web,回归别把这条打坏。"""
    a, b = logged_in_client, peer_web_client
    r = a.send_p2p_call(b.user_id)
    try:
        assert r["errcode"] == NON_ERR, f"私聊来电上行被拒 errcode=0x{r['errcode']:04x}"
        d = proto_min.parse_p2p_call(b.recv_deliver(SIG_P2P_CALL_DELIVER, timeout=AV_WAIT))
        assert d["msg_id"] == r["sent_msg_id"]
        assert d["from_id"] == a.user_id
    finally:
        try:
            a.send_p2p_hangup(b.user_id, r["call_id"])
        except Exception as e:
            print(f"\n[warn] 私聊挂断失败: {e}")


@pytest.mark.write
def test_m7_app_and_web_both_get_group_call(logged_in_client, peer_app_client, peer_web_client,
                                            group_id):
    """M7②:被叫 App+Web 同时在线,两端都要收到,互不抢。"""
    a = logged_in_client
    r = a.send_group_call(group_id, invite_ids=[peer_web_client.user_id])
    try:
        assert r["errcode"] == NON_ERR, f"群通话上行被拒 errcode=0x{r['errcode']:04x}"
        _recv_group_call(peer_web_client, r["sent_msg_id"])
        _recv_group_call(peer_app_client, r["sent_msg_id"])
    finally:
        _finish(a, group_id, r.get("call_id"))


@pytest.mark.write
def test_m7_three_ends_get_group_call(logged_in_client, peer_app_client, peer_pc_client,
                                      peer_web_client, group_id):
    """M7③:App+PC+Web 三端同时在线都应收到 0x4104。"""
    a = logged_in_client
    r = a.send_group_call(group_id, invite_ids=[peer_web_client.user_id])
    try:
        assert r["errcode"] == NON_ERR, f"群通话上行被拒 errcode=0x{r['errcode']:04x}"
        _recv_group_call(peer_web_client, r["sent_msg_id"])
        _recv_group_call(peer_app_client, r["sent_msg_id"])
        _recv_group_call(peer_pc_client, r["sent_msg_id"])
    finally:
        _finish(a, group_id, r.get("call_id"))


# ── M2 webPulled 三档 ──

@pytest.mark.write
def test_m2_web_ack_does_not_eat_app_offline(logged_in_client, drained_signal_http_b, group_id,
                                             im_config):
    """M2:HTTP 用 clientType=2 拉到并 ack 后,clientType=0 仍能拉到同一条。
    旧逻辑 Web 走 pcPulled,办公双开会互相吞。"""
    a = logged_in_client
    http_b = drained_signal_http_b
    r = a.send_group_call(group_id, invite_ids=[int(im_config["user_id2"])])
    try:
        assert r["errcode"] == NON_ERR, f"群通话上行被拒 errcode=0x{r['errcode']:04x}"
        web_hit = _pull_signal_until(http_b, 2, r["sent_msg_id"])
        assert web_hit["cmd_id"] == SIG_GROUP_CALL_DELIVER, (
            f"Web 离线行应为 0x4104,实际 0x{web_hit['cmd_id']:04x}"
        )
        code, _ = http_b.offline_signal(client_type=2, limit=50,
                                        delivered_ids=[r["sent_msg_id"]])
        assert code == 200, f"Web ack HTTP {code}"

        app_hit = _pull_signal_until(http_b, 0, r["sent_msg_id"])
        assert app_hit["cmd_id"] == SIG_GROUP_CALL_DELIVER

        code, web_again = http_b.offline_signal(client_type=2, limit=100)
        assert code == 200
        assert all(row["msg_id"] != r["sent_msg_id"] for row in web_again), (
            "Web 已 ack,再拉不应还看到同一条(webPulled 未置 1?)"
        )
    finally:
        _finish(a, group_id, r.get("call_id"))


# ── M3 运维,不在 pytest ──

@pytest.mark.skip(reason="M3 是 Mongo 建索引+存量刷数,dev 直连/stg Archery,不在本套")
def test_m3_mongo_index_and_backfill_ops_only():
    pass


# ── M4 DELIVER ACK 路由 ──

@pytest.mark.write
def test_m4_hangup_disconnected_busy_ack_mark_pulled(logged_in_client, peer_web_client,
                                                     drained_signal_http_b, group_id):
    """M4:挂断/断连/忙线三条 DELIVER ACK 必须进路由,否则 default 丢弃、离线队列清不掉。
    被叫 Web 在线收到下行后发 ACK(包体 userId 填自己),断开再拉,对应行应已被标记。"""
    a, b = logged_in_client, peer_web_client
    http_b = drained_signal_http_b
    r = a.send_group_call(group_id, invite_ids=[b.user_id])
    try:
        assert r["errcode"] == NON_ERR, f"群通话上行被拒 errcode=0x{r['errcode']:04x}"
        _recv_group_call(b, r["sent_msg_id"])

        hang = a.send_group_call_finish(group_id, r["call_id"], hangup=True)
        assert hang["errcode"] == NON_ERR, f"挂断上行被拒 0x{hang['errcode']:04x}"
        b.recv_deliver(SIG_GROUP_HANGUP_DELIVER, timeout=AV_WAIT)
        b.send_group_deliver_ack(SIG_GROUP_HANGUP_DELIVER_ACK, hang["sent_msg_id"],
                                 body_user_id=b.user_id)

        disc = a.send_group_call_disconnected(group_id, r["call_id"], users=[b.user_id])
        assert disc["errcode"] == NON_ERR, f"断连上行被拒 0x{disc['errcode']:04x}"
        b.recv_deliver(SIG_GROUP_DISCONNECTED_DELIVER, timeout=AV_WAIT)
        b.send_group_deliver_ack(SIG_GROUP_DISCONNECTED_DELIVER_ACK, disc["sent_msg_id"],
                                 body_user_id=b.user_id)

        busy = a.send_group_call_busy(group_id, r["call_id"], hint_user=b.user_id)
        assert busy["errcode"] == NON_ERR, f"忙线上行被拒 0x{busy['errcode']:04x}"
        b.recv_deliver(SIG_GROUP_BUSY_DELIVER, timeout=AV_WAIT)
        b.send_group_deliver_ack(SIG_GROUP_BUSY_DELIVER_ACK, busy["sent_msg_id"],
                                 body_user_id=b.user_id)

        time.sleep(1.5)  # ACK 落库是 goroutine
        b.close()
        time.sleep(0.4)
        code, rows = http_b.offline_signal(client_type=2, limit=100)
        assert code == 200
        leftover = {row["msg_id"] for row in rows} & {
            hang["sent_msg_id"], disc["sent_msg_id"], busy["sent_msg_id"]}
        assert not leftover, (
            f"Web ACK 后离线队列仍有 {leftover}(0x410f/0x411b/0x411f 被 default 丢掉?)"
        )
    finally:
        _finish(a, group_id, r.get("call_id"))


# ── M5 ACK 用 FromUserId ──

@pytest.mark.write
def test_m5_deliver_ack_ignores_body_user_id(logged_in_client, peer_web_client,
                                             drained_signal_http_b, group_id):
    """M5:DELIVER ACK 包体 userId 填 0,仍应按网关注入的登录 uid 标记 B 的 webPulled。"""
    a, b = logged_in_client, peer_web_client
    http_b = drained_signal_http_b
    r = a.send_group_call(group_id, invite_ids=[b.user_id])
    try:
        assert r["errcode"] == NON_ERR, f"群通话上行被拒 errcode=0x{r['errcode']:04x}"
        _recv_group_call(b, r["sent_msg_id"])
        b.send_group_deliver_ack(SIG_GROUP_CALL_DELIVER_ACK, r["sent_msg_id"], body_user_id=0)
        time.sleep(1.5)
        b.close()
        time.sleep(0.4)
        code, rows = http_b.offline_signal(client_type=2, limit=100)
        assert code == 200
        assert all(row["msg_id"] != r["sent_msg_id"] for row in rows), (
            "包体 userId=0 时仍应记下 B 的 webPulled;还能拉到说明 ACK 信了包体、没信 FromUserId"
        )
    finally:
        _finish(a, group_id, r.get("call_id"))


# ── M6 版本门不挡音视频 ──

@pytest.mark.write
def test_m6_old_web_still_gets_group_call(logged_in_client, old_peer_web_client, group_id):
    """M6:被叫 Web 报老版本,0x4104 仍应下发(编译期门槛表不含音视频 cmd,Web 豁免)。"""
    a, b = logged_in_client, old_peer_web_client
    r = a.send_group_call(group_id, invite_ids=[b.user_id])
    try:
        assert r["errcode"] == NON_ERR, f"群通话上行被拒 errcode=0x{r['errcode']:04x}"
        _recv_group_call(b, r["sent_msg_id"])
    finally:
        _finish(a, group_id, r.get("call_id"))
