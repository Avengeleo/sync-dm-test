"""引用原文回源(按 msgId 精确拉取)—— 三种会话各一条端点。

被测需求:客户端渲染引用回复时,拿 parentMsgId 在本地找不到原消息就显示「原消息不存在」,
但服务端其实有;新增按 msgId 精确回源的接口给 resolveMessage 兜底。
设计文档:需求文档/引用原文回源/按msgId回源接口设计.md

端点(userId 一律由网关用鉴权态注入,body 里传的会被覆盖):
  POST /offline/v1/group/msg/by_id   群聊
  POST /offline/v1/chat/msg/by_id    单聊
  POST /channel/v1/msg/by_id         超级群

需部署:group-srv / msg-srv / channel-pull-server 先发,http-gateway 最后发
(网关先发的话,新路由会因下游还没有对应 RPC 而失败)。

前提:.env 需配 IM_HTTP_BASE_URL;群用例需 IM_GROUP_ID,超级群用例需 IM_CHANNEL_ID。
"""

import time
import uuid

import pytest
import requests

from im_test import proto_min

# 单次批量上限,与服务端 maxMsgIdsPerQuery 一致(设计文档 Q6)
MAX_MSG_IDS = 20

# 回源是同步查库,但消息要先经 Kafka 异步落库,故给一段轮询窗口
RESOLVE_TIMEOUT = 45


@pytest.fixture
def group_id(im_config):
    gid = im_config.get("group_id")
    if not gid:
        pytest.skip("未配置 IM_GROUP_ID,跳过群回源用例")
    return int(gid)


@pytest.fixture
def channel_id(im_config):
    cid = im_config.get("channel_id")
    if not cid:
        pytest.skip("未配置 IM_CHANNEL_ID,跳过超级群回源用例")
    return int(cid)


def _resolve_until(fetch, msg_id, timeout=RESOLVE_TIMEOUT):
    """轮询回源直到取到目标 msgId(等落库);fetch() -> (code, msgs, missing)。"""
    deadline = time.time() + timeout
    last_code = None
    while time.time() < deadline:
        try:
            code, msgs, _missing = fetch()
        except requests.exceptions.RequestException:
            continue  # 冷调用超时/瞬断,重试到 deadline
        last_code = code
        if code == 200:
            hit = next((m for m in msgs if m["msg_id"] == msg_id), None)
            if hit:
                return hit, code
        time.sleep(0.6)
    return None, last_code


# ─────────────────────────── 群聊 ───────────────────────────

@pytest.mark.write
def test_group_msg_by_id_roundtrip(logged_in_client, offline_http, group_id, im_config):
    """发一条群消息 → 按 msgId 回源应取到,且顶层字段与内层正文都对得上。"""
    a = logged_in_client
    text = "[selftest] byid-group-" + uuid.uuid4().hex[:8]
    r = a.send_group_chat(group_id, content=text)
    assert r["errcode"] == 0x8000, f"群上行未被接受 errcode=0x{r['errcode']:04x}"
    msg_id = r["sent_msg_id"]

    hit, code = _resolve_until(
        lambda: offline_http.group_msg_by_id(group_id, [msg_id],
                                             client_type=im_config["client_type"]),
        msg_id)
    assert hit is not None, f"按 msgId 回源未取到刚发的群消息(HTTP {code};落库延迟?群成员?)"
    assert hit["group_id"] == group_id, "回源消息所属群不符"
    assert hit["from_id"] == a.user_id, "回源消息发送者应为 A"
    # 明文消息(测试客户端不加密)可直接比对内层 MESGrpChat 正文
    inner = proto_min.parse_group_deliver(hit["data"])
    assert inner["content"] == text.encode(), "回源正文与发送内容不一致"


@pytest.mark.write
def test_group_msg_by_id_does_not_mark_pulled(logged_in_client, offline_http_b, group_id):
    """🔴 核心约束:回源**不得**修改 pulled 标记。

    做法:A 发消息 → B(离线)先按 msgId 回源一次 → B 再走正常离线拉取,
    该消息**必须仍在**离线结果里。若回源错误地标了 pulled,离线拉取就会漏掉它
    (离线端点按 {端}Pulled=0 过滤),用户会永久少收一条消息。
    """
    a = logged_in_client
    text = "[selftest] byid-nopull-" + uuid.uuid4().hex[:8]
    r = a.send_group_chat(group_id, content=text)
    assert r["errcode"] == 0x8000, f"群上行未被接受 errcode=0x{r['errcode']:04x}"
    msg_id = r["sent_msg_id"]

    # 1) B 先回源(此步若污染 pulled,下一步就会漏消息)
    hit, code = _resolve_until(
        lambda: offline_http_b.group_msg_by_id(group_id, [msg_id], client_type=0),
        msg_id)
    assert hit is not None, f"B 按 msgId 回源未取到该消息(HTTP {code})"

    # 2) B 再走正常离线拉取,消息必须仍然在
    deadline = time.time() + RESOLVE_TIMEOUT
    found = False
    while time.time() < deadline and not found:
        try:
            pull_code, rows = offline_http_b.group_pull(group_id, client_type="0", limit=100)
        except requests.exceptions.RequestException:
            continue
        assert pull_code == 200, f"群离线拉取 HTTP {pull_code}"
        found = any(row["msg_id"] == msg_id for row in rows)
        if not found:
            time.sleep(0.6)
    assert found, "回源之后该消息在离线拉取中消失了 —— 回源污染了 pulled 标记(严重回归)"


@pytest.mark.write
def test_group_msg_by_id_client_type_selection(logged_in_client, offline_http, group_id):
    """按端选套:同一 msgId 分别以 Web(2)/App(0) 回源都应成功。

    ⚠️ 断言强度说明:本套件的测试消息是**明文**(mes_grp_chat 不带 encrypt 字段 → encrypt=0),
    服务端 group-job 对 encrypt=0 直接 `content = contentWeb = raw`,故两端返回的 sMsgData
    必然相同——这里只能验「clientType 被接受且不影响正确性」。
    真正的按端选套差异(Web 得 contentWeb、App 得 content)只在 encrypt≠0 的消息上体现,
    需用真实 H5 客户端发一条加密消息后,拿其 msgId 手工跑一次对比(这也正是 2026-09
    「群消息对 Web 端全部解密失败」那条问题的验证点)。
    """
    a = logged_in_client
    text = "[selftest] byid-clienttype-" + uuid.uuid4().hex[:8]
    r = a.send_group_chat(group_id, content=text)
    assert r["errcode"] == 0x8000
    msg_id = r["sent_msg_id"]

    hit_web, code = _resolve_until(
        lambda: offline_http.group_msg_by_id(group_id, [msg_id], client_type=2), msg_id)
    assert hit_web is not None, f"Web(clientType=2)回源失败(HTTP {code})"

    code0, msgs_app, _ = offline_http.group_msg_by_id(group_id, [msg_id], client_type=0)
    assert code0 == 200, f"App(clientType=0)回源 HTTP {code0}"
    hit_app = next((m for m in msgs_app if m["msg_id"] == msg_id), None)
    assert hit_app is not None, "App(clientType=0)回源未取到同一条消息"

    assert hit_web["data"] == hit_app["data"], (
        "明文消息(encrypt=0)两端应返回相同字节;若此处不等,说明服务端对明文消息也做了"
        "分端改写,与 group-job 的 encrypt==0 直通逻辑矛盾")


@pytest.mark.write
def test_group_msg_by_id_missing_ids(logged_in_client, offline_http, group_id, im_config):
    """不存在的 msgId 必须出现在 missingMsgIds 里,让客户端能区分「原消息已删」与「拉取失败」。"""
    a = logged_in_client
    r = a.send_group_chat(group_id, content="[selftest] byid-missing-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == 0x8000
    real_id = r["sent_msg_id"]
    fake_id = uuid.uuid4().hex  # 从未存在过

    hit, _ = _resolve_until(
        lambda: offline_http.group_msg_by_id(group_id, [real_id],
                                             client_type=im_config["client_type"]),
        real_id)
    assert hit is not None, "前置条件失败:真实消息未回源到"

    code, msgs, missing = offline_http.group_msg_by_id(
        group_id, [real_id, fake_id], client_type=im_config["client_type"])
    assert code == 200, f"混合请求 HTTP {code}"
    got_ids = [m["msg_id"] for m in msgs]
    assert real_id in got_ids, "真实 msgId 应在返回列表里"
    assert fake_id not in got_ids, "不存在的 msgId 不应出现在消息列表里"
    assert fake_id in missing, f"不存在的 msgId 应出现在 missingMsgIds,实际 missing={missing}"
    assert real_id not in missing, "命中的 msgId 不应同时出现在 missingMsgIds"


def test_group_msg_by_id_over_limit(offline_http, group_id, im_config):
    """超批量上限(>20)必须被拒(400),这是防刷的第一道闸。"""
    too_many = [uuid.uuid4().hex for _ in range(MAX_MSG_IDS + 1)]
    code, _msgs, _missing = offline_http.group_msg_by_id(
        group_id, too_many, client_type=im_config["client_type"])
    assert code == 400, f"超上限({MAX_MSG_IDS + 1} 个 msgId)应返回 400,实际 {code}"


def test_group_msg_by_id_empty_ids(offline_http, group_id, im_config):
    """空 msgIds 属参数非法,应 400 而不是返回空列表。"""
    code, _msgs, _missing = offline_http.group_msg_by_id(
        group_id, [], client_type=im_config["client_type"])
    assert code == 400, f"空 msgIds 应返回 400,实际 {code}"


def test_group_msg_by_id_non_member_forbidden(offline_http, group_id, im_config):
    """🔴 越权防护:群消息在 msgSrc 是全群一份、无 owner 维度,
    非群成员按 msgId 裸查等于「知道 msgId 就能读任意群消息」,必须被拒。

    用一个调用者几乎不可能是成员的 groupId(在配置群 id 上加大偏移)来模拟非成员。
    """
    foreign_group = group_id + 999_999_999
    code, msgs, _missing = offline_http.group_msg_by_id(
        foreign_group, [uuid.uuid4().hex], client_type=im_config["client_type"])
    assert code != 200 or not msgs, (
        f"对非成员群的回源不应返回数据(HTTP {code},返回 {len(msgs)} 条)")
    assert code == 403, f"非群成员应被拒为 403,实际 {code}"


# ─────────────────────────── 单聊 ───────────────────────────

@pytest.mark.write
def test_chat_msg_by_id_roundtrip(logged_in_client, offline_http, im_config):
    """单聊按 msgId 回源:自发自收(sToId=self),回源应取到且正文一致。

    单聊查询恒带 owerId=鉴权态 userId,天然隔离,无需成员校验;
    DAO 同时覆盖收件副本(msgOffline_{owerId%20})与发件副本(msgOwnerOffline),
    所以「引用自己发出的消息」也应能取到。
    """
    a = logged_in_client
    text = "[selftest] byid-chat-" + uuid.uuid4().hex[:8]
    r = a.send_chat(to_id=a.user_id, content=text)
    assert r["errcode"] == 0x8000, f"单聊上行未被接受 errcode=0x{r['errcode']:04x}"
    msg_id = r["sent_msg_id"]

    hit, code = _resolve_until(
        lambda: offline_http.chat_msg_by_id([msg_id], client_type=im_config["client_type_b"]),
        msg_id)
    assert hit is not None, f"单聊按 msgId 回源未取到(HTTP {code};落库延迟?)"
    assert hit["from_id"] == a.user_id, "回源消息发送者应为 A"
    inner = proto_min.parse_single_deliver(hit["data"])
    assert inner["content"] == text.encode(), "回源正文与发送内容不一致"


@pytest.mark.write
def test_chat_msg_by_id_does_not_mark_pulled(logged_in_client, drained_offline_http, im_config):
    """单聊同样约束:回源不得修改 pulled。回源后再走 /offline/v1/chat,消息必须仍在。

    用 drained_offline_http:离线拉取是 limit 窗口查询,存量积压会把新消息挤出窗口,
    导致本用例假失败(套件里已有实录)。
    """
    a = logged_in_client
    ct_offline = im_config["client_type_b"]
    text = "[selftest] byid-chat-nopull-" + uuid.uuid4().hex[:8]
    r = a.send_chat(to_id=a.user_id, content=text)
    assert r["errcode"] == 0x8000
    msg_id = r["sent_msg_id"]

    hit, code = _resolve_until(
        lambda: drained_offline_http.chat_msg_by_id([msg_id], client_type=ct_offline), msg_id)
    assert hit is not None, f"单聊回源未取到(HTTP {code})"

    deadline = time.time() + RESOLVE_TIMEOUT
    found = False
    while time.time() < deadline and not found:
        try:
            pull_code, rows = drained_offline_http.offline_chat(client_type=ct_offline, limit=100)
        except requests.exceptions.RequestException:
            continue
        assert pull_code == 200, f"单聊离线拉取 HTTP {pull_code}"
        found = any(row["msg_id"] == msg_id for row in rows)
        if not found:
            time.sleep(0.6)
    assert found, "回源之后该消息在单聊离线拉取中消失了 —— 回源污染了 pulled 标记(严重回归)"


def test_chat_msg_by_id_over_limit(offline_http, im_config):
    """单聊批量上限同为 20。"""
    too_many = [uuid.uuid4().hex for _ in range(MAX_MSG_IDS + 1)]
    code, _msgs, _missing = offline_http.chat_msg_by_id(
        too_many, client_type=im_config["client_type"])
    assert code == 400, f"超上限应返回 400,实际 {code}"


@pytest.mark.write
def test_chat_msg_by_id_missing_ids(logged_in_client, offline_http, im_config):
    """单聊 missingMsgIds:别人会话里的/不存在的 msgId 都应进 missing 而非泄漏内容。"""
    a = logged_in_client
    r = a.send_chat(to_id=a.user_id, content="[selftest] byid-chat-missing-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == 0x8000
    real_id = r["sent_msg_id"]
    fake_id = uuid.uuid4().hex

    hit, _ = _resolve_until(
        lambda: offline_http.chat_msg_by_id([real_id], client_type=im_config["client_type_b"]),
        real_id)
    assert hit is not None, "前置条件失败:真实消息未回源到"

    code, msgs, missing = offline_http.chat_msg_by_id(
        [real_id, fake_id], client_type=im_config["client_type_b"])
    assert code == 200, f"混合请求 HTTP {code}"
    assert real_id in [m["msg_id"] for m in msgs], "真实 msgId 应被返回"
    assert fake_id in missing, f"不存在的 msgId 应进 missingMsgIds,实际 missing={missing}"


# ─────────────────────────── 超级群 ───────────────────────────

@pytest.mark.write
def test_channel_msg_by_id_roundtrip(logged_in_client, offline_http, channel_id, im_config):
    """超级群按 msgId 回源。

    注意与既有 GetSpecificMsgs 的区别:那个按 sIndex(mongo _id)取,本接口按 msgId 取
    (客户端 parentMsgId 即 msgId 语义)。
    """
    a = logged_in_client
    text = "[selftest] byid-channel-" + uuid.uuid4().hex[:8]
    r = a.send_channel_chat(channel_id, content=text)
    assert r["errcode"] == 0x8000, f"超级群上行未被接受 errcode=0x{r['errcode']:04x}"
    msg_id = r["sent_msg_id"]

    hit, code = _resolve_until(
        lambda: offline_http.channel_msg_by_id(channel_id, [msg_id],
                                               client_type=im_config["client_type"]),
        msg_id)
    assert hit is not None, f"超级群按 msgId 回源未取到(HTTP {code};落库延迟?频道成员?)"
    assert hit["chnn_id"] == channel_id, "回源消息所属频道不符"
    assert hit["from_id"] == a.user_id, "回源消息发送者应为 A"
    assert hit["content"] == text.encode(), "回源正文与发送内容不一致"
    assert hit["index"], "sIndex(mongo _id)应有值,供客户端定位跳转"


@pytest.mark.write
def test_channel_msg_by_id_missing_ids(logged_in_client, offline_http, channel_id, im_config):
    """超级群 missingMsgIds。"""
    a = logged_in_client
    r = a.send_channel_chat(channel_id, content="[selftest] byid-chnn-missing-" + uuid.uuid4().hex[:8])
    assert r["errcode"] == 0x8000
    real_id = r["sent_msg_id"]
    fake_id = uuid.uuid4().hex

    hit, _ = _resolve_until(
        lambda: offline_http.channel_msg_by_id(channel_id, [real_id],
                                               client_type=im_config["client_type"]),
        real_id)
    assert hit is not None, "前置条件失败:真实消息未回源到"

    code, msgs, missing = offline_http.channel_msg_by_id(
        channel_id, [real_id, fake_id], client_type=im_config["client_type"])
    assert code == 200, f"混合请求 HTTP {code}"
    assert real_id in [m["msg_id"] for m in msgs], "真实 msgId 应被返回"
    assert fake_id in missing, f"不存在的 msgId 应进 lsMissingMsgId,实际 missing={missing}"


def test_channel_msg_by_id_over_limit(offline_http, channel_id, im_config):
    """超级群批量上限同为 20;该端点非 200 由网关统一回 400。"""
    too_many = [uuid.uuid4().hex for _ in range(MAX_MSG_IDS + 1)]
    code, _msgs, _missing = offline_http.channel_msg_by_id(
        channel_id, too_many, client_type=im_config["client_type"])
    assert code == 400, f"超上限应返回 400,实际 {code}"


def test_channel_msg_by_id_non_member_forbidden(offline_http, channel_id, im_config):
    """🔴 越权防护:非频道成员不得按 msgId 回源该频道消息。

    /channel/v1 家族的惯例是「非成功统一 HTTP 400,具体码放 body 的 errcode」,
    故非成员(下游 errcode=403)在 HTTP 层表现为 400。
    必须同时断言「被拒」与「无数据」——只断言无数据的话,接口坏掉返回空也会通过。
    """
    foreign_channel = channel_id + 999_999_999
    code, msgs, _missing = offline_http.channel_msg_by_id(
        foreign_channel, [uuid.uuid4().hex], client_type=im_config["client_type"])
    assert not msgs, f"对非成员频道的回源不应返回数据(HTTP {code},返回 {len(msgs)} 条)"
    assert code == 400, (
        f"非频道成员应被拒(HTTP 400 + body errcode=403),实际 {code};"
        "若为 200 说明网关又没透传下游业务错误码")
