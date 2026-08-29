"""极简 protobuf 编解码——只覆盖登录/回应几条消息的字段,不引 protoc/protobuf 运行时。

字段号读 im-common/proto/app 核实:
  CMLogin: sUserId=1(int64) sLoginToken=2(string) sDeviceToken=3(string) clientType=8(uint32)
  MESReactionContent: emoji=1(string) action=2(uint32)
  MESChat: sToId=1(int64) sMsgId=3(string) sContent=7(bytes) parentMsgId=12(string)  (sFromId=2 由网关覆盖,不发)
  解码 CMLoginAck: nErr=2;单聊 MESChatAck errcode=4;群 GroupChatAck/超级群 RadioChatAck errcode=5
"""


def _enc_varint(n):
    if n < 0:
        n &= (1 << 64) - 1
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _fv(fn, val):  # varint 字段(wire type 0)
    return _enc_varint(fn << 3) + _enc_varint(val)


def _fb(fn, data):  # 长度定界字段(wire type 2)
    return _enc_varint((fn << 3) | 2) + _enc_varint(len(data)) + data


def _fs(fn, s):
    return _fb(fn, s.encode("utf-8"))


def _dec_varint(data, i):
    shift = 0
    result = 0
    while True:
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i
        shift += 7


def decode(data):
    """解成 {字段号: 值}(varint→int,长度定界→bytes)。"""
    fields = {}
    i = 0
    n = len(data)
    while i < n:
        tag, i = _dec_varint(data, i)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            fields[fn], i = _dec_varint(data, i)
        elif wt == 2:
            ln, i = _dec_varint(data, i)
            fields[fn] = data[i:i + ln]
            i += ln
        elif wt == 1:
            fields[fn] = data[i:i + 8]
            i += 8
        elif wt == 5:
            fields[fn] = data[i:i + 4]
            i += 4
        else:
            break
    return fields


# ── 消息构造 ──
def cm_login(user_id, token, client_type=2, device_token="web", app_version=None,
             channel_type=None):
    # CMLogin: sUserId=1 sLoginToken=2 sDeviceToken=3 sVersionCode=6 clientType=8 channelType=9
    body = _fv(1, int(user_id)) + _fs(2, token) + _fs(3, device_token)
    if app_version is not None:
        body += _fs(6, str(app_version))  # 版本兼容门:服务端按此判定新老客户端
    body += _fv(8, client_type)
    if channel_type is not None:
        # 应用渠道,决定门槛取哪一档(上架系 1/3/2/4/6 与超签 15/16 版本号不是同一套)。
        # 不传=不写该字段,服务端 Redis 取到 0 → 落通配门槛。
        body += _fv(9, int(channel_type))
    return body


def mes_reaction_content(emoji, action=0):
    return _fs(1, emoji) + _fv(2, action)


def mes_chat_reaction(to_id, msg_id, parent_msg_id, content):
    return _fv(1, int(to_id)) + _fs(3, msg_id) + _fb(7, content) + _fs(12, parent_msg_id)


def mes_grp_chat_reaction(grp_id, msg_id, parent_msg_id, content):
    # MESGrpChat: sGrpId=1(int64) sMsgId=5(string) sContent=8(bytes) parentMsgId=13(string)
    return _fv(1, int(grp_id)) + _fs(5, msg_id) + _fb(8, content) + _fs(13, parent_msg_id)


def radio_chat_reaction(radio_id, msg_id, parent_msg_id, content):
    # RadioChat: sRadioId=2(int64) sMsgId=3(string) sContent=6(bytes) parentMsgId=13(string)
    return _fv(2, int(radio_id)) + _fs(3, msg_id) + _fb(6, content) + _fs(13, parent_msg_id)


# ── 普通消息构造(在线/离线投递测试用;字段号读 im-common/proto/app 核实)──
def mes_chat(to_id, msg_id, content, msg_type=1):
    # MESChat(单聊 0x1001): sToId=1 sMsgId=3 msgType=4(1=P2P普通) sContent=7
    body = content.encode("utf-8") if isinstance(content, str) else content
    return _fv(1, int(to_id)) + _fs(3, msg_id) + _fv(4, msg_type) + _fb(7, body)


def mes_grp_chat(grp_id, msg_id, content, msg_type=5):
    # MESGrpChat(群 0x2001): sGrpId=1 sMsgId=5 sContent=8 msgType=10(5=群聊)
    body = content.encode("utf-8") if isinstance(content, str) else content
    return _fv(1, int(grp_id)) + _fs(5, msg_id) + _fb(8, body) + _fv(10, msg_type)


def radio_chat(radio_id, msg_id, content):
    # RadioChat(超级群 0x3001): sRadioId=2 sMsgId=3 sContent=6(无 msgType 字段)
    body = content.encode("utf-8") if isinstance(content, str) else content
    return _fv(2, int(radio_id)) + _fs(3, msg_id) + _fb(6, body)


# ── 下行 deliver 帧解析(收方视角断言用)──
def _s(v):  # bytes→str
    return v.decode("utf-8", "ignore") if isinstance(v, bytes) else (v or "")


def parse_single_deliver(body):
    """单聊下行 0x1004/0x122d = MESChat: sToId=1 sFromId=2 sMsgId=3 sContent=7 parentMsgId=12。"""
    f = decode(body)
    return {"to_id": f.get(1, 0), "from_id": f.get(2, 0), "msg_id": _s(f.get(3, b"")),
            "content": f.get(7, b""), "parent_msg_id": _s(f.get(12, b""))}


def parse_group_deliver(body):
    """群下行 0x2004/0x2314 = MESGrpChat: sGrpId=1 sFromId=2 sMsgId=5 sContent=8 parentMsgId=13。"""
    f = decode(body)
    return {"grp_id": f.get(1, 0), "from_id": f.get(2, 0), "msg_id": _s(f.get(5, b"")),
            "content": f.get(8, b""), "parent_msg_id": _s(f.get(13, b""))}


def parse_radio_deliver(body):
    """超级群下行 0x3004/0x3213 = RadioChat: sFromId=1 sRadioId=2 sMsgId=3 sContent=6 parentMsgId=13。"""
    f = decode(body)
    return {"from_id": f.get(1, 0), "radio_id": f.get(2, 0), "msg_id": _s(f.get(3, b"")),
            "content": f.get(6, b""), "parent_msg_id": _s(f.get(13, b""))}


# ── 离线拉取(HTTP REST;字段号读 im-common/proto/msgsrv/msgsrv.proto 核实)──
def decode_all(data):
    """repeated-aware 解码:同字段号多值收进 list(离线 Resp 的 repeated msgList 必须用这个,
    decode() 会被最后一条覆盖)。返回 {字段号: [值,...]}。"""
    fields = {}
    i, n = 0, len(data)
    while i < n:
        tag, i = _dec_varint(data, i)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = _dec_varint(data, i)
        elif wt == 2:
            ln, i = _dec_varint(data, i)
            v = data[i:i + ln]
            i += ln
        elif wt == 1:
            v = data[i:i + 8]
            i += 8
        elif wt == 5:
            v = data[i:i + 4]
            i += 4
        else:
            break
        fields.setdefault(fn, []).append(v)
    return fields


def offline_chat_msg_req(user_id, limit=50, client_type=0, msg_id="", delivered=None):
    """OfflineChatMsgReq: userId=1 msgId=2 deliveredMsgInfos=3(repeated) limit=4 clientType=5。
    delivered=[{msg_id, msg_time, cmd_id}]:回带"已收到"的消息,服务端据此 MarkPulled
    (只标回带的 msgId——这正是"被 filter 排除的行不会被误标"的机制所在)。"""
    out = _fv(1, int(user_id))
    if msg_id:
        out += _fs(2, msg_id)
    for d in (delivered or []):
        # DeliverMsgInfo: msgId=1 msgTime=2 cmdId=3
        item = _fs(1, d["msg_id"]) + _fv(2, int(d.get("msg_time", 0))) + _fv(3, int(d.get("cmd_id", 0)))
        out += _fb(3, item)
    return out + _fv(4, int(limit)) + _fv(5, int(client_type))


def parse_offline_resp(body):
    """OfflineChatMsgResp: msgList=3(repeated OfflineChatMsg)。
    OfflineChatMsg: cmdId=1 sMsgData=2 sMsgId=3 sFromId=4 sToId=5 msgTime=6 parentMsgId=8 isRead=9。
    返回 [{cmd_id,msg_id,from_id,to_id,parent_msg_id,is_read,data(bytes)}]。"""
    rows = decode_all(body).get(3, [])
    out = []
    for raw in rows:
        f = decode(raw)
        out.append({
            "cmd_id": f.get(1, 0), "data": f.get(2, b""), "msg_id": _s(f.get(3, b"")),
            "from_id": f.get(4, 0), "to_id": f.get(5, 0), "msg_time": f.get(6, 0),
            "parent_msg_id": _s(f.get(8, b"")), "is_read": f.get(9, 0),
        })
    return out


# ── 群离线:有未读会话(会话内联 msgList,普通消息;字段号读 groupsrv/groupsrv.proto)──
def offline_group_session_req(client_type="0", size=50):
    # OfflineGroupSessionReq: userId=1(网关ctx注入,不发) clientType=2(string!) size=3(int64)
    return _fs(2, str(client_type)) + _fv(3, int(size))


def parse_group_session_resp(body):
    """OfflineGroupSessionResp: sessionList=2(repeated OfflineGroupSession)。
    OfflineGroupSession: groupId=1 unreadCount=2 msgList=3(repeated OfflineGroupMsg)。
    OfflineGroupMsg: cmdId=1 sMsgData=2 sMsgId=3 sFromId=4 sGroupId=5 parentMsgId=8。
    展平所有会话的 msgList,返回 [{group_id,unread,cmd_id,msg_id,from_id,parent_msg_id,data}]。"""
    out = []
    for s in decode_all(body).get(2, []):
        sf = decode_all(s)
        gid = sf.get(1, [0])[0]
        unread = sf.get(2, [0])[0]
        for raw in sf.get(3, []):
            m = decode(raw)
            out.append({
                "group_id": gid, "unread": unread,
                "cmd_id": m.get(1, 0), "data": m.get(2, b""), "msg_id": _s(m.get(3, b"")),
                "from_id": m.get(4, 0), "parent_msg_id": _s(m.get(8, b"")),
            })
    return out


# ── 超级群离线:会话列表(每会话带 last=最新一条 + uUnread;普通消息)──
def pull_chnn_session_req(user_id, chnn_id, client_type=0):
    # PullChnnSessionReq: sUserId=1(body,非ctx) lsChnnInfo=2(repeated PullChnnInfo{sChnnId=1}) clientType=3(uint32)
    info = _fv(1, int(chnn_id))
    return _fv(1, int(user_id)) + _fb(2, info) + _fv(3, int(client_type))


def parse_chnn_session_resp(body):
    """PullChnnSessionRsp: lsSession=2(repeated SessionInfo)。
    SessionInfo: sChnnId=1 sReadIndex=2 uUnread=3 last=4(ChnnChat) 。
    ChnnChat: sMsgId=3 sIndex=8 eventType=17。返回 [{chnn_id,unread,last_msg_id,last_index,last_event}]。"""
    out = []
    for s in decode_all(body).get(2, []):
        sf = decode(s)
        last = decode(sf.get(4, b"")) if sf.get(4) else {}
        out.append({
            "chnn_id": sf.get(1, 0), "unread": sf.get(3, 0),
            "last_msg_id": _s(last.get(3, b"")), "last_index": _s(last.get(8, b"")),
            "last_event": last.get(17, 0),
        })
    return out


# ── 群消息拉取(游标端点 /offline/v1/group/pull;回应能拉到,默认不排除)──
def get_group_msg_req(group_id, client_type="0", msg_index="", direct=-1, limit=50):
    # GetGroupMsgReq: userId=1(网关ctx) groupId=2 msgIndex=3(str,空=全部未拉) direct=4(int32 1向后/-1向前=排序)
    #                 limit=5(int32) clientType=6(str,决定按 app/pc/web Pulled=0 过滤)
    out = _fv(2, int(group_id))
    if msg_index:
        out += _fs(3, msg_index)
    return out + _fv(4, int(direct)) + _fv(5, int(limit)) + _fs(6, str(client_type))


def parse_group_msg_resp(body):
    """GetGroupMsgResp: data=2(repeated OfflineGroupMsg)。
    OfflineGroupMsg: cmdId=1 sMsgData=2 sMsgId=3 sFromId=4 sGroupId=5 parentMsgId=8 isRead=9。"""
    out = []
    for raw in decode_all(body).get(2, []):
        f = decode(raw)
        out.append({
            "cmd_id": f.get(1, 0), "data": f.get(2, b""), "msg_id": _s(f.get(3, b"")),
            "from_id": f.get(4, 0), "group_id": f.get(5, 0),
            "parent_msg_id": _s(f.get(8, b"")), "is_read": f.get(9, 0),
        })
    return out


# ── 超级群消息拉取(游标端点 /channel/v1/offlineMessages;服务端硬过滤 Normal,回应拉不到)──
def pull_chnn_message_req(user_id, chnn_id, base_index="", direction=1, count=50, is_contain=1, client_type=0):
    # PullChnnMessageReq: sUserId=1(body,非ctx) lsPull=2(repeated PullChnnMessageInfo) clientType=3(uint32)
    # PullChnnMessageInfo: sChnnId=1 sBaseIndex=2(空+UP=1→最新N条) uDirection=3(1向前/0向后) uCount=4 uIsContain=5
    info = _fv(1, int(chnn_id))
    if base_index:
        info += _fs(2, base_index)
    info += _fv(3, int(direction)) + _fv(4, int(count)) + _fv(5, int(is_contain))
    return _fv(1, int(user_id)) + _fb(2, info) + _fv(3, int(client_type))


def parse_chnn_message_resp(body):
    """PullChnnMessageRsp: lsMessage=2(repeated ChnnChat)。
    ChnnChat: sFromId=1 sChnnId=2 sMsgId=3 sContent=6 sIndex=8 parentMsgId=13 eventType=17(0普通/2回应)。"""
    out = []
    for raw in decode_all(body).get(2, []):
        f = decode(raw)
        out.append({
            "from_id": f.get(1, 0), "chnn_id": f.get(2, 0), "msg_id": _s(f.get(3, b"")),
            "content": f.get(6, b""), "index": _s(f.get(8, b"")),
            "parent_msg_id": _s(f.get(13, b"")), "event_type": f.get(17, 0),
        })
    return out
