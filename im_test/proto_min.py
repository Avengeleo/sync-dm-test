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
def cm_login(user_id, token, client_type=2, device_token="web"):
    return _fv(1, int(user_id)) + _fs(2, token) + _fs(3, device_token) + _fv(8, client_type)


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
