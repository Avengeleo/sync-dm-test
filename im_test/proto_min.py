"""极简 protobuf 编解码——只覆盖登录/回应几条消息的字段,不引 protoc/protobuf 运行时。

字段号读 im-common/proto/app 核实:
  CMLogin: sUserId=1(int64) sLoginToken=2(string) sDeviceToken=3(string) clientType=8(uint32)
  MESReactionContent: emoji=1(string) action=2(uint32)
  MESChat: sToId=1(int64) sMsgId=3(string) sContent=7(bytes) parentMsgId=12(string)  (sFromId=2 由网关覆盖,不发)
  解码 CMLoginAck: nErr=2 ;  MESChatAck: sMsgId=2(string) errcode=4
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
