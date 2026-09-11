"""IM WebSocket 客户端(模拟 H5:连接 → CM_LOGIN → 发心情回应 → 收 ACK)。

鉴权:CM_LOGIN 的 sLoginToken 经 login-srv→identify-srv Check 校验(与 dm-api 同一套 token,大概率通用)。
好友校验规避:回应 sToId 填自己的 user_id(自反应)→ 服务端 sFromId==sToId 跳过好友校验,免真好友。
"""

import time
import uuid

import websocket  # websocket-client

from im_test import frame, proto_min

CM_LOGIN = 0x0101
CM_LOGIN_ACK = 0x0102
HEARTBEAT = 0x0001
REACTION_UPLINK = 0x122A          # 单聊回应上行(收方副本;走好友校验,除非自反应)
REACTION_OPPOSITE = 0x122B        # 单聊回应上行(对端副本;恒跳好友校验)
REACTION_ACK = 0x122C
GROUP_REACTION_UPLINK = 0x2312    # 群回应上行
GROUP_REACTION_ACK = 0x2313
RADIO_REACTION_UPLINK = 0x3211    # 超级群回应上行
RADIO_REACTION_ACK = 0x3212
NON_ERR = 0x8000                  # 成功码

# 普通消息:上行 / ACK / 下行 deliver(收方在线时收到);字段号见 proto_min
SINGLE_CHAT = 0x1001
SINGLE_CHAT_ACK = 0x1002
SINGLE_DELIVER = 0x1004           # 单聊普通下行
SINGLE_REACTION_DELIVER = 0x122D  # 单聊回应下行
GROUP_CHAT = 0x2001
GROUP_CHAT_ACK = 0x2002
GROUP_DELIVER = 0x2004            # 群普通下行
GROUP_REACTION_DELIVER = 0x2314   # 群回应下行
RADIO_CHAT = 0x3001
RADIO_CHAT_ACK = 0x3002
RADIO_DELIVER = 0x3004            # 超级群普通下行
RADIO_REACTION_DELIVER = 0x3213   # 超级群回应下行

# 私聊音视频(对照:Web 扇出本来就有)
SIG_P2P_CALL = 0x4001
SIG_P2P_CALL_ACK = 0x4002
SIG_P2P_CALL_DELIVER = 0x4004     # 0x4004 私聊来电下行
SIG_P2P_HANGUP = 0x400d
SIG_P2P_HANGUP_ACK = 0x400e

# 群通话信令(M1–M7)
SIG_GROUP_CALL = 0x4101
SIG_GROUP_CALL_ACK = 0x4102
SIG_GROUP_CALL_DELIVER_ACK = 0x4103
SIG_GROUP_CALL_DELIVER = 0x4104   # 0x4104 群开场来电
SIG_GROUP_JOIN = 0x4109
SIG_GROUP_JOIN_DELIVER = 0x410c   # 0x410c 群会中拉人
SIG_GROUP_HANGUP = 0x410d
SIG_GROUP_HANGUP_ACK = 0x410e
SIG_GROUP_HANGUP_DELIVER_ACK = 0x410f  # M4 补路由
SIG_GROUP_HANGUP_DELIVER = 0x4110
SIG_GROUP_FINISH = 0x4111
SIG_GROUP_FINISH_ACK = 0x4112
SIG_GROUP_DISCONNECTED = 0x4119
SIG_GROUP_DISCONNECTED_ACK = 0x411a
SIG_GROUP_DISCONNECTED_DELIVER_ACK = 0x411b  # M4 补路由
SIG_GROUP_DISCONNECTED_DELIVER = 0x411c
SIG_GROUP_BUSY = 0x411d
SIG_GROUP_BUSY_ACK = 0x411e
SIG_GROUP_BUSY_DELIVER_ACK = 0x411f          # M4 补路由
SIG_GROUP_BUSY_DELIVER = 0x4120


class ImWsClient:
    def __init__(self, url, user_id, token, client_type=2, timeout=10, app_version=None,
                 channel_type=None, device_token="web"):
        self.url = url
        self.user_id = int(user_id)
        self.token = token
        self.device_token = device_token
        # CMLogin.sVersionCode:版本兼容门用。None=不覆盖(走 proto_min 默认);
        # 传低版本(如 "2.20.0")即模拟老客户端,服务端应拒发新消息类型。
        self.app_version = app_version
        # CMLogin.channelType:版本兼容门按渠道取门槛(上架系 1/3/2/4/6、超签 15/16,
        # 编号同推送服务)。None=不上报,服务端读到 0 → 落通配档。
        self.channel_type = channel_type
        self.client_type = client_type
        self.timeout = timeout
        self.ws = None
        self.seq = 0

    def connect(self):
        self.ws = websocket.create_connection(self.url, timeout=self.timeout)
        return self

    def close(self):
        try:
            if self.ws:
                self.ws.close()
        except Exception:
            pass

    def _send(self, cmd, body):
        self.seq += 1
        self.ws.send_binary(frame.build_frame(cmd, body, self.seq))

    def _recv_until(self, target_cmd, timeout=None):
        """读帧直到拿到 target_cmd,途中跳过心跳/推送/离线消息等无关帧。"""
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            self.ws.settimeout(max(0.1, deadline - time.time()))
            try:
                data = self.ws.recv()
            except (websocket.WebSocketTimeoutException, TimeoutError):
                continue  # 底层读超时:由外层 deadline 统一判定(expect_no_deliver 依赖此语义)
            if isinstance(data, str) or not data:
                continue  # 文本/空帧忽略(业务全走 binary)
            cmd, body = frame.parse_frame(data)
            if cmd == target_cmd:
                return body
        raise TimeoutError(f"未在 {timeout or self.timeout}s 内收到 cmd=0x{target_cmd:04x}")

    def login(self):
        """返回登录错误码(NON_ERR=0x8000 为成功)。"""
        self._send(CM_LOGIN, proto_min.cm_login(self.user_id, self.token, self.client_type,
                                                device_token=self.device_token,
                                                app_version=self.app_version,
                                                channel_type=self.channel_type))
        f = proto_min.decode(self._recv_until(CM_LOGIN_ACK))
        return f.get(2, 0)  # CMLoginAck.nErr

    def send_reaction(self, to_id=None, parent_msg_id=None, emoji="👍", action=0, opposite=False):
        """发一条单聊心情回应,返回 {errcode, ack_msg_id, sent_msg_id}。"""
        to_id = self.user_id if to_id is None else int(to_id)
        parent_msg_id = parent_msg_id or uuid.uuid4().hex
        msg_id = uuid.uuid4().hex
        content = proto_min.mes_reaction_content(emoji, action)
        body = proto_min.mes_chat_reaction(to_id, msg_id, parent_msg_id, content)
        self._send(REACTION_OPPOSITE if opposite else REACTION_UPLINK, body)
        ack = proto_min.decode(self._recv_until(REACTION_ACK))
        ack_mid = ack.get(2, b"")
        return {
            "errcode": ack.get(4, 0),
            "ack_msg_id": ack_mid.decode() if isinstance(ack_mid, bytes) else "",
            "sent_msg_id": msg_id,
        }

    def send_group_reaction(self, group_id, parent_msg_id=None, emoji="👍", action=0):
        """群心情回应(需登录用户确为该群成员)。返回 {errcode, sent_msg_id}。"""
        parent_msg_id = parent_msg_id or uuid.uuid4().hex
        msg_id = uuid.uuid4().hex
        content = proto_min.mes_reaction_content(emoji, action)
        body = proto_min.mes_grp_chat_reaction(group_id, msg_id, parent_msg_id, content)
        self._send(GROUP_REACTION_UPLINK, body)
        ack = proto_min.decode(self._recv_until(GROUP_REACTION_ACK))
        return {"errcode": ack.get(5, 0), "sent_msg_id": msg_id}  # GroupChatAck.errcode=5

    def send_channel_reaction(self, radio_id, parent_msg_id=None, emoji="👍", action=0):
        """超级群心情回应(需登录用户在该频道有权限)。返回 {errcode, sent_msg_id}。"""
        parent_msg_id = parent_msg_id or uuid.uuid4().hex
        msg_id = uuid.uuid4().hex
        content = proto_min.mes_reaction_content(emoji, action)
        body = proto_min.radio_chat_reaction(radio_id, msg_id, parent_msg_id, content)
        self._send(RADIO_REACTION_UPLINK, body)
        ack = proto_min.decode(self._recv_until(RADIO_REACTION_ACK))
        return {"errcode": ack.get(5, 0), "sent_msg_id": msg_id}  # RadioChatAck.errcode=5

    # ── 普通消息发送(投递测试:发送端 A 调这些,收方端 B 调 recv_deliver)──
    def send_chat(self, to_id=None, content="[selftest] hi", msg_type=1):
        """发一条单聊普通消息(默认 sToId=self 跳好友校验)。返回 {errcode, sent_msg_id}。"""
        to_id = self.user_id if to_id is None else int(to_id)
        msg_id = uuid.uuid4().hex
        self._send(SINGLE_CHAT, proto_min.mes_chat(to_id, msg_id, content, msg_type))
        ack = proto_min.decode(self._recv_until(SINGLE_CHAT_ACK))
        return {"errcode": ack.get(4, 0), "sent_msg_id": msg_id}  # MESChatAck.errcode=4

    def send_group_chat(self, group_id, content="[selftest] hi"):
        """发一条群普通消息(需为群成员)。返回 {errcode, sent_msg_id}。"""
        msg_id = uuid.uuid4().hex
        self._send(GROUP_CHAT, proto_min.mes_grp_chat(group_id, msg_id, content))
        ack = proto_min.decode(self._recv_until(GROUP_CHAT_ACK))
        return {"errcode": ack.get(5, 0), "sent_msg_id": msg_id}  # GroupChatAck.errcode=5

    def send_channel_chat(self, radio_id, content="[selftest] hi"):
        """发一条超级群普通消息(需在该频道有权限)。返回 {errcode, sent_msg_id}。"""
        msg_id = uuid.uuid4().hex
        self._send(RADIO_CHAT, proto_min.radio_chat(radio_id, msg_id, content))
        ack = proto_min.decode(self._recv_until(RADIO_CHAT_ACK))
        return {"errcode": ack.get(5, 0), "sent_msg_id": msg_id}  # RadioChatAck.errcode=5

    def recv_deliver(self, cmd, timeout=None):
        """收方视角:读到目标下行 deliver 帧(0x1004/0x122d/0x2004/0x2314/0x3004/0x3213),
        返回原始 body(用 proto_min.parse_*_deliver 解析)。超时抛 TimeoutError。"""
        return self._recv_until(cmd, timeout)

    def send_no_ack(self, cmd, body):
        """发一帧不等 ACK(deliver ACK 服务端 Command=0,网关不回包)。"""
        self._send(cmd, body)

    def heartbeat(self):
        """网关 WebSocket 60s 无上行会踢连接。长等待(离线拉)期间要打一拍。"""
        try:
            self._send(HEARTBEAT, b"")
        except Exception:
            pass

    def send_p2p_call(self, invite_id, call_type=1):
        """发起私聊语音(0x4001)。返回 {errcode, sent_msg_id, call_id}。"""
        msg_id = uuid.uuid4().hex
        call_id = uuid.uuid4().hex
        body = proto_min.sig_sponsor_p2p_call(invite_id, self.user_id, msg_id, call_id, call_type)
        self._send(SIG_P2P_CALL, body)
        ack = proto_min.parse_p2p_call_ack(self._recv_until(SIG_P2P_CALL_ACK))
        return {"errcode": ack["errcode"], "sent_msg_id": msg_id, "call_id": call_id}

    def send_p2p_hangup(self, to_id, call_id):
        msg_id = uuid.uuid4().hex
        body = proto_min.sig_p2p_hangup(to_id, self.user_id, msg_id, call_id)
        self._send(SIG_P2P_HANGUP, body)
        ack = proto_min.parse_p2p_call_ack(self._recv_until(SIG_P2P_HANGUP_ACK))
        return {"errcode": ack["errcode"], "sent_msg_id": msg_id}

    def send_group_call(self, group_id, invite_ids=None):
        """发起群通话(0x4101)。返回 {errcode, sent_msg_id, call_id}。"""
        msg_id = uuid.uuid4().hex
        call_id = uuid.uuid4().hex
        body = proto_min.sig_sponsor_group_call(
            group_id, self.user_id, msg_id, call_id, invite_ids=invite_ids)
        self._send(SIG_GROUP_CALL, body)
        ack = proto_min.parse_group_call_ack(self._recv_until(SIG_GROUP_CALL_ACK))
        return {"errcode": ack["errcode"], "sent_msg_id": msg_id, "call_id": call_id}

    def send_group_call_finish(self, group_id, call_id, hangup=False):
        """结束 0x4111;hangup=True 则发挂断 0x410d(结构相同)。"""
        msg_id = uuid.uuid4().hex
        cmd = SIG_GROUP_HANGUP if hangup else SIG_GROUP_FINISH
        ack_cmd = SIG_GROUP_HANGUP_ACK if hangup else SIG_GROUP_FINISH_ACK
        body = proto_min.sig_group_call_finish(group_id, self.user_id, msg_id, call_id)
        self._send(cmd, body)
        ack = proto_min.parse_group_call_ack(self._recv_until(ack_cmd))
        return {"errcode": ack["errcode"], "sent_msg_id": msg_id}

    def send_group_call_disconnected(self, group_id, call_id, users=None):
        msg_id = uuid.uuid4().hex
        body = proto_min.sig_group_call_disconnected(
            group_id, self.user_id, msg_id, call_id, users=users)
        self._send(SIG_GROUP_DISCONNECTED, body)
        ack = proto_min.parse_group_call_ack(self._recv_until(SIG_GROUP_DISCONNECTED_ACK))
        return {"errcode": ack["errcode"], "sent_msg_id": msg_id}

    def send_group_call_busy(self, group_id, call_id, hint_user=0):
        msg_id = uuid.uuid4().hex
        body = proto_min.sig_group_call_busy(
            group_id, self.user_id, msg_id, call_id, hint_user=hint_user)
        self._send(SIG_GROUP_BUSY, body)
        ack = proto_min.parse_group_call_ack(self._recv_until(SIG_GROUP_BUSY_ACK))
        return {"errcode": ack["errcode"], "sent_msg_id": msg_id}

    def send_group_deliver_ack(self, cmd, msg_id, body_user_id=0):
        """群通话 DELIVER ACK。cmd 取 0x4103/0x410f/0x411b/0x411f。服务端不回包。"""
        self.send_no_ack(cmd, proto_min.sig_group_call_deliver_ack(body_user_id, msg_id))

    def expect_no_deliver(self, cmd, timeout=6):
        """断言在 timeout 内**收不到**该下行(版本兼容门:老客户端不应收到新消息类型)。
        收到即返回 False(门失效);超时未收到返回 True(符合预期)。"""
        try:
            self._recv_until(cmd, timeout)
            return False
        except (TimeoutError, websocket.WebSocketTimeoutException):
            return True
