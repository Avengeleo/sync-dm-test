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


class ImWsClient:
    def __init__(self, url, user_id, token, client_type=2, timeout=10):
        self.url = url
        self.user_id = int(user_id)
        self.token = token
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
            data = self.ws.recv()
            if isinstance(data, str) or not data:
                continue  # 文本/空帧忽略(业务全走 binary)
            cmd, body = frame.parse_frame(data)
            if cmd == target_cmd:
                return body
        raise TimeoutError(f"未在 {timeout or self.timeout}s 内收到 cmd=0x{target_cmd:04x}")

    def login(self):
        """返回登录错误码(NON_ERR=0x8000 为成功)。"""
        self._send(CM_LOGIN, proto_min.cm_login(self.user_id, self.token, self.client_type))
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
