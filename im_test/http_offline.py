"""IM 离线消息拉取(HTTP REST,非 WS;http-gateway,如 https://im-http.ramon2025.com:3801)。

鉴权(读 http-gateway/middleware/auth/auth.go 核实,与抓包一致):
  Header `Authorization: {token}:{userId}` —— 网关 split(":") 后用 token 过 identify-srv Check,
  且要求 Check 回的 userId == header 里的 userId;userId 由此头注入 ctx(body 里的 userId 被覆盖)。
请求体:protobuf 裸字节(Content-Type: application/octet-stream);响应:application/x-protobuf。
所有离线端点共用这套鉴权(单聊 /offline/v1/chat、群 /offline/v1/group/*、超级群 /channel/v1|v2/*)。
"""

import requests

from im_test import proto_min


class OfflineHttpClient:
    def __init__(self, base_url, token, user_id, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.user_id = int(user_id)
        self.timeout = timeout

    def _post(self, path, body):
        headers = {
            "Authorization": f"{self.token}:{self.user_id}",  # {token}:{userId}
            "Content-Type": "application/octet-stream",
        }
        return requests.post(self.base_url + path, data=body, headers=headers, timeout=self.timeout)

    def offline_chat(self, client_type=0, limit=50, delivered=None):
        """拉单聊离线消息(收方副本)。delivered=[{msg_id,msg_time,cmd_id}] 回带已收到的消息
        (服务端据此 MarkPulled,模拟真实客户端 ack)。返回 (status_code, [OfflineChatMsg dict])。"""
        body = proto_min.offline_chat_msg_req(self.user_id, limit=limit, client_type=client_type,
                                              delivered=delivered)
        r = self._post("/offline/v1/chat", body)
        if r.status_code != 200:
            return r.status_code, []
        return 200, proto_min.parse_offline_resp(r.content)

    def group_session(self, client_type="0", size=50):
        """拉「有未读消息的群会话」(会话内联 msgList,普通消息)。返回 (code, [展平的群消息 dict])。"""
        body = proto_min.offline_group_session_req(client_type=client_type, size=size)
        r = self._post("/offline/v1/group/session", body)
        if r.status_code != 200:
            return r.status_code, []
        return 200, proto_min.parse_group_session_resp(r.content)

    def channel_sessions(self, chnn_id, client_type=0):
        """拉超级群会话列表(每会话带 last=最新消息 + uUnread)。返回 (code, [SessionInfo dict])。"""
        body = proto_min.pull_chnn_session_req(self.user_id, chnn_id, client_type=client_type)
        r = self._post("/channel/v1/sessions", body)
        if r.status_code != 200:
            return r.status_code, []
        return 200, proto_min.parse_chnn_session_resp(r.content)

    def group_pull(self, group_id, client_type="0", limit=50, direct=-1):
        """按游标拉群离线消息(默认不排除回应;按 clientType 的 Pulled=0 过滤)。返回 (code, [OfflineGroupMsg dict])。"""
        body = proto_min.get_group_msg_req(group_id, client_type=client_type, direct=direct, limit=limit)
        r = self._post("/offline/v1/group/pull", body)
        if r.status_code != 200:
            return r.status_code, []
        return 200, proto_min.parse_group_msg_resp(r.content)

    def channel_offline_messages(self, chnn_id, count=50, direction=1):
        """按游标拉超级群离线消息。direction=1+空base→最新N条。返回 (code, [ChnnChat dict])。

        msgType 过滤:v2.21.2 起服务端放宽为 $in[Normal, 心情回应](im-common/dao/msg_dao/
        channel_bson.go GetChannelFindKey),故**回应能拉到**;但拉取方若被版本兼容门判为
        老客户端,会改用 GetChannelFindKeyNormalOnly 把回应排除——所以拉不到回应时,
        先确认拉取方在 Redis 里的 app_version/channel_type 是否够版本。
        (原注释"服务端硬过滤 Normal,回应拉不到"已过时,2026-08-29 核实订正。)"""
        body = proto_min.pull_chnn_message_req(self.user_id, chnn_id, direction=direction, count=count)
        r = self._post("/channel/v1/offlineMessages", body)
        if r.status_code != 200:
            return r.status_code, []
        return 200, proto_min.parse_chnn_message_resp(r.content)
