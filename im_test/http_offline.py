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

    def offline_chat(self, client_type=0, limit=50):
        """拉单聊离线消息(收方副本)。返回 (status_code, [OfflineChatMsg dict])。"""
        body = proto_min.offline_chat_msg_req(self.user_id, limit=limit, client_type=client_type)
        r = self._post("/offline/v1/chat", body)
        if r.status_code != 200:
            return r.status_code, []
        return 200, proto_min.parse_offline_resp(r.content)
