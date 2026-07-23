"""dm-api(sync-dm-api 网关)客户端 —— 脚手架,接入时补全。

已核实:dm-api 网关响应信封同为 {code, msg, data, time}(HTTP 恒 200,码在 body.code),
所以直接复用 common.BaseClient;与 bi 的差别只有 base_url、鉴权、接口路径。

待接入时要确定的两点(TODO):
1. 鉴权:dm-api 走用户 JWT,user_id 由网关中间件从 token 解出。
   要么走登录接口换 token(在 login() 里实现),要么测试环境直接注入一个已知 token。
   放进哪个 header 也要核实(常见 Authorization: Bearer,以网关中间件为准)。
2. 接口路径:如贴图客户端接口 /sticker/pack_list、我的最爱 /sticker/my_fav/*、
   聊天设置 /user/switch/{list,set} 等,按 sync-dm-api 路由补方法。
"""

from common.http_client import BaseClient


class DmApiClient(BaseClient):
    # TODO: 核实真实鉴权头名(占位)
    AUTH_HEADER = "Authorization"

    def set_token(self, token):
        # TODO: 若为 Bearer,这里拼 "Bearer " + token
        self.default_headers[self.AUTH_HEADER] = token

    # ── 示例:填了鉴权后即可用 ──
    def sticker_pack_list(self, version=0):
        return self.post("/sticker/pack_list", json={"version": version})

    def my_fav_list(self, fav_type=0):
        return self.post("/sticker/my_fav/list", json={"fav_type": fav_type})

    def user_switch_list(self):
        return self.post("/user/switch/list", json={})
