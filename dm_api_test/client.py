"""dm-api(sync-dm-api 网关)客户端。

dm-api 用户接口在网关串了三层,自测逐一对付(全部读源码核实):
1) AES 层(aes.AesDecrypt):默认要 AES 加密 body。**旁路**:带 header `Encversion=<WIPs值>`
   则 aes.go:32 直接 ctx.Next() 跳过加解密,body 走明文。→ 我们走旁路,免复现 AES。
2) 签名层(verify.VerifySign):要 header `Content-ETag`(nonce)+ query 里 app_id + sign。
   sign = UPPER( MD5( MD5(除sign外所有Form值按key字典序拼接) + MD5(appSecret + nonce) ) )。
   旁路 AES 时 Form 只来自 query,故我们只把 app_id+sign 放 query,业务参数放 JSON body
   (VerifySign 只校验 Form=query,不看 body;handler 用 ShouldBind 读 JSON body)。
   → 签名实际只覆盖 app_id,算式简化为 UPPER(MD5(MD5(app_id) + MD5(appSecret+nonce)))。
3) token 层(verify.VerifyToken):header `token=<会话token>`(identify-srv 发的 32 位串,非 JWT)。

路径:{base}{prefix}/user/<子路径>,prefix 默认 /api/v2(APP 网关);H5 用 /api/h5。
响应信封同 bi:{code,msg,data,time},HTTP 恒 200,业务码看 code。
"""

import hashlib
import uuid

from common.http_client import BaseClient, Envelope


def _md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


class DmApiClient(BaseClient):
    # 真实 App(H5)请求头,防止其它中间件按这些头做校验(值取自抓包,非密钥)
    DEFAULT_APP_HEADERS = {
        "app_version": "1.8.2",
        "brand-id": "1",
        "channel-id": "1",
        "client-type": "2",
        "device_brand": "web",
        "device_info": "Chrome/146.0.0.0",
        "device_number": "146.0.0.0",
        "device_token": "web",
        "lang": "cn",
        "mch-id": "10001",
        "x-app-type": "h5",
    }

    def __init__(self, base_url, app_id, app_secret, token, wips,
                 prefix="/api/h5", client_type="", timeout=15, app_headers=None):
        super().__init__(base_url, timeout=timeout)
        self.app_id = str(app_id)
        self.app_secret = app_secret
        self.token = token
        self.wips = wips           # Encversion 旁路值(跳过 AES)
        self.prefix = prefix.rstrip("/")
        self.app_headers = dict(self.DEFAULT_APP_HEADERS)
        if client_type:
            self.app_headers["client-type"] = client_type
        if app_headers:
            self.app_headers.update(app_headers)

    def _sign(self, query_no_sign, nonce):
        # VerifySign:除 sign 外所有 Form 值按 key 字典序拼接
        keys = sorted(query_no_sign.keys())
        concat = "".join(str(query_no_sign[k]) for k in keys)
        secret = _md5(self.app_secret + nonce)
        return _md5(_md5(concat) + secret).upper()

    def call(self, subpath, body=None):
        """打一个 dm-api 用户接口。subpath 如 '/user/switch/list'。body=业务 JSON。"""
        nonce = uuid.uuid4().hex
        query = {"app_id": self.app_id}
        sign = self._sign(query, nonce)
        headers = dict(self.app_headers)
        headers.update({
            "Encversion": self.wips,     # 旁路 AES(=WIPs 值则 aes.go:32 跳过加解密)
            "Content-ETag": nonce,       # 签名 nonce
            "token": self.token,         # 会话 token
            "Content-Type": "application/json",
        })
        for hk, hv in headers.items():  # HTTP 头须 ASCII;给清晰错误而非 latin-1 崩溃
            try:
                str(hv).encode("latin-1")
            except UnicodeEncodeError:
                raise ValueError(
                    f"请求头 {hk}={hv!r} 含非 ASCII 字符——多半是 .env 里某个 DM_API_* 值误带了注释/中文。"
                    f"检查 DM_API_WIPS / DM_API_TOKEN 是否只填了纯值、行尾没跟 # 注释。"
                )
        url = f"{self.base_url}{self.prefix}{subpath}?app_id={self.app_id}&sign={sign}"
        resp = self.session.post(url, json=(body or {}), headers=headers, timeout=self.timeout)
        return self._wrap(resp)

    # ── 聊天设置 ──
    def switch_list(self):
        return self.call("/user/switch/list")

    def switch_set(self, alias_field, setting_value):
        # setting_value 必须是字符串
        return self.call("/user/switch/set",
                         {"alias_field": alias_field, "setting_value": str(setting_value)})

    # ── 贴图读 ──
    def sticker_pack_list(self, version=0):
        return self.call("/user/sticker/pack_list", {"version": version})

    def sticker_item_list(self, pack_id):
        return self.call("/user/sticker/item_list", {"pack_id": pack_id})

    def my_pack_list(self):
        return self.call("/user/sticker/my_pack/list")

    # ── 我的最爱 ──
    def my_fav_list(self, fav_type=0):
        return self.call("/user/sticker/my_fav/list", {"fav_type": fav_type})

    def my_fav_add(self, fav_type, img_url, pack_id="", file_name="", width=0, height=0):
        return self.call("/user/sticker/my_fav/add", {
            "fav_type": fav_type, "img_url": img_url, "pack_id": pack_id,
            "file_name": file_name, "width": width, "height": height,
        })

    def my_fav_del(self, items):
        # items = [{"fav_type":1,"pack_id":"","img_url":"..."}]
        return self.call("/user/sticker/my_fav/del", {"items": items})
