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
import json
import uuid

from common.http_client import BaseClient, Envelope


def _md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


class DmApiClient(BaseClient):
    # 端类型与 api-common/constant 一致:0=App 1=PC 2=Web
    CLIENT_APP, CLIENT_PC, CLIENT_WEB = "0", "1", "2"

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

    def call(self, subpath, body=None, token=None, extra_headers=None):
        """打一个 dm-api 用户接口。subpath 如 '/user/switch/list'。body=业务 JSON。

        token=None 用构造时的会话 token;传 "" 则不带头(测未登录)。
        extra_headers 覆盖/删除请求头:值为 None 时按大小写不敏感删掉该头。
        """
        nonce = uuid.uuid4().hex
        query = {"app_id": self.app_id}
        sign = self._sign(query, nonce)
        headers = dict(self.app_headers)
        headers.update({
            "Encversion": self.wips,     # 旁路 AES(=WIPs 值则 aes.go:32 跳过加解密)
            "Content-ETag": nonce,       # 签名 nonce
            "Content-Type": "application/json",
        })
        tok = self.token if token is None else token
        if tok:
            headers["token"] = tok
        if extra_headers:
            for hk, hv in extra_headers.items():
                if hv is None:
                    for existing in list(headers):
                        if existing.lower() == str(hk).lower():
                            headers.pop(existing, None)
                else:
                    headers[hk] = hv
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

    def fork(self, token=None, client_type=None):
        """浅拷贝一个客户端,可换会话 token / Client-type(扫码登录后用 PC token 打后续接口)。"""
        headers = dict(self.app_headers)
        if client_type is not None:
            headers["client-type"] = str(client_type)
        return DmApiClient(
            self.base_url, self.app_id, self.app_secret,
            self.token if token is None else token,
            self.wips, prefix=self.prefix, timeout=self.timeout,
            app_headers=headers,
        )

    # ── PC/Web 扫码登录(user-srv LoginScanCode / GetScanCodeResult / AppAllowLogin)──
    # HTTP 头 Client-type 决定写入 Redis 的对端类型;
    # allow_code_login 的 body.client_type 是 App 回传的被授权端。
    def login_scan_code(self, code_key, device_token, device_info="pytest-pc",
                        device_name="pytest PC scan", app_version="1.0.0",
                        os_version="Windows-10", channel_type="1", client_type=None):
        """PC/Web 注册待扫码会话。client_type 默认 PC=1,写入 Redis TTL=180s。只验 Sign。"""
        ct = self.CLIENT_PC if client_type is None else str(client_type)
        return self.call("/user/login/scan_code", {
            "code_key": code_key,
            "device_info": device_info,
            "device_name": device_name,
            "device_token": device_token,
            "app_version": app_version,
            "os_version": os_version,
            "channel_type": channel_type,
        }, extra_headers={"client-type": ct})

    def get_scan_code(self, code_key):
        """PC/Web 轮询授权结果。200+token / 1027 等待 / 1026 失效。只验 Sign。"""
        return self.call("/user/login/get_scan_code", {"code_key": code_key})

    def get_scan_code_info(self, code_key):
        """App 扫码后查看对端设备。需 Token。不写「已扫码」态。"""
        return self.call("/user/login/get_scan_code_info", {"code_key": code_key})

    def allow_code_login(self, code_key, client_type=None, sync_offline_msg_flag="0"):
        """App 确认授权对端登录。需 Token。会跨端踢线(豁免被授权端+App)。"""
        ct = self.CLIENT_PC if client_type is None else str(client_type)
        return self.call("/user/login/allow_code_login", {
            "code_key": code_key,
            "client_type": ct,
            "sync_offline_msg_flag": str(sync_offline_msg_flag),
        })

    def info_get(self):
        """用当前 token 换用户资料(扫码结果不含 user_id,连 IM 前必须先打这条)。"""
        return self.call("/user/info/get")

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

    def my_fav_del(self, ids):
        # ids = 行 id 列表(int)或已拼好的 "id1|id2" 串;取自 my_fav/list 每条的 id
        ids_str = ids if isinstance(ids, str) else "|".join(str(i) for i in ids)
        return self.call("/user/sticker/my_fav/del", {"ids": ids_str})

    # ── 最近使用 ──
    def recent_report(self, fav_type, img_url, pack_id="", file_name="", width=0, height=0):
        return self.call("/user/sticker/recent/report", {
            "fav_type": fav_type, "img_url": img_url, "pack_id": pack_id,
            "file_name": file_name, "width": width, "height": height,
        })

    def recent_list(self, fav_type):
        return self.call("/user/sticker/recent/list", {"fav_type": fav_type})

    def recent_del(self, ids):
        # ids = 行 id 列表(int)或 "id1|id2" 串;取自 recent/list 每条的 id
        ids_str = ids if isinstance(ids, str) else "|".join(str(i) for i in ids)
        return self.call("/user/sticker/recent/del", {"ids": ids_str})

    # ── 快捷回应 bar(最常用回应表情)──
    def reaction_emoji_report(self, emoji):
        return self.call("/user/reaction/emoji/report", {"emoji": emoji})

    def reaction_emoji_top(self, limit=0):
        return self.call("/user/reaction/emoji/top", {"limit": limit})

    # ── 活动中心 H5 入口(v2.22.3)──
    # 注意路径不在 /user 下,而在 /active 下,与其它用户接口分组不同。
    # 刻意不收 openId/userId:玩家身份由网关从登录态换,客户端传不了也不该能传。
    def saas_activity_entry(self, currency="USDT", sys_lang=""):
        body = {"currency": currency}
        if sys_lang:
            body["sys_lang"] = sys_lang
        return self.call("/active/saas/activity/entry", body)

    # ── 消息举报(问题复现用;服务端 sync-dm-api/user-srv/handler/handler_report.go)──
    # 刻意做成"原样透传":messages / desc / user_id 都不在客户端侧做校验或纠正,
    # 这样用例才能构造非法输入来复现服务端的处理缺陷。
    def report_add(self, ctx_type, ctx_id, user_id, messages, desc=""):
        """用户举报消息 POST /user/report/add。

        messages:**原样字符串**。服务端按 JSON 数组解析(只取每项的 id 字段),
        故意允许传非法值以复现「非法 JSON 被当成 500」的问题。
        """
        return self.call("/user/report/add", {
            "ctx_type": str(ctx_type),
            "ctx_id": str(ctx_id),
            "user_id": str(user_id),
            "messages": messages,
            "desc": desc,
        })

    @staticmethod
    def build_report_messages(msg_id=None, content="[selftest] report", content_type=1,
                              logictype=0, ctx_type=1):
        """拼 messages 字段。msg_id=None 时**故意不带 id 键**,用于复现空 id 去重问题。

        字段形状取自 sync-dm-api/api-gateway/request/user/setReportRequest.go 的
        ReportContent(该结构体在服务端其实未被使用,仅作契约说明)。
        """
        item = {"content_type": content_type, "content": content,
                "logictype": logictype, "type": ctx_type}
        if msg_id is not None:
            item["id"] = msg_id
        return json.dumps([item], ensure_ascii=False)
