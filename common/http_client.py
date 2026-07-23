"""跨服务共享的 HTTP 基础客户端与响应信封。

已核实:bi-admin 与 dm-api 网关的响应信封同为 {code, msg, data, time},
HTTP 状态恒 200、业务码在 body.code——所以这层可被所有服务套件复用。
各服务套件只需继承 BaseClient,补自己的登录/鉴权头与接口方法。
"""

import requests


class Envelope:
    """统一响应信封的封装,附断言辅助。"""

    def __init__(self, http_status, body):
        self.http_status = http_status
        self.raw = body
        d = body if isinstance(body, dict) else {}
        self.code = d.get("code")
        self.msg = d.get("msg")
        self.data = d.get("data")

    def is_ok(self):
        return self.code == 200

    def expect(self, code):
        assert self.code == code, (
            f"期望 code={code},实际 code={self.code} "
            f"(msg={self.msg!r}, http={self.http_status}, raw={self.raw!r})"
        )
        return self

    def expect_ok(self):
        return self.expect(200)

    def __repr__(self):
        return f"<Envelope http={self.http_status} code={self.code} msg={self.msg!r}>"


class BaseClient:
    """requests 会话薄封装。子类在 default_headers 里塞鉴权头。"""

    def __init__(self, base_url, timeout=15, default_headers=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.default_headers = dict(default_headers or {})

    def post(self, path, json=None, files=None, data=None, headers=None, auth=True):
        h = {}
        if auth:
            h.update(self.default_headers)  # 鉴权头等
        if files is None:
            h["Content-Type"] = "application/json"  # multipart 时交给 requests 生成
        if headers:
            h.update(headers)
        resp = self.session.post(
            self.base_url + path,
            json=json,
            files=files,
            data=data,
            headers=h,
            timeout=self.timeout,
        )
        return self._wrap(resp)

    def get(self, path, params=None, headers=None, auth=True):
        h = {}
        if auth:
            h.update(self.default_headers)
        if headers:
            h.update(headers)
        resp = self.session.get(
            self.base_url + path, params=params, headers=h, timeout=self.timeout
        )
        return self._wrap(resp)

    @staticmethod
    def _wrap(resp):
        try:
            body = resp.json()
        except ValueError:
            body = {"_non_json_text": resp.text}
        return Envelope(resp.status_code, body)
