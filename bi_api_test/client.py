"""bi-admin(sync-bi-api admin 服务,端口 8094)客户端。

契约要点(读源码核实):
- 模块路由挂 engine 根,**无 bi/api/v1 前缀**:登录 /admin/login、贴图 /admin/sticker/*。
- 鉴权头 X-Chat-admin: <token>(登录响应 data.token)。
"""

from common.http_client import BaseClient


class BiAdminClient(BaseClient):
    AUTH_HEADER = "X-Chat-admin"

    @property
    def token(self):
        return self.default_headers.get(self.AUTH_HEADER)

    @token.setter
    def token(self, value):
        self.default_headers[self.AUTH_HEADER] = value

    def login(self, username, password):
        env = self.post(
            "/admin/login",
            json={"username": username, "password": password},
            auth=False,
        ).expect_ok()
        self.token = env.data["token"]
        return self.token

    # ── 贴图包接口 ──
    def sticker_create(self, **payload):
        return self.post("/admin/sticker/create", json=payload)

    def sticker_update(self, **payload):
        return self.post("/admin/sticker/update", json=payload)

    def sticker_delete(self, pack_id):
        return self.post("/admin/sticker/delete", json={"pack_id": pack_id})

    def sticker_detail(self, pack_id):
        return self.post("/admin/sticker/get_detail", json={"pack_id": pack_id})

    def sticker_list(self, **payload):
        return self.post("/admin/sticker/query_list", json=payload)

    def sticker_update_status(self, pack_id, status):
        return self.post(
            "/admin/sticker/update_status",
            json={"pack_id": pack_id, "status": status},
        )

    def sticker_update_sort(self, pack_id, sort_weight):
        return self.post(
            "/admin/sticker/update_sort",
            json={"pack_id": pack_id, "sort_weight": sort_weight},
        )

    def sticker_zip_import(self, zip_bytes, filename="stickers.zip"):
        return self.post(
            "/admin/sticker/item/zip_import",
            files={"upload_file": (filename, zip_bytes, "application/zip")},
        )

    def safe_delete(self, pack_id):
        """确保删除(草稿/已下架可直删;已上架先下架),清理尽力而为。"""
        try:
            detail = self.sticker_detail(pack_id)
            if detail.is_ok() and detail.data and detail.data.get("status") == 1:
                self.sticker_update_status(pack_id, 2)
            self.sticker_delete(pack_id)
        except Exception:
            pass
