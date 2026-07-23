"""鉴权链路:登录、缺 token、错 token。"""

import pytest


def test_login_success(client):
    # client fixture 已完成登录;拿到非空 token 即通过
    assert client.token, "登录未取得 token"


def test_login_wrong_password(anon_client, config):
    env = anon_client.post(
        "/admin/login",
        json={"username": config["username"], "password": config["password"] + "_wrong"},
        auth=False,
    )
    assert env.code != 200, f"错误密码却登录成功:{env!r}"


def test_login_missing_field_400(anon_client):
    # username/password 均 binding:"required",缺字段应 400 参数错误
    env = anon_client.post("/admin/login", json={"username": "x"}, auth=False)
    env.expect(400)


def test_sticker_without_token_forbidden(anon_client):
    # 缺 X-Chat-admin → AdminCheckToken 返 403 权限不足
    env = anon_client.post("/admin/sticker/query_list", json={"page": 1, "size": 10}, auth=False)
    env.expect(403)


def test_sticker_bad_token_expired(config):
    from bi_api_test.client import BiAdminClient

    c = BiAdminClient(config["base_url"], timeout=config["timeout"])
    c.token = "obviously.invalid.token"
    # token 非法 → ParseToken 失败 → 402 登录已过期
    env = c.sticker_list(page=1, size=10)
    env.expect(402)
