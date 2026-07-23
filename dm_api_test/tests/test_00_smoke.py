"""连通 + 三层鉴权自检:先跑这个,确认 AES 旁路 + 签名 + token 三层都过。

若失败,按返回 code 定位是哪一层(便于排查):
  1020/1021 → AES 层:Encversion(WIPs)值不对,没旁路成功
  1001      → 缺 Content-ETag 或 app_id(客户端 bug,不该发生)
  1006/1007 → 签名层:app_id/app_secret 不对,或签名算错
  401       → token 层:token 无效/过期
  403       → token 被冻结;或(到了业务层)其它
  200       → 三层全过,鉴权链路 OK
"""


def test_auth_stack_ok(dm_client):
    env = dm_client.switch_list()
    assert env.code == 200, (
        f"三层鉴权未通过,code={env.code} msg={env.msg!r}。"
        f"对照:1020/1021=AES旁路值(WIPs)不对;1006/1007=app_id/secret或签名;401=token无效。"
        f" raw={env.raw!r}"
    )
    assert isinstance(env.data, dict), "switch/list 应返回对象"
