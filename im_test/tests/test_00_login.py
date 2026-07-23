"""IM 长连接登录自检:连 WebSocket + 发 CM_LOGIN → 收 CM_LOGIN_ACK。

失败排查:
  连不上 → IM_WS_URL 不对 / VPN 没连 / 端口不通
  nErr != 0x8000 → token 无效或过期(重抓 IM_TOKEN),或 user_id 不对
"""

from im_test.client import NON_ERR


def test_login_ok(im_client):
    err = im_client.login()
    assert err == NON_ERR, (
        f"IM 登录失败 nErr=0x{err:04x}(0x8000=成功)。"
        f"检查 IM_TOKEN 是否有效、IM_USER_ID 是否为你本人。"
    )
