"""44/45 仅使用现有凭证检查 Web 槽位，不登录 API、不踢设备。"""

import time

from im_test.security_device import DeviceRequestError, SecurityDeviceClient


class WritePreflightError(RuntimeError):
    """前置失败必须停止；不自动恢复 token 或关闭其他设备。"""


def require_idle_web_accounts(config, *, all_slots=False, client_factory=SecurityDeviceClient,
                              clock=time.monotonic, sleep=time.sleep, settle_seconds=3):
    for suffix in ("", "2"):
        try:
            client = client_factory(config["http_base"], config["token" + suffix],
                                    config["user_id" + suffix], timeout=config["timeout"])
            deadline = clock() + min(settle_seconds, config["timeout"])
            while True:
                reply = client.device_list(version="v1").require_success(client.user_id, nonempty=False)
                blocked = bool(reply.devices) if all_slots else any(d.client_type == 2 for d in reply.devices)
                if not blocked or clock() >= deadline:
                    break
                # 只等上一条脚本连接正常断开后的离线状态，不顶号或重试失效token。
                sleep(min(0.25, max(0, deadline - clock())))
        except (DeviceRequestError, KeyError):
            raise WritePreflightError("44/45 账号鉴权或设备前置检查失败；停止，不自动登录或刷新凭证") from None
        if all_slots and reply.devices:
            raise WritePreflightError("45 专用账号仍有在线设备；请正常断开 App/PC/Web 后再运行，不调用踢设备")
        if any(device.client_type == 2 for device in reply.devices):
            raise WritePreflightError("44/45 专用账号仍有在线 Web；请正常断开后再运行，不调用踢设备")
