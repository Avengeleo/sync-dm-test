"""超级群心情回应上行(cmdId 0x3211 → ACK 0x3212)。

需 IM_CHANNEL_ID=你真实所在的一个超级群/频道 id(会校验频道权限,不能自反应绕过)。
未配置则 skip。
"""

import pytest

from im_test.client import NON_ERR


@pytest.mark.write
def test_channel_reaction_acked(logged_in_client, im_config):
    if not im_config["channel_id"]:
        pytest.skip("未配置 IM_CHANNEL_ID(你所在的一个超级群 id),跳过超级群回应")
    r = logged_in_client.send_channel_reaction(int(im_config["channel_id"]), emoji="👍", action=0)
    assert r["errcode"] == NON_ERR, (
        f"超级群回应未被接受 errcode=0x{r['errcode']:04x}(0x8000=成功)。"
        f"确认 IM_CHANNEL_ID 是你有权限的超级群。"
    )
