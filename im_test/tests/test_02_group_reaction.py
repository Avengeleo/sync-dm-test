"""群心情回应上行(cmdId 0x2312 → ACK 0x2313)。

需 IM_GROUP_ID=你真实所在的一个群 id(群回应会校验群状态+成员关系,不能像单聊那样自反应绕过)。
未配置则 skip。
"""

import pytest

from im_test.client import NON_ERR


@pytest.mark.write
def test_group_reaction_acked(logged_in_client, im_config):
    if not im_config["group_id"]:
        pytest.skip("未配置 IM_GROUP_ID(你所在的一个群 id),跳过群回应")
    r = logged_in_client.send_group_reaction(int(im_config["group_id"]), emoji="👍", action=0)
    assert r["errcode"] == NON_ERR, (
        f"群回应未被接受 errcode=0x{r['errcode']:04x}(0x8000=成功)。"
        f"确认 IM_GROUP_ID 是你本人所在的群,且群状态正常。"
    )
