"""状态机矩阵与删除约束(19306:当前状态不允许该操作)。

矩阵(读 logic 核实):
  草稿/已下架 → 上架 OK;已上架 → 上架 = 非法
  已上架 → 下架 OK;草稿/已下架 → 下架 = 非法
  删除:仅 草稿/已下架;已上架删除 = 非法
"""

import pytest


@pytest.mark.write
def test_online_cannot_delete(client, make_pack_payload):
    env = client.sticker_create(**make_pack_payload(status=1)).expect_ok()
    pack_id = env.data["pack_id"]
    try:
        # 已上架直接删除 → 19306
        client.sticker_delete(pack_id).expect(19306)
    finally:
        client.safe_delete(pack_id)


@pytest.mark.write
def test_online_cannot_online_again(client, make_pack_payload):
    env = client.sticker_create(**make_pack_payload(status=1)).expect_ok()
    pack_id = env.data["pack_id"]
    try:
        client.sticker_update_status(pack_id, 1).expect(19306)
    finally:
        client.safe_delete(pack_id)


@pytest.mark.write
def test_draft_cannot_offline(client, draft_pack):
    # 草稿不能下架(只有已上架能下架)→ 19306
    client.sticker_update_status(draft_pack, 2).expect(19306)


@pytest.mark.write
def test_update_status_invalid_target(client, draft_pack):
    # 目标状态非 1/2 → default 分支 → 19306
    client.sticker_update_status(draft_pack, 3).expect(19306)


def test_status_on_nonexistent_pack(client):
    # 不存在的包 → ErrPackNotFound → 19307
    client.sticker_update_status("PACK00000000", 1).expect(19307)


def test_detail_nonexistent_pack(client):
    client.sticker_detail("PACK00000000").expect(19307)
