"""预约写库:测完必须恢复,避免污染 develop 上该用户的预约态。"""

import pytest

from dm_api_test.live_display import as_int


@pytest.mark.write
def test_reserve_then_restore(dm_client, sample_preview_item):
    pid = as_int(sample_preview_item["preview_id"])
    before = dm_client.preview_detail(pid).expect_ok().data
    if before.get("is_fulfilled"):
        pytest.skip("该预告已履约,不能预约")
    was_reserved = bool(before.get("is_reserved"))

    def _restore():
        if was_reserved:
            dm_client.preview_reserve(pid)
        else:
            dm_client.preview_cancel_reserve(pid)

    try:
        if was_reserved:
            dm_client.preview_cancel_reserve(pid).expect_ok()
            mid = dm_client.preview_detail(pid).expect_ok().data
            assert mid.get("is_reserved") in (False, 0)
            dm_client.preview_reserve(pid).expect_ok()
        else:
            env = dm_client.preview_reserve(pid).expect_ok()
            assert env.data.get("is_reserved") in (True, 1)
            assert as_int(env.data.get("reserve_count")) >= 0
            dm_client.preview_cancel_reserve(pid).expect_ok()
        after = dm_client.preview_detail(pid).expect_ok().data
        assert bool(after.get("is_reserved")) == was_reserved
    finally:
        _restore()
