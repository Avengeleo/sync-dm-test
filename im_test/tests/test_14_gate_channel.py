"""版本兼容门 · 按渠道取门槛(2026-08-29 生产事故回归)。

事故:iOS 上架包用户心情回应互相看不到。根因是上架包与超签包**版本号不是同一套**
(上架 1.5.4 / 超签 2.22.0),而门槛只有单值 2.22.0 → 上架包被判老拦死。
且单纯降门槛救不了:2.21.2 > 1.5.4,会让不支持回应的老超签包被误放行。
修复:门槛改按 (cmd, client_type, channel_type) 三元组配置。

本文件的价值在于**验证"单一门槛做不到"的那两个方向**:
  A. 上架包 1.5.4 能收到(旧实现必然失败——这就是事故现象)
  B. 老超签 2.21.2 收不到(把门槛降到 1.5.4 的止血方案必然失败)
两条同时绿,才说明真的是按渠道判的,而不是门槛被调松了。

前置:
- 门控代码(fix/bryan/gate-channel-type)已部署到该环境
- app.im_feature_gate 已执行渠道拆分 SQL:通配=2.22.0,上架系(1/3/2/4/6)=1.5.4
- 渠道编号同推送服务:iOS 1/3 上架 15 超签;安卓 2/4/6 上架 16 超签
"""

import uuid

import pytest

from im_test.client import ImWsClient, NON_ERR, SINGLE_DELIVER, SINGLE_REACTION_DELIVER

# 渠道编号(与服务端 im-common/gate/gate.go 常量一致)
CH_IOS_LISTING = 1       # iOS 上架
CH_IOS_LISTING_HIS = 3   # iOS 上架 His 包
CH_IOS_OVERSIGN = 15     # iOS 超签
CH_ANDROID_LISTING = 2   # 安卓上架

# 两套版本号体系的分档值
VER_LISTING_OK = "1.5.4"      # 上架系门槛,恰好达标
VER_LISTING_OLD = "1.5.3"     # 上架系不达标
VER_OVERSIGN_OK = "2.22.0"    # 超签系门槛,恰好达标
VER_OVERSIGN_OLD = "2.21.2"   # 超签系不达标 —— 注意它 > 1.5.4,是本次修复的关键分辨点


def _receiver(im_config, app_version, channel_type):
    """按指定「版本号 + 渠道」登录收方端 B,返回已登录客户端。"""
    if im_config["client_type_b"] == im_config["client_type"]:
        pytest.skip("IM_CLIENT_TYPE_B 与 IM_CLIENT_TYPE 相同,双连接会互踢")
    b = ImWsClient(im_config["url"], im_config["user_id"], im_config["token"],
                   im_config["client_type_b"], im_config["timeout"],
                   app_version=app_version, channel_type=channel_type)
    try:
        b.connect()
    except Exception as e:
        pytest.skip(f"收方端 B 连接失败:{e}")
    if (err := b.login()) != NON_ERR:
        b.close()
        pytest.skip(f"收方端 B 登录失败 nErr=0x{err:04x}")
    return b


def _react_and_expect(a, b, should_receive, why):
    """A 发心情回应,断言 B 是否收到 0x122d。普通消息始终应能收到(证明链路本身是通的)。"""
    react = a.send_reaction(to_id=a.user_id, parent_msg_id=uuid.uuid4().hex)
    assert react["errcode"] == NON_ERR, "回应上行本身应成功(门只拦下行)"

    if should_receive:
        try:
            b.recv_deliver(SINGLE_REACTION_DELIVER)
        except Exception as e:
            raise AssertionError(f"{why}(未收到 0x122d:{type(e).__name__})") from None
    else:
        assert b.expect_no_deliver(SINGLE_REACTION_DELIVER), why

    # 对照组:同一条连接必须能收到普通消息,排除"连接本身坏了/账号异常"导致的假绿。
    # 尤其对 should_receive=False 的用例——没有这一步,连接断了也会"通过"。
    normal = a.send_chat(to_id=a.user_id, content="[selftest] ch-gate-" + uuid.uuid4().hex[:8])
    assert normal["errcode"] == NON_ERR
    try:
        b.recv_deliver(SINGLE_DELIVER)
    except Exception as e:
        raise AssertionError(
            f"普通消息也收不到({type(e).__name__}),本用例前提不成立——"
            f"连接/账号有问题,不能据此判断门控行为") from None


# ── 核心:两个方向的回归 ──

@pytest.mark.write
def test_listing_pkg_receives_reaction(im_config, logged_in_client):
    """【事故直接回归】iOS 上架包 1.5.4 应能收到心情回应。

    修复前:门槛单值 2.22.0,VerAtLeast("1.5.4","2.22.0")=false → 被拦 → 本用例必红。
    """
    b = _receiver(im_config, VER_LISTING_OK, CH_IOS_LISTING)
    try:
        _react_and_expect(logged_in_client, b, True,
                          "上架包 1.5.4 应收到回应;收不到=门槛没按渠道取(仍在用超签门槛 2.22.0 判它)")
    finally:
        b.close()


@pytest.mark.write
def test_old_oversign_still_blocked(im_config, logged_in_client):
    """【止血方案回归】老超签包 2.21.2 仍应被拦。

    若有人图省事把门槛单值降到 1.5.4 来"修"事故,2.21.2 > 1.5.4 会被误放行 → 本用例必红。
    本用例与上一条同时绿,才证明是真按渠道判,而不是门槛被调松。
    """
    b = _receiver(im_config, VER_OVERSIGN_OLD, CH_IOS_OVERSIGN)
    try:
        _react_and_expect(logged_in_client, b, False,
                          "老超签 2.21.2 不应收到回应;收到了=门槛被降成上架档,老客户端保护失效")
    finally:
        b.close()


# ── 各档位边界 ──

@pytest.mark.write
def test_listing_below_threshold_blocked(im_config, logged_in_client):
    """上架包 1.5.3(低于上架门槛 1.5.4)应被拦。"""
    b = _receiver(im_config, VER_LISTING_OLD, CH_IOS_LISTING)
    try:
        _react_and_expect(logged_in_client, b, False, "上架包 1.5.3 低于门槛,应被拦")
    finally:
        b.close()


@pytest.mark.write
def test_oversign_at_threshold_receives(im_config, logged_in_client):
    """超签包 2.22.0(恰好达超签门槛)应能收到。"""
    b = _receiver(im_config, VER_OVERSIGN_OK, CH_IOS_OVERSIGN)
    try:
        _react_and_expect(logged_in_client, b, True, "超签包 2.22.0 达标,应收到")
    finally:
        b.close()


@pytest.mark.write
@pytest.mark.parametrize("channel,label", [
    (CH_IOS_LISTING_HIS, "iOS 上架His(3)"),
    (CH_ANDROID_LISTING, "安卓上架(2)"),
])
def test_other_listing_channels_receive(im_config, logged_in_client, channel, label):
    """上架系其余渠道(3/2)同样按 1.5.4 判,应能收到——防止 SQL 只配了 iOS 主包漏配其它。"""
    b = _receiver(im_config, VER_LISTING_OK, channel)
    try:
        _react_and_expect(logged_in_client, b, True, f"{label} 1.5.4 应收到回应;收不到=该渠道漏配")
    finally:
        b.close()


# ── 交叉验证:同一版本号在不同渠道下判定相反 ──

@pytest.mark.write
def test_same_version_differs_by_channel(im_config, logged_in_client):
    """同一个版本号 2.21.2,在上架渠道应放行、在超签渠道应拦截。

    这是"按渠道取门槛"最直接的证明:版本号完全相同,仅渠道不同,结论相反。
    (2.21.2 > 上架门槛 1.5.4 → 放行;2.21.2 < 超签门槛 2.22.0 → 拦截)
    """
    b1 = _receiver(im_config, VER_OVERSIGN_OLD, CH_IOS_LISTING)
    try:
        _react_and_expect(logged_in_client, b1, True,
                          "2.21.2 在上架渠道高于门槛 1.5.4,应放行")
    finally:
        b1.close()

    b2 = _receiver(im_config, VER_OVERSIGN_OLD, CH_IOS_OVERSIGN)
    try:
        _react_and_expect(logged_in_client, b2, False,
                          "同一个 2.21.2 在超签渠道低于门槛 2.22.0,应拦截")
    finally:
        b2.close()
