"""活动中心 H5 入口(v2.22.3):客户端「活动」tab 加载的整站地址。

契约(读 api-gateway/handler/apiv2/acitve/saas_activity_entry.go 与
activity-srv/handler/activity_entry.go 核实):
  POST /active/saas/activity/entry  {currency, sys_lang?}
  → {enabled, h5_url, expires_in, merchant_id, user_id, tab_title}

这条链路的要点,也是本文件断言的重点:
1) 身份不由客户端给。请求体里没有 openId/userId,网关拿登录态 uid 经
   user-srv GetOpenIdByUserId 换 openid 再去签令牌。所以「换个参数看别人的活动中心」
   这条路在接口形状上就不存在——没有参数可换。
2) h5_url 端上直接加载,不要再拼参数。币种与语言在签令牌时已烘焙进 JWT,
   二次拼接只会与令牌内的值打架。
3) 令牌在 # 之前的真实查询串上(平台刻意设计,便于边缘网关识别),
   端上若按「参数必须在 # 之后」去改写,会把令牌搬到页面读不到的位置。
4) enabled=false 是唯一能让端上隐藏整条 tab 的信号;网络类失败不走它。
"""

import re

import pytest

# 平台整站路由。单活动组件是 #/wheel、#/red-packet 这些,首页只有这一个。
APP_ROUTE = "#/app"


def _entry(dm_client, **kw):
    return dm_client.saas_activity_entry(**kw).expect_ok().data or {}


def test_entry_returns_loadable_url(dm_client):
    d = _entry(dm_client)

    assert d.get("enabled") is True, f"未启用则整条 tab 不展示,当前 enabled={d.get('enabled')}"

    url = d.get("h5_url") or ""
    assert url.startswith("http"), f"h5_url 必须是可直接加载的绝对地址: {url!r}"
    assert "token=" in url, f"h5_url 未携带令牌,页面会退回默认商户与随机用户: {url!r}"
    assert APP_ROUTE in url, f"应指向活动中心整站首页 {APP_ROUTE}: {url!r}"

    # 令牌必须在 # 之前。写死这一条是因为它错了不报错——页面照常打开,
    # 只是读不到令牌,退回默认商户,表现为「能打开但数据是别人的/空的」。
    frag = url.index("#")
    assert url.index("token=") < frag, f"令牌必须在 # 之前的查询串上: {url!r}"

    assert int(d.get("expires_in") or 0) > 0, "expires_in 应为正数,端上据此判断切回 tab 时是否 reload"
    assert d.get("merchant_id"), "merchant_id 应回显,供埋点与排查"
    assert d.get("user_id"), "user_id 应回显"
    assert d.get("tab_title"), "tab_title 不应为空,否则 tab 会没有标题"


def test_entry_identity_not_client_supplied(dm_client):
    """身份由服务端决定:即使请求体里塞 userId/openId,回显的也必须是登录态那个人。"""
    mine = _entry(dm_client).get("user_id")

    forged = dm_client.call("/active/saas/activity/entry", {
        "currency": "USDT",
        "userId": "forged-user-id",
        "openId": "forged-open-id",
        "user_id": "forged-user-id",
    }).expect_ok().data or {}

    assert forged.get("user_id") == mine, (
        f"请求体里的身份必须被忽略:登录态={mine} 实际返回={forged.get('user_id')}"
    )


def test_entry_currency_isolated(dm_client):
    """活动中心按 (玩家,币种) 分账,不同币种必须换到不同令牌。"""
    a = _entry(dm_client, currency="USDT")
    b = _entry(dm_client, currency="CNY")

    ta = re.search(r"token=([^&#]+)", a.get("h5_url") or "")
    tb = re.search(r"token=([^&#]+)", b.get("h5_url") or "")
    if not (ta and tb):
        pytest.skip("某个币种未启用,拿不到两个令牌")
    assert ta.group(1) != tb.group(1), "换币种必须重新签令牌,不能复用"


def test_entry_bad_currency_rejected(dm_client):
    """不在该公司启用范围的币种,平台在签令牌时就拒,不该等打开页面才发现是空白。"""
    dm_client.call("/active/saas/activity/entry", {"currency": "NOT_A_CURRENCY"}).expect(1015)


def test_entry_currency_required(dm_client):
    dm_client.call("/active/saas/activity/entry", {}).expect(1015)


def test_entry_reissues_token(dm_client):
    """无刷新机制,过期重签;两次调用应各签一枚,不是返回同一个缓存令牌。"""
    t1 = re.search(r"token=([^&#]+)", _entry(dm_client).get("h5_url") or "")
    t2 = re.search(r"token=([^&#]+)", _entry(dm_client).get("h5_url") or "")
    assert t1 and t2
    assert t1.group(1) != t2.group(1), "每次调用应现签一枚(jti 不同),便于按需缩短有效期"
