"""消息举报报错 · 问题复现脚本(QA 反馈:点举报会有报错)

被测端点:POST {prefix}/user/report/add
服务端链路:
  api-gateway/handler/apiv2/user/report.go:20  CreateReport
  → user-srv/handler/handler_report.go:16      SetUserReportInfo
  → user-srv/dao/userReportDb.go               SetReport / GetReportMsg
  → MySQL user_report(建表 DDL:sync-dm-api/doc/update_sql/20240304_report.sql
                              + 20240316_report.sql 加了 desc / msg_id 两列)

⚠️ 本文件是**复现脚本,不是回归套件**:断言写的是「正确行为」,
   所以**失败即复现成功**,失败信息里标明了对应第几号问题。
   等修复合入后,这些用例会自动转绿,可直接留作回归。

⚠️ 会写库:每条用例都会在 dev 的 user_report 表插入记录,仅限测试账号/测试环境。

需要的 .env:dm-api 套件常规四件套(见 dm_api_test/conftest.py),外加举报人 userId:
  DM_API_USER_ID   举报人用户ID;未配则回退用 IM_USER_ID(通常是同一个账号)
  (之所以要显式提供,正是因为服务端**从请求体**取 user_id 而不是从 token 取
   —— 这本身就是问题 3。)
"""

import os
import uuid

import pytest

# 服务端错误码(sync-dm-api/api-common/utils/msgError/msg.go)
CODE_OK = 200
CODE_MISSING_PARAM = 1015   # "缺失必要的参数"
CODE_DUP_REPORT = 36990     # "请勿重复投诉!"
CODE_SERVER_ERR = 500

CTX_TYPE_SINGLE = 1         # 1 单聊 / 2 群聊 / 3 超级群


@pytest.fixture(scope="session")
def reporter_user_id():
    v = (os.environ.get("DM_API_USER_ID", "").strip()
         or os.environ.get("IM_USER_ID", "").strip())
    if not v or v.startswith("#"):
        pytest.skip("未配置 DM_API_USER_ID(或 IM_USER_ID),举报接口需要举报人 userId,跳过")
    return v


@pytest.fixture
def ctx_id():
    """会话 id。服务端不校验其真实性(无外键),用固定值便于事后在库里找这批测试数据。"""
    return "selftest-report-ctx"


def _report(dm_client, reporter_user_id, ctx_id, messages, desc=""):
    return dm_client.report_add(ctx_type=CTX_TYPE_SINGLE, ctx_id=ctx_id,
                                user_id=reporter_user_id, messages=messages, desc=desc)


# ─────────────────── 基线:正常举报应当成功 ───────────────────

@pytest.mark.write
def test_00_baseline_report_with_valid_id(dm_client, reporter_user_id, ctx_id):
    """基线:带合法 id 的举报应返回 200。

    这条若失败,说明问题比下面几条更靠前(鉴权/参数/服务不可用),
    先看返回码:1015=参数;401=token;500=服务端异常。后面几条的结论都以这条通过为前提。
    """
    msgs = dm_client.build_report_messages(msg_id=uuid.uuid4().hex)
    env = _report(dm_client, reporter_user_id, ctx_id, msgs)
    assert env.code == CODE_OK, (
        f"基线举报就失败了,code={env.code} msg={env.msg!r} raw={env.raw!r}。"
        f"若 code=500,多半是服务端把业务错误当成了 RPC 错误(见问题 1),需查 user-srv 日志:"
        f" 'dao save UserReport data err'")


# ─────────────── 问题 2:messages 缺 id → 去重键为空串 → 永久"重复投诉" ───────────────

@pytest.mark.write
def test_01_missing_id_must_not_cause_false_duplicate(dm_client, reporter_user_id, ctx_id):
    """🔴 复现问题 2:messages 里不带 id 时,服务端把空串当去重键存进 msg_id。

    服务端 handler_report.go:26 用 msgID[0].ID 查重且**不校验非空**:
        if u.dao.GetReportMsg(ctx, msgID[0].ID, req.UserId) { rsp.Code = 36990 }
    于是同一用户第一次举报(无 id)会存下 msg_id='',之后**举报任何一条同样无 id 的消息**
    都会命中那行 → 36990「请勿重复投诉」。表现就是"点举报报错"。

    正确行为应为:要么拒绝空 id(明确的参数错),要么两条不同消息互不影响。
    """
    first = _report(dm_client, reporter_user_id, ctx_id,
                    dm_client.build_report_messages(msg_id=None, content="repro-A-" + uuid.uuid4().hex[:8]))
    second = _report(dm_client, reporter_user_id, ctx_id,
                     dm_client.build_report_messages(msg_id=None, content="repro-B-" + uuid.uuid4().hex[:8]))

    # 情形一:本次之前已有人跑过 → 第一发就被拦,这本身已经是铁证
    assert first.code != CODE_DUP_REPORT, (
        f"【问题 2 复现】第一次举报一条全新消息就返回 36990「请勿重复投诉」。"
        f"原因是库里已存在该用户 msg_id='' 的历史行(上一次无 id 举报留下的),"
        f"空串把所有无 id 的举报都拦住了。first={first.raw!r}")

    # 情形二:两条**不同**消息被判成重复
    assert second.code != CODE_DUP_REPORT, (
        f"【问题 2 复现】两条内容不同的消息(均未带 id)被判为重复举报:"
        f"第一次 code={first.code},第二次 code={second.code}(36990)。"
        f"根因:去重键取 msgID[0].ID,缺 id 时为空串,两次都存/查 msg_id=''。"
        f"second={second.raw!r}")

    # 若服务端选择"拒绝空 id",那应是明确的参数错而不是成功
    assert second.code in (CODE_OK, CODE_MISSING_PARAM), (
        f"缺 id 的举报既没成功也没给出明确参数错,code={second.code} raw={second.raw!r}")


# ─────────── 问题 1:业务错误被当成 RPC 错误 → 一律 500,丢失真实错误码 ───────────

@pytest.mark.write
def test_02_malformed_messages_should_be_1015_not_500(dm_client, reporter_user_id, ctx_id):
    """🔴 复现问题 1:messages 不是合法 JSON 时,应返回 1015「缺失必要的参数」,实际返回 500。

    handler_report.go:22-25 设置了 rsp.Code=1015 之后又 `return err`;
    go-micro 里 handler 返回非 nil error = RPC 传输层失败,rsp 不会送达,
    网关落到 report.go:51 的 `if err != nil` 分支 → apiResult.Response(500, nil)。
    后果:所有底层失败都伪装成 500,排查时看不出真实原因。
    """
    env = _report(dm_client, reporter_user_id, ctx_id, messages="this-is-not-json")
    assert env.code != CODE_SERVER_ERR, (
        f"【问题 1 复现】非法 JSON 的 messages 返回了 500,而服务端其实已判定为 1015。"
        f"业务错误码被 `return err` 吞掉了(handler_report.go:24)。raw={env.raw!r}")
    assert env.code == CODE_MISSING_PARAM, (
        f"期望 1015「缺失必要的参数」,实际 code={env.code} raw={env.raw!r}")


@pytest.mark.write
def test_03_messages_as_object_should_be_1015_not_500(dm_client, reporter_user_id, ctx_id):
    """🔴 复现问题 1 的变体:messages 是 JSON **对象**(而非数组)。

    服务端按 []msgInfo 解析,传对象会 unmarshal 失败 → 同样走 `return err` → 500。
    客户端若某些场景发的是单对象而不是数组,用户就会看到"举报失败"。
    """
    env = _report(dm_client, reporter_user_id, ctx_id,
                  messages='{"id":"%s","content":"repro-object"}' % uuid.uuid4().hex)
    assert env.code != CODE_SERVER_ERR, (
        f"【问题 1 复现】messages 传 JSON 对象(非数组)返回 500,应为 1015。raw={env.raw!r}")


@pytest.mark.write
def test_04_empty_array_messages(dm_client, reporter_user_id, ctx_id):
    """边界:messages 是空数组 `[]`。

    此路径 unmarshal 成功但 len<1,err 为 nil,故**能正确返回 1015**——
    可用它与 test_02 对照,证明 500 确实来自 `return err` 而非别的原因。
    """
    env = _report(dm_client, reporter_user_id, ctx_id, messages="[]")
    assert env.code == CODE_MISSING_PARAM, (
        f"空数组应返回 1015,实际 code={env.code} raw={env.raw!r}。"
        f"(本条与 test_02 的差异正好指向 `return err`:同为参数问题,一个 1015 一个 500)")


# ─────────── 问题 4:desc 列是 utf8(3字节) varchar(200) NOT NULL ───────────

@pytest.mark.write
def test_05_desc_with_emoji(dm_client, reporter_user_id, ctx_id):
    """🔴 复现问题 4:举报描述含 emoji。

    user_report 表 `CHARACTER SET = utf8`(MySQL 的 3 字节 utf8,非 utf8mb4),
    `desc` varchar(200) 存不下 4 字节字符 → MySQL 1366 Incorrect string value
    → SetReport 返回 err → 走问题 1 的路径 → 500。
    """
    msgs = dm_client.build_report_messages(msg_id=uuid.uuid4().hex)
    env = _report(dm_client, reporter_user_id, ctx_id, msgs, desc="举报测试 😀🔥")
    assert env.code == CODE_OK, (
        f"【问题 4 复现】含 emoji 的举报描述失败,code={env.code} raw={env.raw!r}。"
        f"若为 500,查 user-srv 日志 'dao save UserReport data err' 是否为 "
        f"Error 1366: Incorrect string value —— 即 user_report 表 charset 仍是 utf8,需升 utf8mb4。")


@pytest.mark.write
def test_06_desc_too_long(dm_client, reporter_user_id, ctx_id):
    """🔴 复现问题 4 变体:描述超过 200 字符(desc 列 varchar(200))。

    严格模式下 MySQL 报 1406 Data too long → 同样变成 500。
    正确行为:应在网关侧做长度校验并返回明确的参数错,而不是交给数据库报错。
    """
    msgs = dm_client.build_report_messages(msg_id=uuid.uuid4().hex)
    env = _report(dm_client, reporter_user_id, ctx_id, msgs, desc="x" * 300)
    assert env.code != CODE_SERVER_ERR, (
        f"【问题 4 复现】超长描述(300 字符 > varchar(200))返回 500。"
        f"应由网关做长度校验返回参数错,而非落到 DB 报 1406。raw={env.raw!r}")


# ─────────── 问题 3:user_id 取自请求体而非鉴权态(越权 + 脆弱) ───────────

@pytest.mark.write
def test_07_user_id_comes_from_body_not_token(dm_client, reporter_user_id, ctx_id):
    """🔴 复现问题 3:服务端从**请求体**取 user_id,而不是从 token 的鉴权态取。

    report.go:33-39 用 param.UserId 解析;而本网关其它接口的惯例是
    ctx.GetInt64("user_id")(见 agent.go:60 / agent_report.go:46 / agent_center_report.go:101)。
    后果 (a) 越权:可以冒充任意 userId 提交举报;
         (b) 脆弱:客户端不传或传非数字 → ParseInt 失败**静默返回 0** → 1015。

    本用例用一个明显不存在的 userId 提交;若返回 200,说明服务端**接受了伪造的举报人**。
    """
    fake_uid = "999999999999999999"
    assert fake_uid != str(reporter_user_id), "构造的伪造 userId 不应与真实账号相同"
    msgs = dm_client.build_report_messages(msg_id=uuid.uuid4().hex)
    env = _report(dm_client, fake_uid, ctx_id, msgs)
    assert env.code != CODE_OK, (
        f"【问题 3 复现】用伪造的 user_id={fake_uid} 提交举报被接受(code=200),"
        f"说明举报人身份取自请求体而非 token —— 任何人都能以他人名义举报。"
        f"应改为 ctx.GetInt64(\"user_id\")。raw={env.raw!r}")


@pytest.mark.write
def test_08_non_numeric_user_id_silently_becomes_zero(dm_client, ctx_id):
    """🟡 复现问题 3 的 (b):user_id 传非数字时被静默吞成 0,最终报 1015。

    网关 report.go:33-39 的匿名函数 ParseInt 失败直接 `return 0`,不报错;
    user-srv 再判 php2go.Empty(0) → 1015「缺失必要的参数」。
    用户侧看到的是含糊的"缺参数",而真实原因是 user_id 格式不对。
    """
    msgs = dm_client.build_report_messages(msg_id=uuid.uuid4().hex)
    env = _report(dm_client, "not-a-number", ctx_id, msgs)
    assert env.code != CODE_MISSING_PARAM, (
        f"【问题 3(b) 复现】user_id 传非数字被静默转成 0,最终报 1015「缺失必要的参数」,"
        f"掩盖了真实原因(格式错)。raw={env.raw!r}")
