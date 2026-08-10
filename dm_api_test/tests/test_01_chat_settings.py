"""聊天设置(字体大小 / 默认语速)服务端化。

契约(读 handler_setting.go / switch.go 核实):
  /user/switch/list 响应含 chat_font_size、chat_voice_speed(整数,默认 0)
  /user/switch/set  {alias_field, setting_value(字符串)} → 白名单内 200,非白名单 1015
  白名单含 chat_font_size / chat_voice_speed;setting_value 必须字符串;无范围校验
"""

import pytest


def test_list_has_chat_fields(dm_client):
    data = dm_client.switch_list().expect_ok().data
    assert "chat_font_size" in data, "switch/list 应含 chat_font_size"
    assert "chat_voice_speed" in data, "switch/list 应含 chat_voice_speed"
    assert isinstance(data["chat_font_size"], int)
    assert isinstance(data["chat_voice_speed"], int)


@pytest.mark.write
def test_set_chat_font_size_and_readback(dm_client):
    dm_client.switch_set("chat_font_size", "2").expect_ok()
    data = dm_client.switch_list().expect_ok().data
    assert data["chat_font_size"] == 2, "写后回读应为 2"
    dm_client.switch_set("chat_font_size", "0")  # 复位默认


@pytest.mark.write
def test_set_chat_voice_speed_and_readback(dm_client):
    dm_client.switch_set("chat_voice_speed", "3").expect_ok()
    data = dm_client.switch_list().expect_ok().data
    assert data["chat_voice_speed"] == 3, "写后回读应为 3"
    dm_client.switch_set("chat_voice_speed", "0")  # 复位默认


def test_set_non_whitelist_rejected(dm_client):
    # 非白名单字段应被拒 1015(白名单机制,防客户端拿它改任意列)
    dm_client.switch_set("not_a_real_column", "1").expect(1015)


def test_set_missing_value(dm_client):
    # 缺 setting_value → 网关入参校验 39100
    dm_client.call("/user/switch/set", {"alias_field": "chat_font_size"}).expect(39100)


def test_set_missing_alias(dm_client):
    # 缺 alias_field → 39101
    dm_client.call("/user/switch/set", {"setting_value": "1"}).expect(39101)


@pytest.mark.write
def test_wrong_type_setting_value_returns_envelope_not_500(dm_client):
    """setting_value 传数字(而非文档要求的字符串)时,必须回正常业务信封,不能是 500。

    网关 ShouldBind 失败时原先直接 err.(validator.ValidationErrors) 裸断言,
    而 JSON 类型错误返回的是 *json.UnmarshalTypeError → panic → 客户端拿到 500 空响应。
    联调文档写的是"档位号字符串",客户端传成数字是很自然的笔误,故须给明确错误码。
    """
    env = dm_client.call("/user/switch/set", {"alias_field": "chat_font_size", "setting_value": 2})
    assert env.code != 500, (
        f"传数字型 setting_value 不应触发 500(网关裸类型断言 panic),实际 {env.code}/{env.msg!r}"
    )
    assert env.code in (400, 1015, 39100), f"应返回明确的参数类错误码,实际 {env.code}"


@pytest.mark.write
def test_wrong_type_alias_field_returns_envelope_not_500(dm_client):
    """alias_field 传数字同理,不能 500。"""
    env = dm_client.call("/user/switch/set", {"alias_field": 123, "setting_value": "2"})
    assert env.code != 500, f"传数字型 alias_field 不应触发 500,实际 {env.code}/{env.msg!r}"
