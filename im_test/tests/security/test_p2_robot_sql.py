"""V92只读本地导出，不调用其他漏洞的日志扫描套件。"""
import pytest
from im_test.security_p2_config import P2Blocked, P2Error, load_p2_config
from im_test.security_robot_sql_p2 import audit_robot_sql


def test_robot_sql_parameters(request):
    config = load_p2_config()
    try:
        if config["target_env"] != "dev":
            raise P2Blocked("V92 只验收 dev 的本地日志导出")
        result = audit_robot_sql(config["p2_log_manifest"], config["deployment"])
        request.node.user_properties.extend(result.items())
    except P2Blocked as exc:
        pytest.skip(str(exc))
    except P2Error as exc:
        pytest.fail(str(exc), pytrace=False)
    except Exception:
        pytest.fail("V92 异常停止；不输出日志原文或参数", pytrace=False)
