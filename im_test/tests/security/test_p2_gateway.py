"""V86专项，最多单连接1002个心跳；不执行压测或登录重试。"""
import pytest
from im_test.security_gateway_p2 import CASES, run_gateway_case
from im_test.security_p2_config import P2Blocked, P2Error, load_p2_config


@pytest.mark.write
@pytest.mark.parametrize("case", CASES)
def test_gateway_bounds(case, request):
    config = load_p2_config()
    request.node.user_properties.extend([("scope", "Vuln86"), ("transport", config["p2_transport"]),
                                         ("deployment", config["deployment"])])
    try:
        result = run_gateway_case(config, case)
        request.node.user_properties.extend(result.items())
    except P2Blocked as exc:
        pytest.skip(str(exc))
    except P2Error as exc:
        pytest.fail(str(exc), pytrace=False)
    except Exception:
        pytest.fail("V86 传输异常停止；不输出地址或凭证，不把异常当作通过", pytrace=False)
