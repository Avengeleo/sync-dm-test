"""仅V85已确认的普通群身份修复；禁言不收集、不计通过。"""
import pytest
from im_test.security_group_p2 import CASES, run_group_case
from im_test.security_p2_config import P2Blocked, P2Error, load_p2_config
from im_test.security_wire import SecurityWireError


@pytest.mark.write
@pytest.mark.parametrize("case", CASES)
def test_group_identity(case, request):
    config = load_p2_config()
    request.node.user_properties.extend([("scope", "Vuln85"), ("http_version", config["p2_version"]),
                                         ("deployment", config["deployment"]), ("mute", "pending_not_tested")])
    try:
        run_group_case(config, case, record=lambda key, value: request.node.user_properties.append((key, value)))
    except P2Blocked as exc:
        pytest.skip(str(exc))
    except (P2Error, SecurityWireError) as exc:
        pytest.fail(str(exc), pytrace=False)
    except Exception:
        pytest.fail("V85 异常停止；不输出底层异常，不重发夹具", pytrace=False)
