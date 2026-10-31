"""V43 纯本地协议与判定回归；所有 HTTP 均由 fake post 接管。"""

import socket

import pytest
import requests

from im_test import frame, proto_min, security_device
from im_test.security_device import (
    CM_PUSHTOKENSYNC, CM_PUSHTOKENSYNC_ACK, DeviceRequestError,
    ERR_TRANSMISSION_FORBIDDEN, NON_ERR, SecurityDeviceClient,
    build_push_sync_frame, parse_device_kick, parse_device_list, parse_push_sync_ack,
)
from im_test.tests.security import test_device_identity as cases


MARKER = "UNIT_PRIVATE_DEVICE_SENTINEL"


def _record(uid, token, client_type=2):
    return (proto_min._fv(1, uid) + proto_min._fs(2, token)
            + proto_min._fs(3, MARKER + "_name") + proto_min._fv(5, 17)
            + proto_min._fs(6, MARKER + "_info") + proto_min._fv(7, client_type)
            + proto_min._fs(8, "9.9.9"))


def _list(uid=7, token=MARKER, code=NON_ERR):
    return proto_min._fv(1, code) + proto_min._fb(2, _record(uid, token))


class Response:
    def __init__(self, body, status=200, content_type="application/x-protobuf"):
        self.status_code = status
        self.headers = {"Content-Type": content_type}
        self.content = body


def test_device_request_preserves_authenticated_uid_and_forged_body_without_logging(capsys, caplog):
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return Response(_list())

    client = SecurityDeviceClient("https://dev.invalid", MARKER + "_auth", 7, post=post)
    result = client.device_list(body_user_id=8, version="v2").require_success(7, nonempty=True)
    assert calls[0][0].endswith("/login/v2/user/online_device_list")
    assert proto_min.decode(calls[0][1]["data"])[1] == 8
    assert calls[0][1]["headers"]["Authorization"] == MARKER + "_auth:7"
    assert calls[0][1]["allow_redirects"] is False
    assert MARKER not in repr(client) + repr(result) + repr(result.devices)
    assert MARKER not in caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize("status", [401, 403, 404, 500, 502, 302])
def test_http_auth_and_server_failures_cannot_count_as_device_isolation(status):
    client = SecurityDeviceClient("https://dev.invalid", MARKER, 7,
                                  post=lambda *a, **k: Response(MARKER.encode(), status=status))
    with pytest.raises(DeviceRequestError, match="HTTP 非 200") as caught:
        client.device_list(body_user_id=8)
    assert MARKER not in str(caught.value)


@pytest.mark.parametrize("body,content_type", [
    (b"", "text/html"), (b"<html>failure</html>", "application/x-protobuf"),
    (b"", "application/x-protobuf"), (b"{}", "application/json"),
])
def test_empty_html_json_and_malformed_responses_fail(body, content_type):
    client = SecurityDeviceClient("https://dev.invalid", MARKER, 7,
                                  post=lambda *a, **k: Response(body, content_type=content_type))
    with pytest.raises(DeviceRequestError):
        client.device_list().require_success(7, nonempty=True)


def test_transport_failure_is_redacted_and_never_a_denial_pass():
    def fail(*args, **kwargs):
        raise requests.ConnectionError(MARKER)

    client = SecurityDeviceClient("https://dev.invalid", MARKER, 7, post=fail)
    with pytest.raises(DeviceRequestError) as caught:
        client.device_list()
    assert MARKER not in str(caught.value)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("body", [
    b"\x08", b"\x08" + b"\x80" * 11,
    proto_min._fv(1, NON_ERR) + proto_min._fv(1, NON_ERR),
    proto_min._fv(1, NON_ERR) + b"\x12\x09\x08",
    proto_min._fv(1, NON_ERR) + proto_min._fb(2, proto_min._fv(1, 7)),
    proto_min._fv(1, NON_ERR) + proto_min._fb(2, _record(7, MARKER)) * 2,
])
def test_strict_device_wire_rejects_truncation_duplicates_and_incomplete_records(body):
    with pytest.raises(DeviceRequestError):
        parse_device_list(body)


def test_list_and_kick_success_codes_are_distinct_and_nonempty_control_is_required():
    parse_device_list(_list()).require_success(7, nonempty=True)
    parse_device_kick(proto_min._fv(1, 200)).require_success()
    with pytest.raises(DeviceRequestError):
        parse_device_list(_list(code=200)).require_success(7)
    with pytest.raises(DeviceRequestError):
        parse_device_kick(proto_min._fv(1, NON_ERR)).require_success()
    with pytest.raises(DeviceRequestError, match="非空正控"):
        parse_device_list(proto_min._fv(1, NON_ERR)).require_success(7, nonempty=True)


def _config():
    return dict(http_base="https://dev.invalid", token="a-target", token2="b-target",
                user_id=7, user_id2=8, timeout=5, allow_device_kick=True,
                device_kick_phase="forged_uid", device_kick_version="v1",
                device_token="device-a", device_token2="device-b",
                device_observer_token="a-observer", device_observer_token2="b-observer")


class Backend:
    def __init__(self, mode="bound"):
        self.mode = mode
        self.alive = {7: True, 8: True}
        self.revoked = set()
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        auth = kwargs["headers"]["Authorization"].split(":")[0]
        uid = 7 if auth.startswith("a-") else 8
        body_uid = proto_min.decode(kwargs["data"])[1]
        if auth in self.revoked:
            return Response(b"expired", status=401)
        if url.endswith("kick/user_device"):
            target = body_uid if self.mode == "vulnerable" else uid
            self.alive[target] = False
            self.revoked.add("a-target" if target == 7 else "b-target")
            return Response(proto_min._fv(1, 200))
        lookup = body_uid if self.mode in ("vulnerable", "rewritten_uid_only") else uid
        if not self.alive[lookup] or self.mode == "empty":
            return Response(proto_min._fv(1, NON_ERR))
        row_uid = uid if self.mode == "rewritten_uid_only" else lookup
        return Response(_list(row_uid, "device-a" if lookup == 7 else "device-b"))


def test_readonly_case_proves_actual_device_contents_are_bound(monkeypatch):
    backend = Backend()
    monkeypatch.setattr(security_device.requests, "post", backend.post)
    cases._binding_case(_config(), "v2")
    assert len(backend.calls) == 6
    assert all(url.endswith("online_device_list") for url, _ in backend.calls)


@pytest.mark.parametrize("mode", ["vulnerable", "rewritten_uid_only", "empty"])
def test_readonly_case_fails_for_leaked_contents_or_missing_positive_fixture(monkeypatch, mode):
    backend = Backend(mode)
    monkeypatch.setattr(security_device.requests, "post", backend.post)
    with pytest.raises(pytest.fail.Exception):
        cases._binding_case(_config(), "v1")


def test_kick_requires_explicit_confirmation_before_any_request():
    calls = []
    client = SecurityDeviceClient("https://dev.invalid", MARKER, 7,
                                  post=lambda *a, **k: calls.append(1))
    with pytest.raises(DeviceRequestError, match="显式确认"):
        client.kick(MARKER)
    assert calls == []


def test_kick_phase_missing_dedicated_fixture_skips_before_mutation():
    config = _config()
    config["device_token2"] = ""
    with pytest.raises(pytest.skip.Exception):
        cases._kick_preconditions(config, "v1", "forged_uid")


class Request:
    class Node:
        def __init__(self):
            self.user_properties = []

    def __init__(self):
        self.node = self.Node()


@pytest.mark.parametrize("phase", ["forged_uid", "own_uid"])
def test_kick_phase_requires_B_token_health_and_own_positive_removal(monkeypatch, phase):
    backend = Backend()
    monkeypatch.setattr(security_device.requests, "post", backend.post)
    clock = [0.0]
    monkeypatch.setattr(cases.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cases.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    config = _config()
    config["device_kick_phase"] = phase
    cases._kick_case(config, "v1", phase, Request())
    assert backend.alive == {7: False, 8: True}
    kicks = [kwargs for url, kwargs in backend.calls if url.endswith("kick/user_device")]
    assert len(kicks) == 1
    fields = proto_min.decode(kicks[0]["data"])
    assert fields[1] == (8 if phase == "forged_uid" else 7)
    assert fields[2] == 2 and fields[3] == (b"device-b" if phase == "forged_uid" else b"device-a")


def test_forged_kick_that_revokes_B_credential_is_a_failure(monkeypatch):
    backend = Backend("vulnerable")
    monkeypatch.setattr(security_device.requests, "post", backend.post)
    with pytest.raises(pytest.fail.Exception, match="HTTP 非 200"):
        cases._kick_case(_config(), "v1", "forged_uid", Request())


def test_push_sync_wire_uses_real_field_numbers_and_matched_business_ack():
    request = build_push_sync_frame(7, 9, MARKER, token_type=1, seq=42)
    command, body = frame.parse_frame(request)
    fields = proto_min.decode(body)
    assert command == CM_PUSHTOKENSYNC
    assert fields == {1: 7, 2: 9, 3: MARKER.encode(), 4: 1}
    denied = frame.build_frame(CM_PUSHTOKENSYNC_ACK,
                              proto_min._fv(1, 7) + proto_min._fv(2, ERR_TRANSMISSION_FORBIDDEN), 42)
    parse_push_sync_ack(denied, 42).require_uid_denial(7)
    success = frame.build_frame(CM_PUSHTOKENSYNC_ACK,
                               proto_min._fv(1, 7) + proto_min._fv(2, NON_ERR), 42)
    parse_push_sync_ack(success, 42).require_success(7)
    with pytest.raises(DeviceRequestError):
        parse_push_sync_ack(success, 42).require_uid_denial(7)
    with pytest.raises(DeviceRequestError):
        parse_push_sync_ack(denied, 42).require_uid_denial(8)


@pytest.mark.parametrize("response", [
    b"", "closed", socket.timeout(), b"<html>401</html>",
    frame.build_frame(CM_PUSHTOKENSYNC_ACK, proto_min._fv(1, 7), 42),
    frame.build_frame(CM_PUSHTOKENSYNC_ACK, proto_min._fv(1, 7) + proto_min._fv(2, NON_ERR), 43),
    frame.build_frame(0x0102, proto_min._fv(1, 7) + proto_min._fv(2, NON_ERR), 42),
])
def test_push_sync_cannot_treat_timeout_empty_or_wrong_protocol_as_denial(response):
    with pytest.raises(DeviceRequestError):
        parse_push_sync_ack(response, 42)
