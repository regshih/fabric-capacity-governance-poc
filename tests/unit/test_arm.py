"""ARM client behaviour: retries, error mapping, and LRO polling.

Every test here runs against a fake session. No network, no credentials.
"""

from __future__ import annotations

import json

import pytest
import requests

from fabgov.arm import (
    ArmClient,
    ArmError,
    ArmResponse,
    ArmTimeoutError,
    describe_status,
    parse_error_code,
    parse_error_message,
    retry_after_seconds,
)


class FakeResponse:
    def __init__(self, status_code, body=None, headers=None, text=None):
        self.status_code = status_code
        self.headers = headers or {}
        if text is not None:
            self.text = text
        else:
            self.text = json.dumps(body) if body is not None else ""


class FakeSession:
    """Returns queued responses and records the requests it received."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, params=None, data=None, timeout=None, allow_redirects=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "params": params,
                "data": data,
                "allow_redirects": allow_redirects,
            }
        )
        if not self._responses:
            raise AssertionError("FakeSession ran out of queued responses.")
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def put(self, url, headers=None, params=None, data=None, timeout=None, allow_redirects=None):
        return self.request(
            "PUT",
            url,
            headers=headers,
            params=params,
            data=data,
            allow_redirects=allow_redirects,
        )


def make_client(responses, **kwargs):
    session = FakeSession(responses)
    sleeps = []
    client = ArmClient(
        lambda: "fake-token",
        session=session,
        sleep=sleeps.append,
        backoff_seconds=kwargs.pop("backoff_seconds", 0.01),
        **kwargs,
    )
    return client, session, sleeps


class TestErrorParsing:
    def test_nested_error_code(self):
        assert parse_error_code({"error": {"code": "AuthorizationFailed"}}) == "AuthorizationFailed"

    def test_bare_error_code(self):
        assert parse_error_code({"code": "NotFound"}) == "NotFound"

    def test_code_from_details(self):
        body = {"error": {"message": "outer", "details": [{"code": "RequestDisallowedByPolicy"}]}}
        assert parse_error_code(body) == "RequestDisallowedByPolicy"

    def test_missing(self):
        assert parse_error_code({}) == ""
        assert parse_error_code(None) == ""
        assert parse_error_code("not a dict") == ""

    def test_message(self):
        assert parse_error_message({"error": {"message": "boom"}}) == "boom"

    def test_message_from_details(self):
        body = {"error": {"details": [{"message": "policy said no"}]}}
        assert parse_error_message(body) == "policy said no"


class TestRetryAfter:
    def test_reads_header(self):
        assert retry_after_seconds({"Retry-After": "30"}, 5) == 30.0

    def test_case_insensitive(self):
        assert retry_after_seconds({"retry-after": "12"}, 5) == 12.0

    def test_default_when_absent(self):
        assert retry_after_seconds({}, 7) == 7.0
        assert retry_after_seconds(None, 7) == 7.0

    def test_default_when_unparseable(self):
        assert retry_after_seconds({"Retry-After": "soon"}, 4) == 4.0

    def test_negative_falls_back(self):
        assert retry_after_seconds({"Retry-After": "-5"}, 3) == 3.0

    def test_clamped(self):
        """An absurd server value must not stall the POC for hours."""
        assert retry_after_seconds({"Retry-After": "99999"}, 5) == 300.0


class TestDescribeStatus:
    @pytest.mark.parametrize(
        "status,fragment",
        [
            (401, "az login"),
            (403, "RequestDisallowedByPolicy"),
            (404, "not found"),
            (409, "mid-operation"),
            (429, "Throttled"),
        ],
    )
    def test_actionable_hints(self, status, fragment):
        assert fragment.lower() in describe_status(status).lower()

    def test_includes_error_code_and_message(self):
        text = describe_status(403, "AuthorizationFailed", "no access")
        assert "AuthorizationFailed" in text and "no access" in text


class TestRequests:
    def test_success_returns_body(self):
        client, session, _ = make_client([FakeResponse(200, {"name": "cap1"})])
        response = client.get("/subscriptions/s/resourceGroups/rg")
        assert response.status_code == 200
        assert response.body["name"] == "cap1"

    def test_sends_bearer_token(self):
        client, session, _ = make_client([FakeResponse(200, {})])
        client.get("/x")
        assert session.calls[0]["headers"]["Authorization"] == "Bearer fake-token"

    def test_relative_url_is_absolutized(self):
        client, session, _ = make_client([FakeResponse(200, {})])
        client.get("/subscriptions/s")
        assert session.calls[0]["url"] == "https://management.azure.com/subscriptions/s"

    def test_absolute_url_preserved(self):
        client, session, _ = make_client([FakeResponse(200, {})])
        client.get("https://management.azure.com/other")
        assert session.calls[0]["url"] == "https://management.azure.com/other"

    @pytest.mark.parametrize(
        "url",
        [
            "http://management.azure.com/other",
            "https://example.invalid/collect",
            "https://management.azure.com" + "@" + "example.invalid/collect",
            "https://management.azure.com:444/other",
            "https://management.azure.com:invalid/other",
            "https://management.azure.com/other#fragment",
        ],
    )
    def test_rejects_untrusted_absolute_url_before_sending_token(self, url):
        calls = []
        client = ArmClient(lambda: calls.append("token") or "fake-token", session=FakeSession([]))
        with pytest.raises(ArmError, match="untrusted URL"):
            client.get(url)
        assert calls == []

    def test_redirects_are_disabled(self):
        client, session, _ = make_client([FakeResponse(200, {})])
        client.get("/x")
        assert session.calls[0]["allow_redirects"] is False

    def test_post_sends_no_body_by_default(self):
        """Suspend and resume take no request body."""
        client, session, _ = make_client(
            [FakeResponse(202, {}, {"Location": "https://management.azure.com/poll"})]
        )
        client.post("/x/suspend")
        assert session.calls[0]["data"] is None

    def test_empty_body_parses_to_empty_dict(self):
        client, _, _ = make_client([FakeResponse(200, text="")])
        assert client.get("/x").body == {}

    def test_non_json_body_preserved_as_raw(self):
        client, _, _ = make_client([FakeResponse(200, text="not json")])
        assert client.get("/x").body == {"raw": "not json"}


class TestRetryBehaviour:
    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
    def test_retries_transient(self, status):
        client, session, sleeps = make_client([FakeResponse(status, {}), FakeResponse(200, {"ok": True})])
        assert client.get("/x").body == {"ok": True}
        assert len(session.calls) == 2
        assert len(sleeps) == 1

    def test_honours_retry_after_on_429(self):
        client, _, sleeps = make_client([FakeResponse(429, {}, {"Retry-After": "17"}), FakeResponse(200, {})])
        client.get("/x")
        assert sleeps == [17.0]

    def test_backoff_is_exponential(self):
        client, _, sleeps = make_client(
            [FakeResponse(503, {}), FakeResponse(503, {}), FakeResponse(200, {})],
            backoff_seconds=1.0,
        )
        client.get("/x")
        assert sleeps == [1.0, 2.0]

    def test_gives_up_after_max_attempts(self):
        client, session, _ = make_client([FakeResponse(503, {})] * 3, max_attempts=3)
        with pytest.raises(ArmError):
            client.get("/x")
        assert len(session.calls) == 3

    def test_retries_network_errors(self):
        client, session, _ = make_client(
            [requests.ConnectionError("dropped"), FakeResponse(200, {"ok": True})]
        )
        assert client.get("/x").body == {"ok": True}
        assert len(session.calls) == 2

    def test_network_failure_eventually_raises(self):
        client, _, _ = make_client([requests.ConnectionError("dropped")] * 3, max_attempts=3)
        with pytest.raises(ArmError, match="Network failure"):
            client.get("/x")

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 409])
    def test_does_not_retry_client_errors(self, status):
        client, session, _ = make_client([FakeResponse(status, {"error": {"code": "X"}})])
        with pytest.raises(ArmError) as exc_info:
            client.get("/x")
        assert exc_info.value.status_code == status
        assert len(session.calls) == 1

    def test_policy_denial_surfaces_error_code(self):
        body = {"error": {"code": "RequestDisallowedByPolicy", "message": "denied by policy"}}
        client, _, _ = make_client([FakeResponse(403, body)])
        with pytest.raises(ArmError) as exc_info:
            client.put("/x", body={})
        assert exc_info.value.error_code == "RequestDisallowedByPolicy"
        assert exc_info.value.status_code == 403


class TestLongRunningOperations:
    def test_non_202_returns_immediately(self):
        client, session, _ = make_client([])
        response = ArmResponse(200, {}, {"done": True})
        assert client.wait_for_lro(response) is response
        assert session.calls == []

    def test_polls_azure_async_operation_to_success(self):
        client, session, _ = make_client(
            [FakeResponse(200, {"status": "InProgress"}), FakeResponse(200, {"status": "Succeeded"})]
        )
        accepted = ArmResponse(202, {"Azure-AsyncOperation": "https://management.azure.com/poll/op"}, {})
        result = client.wait_for_lro(accepted, poll_seconds=0)
        assert result.body["status"] == "Succeeded"
        assert len(session.calls) == 2

    def test_prefers_azure_async_operation_over_location(self):
        client, session, _ = make_client([FakeResponse(200, {"status": "Succeeded"})])
        accepted = ArmResponse(
            202,
            {
                "Azure-AsyncOperation": "https://management.azure.com/async/op",
                "Location": "https://management.azure.com/location/op",
            },
            {},
        )
        client.wait_for_lro(accepted, poll_seconds=0)
        assert session.calls[0]["url"] == "https://management.azure.com/async/op"

    def test_falls_back_to_location_header(self):
        client, session, _ = make_client([FakeResponse(200, {"status": "Succeeded"})])
        accepted = ArmResponse(202, {"Location": "https://management.azure.com/location/op"}, {})
        client.wait_for_lro(accepted, poll_seconds=0)
        assert session.calls[0]["url"] == "https://management.azure.com/location/op"

    def test_header_lookup_is_case_insensitive(self):
        client, session, _ = make_client([FakeResponse(200, {"status": "Succeeded"})])
        accepted = ArmResponse(202, {"azure-asyncoperation": "https://management.azure.com/async/op"}, {})
        client.wait_for_lro(accepted, poll_seconds=0)
        assert session.calls[0]["url"] == "https://management.azure.com/async/op"

    def test_failed_operation_raises(self):
        client, _, _ = make_client(
            [FakeResponse(200, {"status": "Failed", "error": {"message": "capacity broke"}})]
        )
        accepted = ArmResponse(202, {"Azure-AsyncOperation": "https://management.azure.com/poll"}, {})
        with pytest.raises(ArmError, match="capacity broke"):
            client.wait_for_lro(accepted, poll_seconds=0)

    @pytest.mark.parametrize("status", ["Canceled", "Cancelled"])
    def test_canceled_operation_raises(self, status):
        client, _, _ = make_client([FakeResponse(200, {"status": status})])
        accepted = ArmResponse(202, {"Azure-AsyncOperation": "https://management.azure.com/poll"}, {})
        with pytest.raises(ArmError):
            client.wait_for_lro(accepted, poll_seconds=0)

    def test_provisioning_state_used_when_no_status(self):
        client, _, _ = make_client([FakeResponse(200, {"properties": {"provisioningState": "Succeeded"}})])
        accepted = ArmResponse(202, {"Location": "https://management.azure.com/poll"}, {})
        result = client.wait_for_lro(accepted, poll_seconds=0)
        assert result.status_code == 200

    def test_location_style_completion_returns_resource(self):
        """A Location LRO that finished returns 200 with the resource and no status."""
        client, _, _ = make_client([FakeResponse(200, {"name": "cap1"})])
        accepted = ArmResponse(202, {"Location": "https://management.azure.com/poll"}, {})
        result = client.wait_for_lro(accepted, poll_seconds=0)
        assert result.body["name"] == "cap1"

    def test_202_without_pollable_header_returns_accepted(self):
        client, session, _ = make_client([])
        accepted = ArmResponse(202, {}, {})
        assert client.wait_for_lro(accepted) is accepted
        assert session.calls == []

    def test_timeout_raises_rather_than_claiming_success(self):
        client, _, _ = make_client([FakeResponse(200, {"status": "InProgress"})] * 50)
        accepted = ArmResponse(202, {"Azure-AsyncOperation": "https://management.azure.com/poll"}, {})
        with pytest.raises(ArmTimeoutError):
            client.wait_for_lro(accepted, timeout_seconds=0, poll_seconds=0)
