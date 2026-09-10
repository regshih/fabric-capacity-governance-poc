"""Capacity state handling, idempotency, and request construction."""

from __future__ import annotations

import pytest

from fabgov.arm import ArmTimeoutError
from fabgov.capacity import (
    POC_PURPOSE_TAG,
    CapacityClient,
    CapacityInfo,
    CapacityStateError,
    build_create_body,
    normalize_state,
    validate_capacity_name,
)


class TestNormalizeState:
    @pytest.mark.parametrize("state", ["Paused", "Suspended", "paused", "SUSPENDED"])
    def test_paused_variants(self, state):
        """Microsoft documents both Paused and Suspended; we must accept either."""
        assert normalize_state(state) == "paused"

    def test_active_is_running(self):
        assert normalize_state("Active") == "running"

    @pytest.mark.parametrize(
        "state",
        [
            "Suspending",
            "Pausing",
            "Resuming",
            "Scaling",
            "Updating",
            "Provisioning",
            "Preparing",
            "Deleting",
        ],
    )
    def test_transitional_states(self, state):
        assert normalize_state(state) == "in-flight"

    def test_failed(self):
        assert normalize_state("Failed") == "failed"

    @pytest.mark.parametrize("state", ["", None, "SomethingNew"])
    def test_unknown(self, state):
        assert normalize_state(state) == "unknown"


class TestValidateCapacityName:
    @pytest.mark.parametrize("name", ["abc", "fabgovpoc1", "a1b2c3"])
    def test_valid(self, name):
        assert validate_capacity_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "AB1",  # uppercase not allowed
            "1abc",  # must start with a letter
            "ab",  # too short
            "my-capacity",  # hyphen not allowed
            "my_capacity",  # underscore not allowed
            "",
        ],
    )
    def test_invalid(self, name):
        with pytest.raises(ValueError):
            validate_capacity_name(name)

    def test_too_long(self):
        with pytest.raises(ValueError):
            validate_capacity_name("a" * 64)

    def test_max_length_ok(self):
        assert validate_capacity_name("a" * 63)


class TestCapacityInfo:
    def _body(self, **overrides):
        body = {
            "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Fabric/capacities/cap1",
            "name": "cap1",
            "location": "westus3",
            "sku": {"name": "F2", "tier": "Fabric"},
            "properties": {
                "state": "Active",
                "provisioningState": "Succeeded",
                "administration": {"members": ["a@example.com", "b@example.com"]},
            },
            "tags": {},
        }
        body.update(overrides)
        return body

    def test_parses_fields(self):
        info = CapacityInfo(self._body())
        assert info.name == "cap1"
        assert info.sku_name == "F2"
        assert info.sku_tier == "Fabric"
        assert info.state == "Active"
        assert info.is_running and not info.is_paused
        assert len(info.administrators) == 2

    def test_paused_detection(self):
        info = CapacityInfo(self._body(properties={"state": "Paused"}))
        assert info.is_paused and not info.is_running

    def test_suspended_is_also_paused(self):
        info = CapacityInfo(self._body(properties={"state": "Suspended"}))
        assert info.is_paused

    def test_created_by_poc_requires_tag(self):
        assert CapacityInfo(self._body()).created_by_poc is False
        tagged = self._body(tags={"purpose": POC_PURPOSE_TAG, "managed-by": "poc"})
        assert CapacityInfo(tagged).created_by_poc is True

    def test_single_public_tag_is_not_ownership(self):
        tagged = self._body(tags={"purpose": POC_PURPOSE_TAG})
        assert CapacityInfo(tagged).created_by_poc is False

    def test_wrong_tag_value_is_not_poc_owned(self):
        body = self._body(tags={"purpose": "something-else"})
        assert CapacityInfo(body).created_by_poc is False

    def test_handles_missing_properties(self):
        info = CapacityInfo({"name": "cap1"})
        assert info.state == ""
        assert info.normalized_state == "unknown"
        assert info.administrators == []

    def test_summary_has_no_raw_ids(self):
        summary = CapacityInfo(self._body()).summary()
        assert "administratorCount" in summary
        assert "administrators" not in summary


class FakeArm:
    """Minimal ARM stand-in that serves a scripted sequence of capacity states."""

    def __init__(self, states, *, post_status=202):
        self._states = list(states)
        self.posts = []
        self.gets = []
        self._post_status = post_status

    def _body(self, state):
        return {
            "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Fabric/capacities/cap1",
            "name": "cap1",
            "location": "westus3",
            "sku": {"name": "F2", "tier": "Fabric"},
            "properties": {"state": state, "provisioningState": "Succeeded"},
            "tags": {},
        }

    def get(self, url, params=None):
        from fabgov.arm import ArmResponse

        self.gets.append(url)
        state = self._states.pop(0) if len(self._states) > 1 else self._states[0]
        return ArmResponse(200, {}, self._body(state))

    def post(self, url, params=None, body=None):
        from fabgov.arm import ArmResponse

        self.posts.append({"url": url, "body": body})
        return ArmResponse(self._post_status, {"Azure-AsyncOperation": "https://poll"}, {})

    def put(self, url, params=None, body=None):
        from fabgov.arm import ArmResponse

        self.posts.append({"url": url, "body": body, "method": "PUT"})
        return ArmResponse(201, {}, self._body("Provisioning"))

    def wait_for_lro(self, response, **kwargs):
        return response


class TestSetStateIdempotency:
    def test_pause_when_already_paused_is_noop(self):
        arm = FakeArm(["Paused"])
        client = CapacityClient(arm, "sub-1")
        result = client.set_state("rg", "cap1", "pause")
        assert result["noOp"] is True
        assert result["changed"] is False
        assert arm.posts == []

    def test_resume_when_already_active_is_noop(self):
        arm = FakeArm(["Active"])
        client = CapacityClient(arm, "sub-1")
        result = client.set_state("rg", "cap1", "resume")
        assert result["noOp"] is True
        assert arm.posts == []

    def test_suspended_state_also_treated_as_paused_for_idempotency(self):
        arm = FakeArm(["Suspended"])
        client = CapacityClient(arm, "sub-1")
        assert client.set_state("rg", "cap1", "pause")["noOp"] is True
        assert arm.posts == []

    def test_pause_when_active_issues_suspend(self):
        arm = FakeArm(["Active", "Paused"])
        client = CapacityClient(arm, "sub-1")
        result = client.set_state("rg", "cap1", "pause")
        assert result["changed"] is True
        assert result["noOp"] is False
        assert len(arm.posts) == 1
        assert arm.posts[0]["url"].endswith("/suspend")
        assert result["reachedDesiredState"] is True

    def test_resume_when_paused_issues_resume(self):
        arm = FakeArm(["Paused", "Active"])
        client = CapacityClient(arm, "sub-1")
        result = client.set_state("rg", "cap1", "resume")
        assert arm.posts[0]["url"].endswith("/resume")
        assert result["reachedDesiredState"] is True

    def test_suspend_sends_no_body(self):
        arm = FakeArm(["Active", "Paused"])
        CapacityClient(arm, "sub-1").set_state("rg", "cap1", "pause")
        assert arm.posts[0]["body"] is None

    def test_reads_state_before_acting(self):
        arm = FakeArm(["Active", "Paused"])
        CapacityClient(arm, "sub-1").set_state("rg", "cap1", "pause")
        assert len(arm.gets) >= 1

    def test_raises_when_desired_state_is_not_reached(self):
        """An accepted operation must not be reported as a successful state change."""
        arm = FakeArm(["Active", "Active"])
        with pytest.raises(ArmTimeoutError):
            CapacityClient(arm, "sub-1").set_state("rg", "cap1", "pause", timeout_seconds=0)

    def test_polls_capacity_until_target_state(self, monkeypatch):
        monkeypatch.setattr("fabgov.capacity.time.sleep", lambda _: None)
        arm = FakeArm(["Active", "Suspending", "Paused"])
        result = CapacityClient(arm, "sub-1").set_state("rg", "cap1", "pause")
        assert result["reachedDesiredState"] is True
        assert result["stateAfter"] == "Paused"

    @pytest.mark.parametrize("state", ["Suspending", "Resuming", "Scaling", "Updating"])
    def test_refuses_when_operation_in_flight(self, state):
        arm = FakeArm([state])
        with pytest.raises(CapacityStateError, match="in flight"):
            CapacityClient(arm, "sub-1").set_state("rg", "cap1", "pause")
        assert arm.posts == []

    def test_refuses_when_failed(self):
        arm = FakeArm(["Failed"])
        with pytest.raises(CapacityStateError):
            CapacityClient(arm, "sub-1").set_state("rg", "cap1", "pause")

    def test_rejects_unknown_action(self):
        arm = FakeArm(["Active"])
        with pytest.raises(ValueError):
            CapacityClient(arm, "sub-1").set_state("rg", "cap1", "destroy")


class TestBuildCreateBody:
    def test_documented_minimum_shape(self):
        body = build_create_body("westus3", "F2", ["admin@example.com"])
        assert body["location"] == "westus3"
        assert body["sku"] == {"name": "F2", "tier": "Fabric"}
        assert body["properties"]["administration"]["members"] == ["admin@example.com"]

    def test_tier_is_always_fabric(self):
        """RpSkuTier has exactly one documented value."""
        assert build_create_body("eastus", "F64", ["a@example.com"])["sku"]["tier"] == "Fabric"

    def test_default_tags_mark_poc_ownership(self):
        tags = build_create_body("westus3", "F2", ["a@example.com"])["tags"]
        assert tags["purpose"] == POC_PURPOSE_TAG

    def test_custom_tags_respected(self):
        body = build_create_body("westus3", "F2", ["a@example.com"], tags={"x": "y"})
        assert body["tags"] == {"x": "y"}


class TestCreateValidation:
    def test_rejects_empty_administrators(self):
        arm = FakeArm(["Active"])
        client = CapacityClient(arm, "sub-1")
        with pytest.raises(ValueError, match="administrator"):
            client.create("rg", "cap1", location="westus3", sku="F2", administrators=[])

    def test_rejects_blank_administrators(self):
        arm = FakeArm(["Active"])
        client = CapacityClient(arm, "sub-1")
        with pytest.raises(ValueError):
            client.create("rg", "cap1", location="westus3", sku="F2", administrators=["  "])

    def test_rejects_invalid_name(self):
        arm = FakeArm(["Active"])
        client = CapacityClient(arm, "sub-1")
        with pytest.raises(ValueError):
            client.create("rg", "BadName", location="westus3", sku="F2", administrators=["a@example.com"])


class TestResourceId:
    def test_construction(self):
        client = CapacityClient(FakeArm(["Active"]), "sub-1")
        assert client.resource_id("rg", "cap1") == (
            "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Fabric/capacities/cap1"
        )
