"""Fabric capacity lifecycle: read state, pause, resume, create.

All ARM shapes here were verified against the stable ``2023-11-01`` API:
https://learn.microsoft.com/en-us/rest/api/microsoftfabric/fabric-capacities

Two details drive most of the code below.

**State is a wider enum than you would expect.** ``properties.state`` is
documented with the values Active, Provisioning, Failed, Updating, Deleting,
Suspending, Suspended, Pausing, Paused, Resuming, Scaling, Preparing. Note that
it contains *both* ``Suspended`` and ``Paused``, and the documentation does not
say which one a suspend operation settles on. We therefore treat both as
"paused" rather than guessing, and treat the transitional values as "in flight"
so we never race an operation that Azure is still performing.

**Suspend and resume may or may not be asynchronous.** Both are documented to
return 200 (done) or 202 (poll me). The caller must handle both.
"""

from __future__ import annotations

import logging
import re
import time

from .arm import ArmClient, ArmError, ArmTimeoutError, retry_after_seconds
from .config import FABRIC_API_VERSION, build_capacity_resource_id

LOGGER = logging.getLogger("fabgov.capacity")

# Documented ResourceState enum values, grouped by what they mean for us.
PAUSED_STATES = frozenset({"paused", "suspended"})
RUNNING_STATES = frozenset({"active"})
IN_FLIGHT_STATES = frozenset(
    {"suspending", "pausing", "resuming", "scaling", "updating", "provisioning", "preparing", "deleting"}
)
FAILED_STATES = frozenset({"failed"})

# Azure requires Fabric capacity names to be lowercase alphanumeric, starting
# with a letter, 3-63 characters.
CAPACITY_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9]*$")
CAPACITY_NAME_MIN = 3
CAPACITY_NAME_MAX = 63

# Tags applied to anything this POC creates. cleanup.py will refuse to delete
# a resource that does not carry the purpose tag.
POC_PURPOSE_TAG = "fabric-capacity-governance-poc"
POC_TAGS = {"purpose": POC_PURPOSE_TAG, "managed-by": "poc"}


class CapacityStateError(RuntimeError):
    """Raised when a capacity is in a state we refuse to act on."""


def validate_capacity_name(name: str) -> str:
    """Validate a Fabric capacity name against the documented ARM constraint.

    Catching this locally produces a far better message than the raw ARM 400.
    """
    if not name or not str(name).strip():
        raise ValueError("Capacity name is required.")
    candidate = str(name).strip()
    if not (CAPACITY_NAME_MIN <= len(candidate) <= CAPACITY_NAME_MAX):
        raise ValueError(
            "Capacity name {0!r} must be {1}-{2} characters.".format(
                candidate, CAPACITY_NAME_MIN, CAPACITY_NAME_MAX
            )
        )
    if not CAPACITY_NAME_PATTERN.match(candidate):
        raise ValueError(
            "Capacity name {0!r} is invalid. Fabric requires lowercase letters and digits "
            "only, starting with a letter (pattern ^[a-z][a-z0-9]*$).".format(candidate)
        )
    return candidate


def normalize_state(state) -> str:
    """Reduce the ARM state enum to one of: paused, running, in-flight, failed, unknown."""
    if not state:
        return "unknown"
    lowered = str(state).strip().lower()
    if lowered in PAUSED_STATES:
        return "paused"
    if lowered in RUNNING_STATES:
        return "running"
    if lowered in IN_FLIGHT_STATES:
        return "in-flight"
    if lowered in FAILED_STATES:
        return "failed"
    return "unknown"


class CapacityInfo:
    """A read-only snapshot of a Fabric capacity."""

    def __init__(self, body):
        self.raw = body if isinstance(body, dict) else {}
        properties = self.raw.get("properties") or {}
        sku = self.raw.get("sku") or {}
        self.id = self.raw.get("id", "")
        self.name = self.raw.get("name", "")
        self.location = self.raw.get("location", "")
        self.sku_name = sku.get("name", "")
        self.sku_tier = sku.get("tier", "")
        self.state = properties.get("state", "")
        self.provisioning_state = properties.get("provisioningState", "")
        administration = properties.get("administration") or {}
        self.administrators = list(administration.get("members") or [])
        self.tags = dict(self.raw.get("tags") or {})

    @property
    def normalized_state(self) -> str:
        return normalize_state(self.state)

    @property
    def is_paused(self) -> bool:
        return self.normalized_state == "paused"

    @property
    def is_running(self) -> bool:
        return self.normalized_state == "running"

    @property
    def is_in_flight(self) -> bool:
        return self.normalized_state == "in-flight"

    @property
    def created_by_poc(self) -> bool:
        """Whether the capacity carries the complete POC tag pair.

        This is only a classification hint. Destructive callers must also
        require an exact match in the ignored deployment manifest; tags alone
        are not proof of ownership.
        """
        return self.tags.get("purpose") == POC_PURPOSE_TAG and self.tags.get("managed-by") == "poc"

    def summary(self) -> dict:
        return {
            "name": self.name,
            "location": self.location,
            "sku": self.sku_name,
            "tier": self.sku_tier,
            "state": self.state,
            "normalizedState": self.normalized_state,
            "provisioningState": self.provisioning_state,
            "administratorCount": len(self.administrators),
            "createdByPoc": self.created_by_poc,
            "tags": self.tags,
        }


class CapacityClient:
    """Operations against a single Fabric capacity."""

    def __init__(self, arm: ArmClient, subscription_id: str, api_version: str = FABRIC_API_VERSION):
        self._arm = arm
        self._subscription_id = subscription_id
        self._api_version = api_version

    def _params(self) -> dict:
        return {"api-version": self._api_version}

    def resource_id(self, resource_group: str, capacity_name: str) -> str:
        return build_capacity_resource_id(self._subscription_id, resource_group, capacity_name)

    # ---- read ------------------------------------------------------------

    def get(self, resource_group: str, capacity_name: str):
        """Fetch a capacity, or return ``None`` when it does not exist.

        A missing capacity is a normal, expected condition in ``create`` mode,
        so 404 is not raised - every other error still is.
        """
        try:
            response = self._arm.get(self.resource_id(resource_group, capacity_name), params=self._params())
        except ArmError as exc:
            if exc.status_code == 404:
                return None
            raise
        return CapacityInfo(response.body)

    def require(self, resource_group: str, capacity_name: str) -> CapacityInfo:
        """Fetch a capacity, raising a clear error when it is absent."""
        info = self.get(resource_group, capacity_name)
        if info is None:
            raise ArmError(
                "Fabric capacity {0!r} was not found in resource group {1!r}. "
                "Check FABRIC_CAPACITY_NAME and RESOURCE_GROUP_NAME.".format(capacity_name, resource_group),
                status_code=404,
                error_code="ResourceNotFound",
            )
        return info

    def list_in_subscription(self) -> list:
        """List every Fabric capacity visible in the subscription."""
        response = self._arm.get(
            "/subscriptions/{0}/providers/Microsoft.Fabric/capacities".format(self._subscription_id),
            params=self._params(),
        )
        return [CapacityInfo(item) for item in response.body.get("value", [])]

    def list_skus(self) -> list:
        """List F-SKUs eligible in this subscription."""
        response = self._arm.get(
            "/subscriptions/{0}/providers/Microsoft.Fabric/skus".format(self._subscription_id),
            params=self._params(),
        )
        names = []
        for item in response.body.get("value", []):
            name = item.get("name")
            if name and name not in names:
                names.append(name)
        return names

    # ---- state changes ---------------------------------------------------

    def set_state(
        self,
        resource_group: str,
        capacity_name: str,
        desired: str,
        *,
        wait: bool = True,
        timeout_seconds: int = 900,
    ) -> dict:
        """Idempotently drive a capacity to ``pause`` or ``resume``.

        Returns a structured result describing what happened, including the
        no-op case. The capacity is always read first: issuing a suspend
        against an already-suspended capacity is a pointless API call that can
        also return a confusing 409.
        """
        action = str(desired).strip().lower()
        if action not in ("pause", "resume"):
            raise ValueError("Desired state must be 'pause' or 'resume', got {0!r}.".format(desired))

        target_normalized = "paused" if action == "pause" else "running"
        before = self.require(resource_group, capacity_name)

        result = {
            "action": action,
            "capacity": capacity_name,
            "resourceGroup": resource_group,
            "stateBefore": before.state,
            "normalizedStateBefore": before.normalized_state,
            "changed": False,
            "noOp": False,
            "stateAfter": before.state,
            "normalizedStateAfter": before.normalized_state,
        }

        if before.is_in_flight:
            raise CapacityStateError(
                "Capacity {0!r} is currently {1!r} - another operation is already in flight. "
                "Refusing to issue a {2}; wait for the current operation to finish.".format(
                    capacity_name, before.state, action
                )
            )

        if before.normalized_state == target_normalized:
            result["noOp"] = True
            result["message"] = "No action required. Capacity is already {0} (state={1}).".format(
                target_normalized, before.state
            )
            LOGGER.info("Requested: %s | Current: %s | Result: no action required.", action, before.state)
            return result

        if before.normalized_state == "failed":
            raise CapacityStateError(
                "Capacity {0!r} is in state {1!r}. Resolve the failure in the Azure portal "
                "before issuing a {2}.".format(capacity_name, before.state, action)
            )

        operation = "suspend" if action == "pause" else "resume"
        url = "{0}/{1}".format(self.resource_id(resource_group, capacity_name), operation)

        LOGGER.info("Issuing POST %s (current state: %s)", operation, before.state)
        # Both operations take no request body - verified against the REST reference.
        response = self._arm.post(url, params=self._params())

        if wait:
            try:
                self._arm.wait_for_lro(response, timeout_seconds=timeout_seconds)
            except ArmError as exc:
                if exc.status_code != 403:
                    raise
                # A capacity-scoped lifecycle role cannot read the provider-
                # level operation status URL. The action itself was accepted,
                # so fall back to the capacity GET used for final verification.
                LOGGER.warning(
                    "LRO status URL was outside the assigned RBAC scope; "
                    "verifying the capacity resource state instead."
                )

        after = self.require(resource_group, capacity_name)
        if wait:
            # LRO completion and resource-state completion are related but not
            # interchangeable. Azure may omit the polling header or report the
            # operation complete before the capacity GET reaches its target.
            # Never return a successful state-change result until the target
            # state is independently observed.
            deadline = time.monotonic() + timeout_seconds
            interval = retry_after_seconds(response.headers, 10)
            while after.normalized_state != target_normalized:
                if after.normalized_state == "failed":
                    raise CapacityStateError(
                        "Capacity entered Failed state while waiting for {0}.".format(action)
                    )
                if time.monotonic() >= deadline:
                    raise ArmTimeoutError(
                        "Capacity did not reach {0} within {1}s after Azure accepted the request.".format(
                            target_normalized, timeout_seconds
                        )
                    )
                time.sleep(interval)
                after = self.require(resource_group, capacity_name)
        result["changed"] = True
        result["stateAfter"] = after.state
        result["normalizedStateAfter"] = after.normalized_state
        result["reachedDesiredState"] = after.normalized_state == target_normalized
        result["message"] = "{0}: {1} -> {2}".format(action, before.state, after.state)
        LOGGER.info("Requested: %s | %s -> %s", action, before.state, after.state)
        return result

    def pause(self, resource_group: str, capacity_name: str, **kwargs) -> dict:
        return self.set_state(resource_group, capacity_name, "pause", **kwargs)

    def resume(self, resource_group: str, capacity_name: str, **kwargs) -> dict:
        return self.set_state(resource_group, capacity_name, "resume", **kwargs)

    # ---- create ----------------------------------------------------------

    def create(
        self,
        resource_group: str,
        capacity_name: str,
        *,
        location: str,
        sku: str,
        administrators,
        tags=None,
        wait: bool = True,
        timeout_seconds: int = 900,
    ) -> CapacityInfo:
        """Create a Fabric capacity.

        The body shape is the documented minimum: ``location``, ``sku``
        (name plus the single valid tier ``Fabric``), and
        ``properties.administration.members``, which is required and is an
        array of administrator user identities. Official samples use UPNs.
        """
        validate_capacity_name(capacity_name)
        members = [m for m in (administrators or []) if str(m).strip()]
        if not members:
            raise ValueError(
                "At least one capacity administrator is required "
                "(properties.administration.members cannot be empty)."
            )

        body = {
            "location": location,
            "sku": {"name": sku, "tier": "Fabric"},
            "properties": {"administration": {"members": members}},
            "tags": dict(tags or POC_TAGS),
        }

        LOGGER.info("Creating Fabric capacity %s (%s) in %s", capacity_name, sku, location)
        response = self._arm.put(
            self.resource_id(resource_group, capacity_name), params=self._params(), body=body
        )
        if wait:
            self._arm.wait_for_lro(response, timeout_seconds=timeout_seconds)
        return self.require(resource_group, capacity_name)

    def delete(self, resource_group: str, capacity_name: str, *, wait: bool = True) -> dict:
        """Delete a capacity. Callers are responsible for authorization checks.

        This method deliberately contains no safety logic of its own; the
        guard rails live in ``scripts/cleanup.py`` where the operator's intent
        is known. Nothing else in this package calls it.
        """
        response = self._arm.delete(self.resource_id(resource_group, capacity_name), params=self._params())
        if wait:
            self._arm.wait_for_lro(response)
        return {"deleted": capacity_name, "resourceGroup": resource_group}


def build_create_body(location: str, sku: str, administrators, tags=None) -> dict:
    """Build a capacity create request body.

    Exposed separately so unit tests can assert the exact ARM payload without
    a client or any network access.
    """
    return {
        "location": location,
        "sku": {"name": sku, "tier": "Fabric"},
        "properties": {"administration": {"members": list(administrators)}},
        "tags": dict(tags or POC_TAGS),
    }
