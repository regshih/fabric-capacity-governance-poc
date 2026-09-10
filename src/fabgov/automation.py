"""Azure Automation deployment: account, managed identity, runbook, schedules.

The Automation account is created with a system-assigned managed identity and
no credential assets of any kind. The runbook authenticates with that identity
at run time, so nothing secret is ever stored in Automation, in this repository,
or in the deployment path between them.

Schedules are optional and disabled by default. A schedule that pauses a
capacity is a genuinely disruptive object to create on someone's subscription
without their explicit say-so.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from .arm import ArmError

LOGGER = logging.getLogger("fabgov.automation")

AUTOMATION_API_VERSION = "2023-11-01"

RUNBOOK_NAME = "Set-FabricCapacityState"
RUNBOOK_TYPE = "PowerShell"

SCHEDULE_RESUME_NAME = "fabric-capacity-resume"
SCHEDULE_PAUSE_NAME = "fabric-capacity-pause"


def existing_account_change_allowed(account_body, manifest, *, explicitly_allowed: bool) -> bool:
    """Whether deployment may modify a pre-existing Automation account."""
    if not account_body:
        return True
    if manifest and manifest.owns_tagged_resource(account_body):
        return True
    return bool(explicitly_allowed)


def automation_account_id(subscription_id: str, resource_group: str, account_name: str) -> str:
    return (
        "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Automation/automationAccounts/{2}".format(
            subscription_id, resource_group, account_name
        )
    )


def build_account_body(location: str, tags=None) -> dict:
    """Automation account with a system-assigned managed identity.

    ``Basic`` SKU is the standard choice; the Free SKU caps job minutes in a way
    that is easy to hit and confusing to debug.
    """
    return {
        "location": location,
        "identity": {"type": "SystemAssigned"},
        "properties": {
            "sku": {"name": "Basic"},
            # Local authentication uses Automation's own keys. The runbook needs
            # only the managed identity, so this is turned off to remove a
            # credential surface entirely.
            "disableLocalAuth": True,
            "publicNetworkAccess": True,
        },
        "tags": dict(tags or {}),
    }


def build_runbook_body(location: str, description: str = "", tags=None) -> dict:
    return {
        "location": location,
        "properties": {
            "runbookType": RUNBOOK_TYPE,
            "logVerbose": True,
            "logProgress": True,
            "description": description
            or "Pause or resume a Microsoft Fabric capacity using the Automation account's managed identity.",
            # An empty draft is created first; content is uploaded separately.
            "draft": {},
        },
        "tags": dict(tags or {}),
    }


def next_occurrence_utc(time_of_day: str, *, now=None) -> datetime:
    """Compute the next UTC instant matching ``HH:MM``, at least 5 minutes out.

    Azure Automation rejects a schedule whose start time is in the past, and is
    unreliable within a few minutes of 'now'. The returned value is a *UTC*
    instant; the schedule body carries the operator's time zone separately, and
    Azure interprets recurrence in that zone.
    """
    reference = now or datetime.now(timezone.utc)
    hour, minute = [int(part) for part in time_of_day.split(":")]
    candidate = reference.replace(hour=hour, minute=minute, second=0, microsecond=0)
    # Azure requires the start time to be comfortably in the future.
    if candidate <= reference + timedelta(minutes=5):
        candidate = candidate + timedelta(days=1)
    return candidate


def build_schedule_body(*, description: str, time_of_day: str, time_zone: str, start_time=None) -> dict:
    """A daily schedule at ``time_of_day`` in ``time_zone``.

    ``time_zone`` is required by this POC rather than defaulted. A schedule
    that pauses a capacity at 19:00 in the wrong zone pauses it in the middle
    of someone's working afternoon.
    """
    if not time_zone or not str(time_zone).strip():
        raise ValueError(
            "A time zone is required to create a schedule. Set AUTOMATION_TIME_ZONE "
            "to a value such as 'UTC' or 'Pacific Standard Time'."
        )
    start = start_time or next_occurrence_utc(time_of_day)
    return {
        "name": description,
        "properties": {
            "description": description,
            "startTime": start.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "frequency": "Day",
            "interval": 1,
            "timeZone": time_zone,
        },
    }


def build_job_schedule_body(*, runbook_name: str, schedule_name: str, parameters: dict) -> dict:
    """Link a schedule to the runbook with the parameters it should run with.

    Automation lower-cases runbook parameter names when it stores them, and
    matches them case-insensitively at run time.
    """
    return {
        "properties": {
            "schedule": {"name": schedule_name},
            "runbook": {"name": runbook_name},
            "parameters": {str(k).lower(): str(v) for k, v in (parameters or {}).items()},
        }
    }


class AutomationDeployer:
    """Creates or updates the Automation resources for the POC, idempotently."""

    def __init__(self, arm, subscription_id: str, resource_group: str, api_version=AUTOMATION_API_VERSION):
        self._arm = arm
        self._subscription_id = subscription_id
        self._resource_group = resource_group
        self._api_version = api_version

    def _params(self) -> dict:
        return {"api-version": self._api_version}

    def account_id(self, account_name: str) -> str:
        return automation_account_id(self._subscription_id, self._resource_group, account_name)

    def get_account(self, account_name: str):
        """Return the Automation account, or ``None`` when absent."""
        try:
            response = self._arm.get(self.account_id(account_name), params=self._params())
        except ArmError as exc:
            if exc.status_code == 404:
                return None
            raise
        return response.body

    def ensure_account(self, account_name: str, location: str, tags=None) -> dict:
        """Create the Automation account, or reuse an existing one.

        An existing account is deliberately NOT reconfigured beyond ensuring a
        system-assigned identity exists: it may be someone else's account
        serving other runbooks, and rewriting its SKU or network settings would
        be an unrelated change.
        """
        existing = self.get_account(account_name)
        if existing:
            identity = (existing.get("identity") or {}).get("type", "")
            principal_id = (existing.get("identity") or {}).get("principalId", "")
            if "SystemAssigned" not in str(identity):
                LOGGER.info(
                    "Automation account %s exists without a system-assigned identity; enabling it.",
                    account_name,
                )
                patched = self._arm.request(
                    "PATCH",
                    self.account_id(account_name),
                    params=self._params(),
                    body={"identity": {"type": "SystemAssigned"}},
                )
                return {"created": False, "updated": True, "account": patched.body}
            LOGGER.info(
                "Automation account %s already exists with a managed identity; reusing it.",
                account_name,
            )
            existing["_principalId"] = principal_id
            return {"created": False, "updated": False, "account": existing}

        LOGGER.info("Creating Automation account %s in %s", account_name, location)
        response = self._arm.put(
            self.account_id(account_name),
            params=self._params(),
            body=build_account_body(location, tags),
        )
        return {"created": True, "updated": False, "account": response.body}

    def managed_identity_principal_id(self, account_name: str) -> str:
        """The system-assigned identity's object id, or an empty string."""
        account = self.get_account(account_name)
        if not account:
            return ""
        return str((account.get("identity") or {}).get("principalId") or "")

    def ensure_runbook(
        self, account_name: str, runbook_name: str, content: str, location: str, tags=None
    ) -> dict:
        """Create or update the runbook and publish it.

        Automation runbooks are a three-step deployment: create the runbook
        shell, upload draft content, then publish the draft. Skipping the
        publish leaves a runbook that exists but cannot be started.
        """
        base = "{0}/runbooks/{1}".format(self.account_id(account_name), runbook_name)

        existing = None
        try:
            existing = self._arm.get(base, params=self._params()).body
        except ArmError as exc:
            if exc.status_code != 404:
                raise

        LOGGER.info("%s runbook %s", "Updating" if existing else "Creating", runbook_name)
        self._arm.put(base, params=self._params(), body=build_runbook_body(location, tags=tags))

        # Upload the PowerShell as raw text, then publish it.
        self._arm.put_text(
            "{0}/draft/content".format(base),
            content,
            params=self._params(),
            content_type="text/powershell",
        )
        publish = self._arm.post("{0}/publish".format(base), params=self._params())
        self._arm.wait_for_lro(publish, timeout_seconds=300)

        return {"created": existing is None, "runbook": runbook_name}

    def ensure_schedule(
        self, account_name: str, schedule_name: str, *, time_of_day: str, time_zone: str
    ) -> dict:
        """Create a daily schedule, reusing one that already exists."""
        url = "{0}/schedules/{1}".format(self.account_id(account_name), schedule_name)
        try:
            existing = self._arm.get(url, params=self._params()).body
            LOGGER.info("Schedule %s already exists; reusing it.", schedule_name)
            return {"created": False, "schedule": existing}
        except ArmError as exc:
            if exc.status_code != 404:
                raise

        body = build_schedule_body(description=schedule_name, time_of_day=time_of_day, time_zone=time_zone)
        response = self._arm.put(url, params=self._params(), body=body)
        LOGGER.info("Created schedule %s at %s %s", schedule_name, time_of_day, time_zone)
        return {"created": True, "schedule": response.body}

    def ensure_job_schedule(
        self, account_name: str, *, runbook_name: str, schedule_name: str, parameters: dict
    ) -> dict:
        """Link a schedule to the runbook.

        The link's name is a GUID derived deterministically from the runbook and
        schedule names, so re-running deploy does not create duplicate links.
        """
        import uuid

        link_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "{0}/{1}".format(runbook_name, schedule_name)))
        url = "{0}/jobSchedules/{1}".format(self.account_id(account_name), link_id)

        try:
            self._arm.get(url, params=self._params())
            LOGGER.info("Schedule %s is already linked to %s.", schedule_name, runbook_name)
            return {"created": False, "jobScheduleId": link_id}
        except ArmError as exc:
            if exc.status_code != 404:
                raise

        body = build_job_schedule_body(
            runbook_name=runbook_name, schedule_name=schedule_name, parameters=parameters
        )
        self._arm.put(url, params=self._params(), body=body)
        LOGGER.info("Linked schedule %s to runbook %s.", schedule_name, runbook_name)
        return {"created": True, "jobScheduleId": link_id}
