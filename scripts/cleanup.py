#!/usr/bin/env python3
"""Remove resources this POC created. Dry run by default.

Two independent gates protect every deletion:

1. ``ALLOW_POC_RESOURCE_DELETION=true`` must be set. Without it this script only
   ever reports what it would do.
2. The ignored manifest must contain the exact resource ID. Tagged resources
   must also carry the matching purpose, manager, and random deployment tags.
   An unproven Fabric capacity is treated as someone else's and is never
   deleted, whatever the flags say.

A POC-created capacity that is not deleted is PAUSED instead, so that declining
to delete never leaves a billing resource running.

    python scripts/cleanup.py              # dry run
    python scripts/cleanup.py --confirm    # delete, if the env flag also allows it
"""

from __future__ import annotations

import argparse
import sys

from _bootstrap import configure_logging, fail, resolve_env_file, resolve_subscription_id  # noqa: E402
from fabgov.arm import ArmClient, ArmError, default_token_provider  # noqa: E402
from fabgov.automation import AUTOMATION_API_VERSION, automation_account_id  # noqa: E402
from fabgov.capacity import POC_PURPOSE_TAG, CapacityClient  # noqa: E402
from fabgov.config import ConfigError, load_config  # noqa: E402
from fabgov.policy import POLICY_DEFINITION_NAME, policy_definition_id  # noqa: E402
from fabgov.provenance import DeploymentManifest  # noqa: E402
from fabgov.rbac import ROLE_NAME  # noqa: E402

AUTHORIZATION_API_VERSION = "2022-04-01"
POLICY_API_VERSION = "2023-04-01"
POLICY_ASSIGNMENT_NAME = "fabric-allowed-skus-poc"


class Plan:
    """A list of intended actions, printed before anything happens."""

    def __init__(self):
        self.items = []

    def add(self, action: str, target: str, *, eligible: bool, reason: str = "") -> None:
        self.items.append({"action": action, "target": target, "eligible": eligible, "reason": reason})

    def render(self, *, will_execute: bool) -> None:
        print("")
        print("Cleanup plan")
        print("=" * 78)
        if not self.items:
            print("  Nothing found that belongs to this POC.")
        for item in self.items:
            marker = "DELETE" if item["eligible"] else "KEEP  "
            print("  [{0}] {1}: {2}".format(marker, item["action"], item["target"]))
            if item["reason"]:
                print("           {0}".format(item["reason"]))
        print("=" * 78)
        eligible = [i for i in self.items if i["eligible"]]
        print(
            "  {0} item(s) eligible for deletion, {1} protected.".format(
                len(eligible), len(self.items) - len(eligible)
            )
        )
        print("  Mode: {0}".format("EXECUTING" if will_execute else "DRY RUN - nothing will change"))
        print("")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cleanup.py",
        description="Remove POC-created resources. Dry run unless --confirm and the env flag are set.",
    )
    parser.add_argument("--env-file", default=".env", help="Path to the .env file.")
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Actually delete. Also requires ALLOW_POC_RESOURCE_DELETION=true.",
    )
    parser.add_argument(
        "--keep-capacity",
        action="store_true",
        help="Never delete the capacity; pause it instead.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)

    try:
        config = load_config(resolve_env_file(args.env_file))
    except ConfigError as exc:
        fail(str(exc))
        return 1

    subscription_id = resolve_subscription_id(config.subscription_id)
    if not subscription_id:
        fail("No subscription id. Set AZURE_SUBSCRIPTION_ID or run `az login`.")
        return 1

    will_execute = bool(args.confirm and config.allow_poc_resource_deletion)
    if args.confirm and not config.allow_poc_resource_deletion:
        print("")
        print("  --confirm was passed but ALLOW_POC_RESOURCE_DELETION=false.")
        print("  Continuing as a DRY RUN. Both are required to delete anything.")
        print("")

    arm = ArmClient(default_token_provider())
    capacity_client = CapacityClient(arm, subscription_id)
    manifest = DeploymentManifest.load()
    plan = Plan()

    if manifest is None:
        print("")
        print("  No ignored deployment manifest was found. Nothing is eligible for deletion.")
        print("  Tags alone are not accepted as proof that this POC created a resource.")
        print("")

    # ---- capacity --------------------------------------------------------
    capacity = None
    if config.capacity_name and config.resource_group:
        try:
            capacity = capacity_client.get(config.resource_group, config.capacity_name)
        except ArmError as exc:
            print("  Could not read the capacity: {0}".format(str(exc)[:150]))

    if capacity is None:
        plan.add(
            "Fabric capacity",
            config.capacity_name or "(none configured)",
            eligible=False,
            reason="Not found; nothing to do.",
        )
    elif not manifest or not manifest.owns_tagged_resource(capacity.raw):
        plan.add(
            "Fabric capacity",
            capacity.name,
            eligible=False,
            reason="PROTECTED: exact manifest record and matching ownership tags are required.",
        )
    elif args.keep_capacity:
        plan.add(
            "Fabric capacity",
            capacity.name,
            eligible=False,
            reason="--keep-capacity passed; it will be paused instead.",
        )
    else:
        plan.add(
            "Fabric capacity",
            capacity.name,
            eligible=True,
            reason="Tagged purpose={0}; created by this POC.".format(POC_PURPOSE_TAG),
        )

    # ---- automation account ---------------------------------------------
    automation_body = None
    if config.automation_account_name:
        account_url = automation_account_id(
            subscription_id, config.resource_group, config.automation_account_name
        )
        try:
            automation_body = arm.get(account_url, params={"api-version": AUTOMATION_API_VERSION}).body
        except ArmError as exc:
            if exc.status_code != 404:
                print("  Could not read the Automation account: {0}".format(str(exc)[:150]))

        if automation_body is None:
            plan.add(
                "Automation account", config.automation_account_name, eligible=False, reason="Not found."
            )
        elif not manifest or not manifest.owns_tagged_resource(automation_body):
            plan.add(
                "Automation account",
                config.automation_account_name,
                eligible=False,
                reason="PROTECTED: exact manifest record and matching ownership tags are required.",
            )
        else:
            plan.add(
                "Automation account",
                config.automation_account_name,
                eligible=True,
                reason="Tagged as POC-created.",
            )

    # ---- policy assignment and definition -------------------------------
    assignment_id = "{0}/providers/Microsoft.Authorization/policyAssignments/{1}".format(
        config.resource_group_scope, POLICY_ASSIGNMENT_NAME
    )
    assignment_exists = False
    try:
        arm.get(assignment_id, params={"api-version": POLICY_API_VERSION})
        assignment_exists = True
    except ArmError:
        pass
    plan.add(
        "Policy assignment",
        POLICY_ASSIGNMENT_NAME,
        eligible=bool(assignment_exists and manifest and manifest.contains(assignment_id)),
        reason=(
            "Recorded in this POC manifest."
            if assignment_exists and manifest and manifest.contains(assignment_id)
            else "Not found or ownership is unproven."
        ),
    )

    definition_id = policy_definition_id(subscription_id, POLICY_DEFINITION_NAME)
    definition_exists = False
    try:
        arm.get(definition_id, params={"api-version": POLICY_API_VERSION})
        definition_exists = True
    except ArmError:
        pass
    plan.add(
        "Policy definition",
        POLICY_DEFINITION_NAME,
        eligible=bool(definition_exists and manifest and manifest.contains(definition_id)),
        reason=(
            "Recorded in this POC manifest."
            if definition_exists and manifest and manifest.contains(definition_id)
            else "Not found or ownership is unproven."
        ),
    )

    # ---- custom role definition -----------------------------------------
    role_id = ""
    try:
        response = arm.get(
            "/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions".format(subscription_id),
            params={"api-version": AUTHORIZATION_API_VERSION, "$filter": "type eq 'CustomRole'"},
        )
        for item in response.body.get("value", []):
            if (item.get("properties") or {}).get("roleName") == ROLE_NAME:
                role_id = item["id"]
                break
    except ArmError:
        pass
    plan.add(
        "Custom role definition",
        ROLE_NAME,
        eligible=bool(role_id and manifest and manifest.contains(role_id)),
        reason=(
            "Recorded in this POC manifest."
            if role_id and manifest and manifest.contains(role_id)
            else "Not found or ownership is unproven."
        ),
    )

    role_assignment_ids = []
    if manifest and config.resource_group and config.capacity_name:
        required_prefix = (
            config.capacity_resource_id + "/providers/Microsoft.Authorization/roleAssignments/"
        ).lower()
        role_assignment_ids = manifest.resource_ids(kind="role-assignment", prefix=required_prefix)
    for index, _role_assignment_id in enumerate(role_assignment_ids, start=1):
        plan.add(
            "Capacity role assignment {0}".format(index),
            "manifest-recorded assignment",
            eligible=True,
            reason="Exact capacity-scoped ID recorded in this POC manifest.",
        )

    plan.render(will_execute=will_execute)

    if not will_execute:
        print("  To delete: set ALLOW_POC_RESOURCE_DELETION=true in .env and pass --confirm.")
        print("")
        return 0

    # ---- execute ---------------------------------------------------------
    deleted, failed = [], []

    if assignment_exists and manifest and manifest.contains(assignment_id):
        _try_delete(arm, assignment_id, POLICY_API_VERSION, "policy assignment", deleted, failed)
    if definition_exists and manifest and manifest.contains(definition_id):
        _try_delete(arm, definition_id, POLICY_API_VERSION, "policy definition", deleted, failed)
    for index, role_assignment_id in enumerate(role_assignment_ids, start=1):
        _try_delete(
            arm,
            role_assignment_id,
            AUTHORIZATION_API_VERSION,
            "capacity role assignment {0}".format(index),
            deleted,
            failed,
        )
    if role_id and manifest and manifest.contains(role_id):
        _try_delete(arm, role_id, AUTHORIZATION_API_VERSION, "custom role definition", deleted, failed)

    if automation_body is not None and manifest and manifest.owns_tagged_resource(automation_body):
        _try_delete(
            arm,
            automation_account_id(subscription_id, config.resource_group, config.automation_account_name),
            AUTOMATION_API_VERSION,
            "automation account",
            deleted,
            failed,
        )

    if (
        capacity is not None
        and manifest
        and manifest.owns_tagged_resource(capacity.raw)
        and not args.keep_capacity
    ):
        try:
            capacity_client.delete(config.resource_group, capacity.name)
            deleted.append("Fabric capacity {0}".format(capacity.name))
            capacity = None
        except ArmError as exc:
            failed.append("Fabric capacity {0}: {1}".format(capacity.name, str(exc)[:150]))

    _pause_if_needed(capacity_client, config, capacity)

    print("")
    print("Cleanup complete")
    print("-" * 78)
    for item in deleted:
        print("  DELETED: {0}".format(item))
    for item in failed:
        print("  FAILED:  {0}".format(item))
    if not deleted and not failed:
        print("  Nothing was deleted.")
    print("")
    return 1 if failed else 0


def _try_delete(arm, resource_id, api_version, label, deleted, failed) -> None:
    try:
        arm.delete(resource_id, params={"api-version": api_version})
        deleted.append(label)
    except ArmError as exc:
        failed.append("{0}: {1}".format(label, str(exc)[:150]))


def _pause_if_needed(capacity_client, config, capacity) -> None:
    """Pause a surviving POC-created capacity so it stops billing."""
    manifest = DeploymentManifest.load()
    if capacity is None or not manifest or not manifest.owns_tagged_resource(capacity.raw):
        return
    try:
        current = capacity_client.get(config.resource_group, capacity.name)
        if current is None or current.is_paused or current.is_in_flight:
            return
        print("  POC capacity '{0}' is {1}; pausing it to stop billing.".format(capacity.name, current.state))
        capacity_client.pause(config.resource_group, capacity.name)
        print("  Paused.")
    except ArmError as exc:
        print("  WARNING: could not pause '{0}': {1}".format(capacity.name, str(exc)[:150]))


if __name__ == "__main__":
    sys.exit(main())
