#!/usr/bin/env python3
"""Unified deployment entry point for the Fabric Capacity Governance POC.

Runs the full provisioning sequence, idempotently. Every step reports PASS,
SKIPPED, or NOT VALIDATED, and every step that could change or create an Azure
resource is gated behind an explicit safety flag.

    python scripts/deploy.py                 # deploy per .env
    python scripts/deploy.py --dry-run       # show the plan, change nothing
    python scripts/deploy.py --skip-policy   # deploy everything except policy

Nothing here deletes anything. Deletion lives in scripts/cleanup.py.
"""

from __future__ import annotations

import argparse
import sys
import uuid

from _bootstrap import (  # noqa: E402
    REPO_ROOT,
    configure_logging,
    fail,
    resolve_env_file,
    resolve_subscription_id,
)
from fabgov.arm import ArmClient, ArmError, default_token_provider  # noqa: E402
from fabgov.automation import (  # noqa: E402
    RUNBOOK_NAME,
    SCHEDULE_PAUSE_NAME,
    SCHEDULE_RESUME_NAME,
    AutomationDeployer,
    existing_account_change_allowed,
)
from fabgov.capacity import CapacityClient  # noqa: E402
from fabgov.config import ConfigError, load_config  # noqa: E402
from fabgov.policy import (  # noqa: E402
    POLICY_DEFINITION_NAME,
    AliasNotFoundError,
    build_policy_assignment,
    build_policy_definition,
    definitions_equivalent,
    extract_capacity_aliases,
    policy_definition_id,
    verify_sku_alias,
)
from fabgov.provenance import DeploymentManifest  # noqa: E402
from fabgov.rbac import ROLE_NAME, build_role_definition, role_actions  # noqa: E402
from fabgov.results import ResultRecorder  # noqa: E402

RESOURCE_API_VERSION = "2021-04-01"
POLICY_API_VERSION = "2023-04-01"
AUTHORIZATION_API_VERSION = "2022-04-01"
POLICY_ASSIGNMENT_NAME = "fabric-allowed-skus-poc"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deploy.py",
        description="Provision the Fabric Capacity Governance POC resources.",
    )
    parser.add_argument("--env-file", default=".env", help="Path to the .env file.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the plan without creating or changing anything.",
    )
    parser.add_argument("--skip-automation", action="store_true", help="Skip the Automation POC.")
    parser.add_argument("--skip-rbac", action="store_true", help="Skip the RBAC POC.")
    parser.add_argument("--skip-policy", action="store_true", help="Skip the Azure Policy POC.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return parser


def ensure_resource_group(arm, subscription_id, name, location, tags, *, dry_run):
    """Create the POC resource group if it does not already exist."""
    url = "/subscriptions/{0}/resourceGroups/{1}".format(subscription_id, name)
    params = {"api-version": RESOURCE_API_VERSION}
    try:
        body = arm.get(url, params=params).body
        return {
            "created": False,
            "location": body.get("location", ""),
            "existing": True,
            "id": body.get("id", url),
            "body": body,
        }
    except ArmError as exc:
        if exc.status_code != 404:
            raise
    if dry_run:
        return {"created": False, "planned": True, "existing": False, "id": url}
    body = arm.put(url, params=params, body={"location": location, "tags": dict(tags)}).body
    return {
        "created": True,
        "location": body.get("location", ""),
        "existing": False,
        "id": body.get("id", url),
        "body": body,
    }


def deploy_capacity(arm, config, subscription_id, recorder, manifest, *, dry_run):
    """Resolve or create the target Fabric capacity.

    Returns ``(CapacityInfo | None, poc_created: bool)``.
    """
    client = CapacityClient(arm, subscription_id)
    existing = client.get(config.resource_group, config.capacity_name)

    if existing is not None:
        owned = bool(manifest and manifest.owns_tagged_resource(existing.raw))
        recorder.record_pass(
            "Capacity resolved",
            details={
                "mode": config.capacity_mode,
                "sku": existing.sku_name,
                "state": existing.state,
                "createdByPoc": owned,
            },
        )
        return existing, owned

    if config.capacity_mode != "create":
        recorder.record_fail(
            "Capacity resolved",
            "CAPACITY_MODE=existing but capacity '{0}' was not found in resource group '{1}'.".format(
                config.capacity_name, config.resource_group
            ),
        )
        return None, False

    if not config.allow_capacity_creation:
        recorder.record_skipped(
            "Capacity created",
            "ALLOW_CAPACITY_CREATION=false. Set it to true to create a {0} capacity named '{1}'.".format(
                config.fabric_sku, config.capacity_name
            ),
        )
        return None, False

    if dry_run:
        recorder.record_skipped(
            "Capacity created",
            "Dry run. Would create {0} capacity '{1}' in {2}.".format(
                config.fabric_sku, config.capacity_name, config.location
            ),
        )
        return None, False

    created = client.create(
        config.resource_group,
        config.capacity_name,
        location=config.location,
        sku=config.fabric_sku,
        administrators=[config.capacity_admin],
        tags=manifest.tags,
    )
    manifest.record(created.id, "fabric-capacity")
    recorder.record_pass(
        "Capacity created",
        details={"sku": created.sku_name, "state": created.state, "location": created.location},
    )
    return created, True


def deploy_automation(arm, config, subscription_id, recorder, manifest, *, dry_run):
    """Create the Automation account, managed identity, runbook, and schedules."""
    if not config.automation_account_name:
        recorder.record_skipped("Automation account", "AUTOMATION_ACCOUNT_NAME is not set.")
        return {}

    deployer = AutomationDeployer(arm, subscription_id, config.resource_group)
    existing_account = deployer.get_account(config.automation_account_name)
    existing_owned = bool(existing_account and manifest and manifest.owns_tagged_resource(existing_account))
    if not existing_account_change_allowed(
        existing_account,
        manifest,
        explicitly_allowed=config.allow_existing_automation_modification,
    ):
        recorder.record_not_validated(
            "Automation account",
            "An Automation account with this name already exists, but this deployment's "
            "manifest and tags do not prove ownership. Refusing to enable an identity or "
            "overwrite a runbook. Set ALLOW_EXISTING_AUTOMATION_MODIFICATION=true only "
            "after reviewing that shared account.",
        )
        return {}

    if dry_run:
        recorder.record_skipped(
            "Automation account",
            "Dry run. Would ensure account '{0}' with a system-assigned managed identity, "
            "publish runbook '{1}', and {2} schedules.".format(
                config.automation_account_name,
                RUNBOOK_NAME,
                "create" if config.enable_schedules else "skip",
            ),
            details={
                "accountExists": existing_account is not None,
                "ownershipProven": existing_owned,
                "existingModificationExplicitlyAllowed": (config.allow_existing_automation_modification),
            },
        )
        return {}

    account_result = deployer.ensure_account(
        config.automation_account_name, config.location or "", tags=manifest.tags
    )
    account_body = account_result.get("account") or {}
    if account_result["created"] and account_body.get("id"):
        manifest.record(account_body["id"], "automation-account")
    recorder.record_pass(
        "Automation account",
        details={
            "name": config.automation_account_name,
            "created": account_result["created"],
            "reused": not account_result["created"],
        },
    )

    principal_id = deployer.managed_identity_principal_id(config.automation_account_name)
    if principal_id:
        recorder.record_pass(
            "Managed identity", details={"type": "SystemAssigned", "principalIdPresent": True}
        )
    else:
        recorder.record_fail(
            "Managed identity",
            "The Automation account has no system-assigned identity principal id.",
        )

    runbook_path = REPO_ROOT / "automation" / "Set-FabricCapacityState.ps1"
    if not runbook_path.is_file():
        recorder.record_fail("Runbook published", "Runbook file not found at {0}".format(runbook_path))
    else:
        content = runbook_path.read_text(encoding="utf-8")
        result = deployer.ensure_runbook(
            config.automation_account_name,
            RUNBOOK_NAME,
            content,
            config.location or "",
            tags=manifest.tags,
        )
        recorder.record_pass(
            "Runbook published",
            details={"runbook": RUNBOOK_NAME, "created": result["created"], "bytes": len(content)},
        )

    if not config.enable_schedules:
        recorder.record_skipped(
            "Schedules",
            "ENABLE_SCHEDULES=false. Set it to true (with AUTOMATION_TIME_ZONE) to create "
            "the daily resume/pause schedules.",
        )
    else:
        parameters_common = {
            "SubscriptionId": subscription_id,
            "ResourceGroupName": config.resource_group,
            "CapacityName": config.capacity_name,
        }
        for schedule_name, time_of_day, desired in (
            (SCHEDULE_RESUME_NAME, config.resume_time, "Resume"),
            (SCHEDULE_PAUSE_NAME, config.pause_time, "Pause"),
        ):
            deployer.ensure_schedule(
                config.automation_account_name,
                schedule_name,
                time_of_day=time_of_day,
                time_zone=config.automation_time_zone,
            )
            params = dict(parameters_common)
            params["DesiredState"] = desired
            deployer.ensure_job_schedule(
                config.automation_account_name,
                runbook_name=RUNBOOK_NAME,
                schedule_name=schedule_name,
                parameters=params,
            )
        recorder.record_pass(
            "Schedules",
            details={
                "resume": "{0} {1}".format(config.resume_time, config.automation_time_zone),
                "pause": "{0} {1}".format(config.pause_time, config.automation_time_zone),
            },
        )

    return {"principalId": principal_id}


def find_role_definition(arm, scope, role_name):
    """Look up a custom role definition by display name at a scope."""
    response = arm.get(
        "{0}/providers/Microsoft.Authorization/roleDefinitions".format(scope),
        params={
            "api-version": AUTHORIZATION_API_VERSION,
            "$filter": "type eq 'CustomRole'",
        },
    )
    for item in response.body.get("value", []):
        if (item.get("properties") or {}).get("roleName") == role_name:
            return item
    return None


def deploy_rbac(arm, config, subscription_id, recorder, manifest, *, automation_principal_id="", dry_run):
    """Create the custom lifecycle role and optionally assign it."""
    scope = "/subscriptions/{0}".format(subscription_id)
    desired = build_role_definition(subscription_id=subscription_id)

    if dry_run:
        recorder.record_skipped(
            "Custom role definition",
            "Dry run. Would ensure role '{0}' with actions: {1}".format(ROLE_NAME, ", ".join(role_actions())),
        )
        return {}

    existing = find_role_definition(arm, scope, ROLE_NAME)
    if existing:
        role_id = existing["id"]
        existing_actions = sorted(
            (existing.get("properties") or {}).get("permissions", [{}])[0].get("actions", [])
        )
        if existing_actions == sorted(role_actions()):
            recorder.record_pass(
                "Custom role definition",
                details={"role": ROLE_NAME, "created": False, "reused": True},
            )
        elif manifest.contains(role_id):
            arm.put(role_id, params={"api-version": AUTHORIZATION_API_VERSION}, body=desired)
            recorder.record_pass(
                "Custom role definition",
                details={"role": ROLE_NAME, "created": False, "updated": True},
            )
        else:
            recorder.record_fail(
                "Custom role definition",
                "A custom role with this public name exists but is not recorded in this "
                "deployment manifest and has different permissions. Refusing to overwrite it.",
            )
            return {}
    else:
        role_guid = str(uuid.uuid4())
        role_id = "{0}/providers/Microsoft.Authorization/roleDefinitions/{1}".format(scope, role_guid)
        arm.put(role_id, params={"api-version": AUTHORIZATION_API_VERSION}, body=desired)
        manifest.record(role_id, "custom-role-definition")
        recorder.record_pass("Custom role definition", details={"role": ROLE_NAME, "created": True})

    # ---- scoped assignments ---------------------------------------------
    principals = []
    if automation_principal_id:
        principals.append((automation_principal_id, "ServicePrincipal", "Automation managed identity"))
    if config.test_principal_object_id:
        principals.append((config.test_principal_object_id, config.test_principal_type, "Test principal"))

    if not principals:
        recorder.record_skipped(
            "Role assignment",
            "TEST_PRINCIPAL_OBJECT_ID is not set. This POC does not create identities. "
            "See rbac/README.md for the assignment commands.",
        )
        return {"roleDefinitionId": role_id}

    capacity_scope = config.capacity_resource_id
    for principal_id, principal_type, label in principals:
        assignment_guid = str(uuid.uuid5(uuid.NAMESPACE_URL, capacity_scope + principal_id + role_id))
        assignment_id = "{0}/providers/Microsoft.Authorization/roleAssignments/{1}".format(
            capacity_scope, assignment_guid
        )
        body = {
            "properties": {
                "roleDefinitionId": role_id,
                "principalId": principal_id,
                "principalType": principal_type,
            }
        }
        try:
            arm.put(assignment_id, params={"api-version": AUTHORIZATION_API_VERSION}, body=body)
            manifest.record(assignment_id, "role-assignment")
            recorder.record_pass(
                "Role assignment - {0}".format(label),
                details={"scope": "individual capacity", "role": ROLE_NAME},
            )
        except ArmError as exc:
            if exc.error_code == "RoleAssignmentExists":
                recorder.record_pass(
                    "Role assignment - {0}".format(label),
                    details={"scope": "individual capacity", "reused": True},
                )
            else:
                recorder.record_fail("Role assignment - {0}".format(label), str(exc)[:250])

    return {"roleDefinitionId": role_id}


def deploy_policy(arm, config, subscription_id, recorder, manifest, *, dry_run):
    """Discover the SKU alias, then create and optionally assign the policy.

    A missing alias is fatal for this step and reported as NOT VALIDATED. It is
    never worked around.
    """
    try:
        provider = arm.get(
            "/subscriptions/{0}/providers/Microsoft.Fabric".format(subscription_id),
            params={"api-version": RESOURCE_API_VERSION, "$expand": "resourceTypes/aliases"},
        ).body
        aliases = extract_capacity_aliases(provider)
    except ArmError as exc:
        recorder.record_not_validated("Policy alias discovery", str(exc)[:250])
        return {}

    try:
        alias = verify_sku_alias(aliases)
    except AliasNotFoundError as exc:
        recorder.record_not_validated(
            "Policy alias discovery",
            "No Fabric SKU alias exists. SKU restriction by Azure Policy cannot be "
            "implemented. Detail: {0}".format(str(exc)[:400]),
            details={"aliasesFound": [a["name"] for a in aliases]},
        )
        return {}

    alias_name = alias["name"]
    recorder.record_pass(
        "Policy alias discovery",
        details={"alias": alias_name, "defaultPath": alias.get("defaultPath", "")},
    )

    definition = build_policy_definition(
        alias_name,
        allowed_skus=config.allowed_fabric_skus,
        default_effect=config.policy_effect,
    )
    definition_id = policy_definition_id(subscription_id, POLICY_DEFINITION_NAME)

    if dry_run:
        recorder.record_skipped(
            "Policy definition",
            "Dry run. Would create definition '{0}' allowing {1}.".format(
                POLICY_DEFINITION_NAME, ", ".join(config.allowed_fabric_skus)
            ),
        )
        return {"alias": alias_name}

    params = {"api-version": POLICY_API_VERSION}
    existing = None
    try:
        existing = arm.get(definition_id, params=params).body
    except ArmError as exc:
        if exc.status_code != 404:
            raise

    if existing and definitions_equivalent(existing, definition):
        recorder.record_pass("Policy definition", details={"name": POLICY_DEFINITION_NAME, "reused": True})
    elif existing and not manifest.contains(definition_id):
        recorder.record_fail(
            "Policy definition",
            "A policy with this public name exists but is not in the deployment manifest "
            "and differs from the requested policy. Refusing to overwrite it.",
        )
        return {"alias": alias_name}
    else:
        arm.put(definition_id, params=params, body=definition)
        manifest.record(definition_id, "policy-definition")
        recorder.record_pass(
            "Policy definition",
            details={
                "name": POLICY_DEFINITION_NAME,
                "created": existing is None,
                "updated": existing is not None,
                "alias": alias_name,
            },
        )

    # ---- assignment (resource group scope only) --------------------------
    assignment_scope = config.resource_group_scope
    assignment_id = "{0}/providers/Microsoft.Authorization/policyAssignments/{1}".format(
        assignment_scope, POLICY_ASSIGNMENT_NAME
    )
    assignment = build_policy_assignment(
        policy_definition_id=definition_id,
        display_name="Fabric Capacity Governance POC - allowed SKUs",
        allowed_skus=config.allowed_fabric_skus,
        effect=config.policy_effect,
    )

    try:
        assignment_existing = None
        try:
            assignment_existing = arm.get(assignment_id, params=params).body
        except ArmError as read_exc:
            if read_exc.status_code != 404:
                raise
        if assignment_existing and not manifest.contains(assignment_id):
            recorder.record_fail(
                "Policy assignment",
                "An assignment with this name exists but is not recorded in the deployment "
                "manifest. Refusing to overwrite it.",
            )
            return {"alias": alias_name, "definitionId": definition_id}
        arm.put(assignment_id, params=params, body=assignment)
        manifest.record(assignment_id, "policy-assignment")
        recorder.record_pass(
            "Policy assignment",
            details={
                "scope": "resource group",
                "effect": config.policy_effect,
                "allowedSkus": config.allowed_fabric_skus,
            },
        )
    except ArmError as exc:
        recorder.record_fail("Policy assignment", str(exc)[:250])

    return {"alias": alias_name, "definitionId": definition_id, "assignmentId": assignment_id}


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
    if not config.resource_group:
        fail("RESOURCE_GROUP_NAME is required.")
        return 1

    recorder = ResultRecorder("deploy")
    recorder.metadata = {
        "capacityMode": config.capacity_mode,
        "dryRun": args.dry_run,
        "policyEffect": config.policy_effect,
        "allowedSkus": config.allowed_fabric_skus,
        "safetyFlags": {
            "allowCapacityCreation": config.allow_capacity_creation,
            "allowExistingCapacityStateChange": config.allow_existing_capacity_state_change,
            "allowPocResourceDeletion": config.allow_poc_resource_deletion,
            "enableSchedules": config.enable_schedules,
        },
    }

    if args.dry_run:
        print("")
        print("  DRY RUN - no Azure resource will be created or modified.")
        print("")

    arm = ArmClient(default_token_provider())
    manifest = DeploymentManifest.load_or_create(persist=not args.dry_run)
    resource_tags = manifest.tags

    # ---- resource group --------------------------------------------------
    try:
        rg = ensure_resource_group(
            arm,
            subscription_id,
            config.resource_group,
            config.location,
            resource_tags,
            dry_run=args.dry_run,
        )
        if rg.get("created"):
            manifest.record(rg["id"], "resource-group")
        recorder.record_pass(
            "Resource group",
            details={
                "name": config.resource_group,
                "created": rg.get("created", False),
                "reused": rg.get("existing", False),
            },
        )
    except ArmError as exc:
        recorder.record_fail("Resource group", str(exc)[:250])
        recorder.print_summary()
        recorder.write()
        return 1

    # ---- capacity --------------------------------------------------------
    try:
        capacity, poc_created = deploy_capacity(
            arm, config, subscription_id, recorder, manifest, dry_run=args.dry_run
        )
    except ArmError as exc:
        recorder.record_fail("Capacity", str(exc)[:250])
        capacity, poc_created = None, False

    recorder.metadata["capacityCreatedByPoc"] = poc_created

    # ---- automation ------------------------------------------------------
    automation_result = {}
    if config.enable_automation and not args.skip_automation:
        try:
            automation_result = deploy_automation(
                arm, config, subscription_id, recorder, manifest, dry_run=args.dry_run
            )
        except ArmError as exc:
            recorder.record_fail("Automation", str(exc)[:250])
    else:
        recorder.record_skipped("Automation", "Disabled by configuration or --skip-automation.")

    # ---- rbac ------------------------------------------------------------
    if config.enable_rbac_poc and not args.skip_rbac:
        try:
            deploy_rbac(
                arm,
                config,
                subscription_id,
                recorder,
                manifest,
                automation_principal_id=automation_result.get("principalId", ""),
                dry_run=args.dry_run,
            )
        except ArmError as exc:
            recorder.record_fail("RBAC", str(exc)[:250])
    else:
        recorder.record_skipped("RBAC", "Disabled by configuration or --skip-rbac.")

    # ---- policy ----------------------------------------------------------
    if config.enable_policy_poc and not args.skip_policy:
        try:
            deploy_policy(arm, config, subscription_id, recorder, manifest, dry_run=args.dry_run)
        except ArmError as exc:
            recorder.record_fail("Policy", str(exc)[:250])
    else:
        recorder.record_skipped("Policy", "Disabled by configuration or --skip-policy.")

    recorder.print_summary()
    path = recorder.write("deploy-latest.json")
    print("  Results: {0} (gitignored)".format(path))
    print("")

    if capacity is not None and poc_created:
        print("  NOTE: this POC created a Fabric capacity. It bills while Active.")
        print("        Run `python scripts/capacity.py pause` when you are done,")
        print("        or `python scripts/validate.py` which leaves it paused.")
        print("")

    return 1 if recorder.has_failures else 0


if __name__ == "__main__":
    sys.exit(main())
