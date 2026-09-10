#!/usr/bin/env python3
"""Validate the three governance controls and record evidence.

This is the script that produces the material for docs/POC_FINDINGS.md. It is
deliberately conservative about what it claims: any test it cannot actually
perform is recorded as NOT VALIDATED with the reason, never quietly omitted and
never upgraded to a pass.

    python scripts/validate.py                    # run everything permitted
    python scripts/validate.py --only pause-resume
    python scripts/validate.py --policy-negative-test

Safety:
  * The pause/resume test runs against an existing capacity only when
    ALLOW_EXISTING_CAPACITY_STATE_CHANGE=true. It always restores the original
    state afterwards.
  * A capacity this POC created is left PAUSED on exit, to stop billing.
  * The policy negative test attempts to CREATE a capacity with a disallowed
    SKU and expects Azure to refuse. It never resizes an existing capacity.
"""

from __future__ import annotations

import argparse
import sys
import time

from _bootstrap import configure_logging, fail, resolve_env_file, resolve_subscription_id  # noqa: E402
from fabgov.arm import ArmClient, ArmError, default_token_provider  # noqa: E402
from fabgov.capacity import CapacityClient, build_create_body  # noqa: E402
from fabgov.config import FABRIC_API_VERSION, ConfigError, load_config  # noqa: E402
from fabgov.policy import (  # noqa: E402
    POLICY_DEFINITION_NAME,
    build_negative_test_identity,
    policy_definition_id,
)
from fabgov.provenance import DeploymentManifest  # noqa: E402
from fabgov.rbac import ROLE_NAME, role_actions  # noqa: E402
from fabgov.results import ResultRecorder  # noqa: E402

AUTHORIZATION_API_VERSION = "2022-04-01"
POLICY_API_VERSION = "2023-04-01"
POLICY_INSIGHTS_API_VERSION = "2019-10-01"

# A SKU far outside any sensible POC allow-list, used for the negative test.
DISALLOWED_TEST_SKU = "F64"
ALL_SUITES = ("pause-resume", "rbac", "policy")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validate.py",
        description="Test the pause/resume, RBAC, and SKU policy controls.",
    )
    parser.add_argument("--env-file", default=".env", help="Path to the .env file.")
    parser.add_argument(
        "--only",
        choices=ALL_SUITES,
        action="append",
        default=None,
        help="Run only the named suite (repeatable).",
    )
    parser.add_argument(
        "--policy-negative-test",
        action="store_true",
        help=(
            "Attempt to create a capacity with a disallowed SKU and assert Azure refuses it. "
            "Only meaningful when the policy assignment effect is Deny."
        ),
    )
    parser.add_argument(
        "--skip-restore",
        action="store_true",
        help="Do not restore the capacity's original state after the pause/resume test.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return parser


# ---------------------------------------------------------------------------
# Suite 1: pause / resume
# ---------------------------------------------------------------------------


def validate_pause_resume(client, config, recorder, manifest, *, restore: bool) -> None:
    """Full pause -> verify -> resume -> verify cycle, restoring original state."""
    info = client.get(config.resource_group, config.capacity_name)
    if info is None:
        recorder.record_fail(
            "Capacity readable",
            "Capacity '{0}' not found in '{1}'.".format(config.capacity_name, config.resource_group),
        )
        return

    poc_owned = bool(manifest and manifest.owns_tagged_resource(info.raw))
    recorder.record_pass(
        "Capacity readable",
        details={"sku": info.sku_name, "state": info.state, "createdByPoc": poc_owned},
    )

    original_state = info.normalized_state
    authorized = poc_owned or config.allow_existing_capacity_state_change

    if not authorized:
        recorder.record_not_validated(
            "Pause API",
            "Capacity was not created by this POC and ALLOW_EXISTING_CAPACITY_STATE_CHANGE=false. "
            "Read-only validation only; no state change was attempted.",
        )
        recorder.record_not_validated(
            "Resume API",
            "Not attempted for the same reason as the pause test.",
        )
        return

    if info.is_in_flight:
        recorder.record_not_validated(
            "Pause API",
            "Capacity is '{0}' - an operation is already in flight.".format(info.state),
        )
        return

    # Drive to Active first so that pause is a real transition to observe.
    if original_state == "paused":
        recorder.record_pass("Initial state", details={"state": info.state, "note": "Starting from paused."})
        resumed = client.resume(config.resource_group, config.capacity_name)
        if resumed.get("reachedDesiredState"):
            recorder.record_pass("Resume API", details=_state_detail(resumed))
        else:
            recorder.record_fail(
                "Resume API", "Capacity did not reach Active.", details=_state_detail(resumed)
            )
            return
        paused = client.pause(config.resource_group, config.capacity_name)
        if paused.get("reachedDesiredState"):
            recorder.record_pass("Pause API", details=_state_detail(paused))
            recorder.record_pass("Paused state verified", details={"state": paused["stateAfter"]})
        else:
            recorder.record_fail("Pause API", "Capacity did not reach Paused.", details=_state_detail(paused))
    else:
        recorder.record_pass("Initial state", details={"state": info.state})
        paused = client.pause(config.resource_group, config.capacity_name)
        if paused.get("reachedDesiredState"):
            recorder.record_pass("Pause API", details=_state_detail(paused))
            recorder.record_pass("Paused state verified", details={"state": paused["stateAfter"]})
        else:
            recorder.record_fail("Pause API", "Capacity did not reach Paused.", details=_state_detail(paused))
            return

        resumed = client.resume(config.resource_group, config.capacity_name)
        if resumed.get("reachedDesiredState"):
            recorder.record_pass("Resume API", details=_state_detail(resumed))
            recorder.record_pass("Active state verified", details={"state": resumed["stateAfter"]})
        else:
            recorder.record_fail(
                "Resume API", "Capacity did not reach Active.", details=_state_detail(resumed)
            )

    # Idempotency: a second identical request must be a no-op.
    current = client.get(config.resource_group, config.capacity_name)
    repeat_action = "pause" if current.is_paused else "resume"
    repeated = client.set_state(config.resource_group, config.capacity_name, repeat_action)
    if repeated["noOp"]:
        recorder.record_pass(
            "Idempotency",
            details={"repeatedAction": repeat_action, "result": "no action required"},
        )
    else:
        recorder.record_fail(
            "Idempotency",
            "Repeating '{0}' against an already-{1} capacity issued an API call.".format(
                repeat_action, repeat_action
            ),
        )

    if not restore:
        recorder.record_skipped("Original state restored", "--skip-restore was passed.")
        return

    final = client.get(config.resource_group, config.capacity_name)
    if final.normalized_state != original_state:
        action = "pause" if original_state == "paused" else "resume"
        client.set_state(config.resource_group, config.capacity_name, action)
        final = client.get(config.resource_group, config.capacity_name)

    if final.normalized_state == original_state:
        recorder.record_pass(
            "Original state restored",
            details={"original": original_state, "final": final.state},
        )
    else:
        recorder.record_fail(
            "Original state restored",
            "Expected '{0}', capacity is '{1}'.".format(original_state, final.state),
        )


def _state_detail(result) -> dict:
    return {
        "before": result.get("stateBefore"),
        "after": result.get("stateAfter"),
        "changed": result.get("changed"),
    }


# ---------------------------------------------------------------------------
# Suite 2: RBAC
# ---------------------------------------------------------------------------


def validate_rbac(arm, config, subscription_id, recorder) -> None:
    """Verify the custom role exists with exactly the documented actions."""
    scope = "/subscriptions/{0}".format(subscription_id)
    try:
        response = arm.get(
            "{0}/providers/Microsoft.Authorization/roleDefinitions".format(scope),
            params={"api-version": AUTHORIZATION_API_VERSION, "$filter": "type eq 'CustomRole'"},
        )
    except ArmError as exc:
        recorder.record_not_validated("Custom role exists", str(exc)[:200])
        return

    match = None
    for item in response.body.get("value", []):
        if (item.get("properties") or {}).get("roleName") == ROLE_NAME:
            match = item
            break

    if match is None:
        recorder.record_not_validated(
            "Custom role exists",
            "Role '{0}' was not found. Run scripts/deploy.py first.".format(ROLE_NAME),
        )
        return

    actual = sorted((match["properties"].get("permissions") or [{}])[0].get("actions", []))
    expected = sorted(role_actions())
    if actual == expected:
        recorder.record_pass("Custom role exists", details={"role": ROLE_NAME, "actions": actual})
    else:
        recorder.record_fail(
            "Custom role exists",
            "Action list does not match. Expected {0}, got {1}.".format(expected, actual),
        )

    # The permission boundary that matters most for honest documentation.
    if "Microsoft.Fabric/capacities/write" in actual:
        recorder.record_pass(
            "Permission boundary documented",
            details={
                "finding": (
                    "The role includes Microsoft.Fabric/capacities/write, which Microsoft "
                    "documents as required for pause/resume. That same action permits "
                    "changing the capacity SKU, so this role is NOT limited to pause/resume."
                )
            },
        )

    # Effective-access check for a supplied principal, when the API allows it.
    if not config.test_principal_object_id:
        recorder.record_not_validated(
            "Effective permissions tested",
            "TEST_PRINCIPAL_OBJECT_ID is not set. This POC does not create identities, so "
            "no principal was available to test role assignment behaviour against.",
        )
        return

    try:
        assignments = arm.get(
            "{0}/providers/Microsoft.Authorization/roleAssignments".format(config.capacity_resource_id),
            params={
                "api-version": AUTHORIZATION_API_VERSION,
                "$filter": "principalId eq '{0}'".format(config.test_principal_object_id),
            },
        )
        found = [
            a
            for a in assignments.body.get("value", [])
            if (a.get("properties") or {}).get("roleDefinitionId", "").endswith(match["name"])
        ]
        if found:
            recorder.record_pass(
                "Role assigned at capacity scope",
                details={"scope": "individual capacity", "assignmentCount": len(found)},
            )
        else:
            recorder.record_not_validated(
                "Role assigned at capacity scope",
                "No assignment of '{0}' found for the configured test principal at the "
                "capacity scope.".format(ROLE_NAME),
            )
    except ArmError as exc:
        recorder.record_not_validated("Role assigned at capacity scope", str(exc)[:200])


# ---------------------------------------------------------------------------
# Suite 3: policy
# ---------------------------------------------------------------------------


def validate_policy(arm, config, subscription_id, recorder, *, negative_test: bool) -> None:
    """Verify the policy definition, its assignment, and (optionally) its effect."""
    definition_id = policy_definition_id(subscription_id, POLICY_DEFINITION_NAME)
    params = {"api-version": POLICY_API_VERSION}

    try:
        definition = arm.get(definition_id, params=params).body
    except ArmError as exc:
        recorder.record_not_validated(
            "Policy definition exists",
            "Not found. Run scripts/deploy.py first. ({0})".format(str(exc)[:150]),
        )
        return

    props = definition.get("properties") or {}
    rule = props.get("policyRule") or {}
    alias_used = ""
    for clause in (rule.get("if") or {}).get("allOf", []):
        nested = clause.get("not") or {}
        if nested.get("field"):
            alias_used = nested["field"]

    recorder.record_pass(
        "Policy definition exists",
        details={
            "name": POLICY_DEFINITION_NAME,
            "alias": alias_used,
            "parameters": sorted((props.get("parameters") or {}).keys()),
        },
    )

    if "allowedSkus" in (props.get("parameters") or {}):
        recorder.record_pass(
            "Allowed SKU list is parameterized",
            details={"default": (props["parameters"]["allowedSkus"] or {}).get("defaultValue")},
        )
    else:
        recorder.record_fail("Allowed SKU list is parameterized", "No allowedSkus parameter.")

    effects = ((props.get("parameters") or {}).get("effect") or {}).get("allowedValues") or []
    if "Audit" in effects and "Deny" in effects:
        recorder.record_pass("Audit and Deny both supported", details={"allowedValues": effects})
    else:
        recorder.record_fail("Audit and Deny both supported", "effect allowedValues = {0}".format(effects))

    # ---- assignment ------------------------------------------------------
    assignment_effect = ""
    try:
        assignments = arm.get(
            "{0}/providers/Microsoft.Authorization/policyAssignments".format(config.resource_group_scope),
            params=params,
        ).body
        ours = [
            a
            for a in assignments.get("value", [])
            if (a.get("properties") or {}).get("policyDefinitionId", "").lower() == definition_id.lower()
        ]
        if ours:
            assignment_props = ours[0].get("properties") or {}
            assignment_effect = (assignment_props.get("parameters") or {}).get("effect", {}).get("value", "")
            recorder.record_pass(
                "Policy assigned at POC resource group",
                details={
                    "effect": assignment_effect,
                    "allowedSkus": (assignment_props.get("parameters") or {})
                    .get("allowedSkus", {})
                    .get("value"),
                },
            )
        else:
            recorder.record_not_validated(
                "Policy assigned at POC resource group", "No assignment of this definition found."
            )
    except ArmError as exc:
        recorder.record_not_validated("Policy assigned at POC resource group", str(exc)[:200])

    # ---- positive (compliance) test -------------------------------------
    client = CapacityClient(arm, subscription_id)
    info = client.get(config.resource_group, config.capacity_name)
    if info is not None:
        if info.sku_name in config.allowed_fabric_skus:
            recorder.record_pass(
                "Allowed SKU permitted",
                details={
                    "capacitySku": info.sku_name,
                    "allowedSkus": config.allowed_fabric_skus,
                    "note": (
                        "The existing POC capacity uses an allowed SKU and exists under the "
                        "policy assignment scope, so the policy does not block it."
                    ),
                },
            )
        else:
            recorder.record_fail(
                "Allowed SKU permitted",
                "Capacity SKU {0} is not in the allowed list {1}.".format(
                    info.sku_name, config.allowed_fabric_skus
                ),
            )
    else:
        recorder.record_not_validated(
            "Allowed SKU permitted", "No capacity available for the compliance test."
        )

    # ---- negative (deny) test -------------------------------------------
    if not negative_test:
        recorder.record_not_validated(
            "Disallowed SKU denied",
            "Negative test not requested. Re-run with --policy-negative-test to attempt "
            "creating a {0} capacity and assert Azure refuses it.".format(DISALLOWED_TEST_SKU),
        )
        return

    if assignment_effect != "Deny":
        recorder.record_not_validated(
            "Disallowed SKU denied",
            "The policy assignment effect is '{0}', not 'Deny'. An Audit assignment records "
            "non-compliance but does not block deployment, so a denial cannot be observed. "
            "Set POLICY_EFFECT=Deny, re-run deploy.py, then re-run this test.".format(
                assignment_effect or "unknown"
            ),
        )
        return

    if DISALLOWED_TEST_SKU in config.allowed_fabric_skus:
        recorder.record_not_validated(
            "Disallowed SKU denied",
            "{0} is in ALLOWED_FABRIC_SKUS, so it cannot serve as the negative test.".format(
                DISALLOWED_TEST_SKU
            ),
        )
        return

    negative_test_capacity, validation_tags = build_negative_test_identity()

    # Defense in depth: the random name should be unique, but a preflight GET
    # makes collision handling explicit and guarantees this test never updates
    # an existing resource.
    if client.get(config.resource_group, negative_test_capacity) is not None:
        recorder.record_not_validated(
            "Disallowed SKU denied",
            "The randomly generated negative-test name already exists. Refusing to touch it.",
        )
        return

    recorder.record_pass(
        "Negative test starting",
        details={
            "attempting": "create {0} capacity '{1}'".format(DISALLOWED_TEST_SKU, negative_test_capacity),
            "expected": "RequestDisallowedByPolicy",
        },
    )

    body = build_create_body(
        config.location,
        DISALLOWED_TEST_SKU,
        [config.capacity_admin or "placeholder@example.com"],
        tags=validation_tags,
    )
    target = "{0}/providers/Microsoft.Fabric/capacities/{1}".format(
        config.resource_group_scope, negative_test_capacity
    )

    denied = False
    response = None
    try:
        response = arm.put(target, params={"api-version": FABRIC_API_VERSION}, body=body)
    except ArmError as exc:
        error_code = exc.error_code or ""
        denied = exc.status_code == 403 and "policy" in (error_code + str(exc)).lower()
        if denied:
            recorder.record_pass(
                "Disallowed SKU denied",
                details={
                    "attemptedSku": DISALLOWED_TEST_SKU,
                    "httpStatus": exc.status_code,
                    "errorCode": error_code,
                    "note": "Azure Policy refused the deployment. No capacity was created.",
                },
            )
        else:
            recorder.record_fail(
                "Disallowed SKU denied",
                "Creation failed, but not with a policy denial: {0}".format(str(exc)[:250]),
            )

    if denied:
        # Confirm that even a denied request did not leave a resource behind.
        leftover = client.get(config.resource_group, negative_test_capacity)
        if leftover is None:
            recorder.record_pass(
                "No resource created by denied request",
                details={"capacity": negative_test_capacity, "exists": False},
            )
        else:
            recorder.record_fail(
                "No resource created by denied request",
                "A resource exists after the denied request. It was not deleted automatically.",
            )
        return

    if response is not None:
        recorder.record_fail(
            "Disallowed SKU denied",
            "Azure ACCEPTED a {0} capacity despite the Deny policy. Attempting immediate cleanup.".format(
                DISALLOWED_TEST_SKU
            ),
        )
        try:
            arm.wait_for_lro(response, timeout_seconds=300)
        except ArmError as exc:
            recorder.record_fail(
                "Negative test provisioning",
                "The accepted request did not reach a clean terminal result: {0}".format(str(exc)[:200]),
            )

    # Whether Azure accepted the request or returned a non-policy error, check
    # for a partially created resource. Delete only the unique resource whose
    # live tags match this exact validation run.
    leftover = None
    for _ in range(6):
        leftover = client.get(config.resource_group, negative_test_capacity)
        if leftover is not None or response is None:
            break
        time.sleep(2)

    if leftover is None:
        if response is not None:
            recorder.record_pass(
                "Negative test cleanup",
                details={"deleted": False, "reason": "accepted request left no resource"},
            )
        return

    owned = all(leftover.tags.get(key) == value for key, value in validation_tags.items())
    if not owned:
        recorder.record_fail(
            "Negative test cleanup",
            "A resource exists at the random test name but its ownership tags do not match. "
            "Refusing automatic deletion.",
        )
        return

    try:
        client.delete(config.resource_group, negative_test_capacity)
        recorder.record_pass(
            "Negative test cleanup",
            details={"deleted": negative_test_capacity, "reason": "policy did not block it"},
        )
    except ArmError as exc:
        recorder.record_fail(
            "Negative test cleanup",
            "Could not delete the uniquely tagged negative-test capacity. DELETE IT MANUALLY "
            "because it may be billing. ({0})".format(str(exc)[:200]),
        )


# ---------------------------------------------------------------------------


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

    suites = tuple(args.only) if args.only else ALL_SUITES
    arm = ArmClient(default_token_provider())
    client = CapacityClient(arm, subscription_id)
    manifest = DeploymentManifest.load()

    recorder = ResultRecorder("validate")
    recorder.metadata = {
        "suites": list(suites),
        "capacityMode": config.capacity_mode,
        "policyEffect": config.policy_effect,
        "negativeTestRequested": args.policy_negative_test,
    }

    if "pause-resume" in suites:
        try:
            validate_pause_resume(client, config, recorder, manifest, restore=not args.skip_restore)
        except ArmError as exc:
            recorder.record_fail("Pause/resume suite", str(exc)[:250])

    if "rbac" in suites:
        try:
            validate_rbac(arm, config, subscription_id, recorder)
        except ArmError as exc:
            recorder.record_fail("RBAC suite", str(exc)[:250])

    if "policy" in suites:
        try:
            validate_policy(arm, config, subscription_id, recorder, negative_test=args.policy_negative_test)
        except ArmError as exc:
            recorder.record_fail("Policy suite", str(exc)[:250])

    # ---- leave a POC-created capacity paused -----------------------------
    final = client.get(config.resource_group, config.capacity_name)
    final_owned = bool(final and manifest and manifest.owns_tagged_resource(final.raw))
    if final is not None and final_owned and not final.is_paused:
        if final.is_in_flight:
            recorder.record_not_validated(
                "POC capacity left paused",
                "Capacity is '{0}'; could not pause it now. Run "
                "`python scripts/capacity.py pause` once it settles.".format(final.state),
            )
        else:
            client.pause(config.resource_group, config.capacity_name)
            after = client.get(config.resource_group, config.capacity_name)
            recorder.record_pass(
                "POC capacity left paused",
                details={"state": after.state, "reason": "minimize billing"},
            )
    elif final is not None and final_owned:
        recorder.record_pass("POC capacity left paused", details={"state": final.state})

    recorder.print_summary()
    path = recorder.write("validate-latest.json")
    print("  Results: {0} (gitignored)".format(path))
    print("")
    return 1 if recorder.has_failures else 0


if __name__ == "__main__":
    sys.exit(main())
