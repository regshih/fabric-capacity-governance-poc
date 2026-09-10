#!/usr/bin/env python3
"""Pre-deployment environment checks.

Verifies everything the POC depends on before any resource is touched:
authentication, subscription context, provider registration, SKU availability,
capacity resolution, and the safety flags currently in force.

Read-only. This script never creates, modifies, or deletes anything.

    python scripts/preflight.py
    python scripts/preflight.py --json
"""

from __future__ import annotations

import argparse
import json
import sys

from _bootstrap import configure_logging, resolve_env_file, resolve_subscription_id, run_az  # noqa: E402
from fabgov.arm import ArmClient, ArmError, default_token_provider  # noqa: E402
from fabgov.capacity import CapacityClient, validate_capacity_name  # noqa: E402
from fabgov.config import ConfigError, load_config, sku_capacity_units  # noqa: E402
from fabgov.policy import EXPECTED_SKU_ALIAS  # noqa: E402

CHECK_OK = "PASS"
CHECK_FAIL = "FAIL"
CHECK_WARN = "WARN"
CHECK_INFO = "INFO"


class Preflight:
    """Accumulates check results and decides whether deployment may proceed."""

    def __init__(self):
        self.checks = []

    def add(self, name: str, status: str, detail: str = "", *, blocking: bool = False) -> None:
        self.checks.append({"check": name, "status": status, "detail": detail, "blocking": blocking})

    @property
    def blocked(self) -> bool:
        return any(c["status"] == CHECK_FAIL and c["blocking"] for c in self.checks)

    def render(self) -> None:
        print("")
        print("Preflight checks")
        print("=" * 78)
        width = max((len(c["check"]) for c in self.checks), default=20)
        for check in self.checks:
            print("  {0:<{1}}  {2:<5}  {3}".format(check["check"], width, check["status"], check["detail"]))
        print("=" * 78)
        failures = [c for c in self.checks if c["status"] == CHECK_FAIL]
        warnings = [c for c in self.checks if c["status"] == CHECK_WARN]
        print("  {0} checks, {1} failed, {2} warnings".format(len(self.checks), len(failures), len(warnings)))
        if self.blocked:
            print("")
            print("  DEPLOYMENT BLOCKED. Resolve the failed checks above and re-run.")
        print("")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preflight.py",
        description="Read-only environment checks for the Fabric Capacity Governance POC.",
    )
    parser.add_argument("--env-file", default=".env", help="Path to the .env file.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)
    pf = Preflight()

    # ---- configuration ---------------------------------------------------
    try:
        config = load_config(resolve_env_file(args.env_file))
        pf.add("Configuration", CHECK_OK, "Loaded and validated.")
    except ConfigError as exc:
        pf.add("Configuration", CHECK_FAIL, str(exc), blocking=True)
        pf.render()
        return 1

    # ---- Azure CLI authentication ---------------------------------------
    code, stdout, stderr = run_az(["account", "show", "-o", "json"], timeout=30)
    if code == 127:
        pf.add("Azure CLI", CHECK_WARN, "Not found on PATH. DefaultAzureCredential may still work.")
        account = {}
    elif code != 0:
        pf.add(
            "Azure CLI login",
            CHECK_FAIL,
            "Not logged in. Run `az login`. ({0})".format(stderr[:120]),
            blocking=True,
        )
        account = {}
    else:
        account = json.loads(stdout)
        pf.add(
            "Azure CLI login",
            CHECK_OK,
            "Signed in as {0}".format(account.get("user", {}).get("name", "(unknown)")),
        )

    subscription_id = resolve_subscription_id(config.subscription_id)
    if not subscription_id:
        pf.add("Subscription", CHECK_FAIL, "No subscription resolved.", blocking=True)
        pf.render()
        return 1
    pf.add("Subscription", CHECK_OK, "Resolved (id withheld from output).")

    # ---- ARM token -------------------------------------------------------
    try:
        arm = ArmClient(default_token_provider())
        arm.get("/subscriptions/{0}".format(subscription_id), params={"api-version": "2022-12-01"})
        pf.add("ARM access", CHECK_OK, "Acquired a token and read the subscription.")
    except Exception as exc:  # noqa: BLE001 - report any auth failure clearly
        pf.add("ARM access", CHECK_FAIL, str(exc)[:200], blocking=True)
        pf.render()
        return 1

    # ---- provider registration ------------------------------------------
    for namespace, blocking in (
        ("Microsoft.Fabric", True),
        ("Microsoft.Automation", config.enable_automation),
    ):
        try:
            body = arm.get(
                "/subscriptions/{0}/providers/{1}".format(subscription_id, namespace),
                params={"api-version": "2021-04-01"},
            ).body
            state = body.get("registrationState", "Unknown")
            if state == "Registered":
                pf.add("Provider {0}".format(namespace), CHECK_OK, state)
            else:
                pf.add(
                    "Provider {0}".format(namespace),
                    CHECK_FAIL if blocking else CHECK_WARN,
                    "{0}. Run: az provider register --namespace {1}".format(state, namespace),
                    blocking=bool(blocking),
                )
        except ArmError as exc:
            pf.add("Provider {0}".format(namespace), CHECK_WARN, str(exc)[:150])

    # ---- policy alias ----------------------------------------------------
    if config.enable_policy_poc:
        try:
            from fabgov.policy import extract_capacity_aliases, find_sku_alias

            body = arm.get(
                "/subscriptions/{0}/providers/Microsoft.Fabric".format(subscription_id),
                params={"api-version": "2021-04-01", "$expand": "resourceTypes/aliases"},
            ).body
            aliases = extract_capacity_aliases(body)
            alias = find_sku_alias(aliases)
            if alias:
                pf.add("Policy SKU alias", CHECK_OK, "Verified: {0}".format(alias["name"]))
            else:
                pf.add(
                    "Policy SKU alias",
                    CHECK_WARN,
                    "{0} not found among {1} aliases. SKU policy will be skipped and "
                    "reported NOT VERIFIED.".format(EXPECTED_SKU_ALIAS, len(aliases)),
                )
        except ArmError as exc:
            pf.add("Policy SKU alias", CHECK_WARN, str(exc)[:150])

    # ---- SKUs ------------------------------------------------------------
    capacity_client = CapacityClient(arm, subscription_id)
    try:
        skus = capacity_client.list_skus()
        pf.add("Fabric SKUs", CHECK_OK, "{0} SKU entries visible.".format(len(skus)))
        missing = [s for s in config.allowed_fabric_skus if s not in skus]
        if missing:
            pf.add(
                "ALLOWED_FABRIC_SKUS",
                CHECK_WARN,
                "Not offered in this subscription: {0}".format(", ".join(missing)),
            )
        else:
            pf.add("ALLOWED_FABRIC_SKUS", CHECK_OK, ", ".join(config.allowed_fabric_skus))
    except ArmError as exc:
        pf.add("Fabric SKUs", CHECK_WARN, str(exc)[:150])

    # ---- capacity resolution --------------------------------------------
    if not config.capacity_name:
        pf.add("Capacity name", CHECK_FAIL, "FABRIC_CAPACITY_NAME is not set.", blocking=True)
    else:
        if config.capacity_mode == "create":
            try:
                validate_capacity_name(config.capacity_name)
                pf.add("Capacity name", CHECK_OK, "Valid for creation.")
            except ValueError as exc:
                pf.add("Capacity name", CHECK_FAIL, str(exc), blocking=True)

        if not config.resource_group:
            pf.add("Resource group", CHECK_FAIL, "RESOURCE_GROUP_NAME is not set.", blocking=True)
        else:
            try:
                info = capacity_client.get(config.resource_group, config.capacity_name)
            except ArmError as exc:
                info = None
                pf.add("Capacity lookup", CHECK_WARN, str(exc)[:150])

            if info is not None:
                pf.add(
                    "Capacity",
                    CHECK_OK,
                    "Found. SKU {0}, state {1}, createdByPoc={2}".format(
                        info.sku_name, info.state, info.created_by_poc
                    ),
                )
                if config.capacity_mode == "existing" and not info.created_by_poc:
                    pf.add(
                        "Existing capacity safety",
                        CHECK_INFO,
                        "State changes {0}".format(
                            "AUTHORIZED (ALLOW_EXISTING_CAPACITY_STATE_CHANGE=true)"
                            if config.allow_existing_capacity_state_change
                            else "BLOCKED (read-only validation only)"
                        ),
                    )
            else:
                if config.capacity_mode == "create":
                    if config.allow_capacity_creation:
                        pf.add(
                            "Capacity",
                            CHECK_INFO,
                            "Does not exist. Will be created as {0}.".format(config.fabric_sku),
                        )
                    else:
                        pf.add(
                            "Capacity",
                            CHECK_WARN,
                            "Does not exist and ALLOW_CAPACITY_CREATION=false. Creation will be skipped.",
                        )
                else:
                    pf.add(
                        "Capacity",
                        CHECK_FAIL,
                        "CAPACITY_MODE=existing but the capacity was not found.",
                        blocking=True,
                    )

    # ---- safety posture --------------------------------------------------
    pf.add(
        "Safety flags",
        CHECK_INFO,
        "creation={0} existingStateChange={1} deletion={2} schedules={3}".format(
            config.allow_capacity_creation,
            config.allow_existing_capacity_state_change,
            config.allow_poc_resource_deletion,
            config.enable_schedules,
        ),
    )
    if config.policy_effect == "Deny":
        pf.add(
            "Policy effect",
            CHECK_WARN,
            "POLICY_EFFECT=Deny will BLOCK non-compliant capacity deployments at the assignment scope.",
        )
    else:
        pf.add("Policy effect", CHECK_OK, config.policy_effect)

    if config.capacity_mode == "create" and sku_capacity_units(config.fabric_sku) > 2:
        pf.add("SKU size", CHECK_WARN, "Creating larger than F2 is not recommended for a POC.")

    if args.json:
        print(json.dumps({"checks": pf.checks, "blocked": pf.blocked}, indent=2))
    else:
        pf.render()
    return 1 if pf.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
