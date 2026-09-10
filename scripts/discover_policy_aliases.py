#!/usr/bin/env python3
"""Discover the Azure Policy aliases exposed for Microsoft.Fabric/capacities.

This must run before any SKU policy is generated. An Azure Policy that
references a non-existent alias deploys without error and then matches nothing,
producing a governance control that appears green while enforcing nothing at
all. This script is the gate that prevents that.

    python scripts/discover_policy_aliases.py
    python scripts/discover_policy_aliases.py --json
    python scripts/discover_policy_aliases.py --save results/aliases.json

Exit codes:
    0  the SKU alias was found and verified
    3  the provider responded but no usable SKU alias exists (a real finding)
    1  the discovery call itself failed
"""

from __future__ import annotations

import argparse
import json
import sys

from _bootstrap import configure_logging, fail, resolve_env_file, resolve_subscription_id  # noqa: E402
from fabgov.arm import ArmClient, ArmError, default_token_provider  # noqa: E402
from fabgov.config import load_config  # noqa: E402
from fabgov.policy import (  # noqa: E402
    EXPECTED_SKU_ALIAS,
    AliasNotFoundError,
    extract_capacity_aliases,
    verify_sku_alias,
)

# The provider API version used to expand aliases. This is the Resource Manager
# provider API, not the Fabric API.
PROVIDER_API_VERSION = "2021-04-01"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="discover_policy_aliases.py",
        description=(
            "List Azure Policy aliases for Microsoft.Fabric/capacities and verify that a "
            "SKU alias exists before any policy is generated."
        ),
    )
    parser.add_argument("--subscription", default="", help="Override AZURE_SUBSCRIPTION_ID.")
    parser.add_argument("--env-file", default=".env", help="Path to the .env file.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")
    parser.add_argument("--save", default="", help="Also write the raw discovery output here.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return parser


def fetch_aliases(arm: ArmClient, subscription_id: str) -> list:
    """Query the provider with aliases expanded."""
    response = arm.get(
        "/subscriptions/{0}/providers/Microsoft.Fabric".format(subscription_id),
        params={"api-version": PROVIDER_API_VERSION, "$expand": "resourceTypes/aliases"},
    )
    return extract_capacity_aliases(response.body)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)

    config = load_config(resolve_env_file(args.env_file))
    subscription_id = args.subscription or resolve_subscription_id(config.subscription_id)
    if not subscription_id:
        fail("No subscription id. Set AZURE_SUBSCRIPTION_ID, pass --subscription, or run `az login`.")
        return 1

    arm = ArmClient(default_token_provider())

    try:
        aliases = fetch_aliases(arm, subscription_id)
    except ArmError as exc:
        fail("Alias discovery failed: {0}".format(exc))
        return 1

    payload = {
        "resourceType": "Microsoft.Fabric/capacities",
        "expectedSkuAlias": EXPECTED_SKU_ALIAS,
        "aliasCount": len(aliases),
        "aliases": aliases,
    }

    try:
        verified = verify_sku_alias(aliases)
        payload["skuAliasVerified"] = True
        payload["verifiedSkuAlias"] = verified["name"]
        payload["verifiedSkuAliasDefaultPath"] = verified.get("defaultPath", "")
        exit_code = 0
    except AliasNotFoundError as exc:
        payload["skuAliasVerified"] = False
        payload["verifiedSkuAlias"] = None
        payload["failureDetail"] = str(exc)
        exit_code = 3

    if args.save:
        from pathlib import Path

        target = Path(args.save)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print("Discovery output written to {0}".format(target))

    if args.json:
        print(json.dumps(payload, indent=2))
        return exit_code

    print("")
    print("Azure Policy aliases for Microsoft.Fabric/capacities")
    print("=" * 72)
    if not aliases:
        print("  (none returned by the provider)")
    for alias in aliases:
        default_path = alias.get("defaultPath") or "-"
        print("  {0}".format(alias["name"]))
        print("      defaultPath: {0}".format(default_path))
    print("=" * 72)
    print("")

    if payload["skuAliasVerified"]:
        print("  SKU alias VERIFIED: {0}".format(payload["verifiedSkuAlias"]))
        print("  maps to property:   {0}".format(payload["verifiedSkuAliasDefaultPath"] or "-"))
        print("")
        print("  A SKU restriction policy can be generated against this alias.")
    else:
        print("  SKU alias NOT VERIFIED.")
        print("")
        print(payload["failureDetail"])
    print("")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
