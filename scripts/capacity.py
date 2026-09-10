#!/usr/bin/env python3
"""Fabric capacity lifecycle CLI: status, pause, resume.

Every operation reads the capacity's current state first, so the commands are
idempotent: pausing an already-paused capacity reports "no action required"
rather than issuing a redundant API call.

    python scripts/capacity.py status
    python scripts/capacity.py pause
    python scripts/capacity.py resume

Pausing or resuming a capacity this POC did not create requires
ALLOW_EXISTING_CAPACITY_STATE_CHANGE=true, or --force on the command line.
"""

from __future__ import annotations

import argparse
import sys

from _bootstrap import configure_logging, fail, resolve_env_file, resolve_subscription_id  # noqa: E402
from fabgov.arm import ArmClient, ArmError, default_token_provider  # noqa: E402
from fabgov.capacity import CapacityClient, CapacityStateError  # noqa: E402
from fabgov.config import ConfigError, load_config  # noqa: E402
from fabgov.provenance import DeploymentManifest  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capacity.py",
        description="Read, pause, and resume a Microsoft Fabric capacity.",
        epilog=(
            "Safety: pausing or resuming a capacity that this POC did not create requires "
            "ALLOW_EXISTING_CAPACITY_STATE_CHANGE=true in .env, or the --force flag."
        ),
    )
    parser.add_argument(
        "command",
        choices=("status", "pause", "resume"),
        help="status prints current state; pause/resume change it.",
    )
    parser.add_argument("--capacity", default="", help="Override FABRIC_CAPACITY_NAME.")
    parser.add_argument("--resource-group", default="", help="Override RESOURCE_GROUP_NAME.")
    parser.add_argument("--subscription", default="", help="Override AZURE_SUBSCRIPTION_ID.")
    parser.add_argument("--env-file", default=".env", help="Path to the .env file (default: .env).")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Authorize a state change on a capacity this POC did not create.",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Return as soon as Azure accepts the request, without polling to completion.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Seconds to wait for the operation to complete (default: 900).",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    return parser


def print_status(info, *, owned_by_manifest=False) -> None:
    print("")
    print("  Capacity:          {0}".format(info.name))
    print("  Location:          {0}".format(info.location))
    print("  SKU:               {0} (tier {1})".format(info.sku_name, info.sku_tier))
    print("  State:             {0}".format(info.state or "(unknown)"))
    print("  Normalized state:  {0}".format(info.normalized_state))
    print("  Provisioning:      {0}".format(info.provisioning_state or "(unknown)"))
    print("  Administrators:    {0} configured".format(len(info.administrators)))
    print("  Created by POC:    {0}".format("yes" if owned_by_manifest else "no/unproven"))
    if info.tags:
        print("  Tags:              {0}".format(", ".join(sorted(info.tags))))
    print("")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose)

    try:
        config = load_config(resolve_env_file(args.env_file))
    except ConfigError as exc:
        fail(str(exc))
        return 1

    subscription_id = args.subscription or resolve_subscription_id(config.subscription_id)
    resource_group = args.resource_group or config.resource_group
    capacity_name = args.capacity or config.capacity_name

    if not subscription_id:
        fail(
            "No subscription id. Set AZURE_SUBSCRIPTION_ID in .env, pass --subscription, "
            "or run `az login` and select a subscription."
        )
    if not resource_group:
        fail("No resource group. Set RESOURCE_GROUP_NAME in .env or pass --resource-group.")
    if not capacity_name:
        fail("No capacity name. Set FABRIC_CAPACITY_NAME in .env or pass --capacity.")

    arm = ArmClient(default_token_provider())
    client = CapacityClient(arm, subscription_id)
    manifest = DeploymentManifest.load()

    try:
        info = client.get(resource_group, capacity_name)
        if info is None:
            fail(
                "Fabric capacity '{0}' was not found in resource group '{1}'. "
                "Check the names, the subscription, and that Microsoft.Fabric is "
                "registered.".format(capacity_name, resource_group)
            )
            return 1

        poc_owned = bool(manifest and manifest.owns_tagged_resource(info.raw))
        if args.command == "status":
            print_status(info, owned_by_manifest=poc_owned)
            return 0

        # Authorization gate for anything that changes state.
        authorized = poc_owned or config.allow_existing_capacity_state_change or args.force
        if not authorized:
            print("")
            print("  Requested:  {0}".format(args.command))
            print("  Current:    {0}".format(info.state))
            print("")
            print("  BLOCKED - this capacity was not created by this POC.")
            print("")
            print("  What would happen if authorized:")
            if info.normalized_state == ("paused" if args.command == "pause" else "running"):
                print("    Nothing. The capacity is already in the requested state.")
            else:
                print(
                    "    POST .../capacities/{0}/{1}".format(
                        capacity_name, "suspend" if args.command == "pause" else "resume"
                    )
                )
                print(
                    "    State would change from '{0}' to '{1}'.".format(
                        info.state, "Paused/Suspended" if args.command == "pause" else "Active"
                    )
                )
                if args.command == "pause":
                    print("    Every Fabric workload on this capacity would stop.")
            print("")
            print("  To authorize: set ALLOW_EXISTING_CAPACITY_STATE_CHANGE=true in .env,")
            print("  or re-run with --force.")
            print("")
            return 2

        result = client.set_state(
            resource_group,
            capacity_name,
            args.command,
            wait=not args.no_wait,
            timeout_seconds=args.timeout,
        )

        print("")
        print("  Requested:  {0}".format(result["action"]))
        print("  Current:    {0}".format(result["stateBefore"]))
        print("")
        print("  Result:")
        if result["noOp"]:
            print("  No action required.")
        else:
            print("  {0}".format(result["message"]))
            if not args.no_wait and not result.get("reachedDesiredState", False):
                print("")
                print(
                    "  WARNING: the capacity did not reach the expected state. Current state: {0}".format(
                        result["stateAfter"]
                    )
                )
                return 1
        print("")
        return 0

    except CapacityStateError as exc:
        fail(str(exc))
    except ArmError as exc:
        fail(str(exc))
    return 1


if __name__ == "__main__":
    sys.exit(main())
