#!/usr/bin/env python3
"""Start the Automation runbook on demand and stream its result.

This exercises the whole pause/resume control path the way a schedule would:
Azure Automation starts the runbook, the runbook authenticates with the
Automation account's system-assigned managed identity, and that identity's
Azure RBAC role is what permits (or refuses) the capacity operation. Running it
end to end is the only way to prove those three pieces work together.

    python scripts/run_runbook.py Pause
    python scripts/run_runbook.py Resume
    python scripts/run_runbook.py Resume --wait-seconds 600

Useful in a customer demo: it shows the same runbook the schedule triggers,
without waiting until 07:00.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid

from _bootstrap import (  # noqa: E402
    configure_logging,
    fail,
    resolve_env_file,
    resolve_subscription_id,
)
from fabgov.arm import ArmClient, ArmError, default_token_provider  # noqa: E402
from fabgov.automation import AUTOMATION_API_VERSION, RUNBOOK_NAME, automation_account_id  # noqa: E402
from fabgov.config import ConfigError, load_config  # noqa: E402

TERMINAL_JOB_STATUSES = ("Completed", "Failed", "Stopped", "Suspended")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_runbook.py",
        description="Start the Fabric capacity runbook in Azure Automation and report the result.",
    )
    parser.add_argument(
        "desired_state",
        choices=("Pause", "Resume"),
        help="State to drive the capacity to.",
    )
    parser.add_argument("--env-file", default=".env", help="Path to the .env file.")
    parser.add_argument(
        "--wait-seconds", type=int, default=600, help="How long to wait for the job (default 600)."
    )
    parser.add_argument("--no-wait", action="store_true", help="Start the job and exit without waiting.")
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
    if not config.automation_account_name:
        fail("AUTOMATION_ACCOUNT_NAME is not set.")
        return 1

    arm = ArmClient(default_token_provider())
    account = automation_account_id(subscription_id, config.resource_group, config.automation_account_name)
    params = {"api-version": AUTOMATION_API_VERSION}

    job_id = str(uuid.uuid4())
    job_url = "{0}/jobs/{1}".format(account, job_id)
    body = {
        "properties": {
            "runbook": {"name": RUNBOOK_NAME},
            # Automation stores runbook parameter names lower-cased.
            "parameters": {
                "subscriptionid": subscription_id,
                "resourcegroupname": config.resource_group,
                "capacityname": config.capacity_name,
                "desiredstate": args.desired_state,
            },
        }
    }

    print("")
    print("  Starting runbook : {0}".format(RUNBOOK_NAME))
    print("  Desired state    : {0}".format(args.desired_state))
    print("  Capacity         : {0}".format(config.capacity_name))
    print("")

    try:
        arm.put(job_url, params=params, body=body)
    except ArmError as exc:
        fail("Could not start the runbook job: {0}".format(exc))
        return 1

    print("  Job started.")
    if args.no_wait:
        print("  --no-wait passed; not waiting for completion.")
        return 0

    deadline = time.time() + args.wait_seconds
    status = "Unknown"
    while time.time() < deadline:
        time.sleep(10)
        try:
            job = arm.get(job_url, params=params).body
        except ArmError as exc:
            print("  Could not read job status: {0}".format(str(exc)[:150]))
            continue
        status = (job.get("properties") or {}).get("status", "Unknown")
        print("  Job status: {0}".format(status))
        if status in TERMINAL_JOB_STATUSES:
            break

    print("")
    # Runbook stdout is the demo evidence, so always try to show it.
    try:
        output = arm.get("{0}/output".format(job_url), params=params)
        text = output.body.get("raw", "") if isinstance(output.body, dict) else ""
        if text:
            print("  ---- runbook output " + "-" * 50)
            for line in text.splitlines():
                print("  " + line)
            print("  " + "-" * 70)
    except ArmError as exc:
        print("  Could not read job output: {0}".format(str(exc)[:150]))

    print("")
    if status == "Completed":
        print("  RESULT: runbook completed successfully.")
        return 0

    print("  RESULT: runbook finished with status '{0}'.".format(status))
    try:
        streams = arm.get(
            "{0}/streams".format(job_url),
            params={"api-version": AUTOMATION_API_VERSION, "$filter": "properties/streamType eq 'Error'"},
        ).body
        for item in streams.get("value", [])[:5]:
            summary = (item.get("properties") or {}).get("summary", "")
            if summary:
                print("  ERROR: {0}".format(summary[:400]))
    except ArmError:
        pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
