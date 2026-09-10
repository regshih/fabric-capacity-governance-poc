# Validation

How this POC is tested, and how to reproduce the results in your own
subscription.

## Two layers

| Layer | Needs Azure? | Command |
|---|---|---|
| Unit tests | No | `pytest tests/unit` |
| Live validation | Yes | `python scripts/validate.py` |
| Live integration tests | Yes, opt-in | `RUN_AZURE_INTEGRATION_TESTS=true pytest tests/integration` |

Unit tests never touch Azure. That is deliberate: anyone can clone this
repository and verify the logic without a subscription, and ordinary CI can run
them without credentials.

## Unit tests

```bash
pytest tests/unit -q
```

They cover the parts where a mistake would be quiet rather than loud:

- **Configuration and safety flags** — including that an ambiguous boolean
  (`ture`) *raises* rather than being coerced. A typo on
  `ALLOW_POC_RESOURCE_DELETION` must never be silently interpreted.
- **Capacity resource ID construction** and Fabric's name constraints.
- **State normalization** across the full documented enum, including that both
  `Paused` and `Suspended` count as paused.
- **Idempotency** — a `pause` against a paused capacity issues no HTTP call.
- **Pause/resume request construction** — correct path, `POST`, no body.
- **ARM long-running-operation polling** — header preference, `Retry-After`,
  failure, cancellation, and that a timeout *raises* instead of reporting
  success.
- **Retry behaviour** — retries `429`/`5xx`, never retries `403`.
- **Policy alias parsing** and the refusal to generate a policy without a
  verified alias.
- **Policy generation** — parameterized SKU list, `Audit` default, `Deny`
  available but never the default.
- **RBAC role construction** — the four actions, exclusions, and that the role
  description discloses the `write` implication.
- **Result sanitization** — GUIDs, emails, tokens, and resource-ID segments.
- **Cleanup safety** — ownership requires manifest *and* tags.

## Live validation

```bash
python scripts/validate.py                      # everything permitted
python scripts/validate.py --only pause-resume
python scripts/validate.py --only rbac
python scripts/validate.py --only policy
python scripts/validate.py --policy-negative-test
```

Results print as a table and are written to `results/` (gitignored).

### Three outcomes, and why the third matters

```
  Pause API                              PASS
  Disallowed SKU denied                  PASS
  Effective permissions tested           NOT VALIDATED
                                         -> TEST_PRINCIPAL_OBJECT_ID is not set.
```

`NOT VALIDATED` is a first-class result, not a soft failure. A test that could
not run is never quietly upgraded to a pass, and never silently dropped. It
always carries a reason, and it flows straight into
[POC_FINDINGS.md](POC_FINDINGS.md).

`validate.py` exits non-zero only on `FAIL`. `NOT VALIDATED` does not fail the
run, because "we could not test this" is information, not a defect.

### What the pause/resume suite does

1. Reads the capacity and records its **original state**.
2. Checks authorization. Without it, records `NOT VALIDATED` and stops — no
   state change is attempted.
3. Drives a full cycle so both transitions are observed:
   `Active -> Paused -> Active` (or `Paused -> Active -> Paused`).
4. Verifies the state after each transition.
5. Repeats the last operation to confirm it is a **no-op**.
6. **Restores the original state.**
7. If the capacity was created by this POC, leaves it **paused** to stop
   billing.

Steps 1 and 6 are what make it safe to run against a capacity you already own —
provided you have authorized it:

```
Original state: Active

Test:
Active
-> Pause
-> Verify Paused
-> Resume
-> Verify Active

Final state: Active
```

### What the policy suite does

The negative test **attempts to create** a capacity with a disallowed SKU and
asserts Azure refuses it. It never resizes an existing capacity — that would
change a real resource, and if the policy failed to block it, would start
billing at the larger SKU.

It only produces a meaningful result when the assignment effect is `Deny`; under
`Audit` it reports `NOT VALIDATED` explaining that an audit assignment records
non-compliance but does not block.

## Live integration tests

Separated from unit tests and skipped unless explicitly enabled:

```bash
RUN_AZURE_INTEGRATION_TESTS=true pytest tests/integration -m integration -q
```

These must never run in ordinary public CI. They require a real subscription, a
real `az login` session, and they read live resources.

## CI

`.github/workflows/ci.yml` runs on pull requests **without any Azure
credentials**:

- unit tests
- JSON validation of the policy and role definitions
- lint
- the public-repo security scan
- secret scanning

Live Azure tests are deliberately excluded. A public repository's PR CI should
never hold credentials to someone's subscription.

## Reproducing the reference run

```bash
cp .env.example .env
# edit .env: RESOURCE_GROUP_NAME, LOCATION, FABRIC_CAPACITY_NAME,
#            FABRIC_CAPACITY_ADMIN, AUTOMATION_ACCOUNT_NAME
# then set: CAPACITY_MODE=create and ALLOW_CAPACITY_CREATION=true

python scripts/preflight.py
python scripts/deploy.py --dry-run
python scripts/deploy.py
python scripts/validate.py
python scripts/run_runbook.py Resume

# The Deny test requires an explicit opt-in:
#   set POLICY_EFFECT=Deny in .env, then:
python scripts/deploy.py
python scripts/validate.py --policy-negative-test

# Return to the safe default:
#   set POLICY_EFFECT=Audit in .env, then:
python scripts/deploy.py

python scripts/capacity.py status     # confirm: Paused
python scripts/cleanup.py             # dry-run teardown plan
```

Expect roughly 15 minutes end to end, most of it waiting on capacity state
transitions.

## Sharing results

Result files contain real identifiers, which is why `results/` is gitignored.
To share one:

```bash
python scripts/sanitize_results.py results/validate-latest.json -o /tmp/shareable.json
```

Review the output before publishing it. Automated redaction is a safety net, not
a substitute for reading what you are about to make public. A sanitized example
lives in [sample-output/](sample-output/).
