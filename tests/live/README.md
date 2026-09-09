# Cortex live E2E harness

`runner.sh` is the fail-closed entry point shared by the live test scenarios. It
creates a unique mode-0700 run directory, exports the authoritative compiled
Rust `SurfaceContract`, seals run/target/contract manifests, writes
concurrency-safe JSONL events, captures only redacted allowlisted artifacts,
and emits `summary.json`, `junit.xml`, and a machine-readable
`capability-ledger.jsonl`. Scenario commands routed through
`live_run_bounded` start with an empty, run-local environment and have an
enforced timeout.

The ledger is fail-closed. Every required surface/case in the selected profile
must have one unique `first_attempt` outcome of `pass` or `fail`; skipped,
missing, duplicate, unknown-surface, and missing-evidence outcomes cannot make
a mandatory capability green. Platform-qualified topology dispositions are
accepted only by an exact allowlist in `contracts/platform-coverage.json` and
remain visible as qualifications, never passes. `diagnostic_retry` events
are retained separately and never replace the original result. Reports reduce
the event stream incrementally and do not accumulate a results array.

Resources must be registered before creation with `live_resource_transition`.
The lifecycle is `PLANNED → CREATING → IDENTIFIED → CREATED → CLEANING →
REMOVED → VERIFIED`. `CREATING` records the feasible provider intent;
`IDENTIFIED` records the provider-assigned canonical identity before success is
claimed. `CREATING` deliberately stores no canonical ID and no cleanup argv;
cleanup of an unresolved intent is refused as
`MANUAL_RECONCILIATION_REQUIRED`. From `IDENTIFIED` onward, every owned state
requires its exact ID, digest, argv-only cleanup command, and separate argv-only
absence probe. Children name a previously registered parent. Cleanup runs in
reverse creation order and is only marked `VERIFIED` after the independent
probe succeeds. Resume replays and validates the complete state history,
including timestamps and immutable ownership data.

Run the hermetic foundation checks with:

```bash
bash tests/live/selftest/run.sh
```

Run the portable pull-request smoke profile:

```bash
bash tests/live/runner.sh --profile smoke
```

Smoke is an imperative, portable subset with direct assertions for its ingest,
REST, CLI, browser, lifecycle, and cleanup phases. It is not an owner in the
authoritative SurfaceContract denominator. A zero exit means those smoke
assertions and cleanup passed; complete denominator qualification requires the
owner profiles and `tests/live/aggregate.sh`.

`--profile noop` is an explicit non-mandatory orchestration check. It exports
and seals the same authoritative contract and exercises setup/report/cleanup,
but has no capability requirements and may succeed with zero results. `--legacy`
writes a versioned `legacy_result` event explicitly isolated
from the capability ledger, so compatibility execution cannot fabricate modern
surface coverage.

Every profile enforces wall time, CPU, peak RSS, total disk, artifact bytes,
fixture records/bytes, polling attempts, opened connections, and spawned
processes. Scenario helpers must account fixtures and connections through
`live_fixture_account` and `live_connection_opened`; command and polling helpers
account their dimensions automatically.

Reconcile only expired runs for one exact provider identity:

```bash
bash tests/live/runner.sh --janitor --runs-root /path/to/runs --provider provider-id
```

The janitor refuses corrupt or symlinked manifests and provider mismatches. A
`MANUAL_RECONCILIATION_REQUIRED`, `RESIDUE`, or `CLEANUP_UNVERIFIED` audit is a
failed cleanup outcome; it is never silently converted to success.

## Platform qualification

Every run writes `platform-coverage.json` and embeds it in `summary.json` with
the detected platform, selected policy, certification level, qualifications,
and required coverage. Darwin and Windows default to `portable`; Linux defaults
to `linux-full`. `--platform-policy` can make the choice explicit but cannot
select a policy that excludes the detected platform.

Portable macOS qualification may be green with only the explicit topology
limitations approved by the contract. The result continues to list Linux-only
coverage and is not a full certification. Linux topology profiles require
`CORTEX_LIVE_DIND_AUTHORIZED=1` and fail closed unless hard quota,
Docker-agent boundary, and redirector-egress denial all pass. CI additionally
runs the agent boundary in full mode for DinD, OOM, daemon restart, and Unix
socket-permission coverage. See `profiles/macos/README.md` for the read-only
host audit and recovery procedure.
