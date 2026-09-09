---
title: Live qualification suite
created: 2026-08-31
updated: 2026-09-01
---

# Live qualification suite

`tests/live/run-profile.sh` is the stable operator and CI entry point. It builds
one candidate image, builds the deterministic oracle, resolves the proxy image,
and delegates to the fail-closed runner. A required profile exits nonzero when
Docker or another prerequisite is absent; missing infrastructure is never a
skip.

## Cadence

| Cadence | Profiles | Budget |
|---|---|---|
| Pull request | `smoke` | 8–12 minutes |
| Release gate | `full`, `auth`, `stateful`, `notifications`, `artifacts`, `upgrade`, `security`, `mutation` | 30–45 minutes sharded; 15–30 minutes per specialist shard |
| Scheduled | `stateful` (resilience), `storage`, `soak` | storage 20–30 minutes; soak 2–6 hours |
| Explicit opt-in | `fleet-read-only`, `fleet-mutating` (provider) | target-specific |

Run `just live-smoke` locally. Use `just live <profile>` for an exact profile;
`just --list` shows shorter stable aliases such as `live-artifact`,
`live-compose`, `live-fleet`, and `live-provider`. `just live-selftest` checks workflow shape,
documentation generation, wrappers, manifests, redaction, cleanup, and result
contracts without contacting a deployed Cortex.

## Prerequisites and safety

Isolated profiles need Bash, Python 3, Rust 1.97.1, jq, OpenSSL, and a reachable
Docker daemon with Compose v2. Artifact qualification additionally needs an
allowlisted, checksum-pinned artifact manifest. Fleet/provider profiles require
an immutable target manifest and separately supplied short-lived grants; they
are never selected by normal CI.

Storage pressure qualification reads the selected daemon's volume accounting
directly. Providers whose Docker data root is not `/var/lib/docker` must export
`LIVE_DOCKER_ROOT_DIR` as the absolute host path backing that daemon's
`/var/lib/docker` directory.

Each run owns a mode-0700 directory below `LIVE_RUNS_ROOT`. Topology-based runs
also own a unique Compose project, exact container/network/volume identities,
and synthetic tokens. The runner captures `summary.json`, `junit.xml`,
`capability-ledger.jsonl`, `cleanup-audit.json`, `run-manifest.json`, and
`budget-metrics.json`; aggregate runs also emit `aggregate-qualification.json`.
CI allowlists these seven possible schema-governed basenames, then scans and
caps the files present before upload;
raw databases, WAL/auth stores, keys, environment dumps, and browser profiles
are never upload artifacts.

## Cancellation, troubleshooting, and recovery

Every workflow has an independent `always()` janitor before artifact upload.
The janitor reconciles only exact identities under the current lease/provider;
it never deletes by a broad name or label query. A normal cancellation runs the
job's `always()` reconciliation. A hard runner eviction can make its local lease
directory unavailable and therefore requires operator cleanup on the same
provider using retained runner diagnostics; it is not claimed as automatically
recoverable by a later GitHub-hosted runner.

If a run fails, inspect `summary.json` first, then `junit.xml`, the capability
ledger, and `cleanup-audit.json`. `RESIDUE`, `CLEANUP_UNVERIFIED`, and
`MANUAL_RECONCILIATION_REQUIRED` are failures. To retry cleanup safely:

```bash
bash tests/live/runner.sh --janitor --runs-root /path/to/runs --provider exact-provider-id
```

Do not manually broaden the target. Preserve the sanitized run directory, use
the emitted exact recovery commands, and escalate identity mismatches.
