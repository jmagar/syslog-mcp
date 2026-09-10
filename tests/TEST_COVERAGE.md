# Live qualification coverage

The canonical entry point is `tests/live/run-profile.sh`; `tests/test_live.sh`,
`scripts/smoke-test.sh`, and `scripts/live-cli-sweep.sh` are compatibility
wrappers only. The runner starts real Cortex, oracle, proxy, browser, agent, and
protocol clients as required by each profile. Direct database fixtures count as
setup and never as proof of an ingest route.

The surface contract denominator includes UDP and TCP syslog, OTLP, managed
file-tail, host-local agent and legacy central-pull ingestion plus MCP, REST,
and CLI surfaces. Browser, artifact, and upgrade behavior are scenario
capabilities layered on those transport entries; they are not separate surface
kinds in the generated inventory. Unit coverage remains available through
`just coverage` (`cargo llvm-cov`).

Every required surface must record exactly one first-attempt semantic outcome
and evidence. Missing, duplicate, skipped, unsupported, qualified, or
not-authorized outcomes fail mandatory isolated profiles. Diagnostic retries do
not replace a first failure. A green run also requires cleanup state `CLEAN` and
zero unaccounted contract entries.

Stable commands and cadence are documented in [Live qualification](../docs/LIVE_QUALIFICATION.md).
The complete safety, artifact, troubleshooting, and recovery contract is in
[the harness README](live/README.md).

```bash
just live-selftest
just live-docs-check
just live-smoke
```

<!-- BEGIN GENERATED LIVE INVENTORY -->

This table is generated from the compiled `SurfaceContract` and `profiles.json`; do not edit counts by hand.

| Inventory | Count |
|---|---:|
| mcp surfaces | 60 |
| rest surfaces | 93 |
| cli surfaces | 180 |
| ingest surfaces | 32 |
| artifact surfaces | 0 |
| browser surfaces | 0 |
| all surfaces | 365 |
| runnable profiles | 21 |

Profiles: `agent`, `artifacts`, `auth`, `compose-isolated`, `docker-boundary-full`, `docker-boundary-reduced`, `fleet-mutating`, `fleet-read-only`, `full`, `isolated`, `legacy-central-pull`, `mcp`, `mutation`, `noop`, `notifications`, `security`, `smoke`, `soak`, `stateful`, `storage`, `upgrade`

<!-- END GENERATED LIVE INVENTORY -->
