#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"; tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-soak.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
LIVE_RUN_ROOT="$tmp/run" LIVE_SOAK_SECONDS=2 LIVE_SOAK_SAMPLE_SECONDS=.2 LIVE_SOAK_WARMUP_SECONDS=0 LIVE_SOAK_CYCLE_SECONDS=1 bash "$root/tests/live/profiles/soak/run.sh"
jq -e '.pass and .samples>=2 and .workload_cycles>0 and (.slopes_per_second|has("rss_bytes") and has("fds") and has("tasks") and has("artifact_bytes"))' "$tmp/run/artifacts/soak/analysis.json" >/dev/null
jq -e '.clean and .cleanup_ms>=0' "$tmp/run/artifacts/soak/cleanup.json" >/dev/null
# External janitor model: TERM an orphanable runner and independently verify its cleanup evidence.
LIVE_RUN_ROOT="$tmp/term" LIVE_SOAK_SECONDS=60 LIVE_SOAK_SAMPLE_SECONDS=.2 LIVE_SOAK_CYCLE_SECONDS=1 bash "$root/tests/live/profiles/soak/run.sh" >"$tmp/term.log" 2>&1 & pid=$!; sleep .5; kill -TERM "$pid"; wait "$pid" || true
jq -e '.clean' "$tmp/term/artifacts/soak/cleanup.json" >/dev/null
echo 'soak selftest: PASS'
