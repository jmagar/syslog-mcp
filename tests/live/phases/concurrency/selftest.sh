#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"; tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-concurrency.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
for n in 1 2; do python3 "$root/tests/live/phases/concurrency/model.py" --producers 3 --items 300 --queue 8 >"$tmp/$n.json" & done; wait
jq -e '.offered==.accounted and .loss==0 and .accepted+.rejected==.offered' "$tmp/1.json" "$tmp/2.json" >/dev/null
LIVE_RUN_ROOT="$tmp/run"; export LIVE_RUN_ROOT; mkdir -p "$LIVE_RUN_ROOT"; bash "$root/tests/live/phases/concurrency/run.sh"
echo 'concurrency selftest: PASS'
