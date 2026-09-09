#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
export LIVE_PROJECT_ROOT="$root"
for lib in common lock redact events report; do
  # shellcheck disable=SC1090
  source "$root/tests/live/lib/$lib.sh"
done
tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-disposition-selftest.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
live_init_run "$tmp" >/dev/null
jq -cn '{disposition:"platform-qualified",green:false}' >"$LIVE_RUN_ROOT/mutant.json"; chmod 600 "$LIVE_RUN_ROOT/mutant.json"
live_terminal_disposition topology.mutant platform-qualified mutant.json
live_report >/dev/null
jq -e '.total==1 and .passed==0 and .failed==0 and .qualified==1' "$LIVE_RUN_ROOT/summary.json" >/dev/null
grep -q '<skipped message="platform-qualified"/>' "$LIVE_RUN_ROOT/junit.xml"
if live_summary_accepts_profile isolated "$root/tests/live/contracts/profiles.json" "$LIVE_RUN_ROOT/summary.json"; then
  echo "mandatory isolated profile falsely accepted qualified mutant" >&2; exit 1
fi
echo "isolated disposition selftest: PASS"
