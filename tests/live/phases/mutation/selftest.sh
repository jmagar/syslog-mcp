#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"; tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-mutation.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
jq -e '.production_runtime_switches==false and (.mutants|length)==9 and ([.mutants[].id]|unique|length)==9' "$root/tests/live/phases/mutation/mutants.json" >/dev/null
python3 "$root/tests/live/phases/mutation/run.py" --manifest "$root/tests/live/phases/mutation/mutants.json" --source "$root" --workspace "$tmp/tree" --killer "$root/tests/live/phases/mutation/killer-selftest.sh" >"$tmp/report"
jq -e '.all_killed and (.results|all(.status=="killed" and (.changed_sha256|length)==64))' "$tmp/report" >/dev/null
! rg -n 'CORTEX_.*MUTANT|MUTANT_ID' "$root/src" >/dev/null
echo 'mutation selftest: PASS'
