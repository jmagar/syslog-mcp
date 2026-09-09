#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
jq -e '.candidate=="3.15.0" and (.supported.n_minus_1.image|test("@sha256:[0-9a-f]{64}$")) and (.supported.oldest_scheduled.image|test("@sha256:[0-9a-f]{64}$"))' "$root/contracts/releases/compatibility.json" >/dev/null
bash -n "$root/phases/upgrade/run.sh"
! grep -q 'result:"scheduled"' "$root/phases/upgrade/run.sh"
grep -q 'interrupted_exit.*137' "$root/phases/upgrade/run.sh"
echo 'upgrade selftest: PASS'
