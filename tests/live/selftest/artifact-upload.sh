#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/work/runs/cortex-e2e-fixture"
run="$tmp/work/runs/cortex-e2e-fixture"
printf '{"status":"pass"}\n' >"$run/summary.json"
printf '{"state":"CLEAN"}\n' >"$run/cleanup-audit.json"
printf '{"status":"pass"}\n' >"$tmp/work/runs/aggregate-qualification.json"
printf 'must not upload\n' >"$run/arbitrary.log"
(
  cd "$tmp/work"
  bash "$root/scripts/ci/prepare-live-artifacts.sh" runs upload
)
[[ -f "$tmp/work/upload/cortex-e2e-fixture/summary.json" ]]
[[ -f "$tmp/work/upload/cortex-e2e-fixture/cleanup-audit.json" ]]
[[ -f "$tmp/work/upload/aggregate-qualification.json" ]]
[[ ! -e "$tmp/work/upload/cortex-e2e-fixture/arbitrary.log" ]]

rm "$run/cleanup-audit.json"
if (cd "$tmp/work" && bash "$root/scripts/ci/prepare-live-artifacts.sh" runs missing-cleanup) >/dev/null 2>&1; then
  echo 'completed run without cleanup evidence was accepted' >&2
  exit 1
fi
printf '{"state":"CLEAN"}\n' >"$run/cleanup-audit.json"

printf '{"token":"credential-shaped-value-123456"}\n' >"$run/summary.json"
if (cd "$tmp/work" && bash "$root/scripts/ci/prepare-live-artifacts.sh" runs rejected) >/dev/null 2>&1; then
  echo 'credential-bearing sanitized artifact was accepted' >&2
  exit 1
fi
echo 'artifact upload sanitizer selftest: PASS'
