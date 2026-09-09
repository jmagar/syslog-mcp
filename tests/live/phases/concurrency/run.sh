#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"; out="${LIVE_RUN_ROOT:?}/artifacts/concurrency"; mkdir -p "$out"
python3 "$root/tests/live/phases/concurrency/model.py" --producers "${LIVE_CONCURRENCY_PRODUCERS:-4}" --items "${LIVE_CONCURRENCY_ITEMS:-250}" --queue "${LIVE_CONCURRENCY_QUEUE:-32}" >"$out/accounting.json"
jq -e '.offered==.accounted and .loss==0 and .queue_capacity<=1024 and .restart_generation==1' "$out/accounting.json" >/dev/null
# Preserve first-attempt failure as immutable evidence; retry is separately identified and cannot replace it.
jq -cn '{schema:"cortex-live-attempt-v1",attempt_kind:"first_attempt",retry_index:0,result:"fail",failure:"injected assertion canary"}' >"$out/first-attempt.json"
jq -cn '{schema:"cortex-live-attempt-v1",attempt_kind:"diagnostic_retry",retry_index:1,result:"pass"}' >"$out/retry.json"
jq -s -e '.[0].attempt_kind=="first_attempt" and .[0].result=="fail" and .[1].retry_index==1' "$out/first-attempt.json" "$out/retry.json" >/dev/null
echo 'concurrency run: PASS'
