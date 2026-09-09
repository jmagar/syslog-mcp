#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"; duration="${LIVE_SOAK_SECONDS:-7200}"; interval="${LIVE_SOAK_SAMPLE_SECONDS:-15}"; warmup="${LIVE_SOAK_WARMUP_SECONDS:-300}"
[[ "$duration" =~ ^[0-9]+$ && "$duration" -ge 1 && "$duration" -le 21600 ]] || { echo 'soak duration must be 1..21600 seconds' >&2; exit 2; }
out="${LIVE_RUN_ROOT:?}/artifacts/soak"; mkdir -p "$out"; collector_pid=""; cycles=0
cleanup() {
  local began ended
  began="$(date +%s)"
  [[ -z "$collector_pid" ]] || { kill -TERM "$collector_pid" 2>/dev/null || true; wait "$collector_pid" 2>/dev/null || true; }
  ended="$(date +%s)"; jq -cn --argjson ms "$(((ended-began)*1000))" '{schema:"cortex-live-soak-cleanup-v1",clean:true,cleanup_ms:$ms}' >"$out/cleanup.json"
}
trap cleanup HUP INT TERM EXIT
if [[ -n "${LIVE_SOAK_CONTAINER:-}" ]]; then
  python3 "$root/tests/live/phases/telemetry/collector.py" --output "$out/telemetry.jsonl" --duration "$duration" --interval "$interval" --cap-bytes "${LIVE_SOAK_ARTIFACT_CAP:-8388608}" --container "$LIVE_SOAK_CONTAINER" >"$out/collector.json" & collector_pid=$!
else
  python3 "$root/tests/live/phases/telemetry/collector.py" --output "$out/telemetry.jsonl" --duration "$duration" --interval "$interval" --cap-bytes "${LIVE_SOAK_ARTIFACT_CAP:-8388608}" >"$out/collector.json" & collector_pid=$!
fi
# Run a bounded live ingest and query cycle throughout collection. An optional
# command may add admin/restart work, but cannot replace the mandatory workload.
while kill -0 "$collector_pid" 2>/dev/null; do
  marker="soak-${LIVE_RUN_ID:-selftest}-$cycles"
  if [[ -n "${LIVE_SOAK_CONTAINER:-}" ]]; then
    printf '<14>1 2026-08-27T12:00:01Z soak-host soak 1 ID47 - %s\n' "$marker" | nc -w 2 127.0.0.1 "${LIVE_SYSLOG_TCP_PORT:?}" || { echo ingest-cycle-failure >>"$out/significant-events.log"; exit 1; }
    curl -fsS --max-time 10 -H 'Host: localhost' "http://127.0.0.1:${LIVE_HTTP_PORT:?}/health" >>"$out/cycles.log" || { echo query-cycle-failure >>"$out/significant-events.log"; exit 1; }
  else
    printf '%s\n' "$marker" >>"$out/cycles.log"
  fi
  cycles=$((cycles+1))
  if [[ -n "${LIVE_SOAK_CYCLE_COMMAND:-}" ]]; then bash -c "$LIVE_SOAK_CYCLE_COMMAND" >>"$out/cycles.log" 2>&1 || { echo cycle-failure >>"$out/significant-events.log"; exit 1; }; fi
  cycle_sleep="${LIVE_SOAK_CYCLE_SECONDS:-30}"; awk -v n="$cycle_sleep" 'BEGIN{exit !(n>1)}' && cycle_sleep=1
  sleep "$cycle_sleep" & wait $! || true
done
wait "$collector_pid"; collector_pid=""
(( cycles > 0 )) || { echo 'soak performed no workload cycles' >&2; exit 1; }
analysis_args=(--warmup-seconds "$warmup"
  --hard rss_bytes="${LIVE_SOAK_HARD_RSS_BYTES:-4294967296}" --hard fds="${LIVE_SOAK_HARD_FDS:-4096}" --hard tasks="${LIVE_SOAK_HARD_TASKS:-2048}"
  --warn-slope rss_bytes="${LIVE_SOAK_WARN_RSS_SLOPE:-1048576}" --warn-slope fds="${LIVE_SOAK_WARN_FD_SLOPE:-0.05}")
[[ -z "${LIVE_SOAK_CONTAINER:-}" ]] || analysis_args+=(--warn-slope wal_bytes="${LIVE_SOAK_WARN_WAL_SLOPE:-1048576}")
python3 "$root/tests/live/phases/telemetry/analyze.py" "$out/telemetry.jsonl" "${analysis_args[@]}" >"$out/analysis.json"
trap - HUP INT TERM EXIT; cleanup
jq --argjson cycles "$cycles" '.+{workload_cycles:$cycles}' "$out/analysis.json" >"$out/analysis.tmp"; mv "$out/analysis.tmp" "$out/analysis.json"
jq -e '.pass and .measured_samples>=1 and .workload_cycles>0' "$out/analysis.json" >/dev/null
echo 'soak run: PASS'
