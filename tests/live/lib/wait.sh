#!/usr/bin/env bash

live_wait_history_file() { printf '%s/artifacts/poll-history.jsonl\n' "${LIVE_RUN_ROOT:?}"; }

live_wait_until() {
  local timeout="$1" description="$2"; shift 2
  local started now attempt=0 delay_ms=100 max_delay_ms=2000 history
  started="$(date +%s)"; history="$(live_wait_history_file)"; touch "$history"; chmod 600 "$history"
  while true; do
    ((attempt+=1)); live_budget_add poll_attempts 1
    live_budget_sample_process || true
    if "$@"; then
      _live_append_line "$history" "$(jq -cn --arg d "$description" --argjson a "$attempt" --arg r ready '{description:$d,attempt:$a,result:$r}')"
      live_event poll "$(jq -cn --arg d "$description" --argjson a "$attempt" '{description:$d,attempts:$a,result:"ready"}')"
      return 0
    fi
    now="$(date +%s)"
    _live_append_line "$history" "$(jq -cn --arg d "$description" --argjson a "$attempt" --argjson elapsed "$((now-started))" '{description:$d,attempt:$a,result:"retry",elapsed_seconds:$elapsed}')"
    if (( now - started >= timeout )); then
      live_event poll "$(jq -cn --arg d "$description" --argjson a "$attempt" '{description:$d,attempts:$a,result:"timeout"}')"
      return 124
    fi
    # Centralized capped exponential backoff with deterministic run-derived jitter.
    local jitter=$(( (16#${LIVE_RUN_ID: -2} + attempt * 17) % 41 ))
    sleep "$(awk -v ms="$((delay_ms+jitter))" 'BEGIN {printf "%.3f", ms/1000}')"
    delay_ms=$((delay_ms*2)); (( delay_ms > max_delay_ms )) && delay_ms=$max_delay_ms
  done
}
