#!/usr/bin/env bash

live_budget_start() {
  LIVE_STARTED_EPOCH="$(date +%s)"; export LIVE_STARTED_EPOCH
  LIVE_BUDGET_METRICS="${LIVE_RUN_ROOT:?}/budget-metrics.json"
  jq -cn '{cpu_seconds:0,rss_bytes:0,fixture_records:0,fixture_bytes:0,poll_attempts:0,connections:0,processes:0}' >"$LIVE_BUDGET_METRICS"
  chmod 600 "$LIVE_BUDGET_METRICS"; export LIVE_BUDGET_METRICS
}

live_budget_observe() {
  local metric="$1" value="$2" tmp
  case "$metric" in cpu_seconds|rss_bytes|fixture_records|fixture_bytes|poll_attempts|connections|processes) ;; *) live_die "unknown budget metric"; return;; esac
  [[ "$value" =~ ^[0-9]+$ ]] || { live_die "budget observation must be non-negative integer"; return; }
  tmp="$(mktemp "${LIVE_RUN_ROOT}/.budget.XXXXXX")"
  jq --arg metric "$metric" --argjson value "$value" '.[$metric] = ([.[$metric],$value]|max)' "$LIVE_BUDGET_METRICS" >"$tmp"
  chmod 600 "$tmp"; mv "$tmp" "$LIVE_BUDGET_METRICS"
}

live_budget_add() {
  local metric="$1" amount="$2" current
  current="$(jq -r --arg metric "$metric" '.[$metric] // empty' "${LIVE_BUDGET_METRICS:?}")"
  [[ "$current" =~ ^[0-9]+$ && "$amount" =~ ^[0-9]+$ ]] || { live_die "invalid additive budget metric"; return; }
  live_budget_observe "$metric" "$((current + amount))"
}

live_fixture_account() { live_budget_add fixture_records "$1"; live_budget_add fixture_bytes "$2"; }
live_connection_opened() { live_budget_add connections "${1:-1}"; }

live_budget_sample_process() {
  local rss_kb cpu_text cpu_seconds=0 processes
  rss_kb="$(ps -o rss= -p $$ | tr -d ' ')"; [[ "$rss_kb" =~ ^[0-9]+$ ]] || { live_die "cannot measure RSS"; return; }
  cpu_text="$(ps -o time= -p $$ | tr -d ' ')"
  if [[ "$cpu_text" =~ ^([0-9]+):([0-9][0-9])\.([0-9][0-9])$ ]]; then cpu_seconds=$((10#${BASH_REMATCH[1]} * 60 + 10#${BASH_REMATCH[2]}));
  elif [[ "$cpu_text" =~ ^([0-9]+):([0-9][0-9]):([0-9][0-9])$ ]]; then cpu_seconds=$((10#${BASH_REMATCH[1]} * 3600 + 10#${BASH_REMATCH[2]} * 60 + 10#${BASH_REMATCH[3]}));
  else live_die "cannot measure CPU time: $cpu_text"; return; fi
  processes="$(pgrep -P $$ 2>/dev/null | wc -l | tr -d ' ')"
  live_budget_observe rss_bytes "$((rss_kb * 1024))"
  live_budget_observe cpu_seconds "$cpu_seconds"
  live_budget_observe processes "$processes"
}

live_tree_bytes() {
  local root="$1"
  if stat -f '%z' "$root" >/dev/null 2>&1; then
    find "$root" -type f -exec stat -f '%z' {} \; | awk '{n+=$1} END {print n+0}'
  else
    find "$root" -type f -exec stat -c '%s' {} \; | awk '{n+=$1} END {print n+0}'
  fi
}

live_budget_check() {
  local profile="$1" config="$2" elapsed artifact_bytes disk_bytes metrics limits
  [[ -f "${LIVE_BUDGET_METRICS:-}" && ! -L "$LIVE_BUDGET_METRICS" ]] || { live_die "budget metrics missing"; return; }
  live_budget_sample_process || return
  elapsed="$(( $(date +%s) - ${LIVE_STARTED_EPOCH:?} ))"
  artifact_bytes="$(live_tree_bytes "${LIVE_RUN_ROOT:?}/artifacts")"
  disk_bytes="$(live_tree_bytes "$LIVE_RUN_ROOT")"
  metrics="$(jq --argjson elapsed "$elapsed" --argjson artifacts "$artifact_bytes" --argjson disk "$disk_bytes" '. + {wall_seconds:$elapsed,artifact_bytes:$artifacts,disk_bytes:$disk}' "$LIVE_BUDGET_METRICS")"
  limits="$(jq -c --arg p "$profile" '.profiles[$p]' "$config")"
  jq -e --argjson limits "$limits" '
    (["wall_seconds","cpu_seconds","rss_bytes","disk_bytes","artifact_bytes","fixture_records","fixture_bytes","poll_attempts","connections","processes"] | all(.[]; ($limits[.]|type)=="number" and ($limits[.]>=0))) and
    all(to_entries[]; .value <= $limits[.key])
  ' <<<"$metrics" >/dev/null || { live_event budget_exceeded "$(jq -cn --argjson observed "$metrics" --argjson limits "$limits" '{observed:$observed,limits:$limits}')"; live_die "run budget exceeded or incomplete"; return; }
  live_event budget "$(jq -cn --argjson observed "$metrics" --argjson limits "$limits" '{observed:$observed,limits:$limits}')"
}
