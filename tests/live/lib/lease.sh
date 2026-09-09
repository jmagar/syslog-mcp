#!/usr/bin/env bash

live_lease_write() {
  local ttl="${1:-60}" file="${LIVE_RUN_ROOT:?}/lease.json" tmp
  [[ "$ttl" =~ ^[1-9][0-9]*$ ]] || { live_die "invalid lease ttl"; return; }
  [[ ! -L "$file" ]] || { live_die "refusing symlink lease"; return; }
  tmp="$(mktemp "${LIVE_RUN_ROOT}/.lease.XXXXXX")"
  jq -cn --arg run_id "$LIVE_RUN_ID" --argjson expires "$(( $(date +%s) + ttl ))" '{run_id:$run_id,expires_epoch:$expires}' >"$tmp"
  chmod 600 "$tmp"; mv -f "$tmp" "$file"
}

live_lease_heartbeat_start() {
  local ttl="${1:-180}" interval="${2:-30}"
  [[ "$ttl" =~ ^[1-9][0-9]*$ && "$interval" =~ ^[1-9][0-9]*$ && "$interval" -lt "$ttl" ]] || {
    live_die "invalid lease heartbeat"; return
  }
  (
    trap 'exit 0' HUP INT TERM
    local elapsed=0
    while :; do
      sleep 1 || exit 0
      elapsed=$((elapsed + 1))
      if (( elapsed >= interval )); then
        live_lease_write "$ttl" || exit 1
        elapsed=0
      fi
    done
  ) &
  LIVE_LEASE_HEARTBEAT_PID=$!; export LIVE_LEASE_HEARTBEAT_PID
}

live_lease_heartbeat_stop() {
  [[ -z "${LIVE_LEASE_HEARTBEAT_PID:-}" ]] || {
    kill -TERM "$LIVE_LEASE_HEARTBEAT_PID" 2>/dev/null || true
    wait "$LIVE_LEASE_HEARTBEAT_PID" 2>/dev/null || true
    LIVE_LEASE_HEARTBEAT_PID=""
  }
}

live_lease_expired() { jq -e '.run_id|type=="string" and length>0' "$1" >/dev/null && [[ "$(jq -r .expires_epoch "$1")" -lt "$(date +%s)" ]]; }

live_audit_write() {
  local state="$1" reason="$2" file="${LIVE_RUN_ROOT:?}/cleanup-audit.json" tmp
  case "$state" in CLEAN|RESIDUE|CLEANUP_UNVERIFIED|MANUAL_RECONCILIATION_REQUIRED) ;; *) live_die "invalid audit state";; esac
  tmp="$(mktemp "${LIVE_RUN_ROOT}/.audit.XXXXXX")"
  jq -cn --arg run_id "$LIVE_RUN_ID" --arg state "$state" --arg reason "$reason" '{run_id:$run_id,state:$state,reason:$reason}' >"$tmp"
  chmod 600 "$tmp"; mv -f "$tmp" "$file"
}

live_janitor() {
  local runs_root="$1" provider="$2" lease root status=0 cleanup_status
  for lease in "$runs_root"/cortex-e2e-*/lease.json; do
    [[ -f "$lease" && ! -L "$lease" ]] || continue
    live_lease_expired "$lease" || continue
    root="$(dirname "$lease")"
    LIVE_RUN_ROOT="$root" LIVE_RUN_ID="$(basename "$root")"; export LIVE_RUN_ROOT LIVE_RUN_ID
    cleanup_status=0
    live_cleanup_resources "$provider" || cleanup_status=$?
    if (( cleanup_status != 0 )); then
      echo "janitor failed to reconcile $LIVE_RUN_ID (status $cleanup_status)" >&2
      (( status == 0 )) && status=$cleanup_status
    fi
  done
  return "$status"
}
