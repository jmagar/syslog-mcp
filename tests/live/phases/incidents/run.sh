#!/usr/bin/env bash
set -euo pipefail
incident_phase_run() {
  local dir="$LIVE_RUN_ROOT/artifacts/incidents" marker="incident-${LIVE_RUN_ID#cortex-e2e-}" host="incident-host-${LIVE_RUN_ID#cortex-e2e-}" sig
  mkdir -p "$dir"
  printf '<11>1 %s %s cortex - - - %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "$host" "$marker" | nc -w 2 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  for _ in $(seq 1 20); do
    notification_mcp '{"action":"unaddressed_errors","limit":100}' "$dir/unaddressed.json"
    sig="$(jq -r --arg m "$marker" '.result.structuredContent.signatures[]?|select(.sample_message|contains($m))|.signature_hash // empty' "$dir/unaddressed.json" | head -1)"; [[ -n "$sig" ]] && break; sleep 1
  done
  [[ -n "$sig" ]]
  notification_mcp "$(jq -cn --arg s "$sig" '{action:"ack_error",signature_hash:$s}')" "$dir/ack.json"; jq -e '.result.isError==false' "$dir/ack.json" >/dev/null
  notification_mcp "$(jq -cn --arg s "$sig" '{action:"ack_error",signature_hash:$s}')" "$dir/ack-cas.json"; jq -e '.result.isError==false' "$dir/ack-cas.json" >/dev/null
  notification_mcp "$(jq -cn --arg s "$sig" '{action:"unack_error",signature_hash:$s}')" "$dir/unack.json"; jq -e '.result.isError==false' "$dir/unack.json" >/dev/null
  notification_mcp '{"action":"notifications_recent","limit":100}' "$dir/audit.json"; jq -e '.result.isError==false and (.result.structuredContent|type=="array")' "$dir/audit.json" >/dev/null
  jq -cn --arg sig "$sig" --arg marker "$marker" '{schema:"cortex-live-incident-lifecycle-v1",signature_hash:$sig,marker:$marker,ack:true,repeat_ack_compare_and_swap_safe:true,unack:true,audit:true}' >"$dir/result.json"
  live_terminal_disposition incidents pass artifacts/incidents/result.json
}
