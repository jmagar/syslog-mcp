#!/usr/bin/env bash
set -euo pipefail

fleet_operation_allowed() {
  case "$1" in
    ingest-low-tagged|heartbeat-tagged|notification-test|admin-audit|restart|file-tail|agent-deploy) return 0;;
    *) echo "mutation prohibited by default: $1" >&2; return 2;;
  esac
}

fleet_mutation_preflight() {
  local baseline="$1" current="$2" grant="$3" operation="$4" key="$5" ledger="$6"
  fleet_operation_allowed "$operation" || return
  fleet_target_revalidate "$baseline" "$current" || return
  local digest identity
  digest="$(fleet_target_digest "$baseline")"
  identity="$(jq -c '{base_url,resolved_ip,tls_spki_sha256,server_instance_id,server_version,deployment_id,database_fingerprint,compose_project:.compose.project,compose_service:.compose.service,compose_container_id:.compose.container_id}' "$baseline")"
  fleet_grant_validate "$grant" "$digest" "$operation" "$key" "$ledger" || return
  [[ "$(jq -cS .identity "$grant")" == "$(jq -cS . <<<"$identity")" ]] || { echo "grant identity mismatch" >&2; return 3; }
}

fleet_cas_rollback() {
  local expected_suite_state="$1" current_state="$2" rollback_argv_json="$3" audit="$4" argv=()
  if [[ "$expected_suite_state" != "$current_state" ]]; then
    jq -n --arg expected "$expected_suite_state" --arg current "$current_state" '{status:"MANUAL_RECONCILIATION_REQUIRED",reason:"concurrent operator mutation",expected_suite_state:$expected,current_state:$current}' >"$audit"
    return 4
  fi
  while IFS= read -r arg; do argv+=("$arg"); done < <(jq -r '.[]' <<<"$rollback_argv_json")
  "${argv[@]}"
}

fleet_residual_report() {
  local output="$1" run_id="$2" exact_records="$3" resources="$4" heartbeats="${5:-0}"
  jq -n --arg run_id "$run_id" --argjson records "$exact_records" --argjson resources "$resources" --argjson heartbeats "$heartbeats" \
    '{schema:"cortex-live-fleet-residual-v1",run_id:$run_id,retained_tagged_records:$records,retained_tagged_heartbeats:$heartbeats,residual_resources:$resources,append_only_residual:($records>0 or $heartbeats>0),green:($resources==0)}' >"$output"
}
