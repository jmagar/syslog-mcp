#!/usr/bin/env bash

live_contract_validate_export() {
  local contract="$1"
  jq -e '.version >= 1 and (.entries|type=="array" and length>0) and
    (([.entries[].id]|length)==([.entries[].id]|unique|length)) and
    all(.entries[]; (.id|type=="string" and length>0) and (.kind|type=="string" and length>0) and
      (.profiles|type=="array" and length>0 and all(.[]; IN(
        "smoke","full","storage","soak","isolated","mcp","auth","stateful",
        "agent","security","artifacts","notifications","upgrade","mutation"
      ))) and
      (.required_cases|type=="array" and length>0 and all(.[]; IN("semantic-positive","executed-refusal-semantic","validation-negative","authorization"))))' \
    "$contract" >/dev/null
}

live_contract_export() {
  local destination="$1" tmp source="${LIVE_SURFACE_CONTRACT_SOURCE:-}" digest mode
  tmp="$(mktemp "${LIVE_RUN_ROOT:?}/.surface-contract.XXXXXX")"
  if [[ -n "$source" ]]; then
    [[ -f "$source" && ! -L "$source" ]] || { rm -f "$tmp"; live_die "reused SurfaceContract source missing or unsafe"; return; }
    live_manifest_verify "$source" || { rm -f "$tmp"; return 1; }
    live_contract_validate_export "$source" || { rm -f "$tmp"; live_die "invalid reused SurfaceContract export"; return; }
    cp "$source" "$tmp"; mode=reused
  else
    cargo run --quiet --manifest-path "$LIVE_PROJECT_ROOT/tests/live/surface-exporter/Cargo.toml" >"$tmp" || { rm -f "$tmp"; live_die "compiled SurfaceContract export failed"; return; }
    mode=compiled
  fi
  live_contract_validate_export "$tmp" || { rm -f "$tmp"; live_die "invalid compiled SurfaceContract export"; return; }
  chmod 600 "$tmp"; mv "$tmp" "$destination"; live_manifest_seal "$destination"
  digest="$(live_sha256 "$destination")"
  jq -cn --arg mode "$mode" --arg digest "$digest" --arg source_digest "$([[ "$mode" == reused ]] && live_sha256 "$source" || printf '%s' "$digest")" \
    '{schema:"cortex-live-surface-contract-provenance-v1",mode:$mode,digest:$digest,source_digest:$source_digest,seal_verified:true,validated:true}' \
    >"$LIVE_RUN_ROOT/artifacts/surface-contract-provenance.json"
  live_manifest_seal "$LIVE_RUN_ROOT/artifacts/surface-contract-provenance.json"
  LIVE_SURFACE_CONTRACT="$destination"; export LIVE_SURFACE_CONTRACT
}

live_contract_consume() {
  local contract="$1"
  live_manifest_verify "$contract" || return
  jq -e '.version >= 1 and (.entries|length>0) and (([.entries[].id]|length)==([.entries[].id]|unique|length))' "$contract" >/dev/null || { live_die "invalid authoritative SurfaceContract"; return; }
  LIVE_SURFACE_CONTRACT="$contract"; export LIVE_SURFACE_CONTRACT
}

live_capability_ledger() {
  local contract="$1" profile="$2" events ledger="${LIVE_RUN_ROOT:?}/capability-ledger.jsonl" tmp
  events="$(live_event_file)"
  tmp="$(mktemp "${LIVE_RUN_ROOT}/.ledger.XXXXXX")"
  if [[ "$profile" == stateful ]]; then
    jq -cn '["analytics-boundaries","restart-exactness","projection-lifecycle","projection-watermark","graph-correlation","llm-audit-exactness","evaluator-idempotence","dependency-recovery","structured-observability","failure-stage-diagnostics"][] | {surface_id:("stateful."+.),case_kind:"semantic-positive",mandatory:true}' >"$tmp.required"
  else jq -c --arg profile "$profile" '
    .entries[] | select(.profiles|index($profile)) as $surface |
    $surface.required_cases[] | {surface_id:$surface.id,case_kind:.,mandatory:true}
  ' "$contract" >"$tmp.required"; fi
  jq -cn --slurpfile required "$tmp.required" --slurpfile events "$events" '
    $required[] as $row |
    ($events | map(select(
      .kind=="result" and
      .payload.surface_id==$row.surface_id and
      .payload.case_kind==$row.case_kind and
      .payload.attempt_kind=="first_attempt"
    )) | first | .payload // null) as $outcome |
    $row + {outcome:$outcome}
  ' >"$tmp"
  rm -f "$tmp.required"
  chmod 600 "$tmp"; mv "$tmp" "$ledger"
  LIVE_CAPABILITY_LEDGER="$ledger"; export LIVE_CAPABILITY_LEDGER
}

live_ledger_validate() {
  local contract="$1" profile="$2" ledger
  live_capability_ledger "$contract" "$profile" || return
  ledger="$LIVE_CAPABILITY_LEDGER"
  jq -e -n --slurpfile ledger "$ledger" --slurpfile events "$(live_event_file)" '
    all($ledger[]; . as $row |
      ($row.outcome != null) and
      ($row.outcome.result == "pass" or $row.outcome.result == "fail") and
      ([ $events[] | select(.kind=="result" and .payload.surface_id==$row.surface_id and .payload.case_kind==$row.case_kind and .payload.attempt_kind=="first_attempt") ] | length)==1
    )' >/dev/null ||
    { live_die "mandatory capability missing or qualified/skipped: $profile"; return; }
}
