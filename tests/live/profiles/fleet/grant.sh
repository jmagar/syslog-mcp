#!/usr/bin/env bash
set -euo pipefail

fleet_grant_payload() { jq -cS 'del(.signature)' "$1"; }

fleet_grant_sign() {
  local grant="$1" key="$2" payload signature tmp
  payload="$(fleet_grant_payload "$grant")"
  signature="$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$key" -binary | openssl base64 -A)"
  tmp="$grant.tmp.$$"; jq --arg signature "$signature" '.signature=$signature' "$grant" >"$tmp"; chmod 600 "$tmp"; mv "$tmp" "$grant"
}

fleet_grant_validate() {
  local grant="$1" target_digest="$2" operation="$3" key="$4" ledger="$5" now="${6:-$(date +%s)}" run_id="${LIVE_RUN_ID:-}"
  [[ -f "$grant" && ! -L "$grant" && -n "$key" ]] || return 2
  local payload expected actual expires nonce max used
  payload="$(fleet_grant_payload "$grant")"
  expected="$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$key" -binary | openssl base64 -A)"
  actual="$(jq -r .signature "$grant")"
  [[ "$(printf '%s' "$expected" | shasum -a 256)" == "$(printf '%s' "$actual" | shasum -a 256)" && "$expected" == "$actual" ]] || return 3
  jq -e --arg d "$target_digest" --arg op "$operation" --arg run "$run_id" '
    .schema=="cortex-live-mutation-grant-v1" and .target_digest==$d and .run_id==$run and
    ((.identity|type)=="object" and
      ((["base_url","resolved_ip","tls_spki_sha256","server_instance_id","server_version","deployment_id","database_fingerprint","compose_project","compose_service","compose_container_id"] - (.identity|keys))|length)==0) and
    (.operations|type=="array" and index($op)!=null) and (.nonce|test("^[A-Za-z0-9._-]{16,}$")) and
    (.max_mutations|type=="number" and .>=1 and .<=10) and (.expires_epoch|type=="number")
  ' "$grant" >/dev/null || return 3
  expires="$(jq -r .expires_epoch "$grant")"; nonce="$(jq -r .nonce "$grant")"; max="$(jq -r .max_mutations "$grant")"
  (( now < expires && expires - now <= 900 )) || return 3
  used=0; [[ ! -f "$ledger" ]] || used="$(jq -rs --arg n "$nonce" '[.[]|select(.nonce==$n and .state=="RESERVED")]|map(.reservation_id)|unique|length' "$ledger")"
  (( used < max )) || return 3
}

fleet_grant_reserve() {
  local grant="$1" target_digest="$2" operation="$3" key="$4" ledger="$5" now="${6:-$(date +%s)}" reservation_id
  reservation_id="${LIVE_RUN_ID}-${operation}-$(openssl rand -hex 8)"
  local lock="${ledger}.lock" tries=0 tmp
  while ! mkdir "$lock" 2>/dev/null; do ((tries+=1)); ((tries<100)) || return 4; sleep .05; done
  if ! fleet_grant_validate "$grant" "$target_digest" "$operation" "$key" "$ledger" "$now"; then rmdir "$lock"; return 3; fi
  tmp="${ledger}.tmp.$$"; { [[ ! -f "$ledger" ]] || cat "$ledger"; jq -cn --arg reservation_id "$reservation_id" --arg nonce "$(jq -r .nonce "$grant")" --arg operation "$operation" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{reservation_id:$reservation_id,nonce:$nonce,operation:$operation,state:"RESERVED",at:$at}'; } >"$tmp"
  chmod 600 "$tmp"; mv "$tmp" "$ledger"; rmdir "$lock"; printf '%s\n' "$reservation_id"
}

fleet_grant_finalize() {
  local ledger="$1" reservation_id="$2" state="$3" detail="$4"
  [[ "$state" == SUCCEEDED || "$state" == FAILED ]] || return 2
  local lock="${ledger}.lock" tmp; while ! mkdir "$lock" 2>/dev/null; do sleep .05; done
  jq -e --arg id "$reservation_id" 'select(.reservation_id==$id and .state=="RESERVED")' "$ledger" >/dev/null || { rmdir "$lock"; return 3; }
  tmp="${ledger}.tmp.$$"; { cat "$ledger"; jq -cn --arg id "$reservation_id" --arg state "$state" --arg detail "$detail" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{reservation_id:$id,state:$state,detail:$detail,at:$at}'; } >"$tmp"; chmod 600 "$tmp"; mv "$tmp" "$ledger"; rmdir "$lock"
}

fleet_grant_consume() {
  local grant="$1" operation="$2" ledger="$3" before_digest="$4" after_digest="$5"
  umask 077
  local lock="${ledger}.lock" tries=0 tmp
  while ! mkdir "$lock" 2>/dev/null; do ((tries+=1)); ((tries<100)) || return 4; sleep .05; done
  trap 'rmdir "$lock" 2>/dev/null || true' RETURN
  tmp="${ledger}.tmp.$$"; { [[ ! -f "$ledger" ]] || cat "$ledger"; jq -cn --arg nonce "$(jq -r .nonce "$grant")" --arg operation "$operation" --arg before "$before_digest" --arg after "$after_digest" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{nonce:$nonce,operation:$operation,before_digest:$before,after_digest:$after,at:$at}'; } >"$tmp"
  chmod 600 "$tmp"; mv "$tmp" "$ledger"; rmdir "$lock"; trap - RETURN
}

fleet_grant_validate_and_consume() {
  local grant="$1" target_digest="$2" operation="$3" key="$4" ledger="$5" before="$6" after="$7" now="${8:-$(date +%s)}"
  local lock="${ledger}.lock" tries=0 tmp
  while ! mkdir "$lock" 2>/dev/null; do ((tries+=1)); ((tries<100)) || return 4; sleep .05; done
  if ! fleet_grant_validate "$grant" "$target_digest" "$operation" "$key" "$ledger" "$now"; then rmdir "$lock"; return 3; fi
  tmp="${ledger}.tmp.$$"
  { [[ ! -f "$ledger" ]] || cat "$ledger"; jq -cn --arg nonce "$(jq -r .nonce "$grant")" --arg operation "$operation" --arg before "$before" --arg after "$after" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{nonce:$nonce,operation:$operation,before_digest:$before,after_digest:$after,at:$at}'; } >"$tmp"
  chmod 600 "$tmp"; mv "$tmp" "$ledger"; rmdir "$lock"
}
