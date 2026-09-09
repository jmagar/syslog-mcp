#!/usr/bin/env bash
set -euo pipefail
fleet_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$fleet_dir/target.sh"; source "$fleet_dir/grant.sh"; source "$fleet_dir/mutations.sh"
manifest="${LIVE_TARGET_MANIFEST:?}"; grants_dir="${LIVE_MUTATION_GRANTS_DIR:?}"; key="${LIVE_MUTATION_GRANT_KEY:?}"; ledger="$LIVE_RUN_ROOT/fleet-grant-ledger.jsonl"
digest="$(fleet_target_digest "$manifest")"; run_tag="$LIVE_RUN_ID"; retained=0
fleet_grant_for() { local file="$grants_dir/$1.json"; [[ -f "$file" && ! -L "$file" ]] || return 1; printf '%s\n' "$file"; }

fleet_before_each() {
  local operation="$1" snap
  snap="$LIVE_RUN_ROOT/revalidate-${operation}.json"
  fleet_target_snapshot "$manifest" "$LIVE_FLEET_READ_TOKEN" "$snap" "before-$operation"
  local operation_grant; operation_grant="$(fleet_grant_for "$operation")" || { echo "missing independent grant: $operation" >&2; return 3; }
  fleet_mutation_preflight "$manifest" "$manifest" "$operation_grant" "$operation" "$key" "$ledger"
}

if grant="$(fleet_grant_for ingest-low-tagged 2>/dev/null)"; then
  fleet_before_each ingest-low-tagged
  reservation="$(fleet_grant_reserve "$grant" "$digest" ingest-low-tagged "$key" "$ledger")"
  payload_file="$LIVE_RUN_ROOT/tagged-log.pb"; python3 "$fleet_dir/otlp_payload.py" "cortex-live-tag=$run_tag" >"$payload_file"
  if fleet_curl "$manifest" /v1/logs -H "Authorization: Bearer ${LIVE_FLEET_INGEST_TOKEN:?}" -H 'Content-Type: application/x-protobuf' --data-binary "@$payload_file" >/dev/null; then fleet_grant_finalize "$ledger" "$reservation" SUCCEEDED retained; else fleet_grant_finalize "$ledger" "$reservation" FAILED remote-error; exit 1; fi
  retained=$((retained+1))
fi

if grant="$(fleet_grant_for heartbeat-tagged 2>/dev/null)"; then
  fleet_before_each heartbeat-tagged
  reservation="$(fleet_grant_reserve "$grant" "$digest" heartbeat-tagged "$key" "$ledger")"
  heartbeat="$(jq -cn --arg tag "$run_tag" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{host:{host_id:("cortex-live-"+$tag),hostname:("cortex-live-"+$tag),os:"test",kernel:"test",architecture:"test",boot_id:$tag,timezone:"UTC"},sample:{sequence:1,sampled_at:$at,uptime_secs:1,monotonic_ms:1,collection_ms:1,partial:false,probe_errors:[],skipped_probes:[]},agent:{version:"live",mode:"test",interval_secs:60,push_latency_ms:1,retry_backlog:0},cpu:{load1:0,load5:0,load15:0,usage_pct:0,iowait_pct:0,steal_pct:0,core_count:1},memory:{mem_total_bytes:1,mem_available_bytes:1,swap_total_bytes:0,swap_used_bytes:0},disks:[],network:[]}')"
  if fleet_curl "$manifest" /v1/heartbeats -H "Authorization: Bearer ${LIVE_FLEET_INGEST_TOKEN:?}" -H 'Content-Type: application/json' -d "$heartbeat" >/dev/null; then fleet_grant_finalize "$ledger" "$reservation" SUCCEEDED retained; else fleet_grant_finalize "$ledger" "$reservation" FAILED remote-error; exit 1; fi
  retained=$((retained+1))
fi

if grant="$(fleet_grant_for notification-test 2>/dev/null)"; then
  fleet_before_each notification-test
  [[ -n "${LIVE_NOTIFICATION_DESTINATION:-}" ]] || { echo "notification destination/effects not configured" >&2; return 3; }
  reservation="$(fleet_grant_reserve "$grant" "$digest" notification-test "$key" "$ledger")"
  if fleet_curl "$manifest" /api/notifications/test -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN" -H "x-cortex-admin-token: $LIVE_FLEET_ADMIN_TOKEN" -H 'Content-Type: application/json' -d "$(jq -cn --arg d "$LIVE_NOTIFICATION_DESTINATION" '{destination:$d}')" >/dev/null; then fleet_grant_finalize "$ledger" "$reservation" SUCCEEDED sent; else fleet_grant_finalize "$ledger" "$reservation" FAILED remote-error; exit 1; fi
fi

if grant="$(fleet_grant_for admin-audit 2>/dev/null)"; then
  fleet_before_each admin-audit; reservation="$(fleet_grant_reserve "$grant" "$digest" admin-audit "$key" "$ledger")"
  if fleet_curl "$manifest" /api/sessions/llm-invocations -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN" -H "x-cortex-admin-token: $LIVE_FLEET_ADMIN_TOKEN" >"$LIVE_RUN_ROOT/admin-audit.json"; then fleet_grant_finalize "$ledger" "$reservation" SUCCEEDED read-only; else fleet_grant_finalize "$ledger" "$reservation" FAILED denied; exit 1; fi
fi

if grant="$(fleet_grant_for restart 2>/dev/null)"; then
  fleet_before_each restart; [[ "$(jq -r .target_id "$manifest")" == actual-isolated* ]] || exit 3
  container="$(jq -r .compose.container_id "$manifest")"; before="$(docker inspect -f '{{.Id}}:{{.State.StartedAt}}' "$container")"
  owner="$(docker inspect -f '{{index .Config.Labels "cortex.live.run_id"}}' "$container")"; [[ -n "$owner" ]] || exit 3
  reservation="$(fleet_grant_reserve "$grant" "$digest" restart "$key" "$ledger")"
  if docker restart "$container" >/dev/null && [[ "$(docker inspect -f '{{.Id}}' "$container")" == "${before%%:*}" ]]; then
    ready=0; for _ in $(seq 1 30); do if fleet_curl "$manifest" /api/version -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN" >/dev/null 2>&1; then ready=1; break; fi; sleep 1; done
    (( ready==1 )) || { fleet_grant_finalize "$ledger" "$reservation" FAILED readiness-timeout; exit 1; }
    fleet_grant_finalize "$ledger" "$reservation" SUCCEEDED "$owner"
  else fleet_grant_finalize "$ledger" "$reservation" FAILED restart-failed; exit 1; fi
fi

if grant="$(fleet_grant_for agent-deploy 2>/dev/null)"; then
  fleet_before_each agent-deploy; [[ "$(jq -r .target_id "$manifest")" == actual-isolated* ]] || exit 3
  name="${LIVE_RUN_ID}-agent-validation"; reservation="$(fleet_grant_reserve "$grant" "$digest" agent-deploy "$key" "$ledger")"
  jq -n --arg run "$LIVE_RUN_ID" '{run_id:$run,mode:"validate-only",target:"disposable"}' >"$LIVE_RUN_ROOT/agent-config.json"
  if docker run --rm --name "$name" --label "cortex.live.run_id=$LIVE_RUN_ID" -v "$LIVE_RUN_ROOT/agent-config.json:/agent/config.json:ro" busybox:1.36 test -s /agent/config.json; then fleet_grant_finalize "$ledger" "$reservation" SUCCEEDED validated-and-removed; else docker rm -f "$name" >/dev/null 2>&1 || true; fleet_grant_finalize "$ledger" "$reservation" FAILED validation-failed; exit 1; fi
fi

if grant="$(fleet_grant_for file-tail 2>/dev/null)"; then
  fleet_before_each file-tail; [[ "$(jq -r .target_id "$manifest")" == actual-isolated* ]] || exit 3
  id="live-$(printf '%s' "$LIVE_RUN_ID" | shasum -a 256 | cut -c1-12)"; path="/file-tail-root/${id}.log"; container="$(jq -r .compose.container_id "$manifest")"
  before_list="$(fleet_curl "$manifest" /api/file-tails -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN" -H "x-cortex-admin-token: $LIVE_FLEET_ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"op":"list"}')"
  reservation="$(fleet_grant_reserve "$grant" "$digest" file-tail "$key" "$ledger")"; docker exec -u 0 "$container" sh -c "mkdir -p /file-tail-root && chmod 777 /file-tail-root"; docker exec "$container" sh -c "printf 'cortex live filetail\n' >'$path'"
  add="$(jq -cn --arg id "$id" --arg path "$path" '{op:"add",id:$id,path:$path,tag:$id,host:"cortex-live",facility:"local4",severity:"info",start_at_end:false}')"
  if ! add_response="$(fleet_curl "$manifest" /api/file-tails -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN" -H "x-cortex-admin-token: $LIVE_FLEET_ADMIN_TOKEN" -H 'Content-Type: application/json' -d "$add")"; then echo "$add_response" >&2; fleet_grant_finalize "$ledger" "$reservation" FAILED add-failed; exit 1; fi
  current="$(fleet_curl "$manifest" /api/file-tails -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN" -H "x-cortex-admin-token: $LIVE_FLEET_ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"op":"list"}')"
  if ! jq -e --arg id "$id" '.sources|map(select(.id==$id))|length==1' <<<"$current" >/dev/null; then fleet_cas_rollback suite-added operator-changed '["false"]' "$LIVE_RUN_ROOT/filetail-manual.json" || true; fleet_grant_finalize "$ledger" "$reservation" FAILED cas-mismatch; exit 4; fi
  fleet_curl "$manifest" /api/file-tails -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN" -H "x-cortex-admin-token: $LIVE_FLEET_ADMIN_TOKEN" -H 'Content-Type: application/json' -d "$(jq -cn --arg id "$id" '{op:"remove",id:$id}')" >/dev/null
  docker exec -u 0 "$container" rm -f "$path"; after_list="$(fleet_curl "$manifest" /api/file-tails -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN" -H "x-cortex-admin-token: $LIVE_FLEET_ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"op":"list"}')"
  [[ "$(jq -cS . <<<"$before_list")" == "$(jq -cS . <<<"$after_list")" ]] || { fleet_cas_rollback before operator-changed '["false"]' "$LIVE_RUN_ROOT/filetail-manual.json" || true; exit 4; }
  fleet_grant_finalize "$ledger" "$reservation" SUCCEEDED rolled-back
fi

jq -n '{heartbeat_retention_days:14,log_retention:"server policy; tagged INFO rows are intentionally append-only residuals",cleanup:"no destructive delete is attempted against deployed/fleet targets"}' >"$LIVE_RUN_ROOT/retention-disclosure.json"
search="$(fleet_curl "$manifest" "/api/search?query=%22cortex%22&limit=1000" -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN")"
retained="$(jq '(.logs // .items // .results // [])|map(select((.message // .body // "")|contains("'"$LIVE_RUN_ID"'")))|length' <<<"$search")"
resource_count=0
if command -v docker >/dev/null 2>&1; then
  resource_count=$(( $(docker ps -aq --filter "label=cortex.live.run_id=$LIVE_RUN_ID" | wc -l) + $(docker volume ls -q --filter "label=cortex.live.run_id=$LIVE_RUN_ID" | wc -l) + $(docker network ls -q --filter "label=cortex.live.run_id=$LIVE_RUN_ID" | wc -l) ))
fi
heartbeat_count=0
if heartbeat_state="$(fleet_curl "$manifest" "/api/host-state?host_id=cortex-live-${LIVE_RUN_ID}" -H "Authorization: Bearer $LIVE_FLEET_READ_TOKEN" 2>/dev/null)"; then
  heartbeat_count="$(jq --arg id "cortex-live-${LIVE_RUN_ID}" 'if (.host_id // .host.host_id // "")==$id then 1 else 0 end' <<<"$heartbeat_state")"
fi
fleet_residual_report "$LIVE_RUN_ROOT/fleet-residual.json" "$LIVE_RUN_ID" "$retained" "$resource_count" "$heartbeat_count"
