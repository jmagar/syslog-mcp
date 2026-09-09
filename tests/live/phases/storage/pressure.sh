#!/usr/bin/env bash
set -euo pipefail
: "${LIVE_RUN_ROOT:?}" "${LIVE_COMPOSE_PROJECT:?}" "${LIVE_CANDIDATE_IMAGE:?}" "${LIVE_ORACLE_IMAGE:?}"
root="${LIVE_PROJECT_ROOT:?}"; contract="$root/tests/live/contracts/storage.json"
# shellcheck disable=SC1091
source "$root/tests/live/lib/common.sh"; source "$root/tests/live/lib/lock.sh"; source "$root/tests/live/lib/redact.sh"; source "$root/tests/live/lib/events.sh"; source "$root/tests/live/lib/report.sh"; source "$root/tests/live/lib/budgets.sh"; source "$root/tests/live/lib/wait.sh"; source "$root/tests/live/lib/resources.sh"; source "$root/tests/live/lib/docker.sh"
mkdir -p "$LIVE_RUN_ROOT/artifacts/storage"; result="$LIVE_RUN_ROOT/artifacts/storage/pressure.json"
if [[ "$(uname -s)" != Linux ]]; then
  jq -cn --arg platform "$(uname -s)" '{schema:"cortex-live-storage-pressure-v1",disposition:"platform-qualified",green:false,platform:$platform,reason:"hard local-volume quota is unavailable; shared Docker VM pressure refused"}' >"$result"
  chmod 600 "$result"; live_terminal_disposition storage.pressure platform-qualified artifacts/storage/pressure.json; exit 0
fi
[[ "${CORTEX_LIVE_STORAGE_PRESSURE_AUTHORIZED:-0}" == 1 ]] || {
  jq -cn '{schema:"cortex-live-storage-pressure-v1",disposition:"not-authorized",green:false,reason:"set CORTEX_LIVE_STORAGE_PRESSURE_AUTHORIZED=1"}' >"$result"
  chmod 600 "$result"; live_terminal_disposition storage.pressure not-authorized artifacts/storage/pressure.json; exit 0;
}
max_seconds="$(jq -r .pressure.max_wall_seconds "$contract")"; max_bytes="$(jq -r .pressure.max_written_bytes "$contract")"
volume="${LIVE_COMPOSE_PROJECT}_quota"; container="${LIVE_COMPOSE_PROJECT}-quota-candidate"
fixtures="$LIVE_RUN_ROOT/artifacts/storage/otlp-pressure-fixtures"; mkdir -p "$fixtures"
for stage in baseline blocked recovered; do
  cargo run --quiet --locked --manifest-path "$root/tests/live/fixtures/ingest/otlpgen/Cargo.toml" -- "${LIVE_RUN_ID#cortex-e2e-}-$stage" "$fixtures/$stage"
done
# LIVE_RUN_ROOT is mode 0700. Copying fixtures into a bind-mounted descendant
# therefore fails for the image's UID 1000 on Linux unless every path component
# from the mount root is traversable. The fixture mount contains no secrets.
chmod 0755 "$fixtures" "$fixtures"/*; chmod 0644 "$fixtures"/*/*.pb
deadline=$(( $(date +%s) + max_seconds ))
docker_root="${LIVE_DOCKER_ROOT_DIR:-/var/lib/docker}"
[[ "$docker_root" == /* && "$docker_root" != / ]] || live_die "LIVE_DOCKER_ROOT_DIR must be an absolute non-root path"
volume_path="$docker_root/volumes/$volume/_data"
"$root/tests/live/profiles/storage/pressure-watchdog.sh" "$$" "$deadline" "$max_bytes" "$volume_path" & lifecycle_watchdog=$!
trap 'kill "$lifecycle_watchdog" 2>/dev/null || true; wait "$lifecycle_watchdog" 2>/dev/null || true' EXIT
provider="${LIVE_RESOURCE_PROVIDER:?}"; resource_script="$root/tests/live/profiles/storage/quota-resource.sh"
volume_labels="$(jq -cn --arg project "$LIVE_COMPOSE_PROJECT" '{"com.docker.compose.project":$project,"cortex.live.kind":"quota"}')"
volume_digest="$(printf '%s' "$provider:$volume:tmpfs:67108864" | shasum -a 256 | awk '{print $1}')"
live_resource_transition storage-quota-volume docker-volume PLANNED "$provider" "" '[]' "" "$volume_labels" '[]' topology
live_resource_transition storage-quota-volume docker-volume CREATING "$provider" "$volume" '[]' "$volume_digest" "$volume_labels" '[]' topology
docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt o=size=67108864 --label "cortex.live.run_id=$LIVE_RUN_ID" --label "cortex.live.provider=$provider" --label "com.docker.compose.project=$LIVE_COMPOSE_PROJECT" --label cortex.live.kind=quota "$volume" >/dev/null
volume_cleanup="$(jq -cn --arg s "$resource_script" --arg id "$volume" --arg r "$LIVE_RUN_ID" --arg p "$provider" '["bash",$s,"cleanup-volume",$id,$r,$p]')"
volume_verify="$(jq -cn --arg s "$resource_script" --arg id "$volume" --arg r "$LIVE_RUN_ID" --arg p "$provider" '["bash",$s,"verify-volume",$id,$r,$p]')"
live_resource_transition storage-quota-volume docker-volume IDENTIFIED "$provider" "$volume" "$volume_cleanup" "$volume_digest" "$volume_labels" "$volume_verify" topology
live_resource_transition storage-quota-volume docker-volume CREATED "$provider" "$volume" "$volume_cleanup" "$volume_digest" "$volume_labels" "$volume_verify" topology
inspect="$LIVE_RUN_ROOT/artifacts/storage/quota-volume.json"; docker volume inspect "$volume" >"$inspect"
jq -e '.[0].Options.o|contains("size=67108864")' "$inspect" >/dev/null || live_die "provider did not retain requested hard quota"
[[ -d "$volume_path" && -r "$volume_path" ]] || live_die "external watchdog cannot read the quota volume byte-accounting path"
preflight="$LIVE_RUN_ROOT/artifacts/storage/quota-preflight.txt"
if docker run --rm --user 0:0 -v "$volume:/data" --entrypoint sh "$LIVE_ORACLE_IMAGE" -ceu 'dd if=/dev/urandom of=/data/over-limit bs=1048576 count=65 conv=fsync' >"$preflight" 2>&1; then live_die "quota preflight over-limit write unexpectedly succeeded"; fi
docker run --rm --user 0:0 -v "$volume:/data" --entrypoint sh "$LIVE_ORACLE_IMAGE" -ceu 'rm -f /data/over-limit; chmod 0777 /data'
host_free="$(df -Pk "$docker_root" 2>/dev/null | awk 'NR==2{print $4*1024}' || df -Pk / | awk 'NR==2{print $4*1024}')"
layers="$(docker image inspect "$LIVE_CANDIDATE_IMAGE" "$LIVE_ORACLE_IMAGE" | jq '[.[].Size]|add')"
(( host_free > max_bytes + layers + 536870912 )) || live_die "insufficient host cleanup margin for quota scenario"
container_labels="$(jq -cn --arg project "$LIVE_COMPOSE_PROJECT" '{"com.docker.compose.project":$project,"cortex.live.kind":"quota-candidate"}')"
container_digest="$(printf '%s' "$provider:$container:$LIVE_CANDIDATE_IMAGE:$volume" | shasum -a 256 | awk '{print $1}')"
live_resource_transition storage-quota-container docker-container PLANNED "$provider" "" '[]' "" "$container_labels" '[]' storage-quota-volume
live_resource_transition storage-quota-container docker-container CREATING "$provider" "$container" '[]' "$container_digest" "$container_labels" '[]' storage-quota-volume
container_id="$(docker create --name "$container" --label "cortex.live.run_id=$LIVE_RUN_ID" --label "cortex.live.provider=$provider" --label "com.docker.compose.project=$LIVE_COMPOSE_PROJECT" --label cortex.live.kind=quota-candidate -v "$volume:/data" -v "$fixtures:/fixtures:ro" -e CORTEX_HOST=127.0.0.1 -e CORTEX_API_TOKEN=pressure-api -e CORTEX_DB_PATH=/data/cortex.db -e CORTEX_MAX_DB_SIZE_MB=0 -e CORTEX_RECOVERY_DB_SIZE_MB=0 -e CORTEX_MIN_FREE_DISK_MB=16 -e CORTEX_RECOVERY_FREE_DISK_MB=32 -e CORTEX_CLEANUP_INTERVAL_SECS=5 -e RUST_LOG=error "$LIVE_CANDIDATE_IMAGE")"
container_cleanup="$(jq -cn --arg s "$resource_script" --arg id "$container_id" --arg r "$LIVE_RUN_ID" --arg p "$provider" '["bash",$s,"cleanup-container",$id,$r,$p]')"
container_verify="$(jq -cn --arg s "$resource_script" --arg id "$container_id" --arg r "$LIVE_RUN_ID" --arg p "$provider" '["bash",$s,"verify-container",$id,$r,$p]')"
live_resource_transition storage-quota-container docker-container IDENTIFIED "$provider" "$container_id" "$container_cleanup" "$container_digest" "$container_labels" "$container_verify" storage-quota-volume
docker start "$container_id" >/dev/null
live_resource_transition storage-quota-container docker-container CREATED "$provider" "$container_id" "$container_cleanup" "$container_digest" "$container_labels" "$container_verify" storage-quota-volume
_quota_stats() { docker exec -e RUST_LOG=error "$container" cortex stats --json 2>/dev/null; }
_quota_ready() { _quota_stats >/dev/null; }; live_wait_until 30 quota-candidate-ready _quota_ready
_otlp_post() {
  local stage="$1" signal="$2" body="$3" headers="$4"
  docker exec "$container" curl -sS --max-time 10 -D /tmp/otlp.headers -o /tmp/otlp.body -w '%{http_code}' -H 'Content-Type: application/x-protobuf' --data-binary "@/fixtures/$stage/$signal.pb" "http://127.0.0.1:3100/v1/$signal" >"$headers.status"
  docker cp "$container:/tmp/otlp.headers" "$headers.headers" >/dev/null
  docker cp "$container:/tmp/otlp.body" "$body" >/dev/null
}
_log_count() { docker exec -e RUST_LOG=error "$container" cortex search --grep "$1" --limit 10 --json 2>/dev/null | jq -r '.count'; }
baseline_log="${LIVE_RUN_ID#cortex-e2e-}-baseline-otlp-log-0040"
for signal in logs metrics traces; do _otlp_post baseline "$signal" "$LIVE_RUN_ROOT/artifacts/storage/otlp-baseline-$signal.body" "$LIVE_RUN_ROOT/artifacts/storage/otlp-baseline-$signal"; [[ "$(cat "$LIVE_RUN_ROOT/artifacts/storage/otlp-baseline-$signal.status")" == 200 ]]; done
_baseline_visible() { [[ "$(_log_count "$baseline_log")" == 1 ]]; }; live_wait_until 20 otlp-pressure-baseline _baseline_visible
docker run --rm --name "${container}-filler" --label "cortex.live.run_id=$LIVE_RUN_ID" -v "$volume:/data" --entrypoint sh "$LIVE_ORACLE_IMAGE" -ceu 'dd if=/dev/urandom of=/data/fill bs=1048576 count=52 conv=fsync' >"$LIVE_RUN_ROOT/artifacts/storage/quota-fill.txt" 2>&1 & filler=$!
wait "$filler"
_blocked() { _quota_stats | jq -e '.write_blocked==true' >/dev/null; }; live_wait_until 30 quota-write-block _blocked
# The stats command measures the filesystem directly, while OTLP admission uses
# the runtime state refreshed by the storage-enforcement task. Synchronize on
# that actual admission gate before exercising the blocked log and trace paths.
_runtime_blocked() {
  _otlp_post blocked metrics "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-metrics.body" "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-metrics"
  [[ "$(cat "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-metrics.status")" == 503 ]]
}
live_wait_until 30 quota-runtime-write-block _runtime_blocked
_quota_stats >"$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-storage.json"
blocked_log="${LIVE_RUN_ID#cortex-e2e-}-blocked-otlp-log-0040"
for signal in logs traces; do _otlp_post blocked "$signal" "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-$signal.body" "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-$signal"; done
[[ "$(cat "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-logs.status")" == 200 ]]
[[ "$(_log_count "$blocked_log")" == 0 ]] || live_die "blocked OTLP log became visible before storage recovery"
[[ "$(cat "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-metrics.status")" == 503 ]]
grep -qi '^retry-after: 1' "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-metrics.headers"
grep -q '"error":"metric_storage_blocked"' "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-metrics.body"
grep -q '"retryable":true' "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-metrics.body"
[[ "$(cat "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-traces.status")" == 200 ]]
python3 - "$LIVE_RUN_ROOT/artifacts/storage/otlp-blocked-traces.body" <<'PY'
import sys
b=open(sys.argv[1],'rb').read(); assert b and b[0]==10
i=1; n=0; s=0
while True:
 x=b[i]; i+=1; n|=(x&127)<<s
 if x<128: break
 s+=7
p=b[i:i+n]; assert p[:2]==bytes((8,1)), p
PY
docker exec -u 0:0 "$container" rm -f /data/fill
_recovered() { _quota_stats | jq -e '.write_blocked==false' >/dev/null; }; live_wait_until 30 quota-hysteresis-recovery _recovered
_blocked_log_recovered() { [[ "$(_log_count "$blocked_log")" == 1 ]]; }; live_wait_until 30 otlp-retained-log-recovery _blocked_log_recovered
recovered_log="${LIVE_RUN_ID#cortex-e2e-}-recovered-otlp-log-0040"
for signal in logs metrics traces; do _otlp_post recovered "$signal" "$LIVE_RUN_ROOT/artifacts/storage/otlp-recovered-$signal.body" "$LIVE_RUN_ROOT/artifacts/storage/otlp-recovered-$signal"; [[ "$(cat "$LIVE_RUN_ROOT/artifacts/storage/otlp-recovered-$signal.status")" == 200 ]]; done
_recovered_log_visible() { [[ "$(_log_count "$recovered_log")" == 1 ]]; }; live_wait_until 20 otlp-recovered-log _recovered_log_visible
otlp_ev="$LIVE_RUN_ROOT/artifacts/storage/otlp-storage-blocked.json"
jq -cn --arg blocked_log "$blocked_log" --arg recovered_log "$recovered_log" '{schema:"cortex-live-otlp-storage-blocked-v1",case:"otlp-storage-blocked",write_blocked:true,logs:{blocked_status:200,visible_while_blocked:false,visible_after_recovery:true,exact_count_after_recovery:1,marker:$blocked_log},metrics:{blocked_status:503,error:"metric_storage_blocked",retryable:true,retry_after:1,recovery_status:200},traces:{blocked_status:200,rejected_spans:1,recovery_status:200},recovery:{log_marker:$recovered_log,log_count:1,metric_accepted:true,trace_accepted:true}}' >"$otlp_ev"
live_event ingest_case "$(jq -cn '{case:"otlp-storage-blocked",result:"pass",evidence:"artifacts/storage/otlp-storage-blocked.json",cross_bead_required:true}')"
jq -e '.case=="otlp-storage-blocked" and .write_blocked and .logs.exact_count_after_recovery==1 and .metrics.blocked_status==503 and .metrics.retryable and .traces.rejected_spans==1 and .recovery.log_count==1' "$otlp_ev" >/dev/null || live_die "OTLP storage obligation evidence is incomplete"
[[ "$(jq -r 'select(.kind=="ingest_case" and .payload.case=="otlp-storage-blocked" and .payload.result=="pass" and .payload.cross_bead_required==true)|1' "$LIVE_RUN_ROOT/events.jsonl" | wc -l | tr -d ' ')" == 1 ]] || live_die "OTLP storage obligation case did not reconcile exactly once"
jq -cn --argjson host_free "$host_free" --argjson layers "$layers" '{schema:"cortex-live-storage-pressure-v1",disposition:"pass",green:true,quota_bytes:67108864,over_limit_write_failed:true,incompressible_source:"/dev/urandom",write_block_observed:true,hysteresis_recovery_observed:true,otlp_storage_blocked_evidence:"artifacts/storage/otlp-storage-blocked.json",external_watchdog:true,accounting:{host_free_bytes:$host_free,image_layer_bytes:$layers,db_wal_shm_backups_logs_artifacts:"bounded by quota and profile budgets"}}' >"$result"
chmod 600 "$result" "$inspect" "$preflight"; live_terminal_disposition storage.pressure pass artifacts/storage/pressure.json
kill "$lifecycle_watchdog" 2>/dev/null || true; wait "$lifecycle_watchdog" 2>/dev/null || true; trap - EXIT
