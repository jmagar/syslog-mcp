#!/usr/bin/env bash
set -euo pipefail
: "${LIVE_RUN_ROOT:?}" "${LIVE_COMPOSE_PROJECT:?}" "${LIVE_HTTP_PORT:?}" "${LIVE_API_TOKEN:?}" "${LIVE_ADMIN_TOKEN:?}"
root="${LIVE_PROJECT_ROOT:?}"; compose="$root/tests/live/profiles/isolated/compose.yaml"
# shellcheck disable=SC1091
source "$root/tests/live/lib/common.sh"; source "$root/tests/live/lib/lock.sh"; source "$root/tests/live/lib/redact.sh"; source "$root/tests/live/lib/events.sh"; source "$root/tests/live/lib/report.sh"; source "$root/tests/live/lib/command.sh"; source "$root/tests/live/lib/budgets.sh"; source "$root/tests/live/lib/wait.sh"; source "$root/tests/live/lib/resources.sh"; source "$root/tests/live/lib/docker.sh"
mkdir -p "$LIVE_RUN_ROOT/artifacts/storage"
# The topology's perpetual producer is useful for readiness but can starve the
# cooperative SQLite backup indefinitely. Stop it; this phase injects its own
# bounded concurrent WAL writer and explicit commit barrier below.
docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" stop workload-producer >/dev/null
# DB-pressure assertions are complete before this phase. Recreate with the base
# storage policy so the five committed backup markers cannot be deleted by a
# concurrent 4 MiB recovery cycle between the barrier and backup snapshot.
docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" up -d --no-deps --force-recreate candidate >/dev/null
live_wait_until 60 storage-maintenance-health _live_http_health_ready

record() {
  local surface="$1" case_kind="$2" result="$3" evidence="$4"
  if jq -e --arg id "$surface" --arg case "$case_kind" --arg profile "${LIVE_PROFILE:?}" \
    'any(.entries[]; .id==$id and (.required_cases|index($case)) and (.profiles|index($profile)))' "$LIVE_SURFACE_CONTRACT" >/dev/null &&
    ! jq -e -n --arg id "$surface" --arg case "$case_kind" \
      'any(inputs; .kind=="result" and .payload.surface_id==$id and .payload.case_kind==$case and .payload.attempt_kind=="first_attempt")' \
      "$LIVE_RUN_ROOT/events.jsonl" >/dev/null; then
    live_result "$surface" storage-maintenance "$result" 0 "$evidence" "$case_kind"
  else
    live_event storage_extra_check "$(jq -cn --arg surface "$surface" --arg case "$case_kind" --arg result "$result" --arg evidence "$evidence" '{surface_id:$surface,case_kind:$case,result:$result,evidence:$evidence}')"
    [[ "$result" == pass ]] || live_die "storage extra check failed: $surface/$case_kind"
  fi
}
artifact() { printf '%s\n' "$2" >"$LIVE_RUN_ROOT/artifacts/storage/$1"; chmod 600 "$LIVE_RUN_ROOT/artifacts/storage/$1"; }
api() {
  local method="$1" path="$2" token="$3" body="${4:-}" out="$5" code
  local args=(-sS --max-time 120 -o "$out" -w '%{http_code}' -X "$method" -H 'Host: localhost' -H "Authorization: Bearer $LIVE_API_TOKEN")
  [[ -z "$token" ]] || args+=(-H "x-cortex-admin-token: $token")
  [[ -z "$body" ]] || args+=(-H 'Content-Type: application/json' --data "$body")
  code="$(curl "${args[@]}" "http://127.0.0.1:$LIVE_HTTP_PORT$path")"; printf '%s' "$code"
}
cli() {
  docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error candidate cortex --http --server http://127.0.0.1:3100 "$@" </dev/null
}

storage_candidate_id() {
  local candidate
  candidate="$(docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" ps -q candidate)"
  [[ -n "$candidate" ]] || { live_die "storage candidate container was not discoverable"; return 1; }
  printf '%s\n' "$candidate"
}

maintenance_audit_count() {
  local action="$1"
  docker logs "$(storage_candidate_id)" 2>&1 | grep -Ec "action=\"?$action\"?([[:space:]]|$)" || true
}

maintenance_audit_advanced() {
  local action="$1" before="$2" current
  current="$(maintenance_audit_count "$action")"
  [[ "$current" =~ ^[0-9]+$ && "$current" -gt "$before" ]]
}

backup_operation_active() {
  local client_pid="$1" path="$2" candidate
  kill -0 "$client_pid" 2>/dev/null || return 1
  candidate="$(storage_candidate_id)"
  docker exec "$candidate" sh -ceu '
    test -s "$1"
    result="$(timeout 1 sqlite3 "$1" "PRAGMA integrity_check;" 2>/dev/null || true)"
    test "$result" != ok
  ' sh "$path"
}

add_maintenance_response_delay() {
  local name="$1"
  curl -fsS --max-time 10 -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg name "$name" '{name:$name,type:"latency",stream:"downstream",toxicity:1.0,attributes:{latency:60000,jitter:0}}')" \
    "http://127.0.0.1:${LIVE_TOXIPROXY_PORT:?}/proxies/${LIVE_RUN_ID}-http/toxics" >/dev/null
}

remove_maintenance_response_delay() {
  local name="$1"
  curl -fsS --max-time 10 -X DELETE \
    "http://127.0.0.1:${LIVE_TOXIPROXY_PORT:?}/proxies/${LIVE_RUN_ID}-http/toxics/$name" >/dev/null
}
cli_semantic_oracle() {
  local surface="$1" evidence="$2"
  case "$surface" in
    cli.db-status) jq -e '.journal_mode=="wal" and (.page_size|type=="number") and (.logical_size_bytes|type=="number")' "$evidence" >/dev/null;;
    cli.db-integrity) jq -e '.ok==true and (.messages|type=="array")' "$evidence" >/dev/null;;
    cli.db-checkpoint) jq -e '.mode=="passive" and (.checkpointed_frames|type=="number") and (.log_frames|type=="number")' "$evidence" >/dev/null;;
    cli.db-vacuum) jq -e '.full==false and .incremental_pages==32 and (.after_physical_size_bytes|type=="number")' "$evidence" >/dev/null;;
    cli.db-backup) jq -e '.backup_path=="/data/live-storage-backup.db" and (.size_bytes|type=="number" and .>0)' "$evidence" >/dev/null;;
    *) return 2;;
  esac
}

# CLI: every DB maintenance command, an invalid invocation, and an HTTP auth denial.
while IFS='|' read -r surface command; do
  read -r -a argv <<<"$command"; out="artifacts/storage/${surface}.json"; semantic_err="artifacts/storage/${surface}.stderr"
  if cli "${argv[@]}" >"$LIVE_RUN_ROOT/$out" 2>"$LIVE_RUN_ROOT/$semantic_err" && cli_semantic_oracle "$surface" "$LIVE_RUN_ROOT/$out"; then record "$surface" semantic-positive pass "$out"; else record "$surface" semantic-positive fail "$out"; fi
  bad="artifacts/storage/${surface}.invalid.txt"
  if ! cli "${argv[0]}" "${argv[1]}" --definitely-invalid >"$LIVE_RUN_ROOT/$bad" 2>&1 &&
    grep -Eqi 'unexpected argument|unknown argument|invalid|usage:' "$LIVE_RUN_ROOT/$bad"; then
    record "$surface" validation-negative pass "$bad"
  else
    record "$surface" validation-negative fail "$bad"
  fi
  auth="artifacts/storage/${surface}.auth.txt"
  if ! docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error -e CORTEX_API_TOKEN= candidate cortex --http --server http://127.0.0.1:3100 "${argv[@]}" </dev/null >"$LIVE_RUN_ROOT/$auth" 2>&1; then record "$surface" authorization pass "$auth"; else record "$surface" authorization fail "$auth"; fi
done <<'COMMANDS'
cli.db-status|db status --json
cli.db-integrity|db integrity --quick --json
cli.db-checkpoint|db checkpoint passive --json
cli.db-vacuum|db vacuum --pages 32 --json
cli.db-backup|db backup --output /data/live-storage-backup.db --json
COMMANDS

# Background integrity has a distinct CLI surface and yields the job used by status.
start="artifacts/storage/cli.db-integrity-status.start.json"
if docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error candidate cortex --http --server http://127.0.0.1:3100 db integrity --quick --background --json </dev/null >"$LIVE_RUN_ROOT/$start" 2>&1; then
  job="$(jq -r '.job_id // .id // empty' "$LIVE_RUN_ROOT/$start")"
else job=""; fi
status_ev="artifacts/storage/cli.db-integrity-status.json"
if [[ "$job" =~ ^[1-9][0-9]*$ ]] && docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error candidate cortex --http --server http://127.0.0.1:3100 db integrity status "$job" --json </dev/null >"$LIVE_RUN_ROOT/$status_ev" 2>&1 &&
  jq -e --argjson job "$job" '.job_id==$job and (.status|IN("running","done","failed")) and .kind=="db_integrity"' "$LIVE_RUN_ROOT/$status_ev" >/dev/null; then result=pass; else result=fail; fi
record cli.db-integrity-status semantic-positive "$result" "$status_ev"
status_invalid="artifacts/storage/cli.db-integrity-status.invalid.txt"
if ! cli db integrity status not-a-number --json >"$LIVE_RUN_ROOT/$status_invalid" 2>&1 &&
  grep -Eqi 'invalid|number|digit|value|argument' "$LIVE_RUN_ROOT/$status_invalid"; then
  result=pass
else
  result=fail
fi
record cli.db-integrity-status validation-negative "$result" "$status_invalid"

# Local-only CLI entries do not require an authorization case in the compiled
# contract. Still exercise the HTTP-backed status command without credentials,
# but retain it as an extra check rather than manufacturing canonical coverage.
status_auth="artifacts/storage/cli.db-integrity-status.auth.txt"
if ! docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error -e CORTEX_API_TOKEN= candidate \
  cortex --http --server http://127.0.0.1:3100 db integrity status "$job" --json </dev/null >"$LIVE_RUN_ROOT/$status_auth" 2>&1; then
  result=pass
else
  result=fail
fi
record cli.db-integrity-status authorization "$result" "$status_auth"

# REST read, mutation, background job, negative validation, and missing-admin cases.
rest_case() {
  local surface="$1" method="$2" path="$3" body="$4" admin="$5" okcodes="$6" invalid_path="$7"
  local ev="artifacts/storage/${surface}.json" code
  code="$(api "$method" "$path" "$admin" "$body" "$LIVE_RUN_ROOT/$ev")"
  if [[ " $okcodes " == *" $code "* ]] && rest_semantic_oracle "$surface" "$LIVE_RUN_ROOT/$ev"; then result=pass; else result=fail; fi; record "$surface" semantic-positive "$result" "$ev"
  local neg="artifacts/storage/${surface}.invalid.json" ncode
  ncode="$(api "$method" "$invalid_path" "$admin" '{"mode":"INVALID","full":"wrong"}' "$LIVE_RUN_ROOT/$neg")"
  if [[ "$ncode" =~ ^4 ]]; then result=pass; else result=fail; fi; record "$surface" validation-negative "$result" "$neg"
  local auth="artifacts/storage/${surface}.auth.json" acode
  if [[ "$admin" == "$LIVE_ADMIN_TOKEN" ]]; then
    acode="$(api "$method" "$path" "" "$body" "$LIVE_RUN_ROOT/$auth")"
  else
    acode="$(curl -sS --max-time 30 -o "$LIVE_RUN_ROOT/$auth" -w '%{http_code}' -X "$method" -H 'Host: localhost' "http://127.0.0.1:$LIVE_HTTP_PORT$path")"
  fi
  if [[ "$acode" =~ ^(401|403)$ ]]; then result=pass; else result=fail; fi
  record "$surface" authorization "$result" "$auth"
}
rest_semantic_oracle() {
  local surface="$1" evidence="$2"
  case "$surface" in
    rest.get-api-db-status) jq -e '.journal_mode=="wal" and (.page_size|type=="number") and (.db_path|type=="string")' "$evidence" >/dev/null;;
    rest.get-api-db-integrity) jq -e '.ok==true and (.messages|type=="array")' "$evidence" >/dev/null;;
    rest.post-api-db-checkpoint) jq -e '.mode=="passive" and (.checkpointed_frames|type=="number") and (.complete|type=="boolean")' "$evidence" >/dev/null;;
    rest.post-api-db-vacuum) jq -e '.full==false and .incremental_pages==32 and (.after_physical_size_bytes|type=="number")' "$evidence" >/dev/null;;
    rest.post-api-db-backup) jq -e '.backup_path=="/data/live-rest-backup.db" and (.size_bytes|type=="number" and .>0)' "$evidence" >/dev/null;;
    rest.post-api-db-integrity-background) jq -e '(.job_id|type=="number" and .>0) and .status=="running"' "$evidence" >/dev/null;;
    rest.get-api-db-integrity-jobs-id) jq -e '(.job_id|type=="number" and .>0) and .kind=="db_integrity" and (.status|IN("running","done","failed"))' "$evidence" >/dev/null;;
    *) return 2;;
  esac
}
rest_case rest.get-api-db-status GET /api/db/status '' '' '200' /api/db/status/invalid
rest_case rest.get-api-db-integrity GET /api/db/integrity?quick=true '' '' '200' /api/db/integrity?bogus=1
rest_case rest.post-api-db-checkpoint POST /api/db/checkpoint '{"mode":"passive"}' "$LIVE_ADMIN_TOKEN" '200' /api/db/checkpoint
rest_case rest.post-api-db-vacuum POST /api/db/vacuum '{"full":false,"incremental_pages":32}' "$LIVE_ADMIN_TOKEN" '200' /api/db/vacuum
rest_case rest.post-api-db-backup POST /api/db/backup '{"output_path":"/data/live-rest-backup.db"}' "$LIVE_ADMIN_TOKEN" '200' /api/db/backup
rest_case rest.post-api-db-integrity-background POST /api/db/integrity/background?quick=true '' "$LIVE_ADMIN_TOKEN" '200' /api/db/integrity/background?quick=bogus

job="$(jq -r '.job_id // .id // empty' "$LIVE_RUN_ROOT/artifacts/storage/rest.post-api-db-integrity-background.json")"
[[ "$job" =~ ^[1-9][0-9]*$ ]] || job=0
rest_case rest.get-api-db-integrity-jobs-id GET "/api/db/integrity/jobs/$job" '' '' '200' /api/db/integrity/jobs/not-a-number

# Failure injection: unwritable/full destinations must fail, and interrupting a
# checkpoint client must not make the server or database unhealthy.
for spec in 'unwritable:/proc/cortex-live.db' 'full:/dev/full'; do
  name="${spec%%:*}"; path="${spec#*:}"; ev="artifacts/storage/backup-$name.txt"
  if live_run_bounded 20 "$LIVE_RUN_ROOT/$ev" "$LIVE_RUN_ROOT/$ev.stderr" docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error candidate cortex --http --server http://127.0.0.1:3100 db backup --output "$path" --json; then
    live_die "backup unexpectedly succeeded for $name destination"
  fi
  live_event storage_failure_injection "$(jq -cn --arg scenario "backup-$name" --arg evidence "$ev" '{scenario:$scenario,result:"pass",evidence:$evidence}')"
done
checkpoint_interrupt="$LIVE_RUN_ROOT/artifacts/storage/checkpoint-interrupted.txt"
checkpoint_audit_before="$(maintenance_audit_count db_checkpoint)"
checkpoint_toxic="checkpoint-interrupt-${LIVE_RUN_ID#cortex-e2e-}"
add_maintenance_response_delay "$checkpoint_toxic"
curl -sS --max-time 120 -X POST -H 'Host: localhost' -H "Authorization: Bearer $LIVE_API_TOKEN" -H "x-cortex-admin-token: $LIVE_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  --data '{"mode":"truncate"}' "http://127.0.0.1:$LIVE_HTTP_PORT/api/db/checkpoint" >"$checkpoint_interrupt" 2>&1 & checkpoint_client=$!
live_wait_until 15 checkpoint-server-start maintenance_audit_advanced db_checkpoint "$checkpoint_audit_before"
kill -TERM "$checkpoint_client"
set +e; wait "$checkpoint_client"; checkpoint_client_status=$?; set -e
remove_maintenance_response_delay "$checkpoint_toxic"
[[ "$checkpoint_client_status" -ne 0 && "$checkpoint_client_status" -ne 124 ]] || live_die "checkpoint client was not interrupted after server-side start"
live_wait_until 30 checkpoint-interrupt-health _live_http_health_ready
cli db integrity --quick --json >>"$checkpoint_interrupt" 2>&1 || live_die "database unhealthy after interrupted checkpoint client"
jq -cn --argjson before "$checkpoint_audit_before" --argjson after "$(maintenance_audit_count db_checkpoint)" --argjson client_status "$checkpoint_client_status" \
  '{schema:"cortex-live-maintenance-interruption-v1",scenario:"interrupted-checkpoint-client",server_audit_action:"db_checkpoint",server_audit_count_before:$before,server_audit_count_after:$after,server_start_observed:($after>$before),client_exit_status:$client_status,client_interrupted:($client_status!=0 and $client_status!=124),database_healthy_afterward:true}' \
  >"$LIVE_RUN_ROOT/artifacts/storage/checkpoint-interrupted.json"
live_event storage_failure_injection "$(jq -cn '{scenario:"interrupted-checkpoint-client",result:"pass",evidence:"artifacts/storage/checkpoint-interrupted.json"}')"

# Establish a committed-transaction barrier while WAL writes are active. Every
# marker observed before the barrier must exist in the independently opened
# backup; a missing marker is a terminal failure.
markers="$LIVE_RUN_ROOT/artifacts/storage/committed-markers.txt"; : >"$markers"
for index in 1 2 3 4 5; do
  marker="backup-${LIVE_RUN_ID#cortex-e2e-}-$index"; printf '%s\n' "$marker" >>"$markers"
  # A transaction barrier cannot be established from fire-and-forget UDP:
  # packet delivery is not guaranteed during the preceding container churn.
  # TCP completion proves the receiver accepted each marker; the query below
  # then proves the final batch was committed before backup starts.
  printf '<134>1 %s cortex-live backup-writer - - - %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$marker" | nc -w 5 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  live_connection_opened 1
done
barrier="backup-${LIVE_RUN_ID#cortex-e2e-}-5"; live_wait_until 30 backup-commit-barrier _live_ingest_ready "$barrier"
backup_started="$(date +%s)"
cli db backup --output /data/live-concurrent-backup.db --json >"$LIVE_RUN_ROOT/artifacts/storage/concurrent-backup.json" 2>&1
backup_duration=$(( $(date +%s) - backup_started ))
backup_ev="artifacts/storage/backup-restore.json"
backup_raw="$LIVE_RUN_ROOT/artifacts/storage/backup-restore.raw"
if docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" exec -T candidate sh -ceu '
  CORTEX_DB_PATH=/data/live-concurrent-backup.db RUST_LOG=error cortex db integrity --quick --json
  test -s /data/live-concurrent-backup.db
' >"$backup_raw" 2>&1; then
  : # exact marker verification follows
else
  live_die "backup integrity verification failed"
fi
# Verify all committed rows in a second isolated Cortex container while the
# primary service remains live.
state_volume="$(docker volume ls -q --filter "label=com.docker.compose.project=$LIVE_COMPOSE_PROJECT" --filter label=cortex.live.kind=state)"
restore_volume="${LIVE_COMPOSE_PROJECT}_restore"
provider="${LIVE_RESOURCE_PROVIDER:?}"; resource_script="$root/tests/live/profiles/storage/quota-resource.sh"
restore_labels="$(jq -cn --arg project "$LIVE_COMPOSE_PROJECT" '{"com.docker.compose.project":$project,"cortex.live.kind":"restore"}')"
restore_digest="$(printf '%s' "$provider:$restore_volume:restore" | shasum -a 256 | awk '{print $1}')"
live_resource_transition storage-restore-volume docker-volume PLANNED "$provider" "" '[]' "" "$restore_labels" '[]' topology
live_resource_transition storage-restore-volume docker-volume CREATING "$provider" "$restore_volume" '[]' "$restore_digest" "$restore_labels" '[]' topology
docker volume create --label "cortex.live.run_id=$LIVE_RUN_ID" --label "cortex.live.provider=$provider" --label "com.docker.compose.project=$LIVE_COMPOSE_PROJECT" --label cortex.live.kind=restore "$restore_volume" >/dev/null
restore_cleanup="$(jq -cn --arg s "$resource_script" --arg id "$restore_volume" --arg r "$LIVE_RUN_ID" --arg p "$provider" '["bash",$s,"cleanup-volume",$id,$r,$p]')"
restore_verify="$(jq -cn --arg s "$resource_script" --arg id "$restore_volume" --arg r "$LIVE_RUN_ID" --arg p "$provider" '["bash",$s,"verify-volume",$id,$r,$p]')"
live_resource_transition storage-restore-volume docker-volume IDENTIFIED "$provider" "$restore_volume" "$restore_cleanup" "$restore_digest" "$restore_labels" "$restore_verify" topology
live_resource_transition storage-restore-volume docker-volume CREATED "$provider" "$restore_volume" "$restore_cleanup" "$restore_digest" "$restore_labels" "$restore_verify" topology
# A root-only preparation container copies both the database and marker evidence
# into the owned volume, then hands them to the production UID explicitly.
docker run --rm --user 0:0 --read-only --tmpfs /tmp --label "cortex.live.run_id=$LIVE_RUN_ID" --label "com.docker.compose.project=$LIVE_COMPOSE_PROJECT" -v "$state_volume:/source:ro" -v "$restore_volume:/data" -v "$markers:/source-markers:ro" --entrypoint sh "$LIVE_CANDIDATE_IMAGE" -ceu \
  'cp /source/live-concurrent-backup.db /data/cortex.db; cp /source-markers /data/committed-markers.txt; chown 1000:1000 /data/cortex.db /data/committed-markers.txt; chmod 0600 /data/cortex.db /data/committed-markers.txt'
if ! docker run --rm --user 1000:1000 --read-only --tmpfs /tmp --label "cortex.live.run_id=$LIVE_RUN_ID" --label "com.docker.compose.project=$LIVE_COMPOSE_PROJECT" -v "$restore_volume:/data" --entrypoint sh "$LIVE_CANDIDATE_IMAGE" -ceu \
  'test "$(stat -c %u:%g:%a /data/cortex.db)" = 1000:1000:600; test "$(stat -c %u:%g:%a /data/committed-markers.txt)" = 1000:1000:600; while IFS= read -r marker; do CORTEX_API_TOKEN=restore-api CORTEX_DB_PATH=/data/cortex.db RUST_LOG=error cortex search --grep "$marker" --limit 1 --json | grep -F "$marker" >/dev/null || exit 1; done < /data/committed-markers.txt' >>"$backup_raw" 2>&1; then
  live_die "restored backup is missing a committed marker"
fi
backup_bytes="$(docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" exec -T candidate sh -ceu 'wc -c < /data/live-concurrent-backup.db')"
jq -cn --argjson bytes "$backup_bytes" --argjson duration "$backup_duration" '{schema:"cortex-live-backup-restore-v1",wal_safe:true,readable:true,marker_consistent:true,committed_markers:5,backup_bytes:$bytes,duration_seconds:$duration,restore_instance:"independent-cortex-process",raw_evidence:"artifacts/storage/backup-restore.raw"}' >"$LIVE_RUN_ROOT/$backup_ev"
chmod 600 "$backup_raw" "$LIVE_RUN_ROOT/$backup_ev"

# Crash the candidate during a separate maintenance backup, then prove restart
# recovery and integrity. The interrupted artifact is never treated as valid.
restart_ev="$LIVE_RUN_ROOT/artifacts/storage/restart-during-maintenance.txt"
backup_audit_before="$(maintenance_audit_count db_backup)"
backup_toxic="backup-interrupt-${LIVE_RUN_ID#cortex-e2e-}"
add_maintenance_response_delay "$backup_toxic"
curl -sS --max-time 30 -X POST -H 'Host: localhost' -H "Authorization: Bearer $LIVE_API_TOKEN" -H "x-cortex-admin-token: $LIVE_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  --data '{"output_path":"/data/interrupted-backup.db"}' "http://127.0.0.1:$LIVE_HTTP_PORT/api/db/backup" >"$restart_ev" 2>&1 & maintenance_client=$!
live_wait_until 15 backup-server-start maintenance_audit_advanced db_backup "$backup_audit_before"
live_wait_until 15 backup-operation-active backup_operation_active "$maintenance_client" /data/interrupted-backup.db
docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" restart candidate >/dev/null
set +e; wait "$maintenance_client"; maintenance_client_status=$?; set -e
remove_maintenance_response_delay "$backup_toxic"
[[ "$maintenance_client_status" -ne 0 && "$maintenance_client_status" -ne 124 ]] || live_die "backup client was not interrupted after server-side start"
live_wait_until 60 maintenance-restart-health _live_http_health_ready
cli db integrity --quick --json >>"$restart_ev" 2>&1 || live_die "database unhealthy after restart during maintenance"
jq -cn --argjson before "$backup_audit_before" --argjson after "$(maintenance_audit_count db_backup)" --argjson client_status "$maintenance_client_status" \
  '{schema:"cortex-live-maintenance-interruption-v1",scenario:"restart-during-maintenance",server_audit_action:"db_backup",server_audit_count_before:$before,server_audit_count_after:$after,server_start_observed:($after>$before),partial_backup_observed_before_restart:true,client_exit_status:$client_status,client_interrupted:($client_status!=0 and $client_status!=124),database_healthy_afterward:true}' \
  >"$LIVE_RUN_ROOT/artifacts/storage/restart-during-maintenance.json"
live_event storage_failure_injection "$(jq -cn '{scenario:"restart-during-maintenance",result:"pass",evidence:"artifacts/storage/restart-during-maintenance.json"}')"
