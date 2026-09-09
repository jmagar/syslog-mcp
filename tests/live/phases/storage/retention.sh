#!/usr/bin/env bash
set -euo pipefail
: "${LIVE_RUN_ROOT:?}" "${LIVE_COMPOSE_PROJECT:?}" "${LIVE_ORACLE_IMAGE:?}"
root="${LIVE_PROJECT_ROOT:?}"; base="$root/tests/live/profiles/isolated/compose.yaml"; override="$root/tests/live/profiles/storage/compose.override.yaml"
# shellcheck disable=SC1091
source "$root/tests/live/lib/common.sh"; source "$root/tests/live/lib/lock.sh"; source "$root/tests/live/lib/redact.sh"; source "$root/tests/live/lib/events.sh"; source "$root/tests/live/lib/report.sh"; source "$root/tests/live/lib/budgets.sh"; source "$root/tests/live/lib/wait.sh"; source "$root/tests/live/lib/docker.sh"
mkdir -p "$LIVE_RUN_ROOT/artifacts/storage"
state="$(docker volume ls -q --filter "label=com.docker.compose.project=$LIVE_COMPOSE_PROJECT" --filter label=cortex.live.kind=state)"
[[ -n "$state" && "$state" == *"$LIVE_COMPOSE_PROJECT"* ]] || live_die "exact owned state volume not found"
docker compose -f "$base" -p "$LIVE_COMPOSE_PROJECT" stop candidate >/dev/null
docker run --rm --user 0:0 --read-only --tmpfs /tmp -v "$state:/data" --entrypoint python "$LIVE_ORACLE_IMAGE" -c '
import sqlite3
db=sqlite3.connect("/data/cortex.db")
rows=[
 ("storage-old-normal","info","storage-test"),
 ("storage-old-adguard","info","adguard-query"),
 ("storage-old-error","err","storage-test")]
for message,severity,app in rows:
 db.execute("INSERT INTO logs(timestamp,hostname,severity,app_name,message,raw,received_at,source_ip) VALUES(?,?,?,?,?,?,?,?)",("2000-01-01T00:00:00Z","storage-retention",severity,app,message,message,"2000-01-01T00:00:00Z","127.0.0.1"))
db.execute("INSERT INTO host_heartbeats(host_id,hostname,sampled_at,received_at,boot_id,uptime_secs,sequence,collection_ms,agent_version,os,architecture) VALUES(?,?,?,?,?,?,?,?,?,?,?)",("storage-old-heartbeat","storage-retention","2000-01-01T00:00:00Z","2000-01-01T00:00:00Z","storage-boot",1,1,1,"live","linux","test"))
db.commit(); db.close()
'
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" up -d --no-deps --force-recreate candidate >/dev/null
live_wait_until 60 retention-health _live_http_health_ready
# Production retention deliberately schedules its first tick after one hour.
# Query through the live CLI after that tick when the extended wait is enabled.
normal="$LIVE_RUN_ROOT/artifacts/storage/retention-normal.json"; adguard="$LIVE_RUN_ROOT/artifacts/storage/retention-adguard.json"; error="$LIVE_RUN_ROOT/artifacts/storage/retention-error.json"
# Positional parameters are intentionally expanded by the child shell.
# shellcheck disable=SC2016
live_wait_until 60 retention-normal-deleted sh -ceu '! docker compose -f "$1" -f "$2" -p "$3" exec -T candidate cortex search --grep storage-old-normal --limit 1 --json | grep -q storage-old-normal' sh "$base" "$override" "$LIVE_COMPOSE_PROJECT"
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" exec -T candidate cortex search --grep storage-old-normal --limit 1 --json >"$normal"
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" exec -T candidate cortex search --grep storage-old-adguard --limit 1 --json >"$adguard"
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" exec -T candidate cortex search --grep storage-old-error --limit 1 --json >"$error"
grep -q storage-old-error "$error"
if grep -q storage-old-normal "$normal"; then live_die "global retention did not delete old normal row"; fi
if grep -q storage-old-adguard "$adguard"; then live_die "AdGuard special cap did not delete old row"; fi
# Verify heartbeat cap and capture FTS phantom diagnostics from an independent,
# read-only SQLite connection after a clean stop.
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" stop candidate >/dev/null
docker run --rm --user 0:0 --read-only --tmpfs /tmp -v "$state:/data:ro" --entrypoint python "$LIVE_ORACLE_IMAGE" -c '
import json,sqlite3
db=sqlite3.connect("file:/data/cortex.db?mode=ro",uri=True)
out={"schema":"cortex-live-retention-v1","old_heartbeats":db.execute("select count(*) from host_heartbeats where host_id=?",("storage-old-heartbeat",)).fetchone()[0],"phantom_fts_rows":db.execute("select count(*) from logs_fts where rowid not in (select id from logs)").fetchone()[0],"error_floor_rows":db.execute("select count(*) from logs where message=?",("storage-old-error",)).fetchone()[0]}
print(json.dumps(out)); db.close()
' >"$LIVE_RUN_ROOT/artifacts/storage/retention.json"
chmod 600 "$LIVE_RUN_ROOT/artifacts/storage/retention"*.json
jq -e '.old_heartbeats==0 and .error_floor_rows==1 and (.phantom_fts_rows|type)=="number"' "$LIVE_RUN_ROOT/artifacts/storage/retention.json" >/dev/null
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" up -d --no-deps candidate >/dev/null
live_wait_until 60 retention-final-health _live_http_health_ready
