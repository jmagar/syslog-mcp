#!/usr/bin/env bash
set -euo pipefail
: "${LIVE_RUN_ROOT:?}" "${LIVE_COMPOSE_PROJECT:?}" "${LIVE_ORACLE_IMAGE:?}"
root="${LIVE_PROJECT_ROOT:?}"; base="$root/tests/live/profiles/isolated/compose.yaml"; override="$root/tests/live/profiles/storage/compose.override.yaml"; fault_override="$root/tests/live/profiles/storage/cleanup-fault.override.yaml"
# shellcheck disable=SC1091
source "$root/tests/live/lib/common.sh"; source "$root/tests/live/lib/lock.sh"; source "$root/tests/live/lib/redact.sh"; source "$root/tests/live/lib/events.sh"; source "$root/tests/live/lib/budgets.sh"; source "$root/tests/live/lib/wait.sh"; source "$root/tests/live/lib/docker.sh"
mkdir -p "$LIVE_RUN_ROOT/artifacts/storage"
state="$(docker volume ls -q --filter "label=com.docker.compose.project=$LIVE_COMPOSE_PROJECT" --filter label=cortex.live.kind=state)"
fixture="$LIVE_RUN_ROOT/artifacts/storage/db-size-fixture.syslog"
docker compose -f "$base" -f "$override" -f "$fault_override" -p "$LIVE_COMPOSE_PROJECT" up -d --no-build --force-recreate candidate >/dev/null
live_wait_until 60 cleanup-fault-health _live_http_health_ready
candidate="$(docker compose -f "$base" -f "$override" -f "$fault_override" -p "$LIVE_COMPOSE_PROJECT" ps -q candidate)"

# Refill well above the 5 MiB trigger, then hold an external SQLite write lock across
# a cleanup tick. The failure must be visible and the following tick recover.
{ cat "$fixture"; cat "$fixture"; } | nc -w 30 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"; live_connection_opened 1
# nc only proves the socket accepted the bytes. Wait until the batch writer has
# committed enough data to cross the configured 5 MiB enforcement threshold;
# otherwise the external lock can precede the write and cleanup correctly has
# no over-budget work to fail.
_cleanup_pressure_ready() { docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error candidate cortex db status --json 2>/dev/null | jq -e '.logical_size_bytes>5242880' >/dev/null; }
live_wait_until 60 cleanup-pressure-ready _cleanup_pressure_ready
lock_ev="$LIVE_RUN_ROOT/artifacts/storage/cleanup-lock.txt"
docker run --rm --user 0:0 -v "$state:/data" --entrypoint python "$LIVE_ORACLE_IMAGE" -c '
import sqlite3,time
db=sqlite3.connect("/data/cortex.db",timeout=30); db.execute("BEGIN EXCLUSIVE"); print("LOCKED",flush=True); time.sleep(45); db.rollback(); db.close()
' >"$lock_ev" 2>&1 & locker=$!
live_wait_until 10 cleanup-lock-acquired grep -q LOCKED "$lock_ev"
# SQLite connections use a five-second busy timeout. A synchronized 45-second
# hold across the fault profile's 30-second cadence guarantees the next tick reaches its
# busy timeout while the external lock is still owned, even under CI jitter.
sleep 41; wait "$locker"
docker logs "$candidate" 2>&1 | grep -F 'Failed to enforce storage budget' >"$LIVE_RUN_ROOT/artifacts/storage/cleanup-failure.log" || live_die "cleanup failure was not observed"
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" up -d --no-build --force-recreate candidate >/dev/null
live_wait_until 60 cleanup-recovery-health _live_http_health_ready
candidate="$(docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" ps -q candidate)"
_cleanup_recovered() { docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error candidate cortex db status --json 2>/dev/null | jq -e '.logical_size_bytes<=3145728' >/dev/null; }
live_wait_until 120 cleanup-failure-recovery _cleanup_recovered

# Refill once more and restart as soon as the one-row cleanup loop begins. The
# replacement must resume cleanup, preserve the newest marker, and remain sound.
marker="cleanup-interrupt-${LIVE_RUN_ID#cortex-e2e-}"; { cat "$fixture"; cat "$fixture"; printf '<134>1 %s cortex-live cleanup - - - %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$marker"; } | nc -w 30 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"; live_connection_opened 1
live_wait_until 30 cleanup-interrupt-marker _live_ingest_ready "$marker"
_cleanup_started() { docker logs "$candidate" 2>&1 | grep -F 'self-trimming oldest telemetry chunk' >/dev/null; }
live_wait_until 30 cleanup-started _cleanup_started
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" restart candidate >/dev/null
live_wait_until 60 cleanup-restart-health _live_http_health_ready
# Replacing the process restarts a one-row-per-chunk cleanup profile from its
# durable DB state. Loaded Docker Desktop runners can require several minutes;
# keep the bounded wait inside the profile wall budget without weakening the
# exact <=3 MiB recovery oracle.
live_wait_until 300 cleanup-restart-recovery _cleanup_recovered
_live_ingest_ready "$marker" || live_die "newest committed marker lost across interrupted cleanup"
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error candidate cortex db integrity --quick --json >"$LIVE_RUN_ROOT/artifacts/storage/cleanup-recovery-integrity.json"
jq -cn '{schema:"cortex-live-cleanup-faults-v1",cleanup_failure_observed:true,failure_recovered:true,cleanup_interrupted_by_restart:true,restart_recovered:true,newest_marker_preserved:true,integrity_ok:true}' >"$LIVE_RUN_ROOT/artifacts/storage/cleanup-faults.json"
chmod 600 "$LIVE_RUN_ROOT/artifacts/storage/cleanup-"* "$LIVE_RUN_ROOT/artifacts/storage/cleanup-faults.json"
