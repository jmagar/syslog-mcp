#!/usr/bin/env bash
set -euo pipefail
: "${LIVE_RUN_ROOT:?}" "${LIVE_COMPOSE_PROJECT:?}" "${LIVE_SYSLOG_TCP_PORT:?}"
root="${LIVE_PROJECT_ROOT:?}"; base="$root/tests/live/profiles/isolated/compose.yaml"; override="$root/tests/live/profiles/storage/compose.override.yaml"
# shellcheck disable=SC1091
source "$root/tests/live/lib/common.sh"; source "$root/tests/live/lib/lock.sh"; source "$root/tests/live/lib/redact.sh"; source "$root/tests/live/lib/events.sh"; source "$root/tests/live/lib/budgets.sh"; source "$root/tests/live/lib/wait.sh"; source "$root/tests/live/lib/docker.sh"
mkdir -p "$LIVE_RUN_ROOT/artifacts/storage"
fixture="$LIVE_RUN_ROOT/artifacts/storage/db-size-fixture.syslog"
padding="$(awk 'BEGIN{for(i=0;i<6900;i++)printf "x"}')"
: >"$fixture"
for index in $(seq 1 200); do printf '<134>1 2026-08-27T00:00:00Z cortex-live pressure - - - db-size-%04d %s\n' "$index" "$padding" >>"$fixture"; done
for index in $(seq 1 715); do printf '<131>1 2026-08-27T00:00:00Z cortex-live pressure - - - db-size-error-%04d %s\n' "$index" "$padding" >>"$fixture"; done
fixture_bytes="$(wc -c <"$fixture" | tr -d ' ')"; live_fixture_account 915 "$fixture_bytes"; live_connection_opened 1
nc -w 30 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT" <"$fixture"
live_wait_until 60 db-size-ingest _live_ingest_ready db-size-error-0715
status="$LIVE_RUN_ROOT/artifacts/storage/db-size-status.json"
_db_size_recovered() {
  docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error candidate cortex db status --json >"$status" 2>/dev/null &&
    [[ "$(jq -r .logical_size_bytes "$status")" -le 3145728 ]]
}
live_wait_until 120 db-size-recovery _db_size_recovered
errors="$LIVE_RUN_ROOT/artifacts/storage/db-size-errors.json"
docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" exec -T -e RUST_LOG=error candidate cortex search --grep db-size-error --limit 100 --json >"$errors"
count="$(jq -r .count "$errors")"; (( count >= 10 && count < 715 )) || live_die "err-floor pressure semantics not observed: $count"
jq -cn --argjson fixture_bytes "$fixture_bytes" --argjson logical_size_bytes "$(jq -r .logical_size_bytes "$status")" --argjson protected_errors "$count" \
  '{schema:"cortex-live-db-size-pressure-v1",disposition:"pass",fixture_bytes:$fixture_bytes,recovered_below_bytes:3145728,logical_size_bytes:$logical_size_bytes,error_floor_per_source_cap:10,remaining_errors:$protected_errors,observed_excess_errors_deleted:($protected_errors<715),observed_floor_minimum_preserved:($protected_errors>=10)}' \
  >"$LIVE_RUN_ROOT/artifacts/storage/db-size.json"
chmod 600 "$LIVE_RUN_ROOT/artifacts/storage/db-size"*.json
