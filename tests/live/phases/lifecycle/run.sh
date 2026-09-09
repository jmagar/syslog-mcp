#!/usr/bin/env bash
set -euo pipefail
: "${LIVE_RUN_ROOT:?}" "${LIVE_COMPOSE_PROJECT:?}" "${LIVE_HTTP_PORT:?}" "${LIVE_CORTEX_TOKEN:?}"
root="${LIVE_PROJECT_ROOT:?}"; compose="$root/tests/live/profiles/isolated/compose.yaml"
# shellcheck disable=SC1091
source "$root/tests/live/lib/common.sh"; source "$root/tests/live/lib/lock.sh"; source "$root/tests/live/lib/redact.sh"; source "$root/tests/live/lib/events.sh"; source "$root/tests/live/lib/budgets.sh"; source "$root/tests/live/lib/wait.sh"; source "$root/tests/live/lib/docker.sh"
mkdir -p "$LIVE_RUN_ROOT/artifacts/lifecycle"
marker="lifecycle-${LIVE_RUN_ID#cortex-e2e-}"
query() {
  curl -fsS --max-time 10 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d "$(jq -cn --arg q "\"$marker\"" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"cortex",arguments:{action:"search",query:$q,limit:5}}}')" \
    "http://127.0.0.1:$LIVE_HTTP_PORT/mcp" | grep -F "$marker"
}
# Persistence requires a committed seed, so use reliable TCP acceptance rather
# than treating an unacknowledged UDP datagram as durable setup.
printf '<134>1 %s cortex-live lifecycle - - - %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$marker" | nc -w 5 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
live_connection_opened 1
live_wait_until 30 lifecycle-marker query
before="$(docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" ps -q candidate)"
docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" restart candidate >/dev/null
live_wait_until 60 lifecycle-restart-health _live_http_health_ready
live_wait_until 30 lifecycle-restart-marker query
docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" up -d --no-deps --force-recreate candidate >/dev/null
after="$(docker compose -f "$compose" -p "$LIVE_COMPOSE_PROJECT" ps -q candidate)"
live_wait_until 60 lifecycle-replacement-health _live_http_health_ready
live_wait_until 30 lifecycle-replacement-marker query
[[ -n "$before" && -n "$after" && "$before" != "$after" ]]
jq -cn --arg marker "$marker" --arg before "$before" --arg after "$after" \
  '{schema:"cortex-live-persistence-v1",marker:$marker,restart:true,replacement:true,container_before:$before,container_after:$after,marker_consistent:true}' \
  >"$LIVE_RUN_ROOT/artifacts/lifecycle/persistence.json"
chmod 600 "$LIVE_RUN_ROOT/artifacts/lifecycle/persistence.json"
