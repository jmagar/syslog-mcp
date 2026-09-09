#!/usr/bin/env bash
set -euo pipefail
[[ "${LIVE_AGENT_DRIVER_TRACE:-0}" != 1 ]] || set -x

control="${LIVE_AGENT_DOCKER_CONTROL_URL:?}"
proxy="${LIVE_AGENT_DOCKER_URL:?}"
fixture="${LIVE_AGENT_FIXTURE_ID:?}"
out="${LIVE_AGENT_SCENARIO_EVIDENCE_DIR:?}"
daemon_id="${LIVE_AGENT_DAEMON_ID:?}"
mkdir -p "$out"; chmod 700 "$out"

dctl() { case "$control" in container-exec://*) docker exec "${control#container-exec://}" docker "$@";; *) docker -H "$control" "$@";; esac; }
checkpoint() { dctl inspect -f '{{.State.StartedAt}}:{{.RestartCount}}:{{.State.Status}}' "$fixture"; }
fixture_sequence() { dctl exec "$fixture" cat /tmp/agent-seq; }
emit() {
  local scenario="$1" before="$2" after="$3" ids="${4:-[\"$fixture\"]}"
  local action state sequence
  case "$scenario" in
    container-die) action=die; state=exited; sequence=201;;
    container-restart) action=start; state=running; sequence=202;;
    container-rename) action=rename; state=renamed; sequence=203;;
    container-unhealthy) action=health_status_unhealthy; state=unhealthy; sequence=204;;
    bounded-backpressure) action=log; state=recovered; sequence=205;;
    log-rotation) action=log; state=rotated-and-continuous; sequence=207;;
    duplicate-prevention) action=restart; state=deduplicated; sequence=208;;
    proxy-outage) action=log; state=reconnected; sequence=209;;
    server-restart) action=log; state=reconnected; sequence=210;;
  esac
  jq -cn --arg scenario "$scenario" --arg run_id "$LIVE_RUN_ID" --arg daemon_id "$daemon_id" \
    --arg before "$before" --arg after "$after" --arg action "$action" --arg state "$state" --argjson sequence "$sequence" --argjson ids "$ids" \
    --arg root "artifacts/ingest-agent-$scenario-$sequence" \
    '{schema:"cortex-live-agent-driver-evidence-v1",scenario:$scenario,disposition:"pass",run_id:$run_id,daemon_id:$daemon_id,checkpoint_before:$before,checkpoint_after:$after,exact_fixture_ids:$ids,expected_action:$action,observed_state:$state,observation_sequence:$sequence,surface_artifacts:[$root+"-mcp.json",$root+"-rest.json",$root+"-cli.json"],cleanup_evidence:"canonical-resource-manifest"}' >"$out/$scenario.json"
}
proxy_inspect() { curl -fsS --max-time 5 "$proxy/containers/$1/json"; }
cortex_marker_watermark() {
  local marker="${1:-agent-live-stdout-marker}" id="${2:-$fixture}"
  curl -fsS -G -H "Authorization: Bearer $LIVE_API_TOKEN" --data-urlencode "query=\"$marker\"" --data-urlencode limit=1000 "$(live_ingest_http /api/search)" |
    jq --arg id "$id" --arg marker "$marker" '[.logs[]|select((.message|contains($marker)) and (((.metadata_json|fromjson).agent_docker.container_id==$id) or (.message|contains($id))))|.id]|max // 0'
}
marker_records_since() {
  local baseline="$1" marker="${2:-agent-live-stdout-marker}" id="${3:-$fixture}"
  curl -fsS -G -H "Authorization: Bearer $LIVE_API_TOKEN" --data-urlencode "query=\"$marker\"" --data-urlencode limit=1000 "$(live_ingest_http /api/search)" |
    jq --arg id "$id" --arg marker "$marker" --argjson baseline "$baseline" '[.logs[]|select(.id>$baseline and (.message|contains($marker)) and (((.metadata_json|fromjson).agent_docker.container_id==$id) or (.message|contains($id))))]|length'
}
sequence_accounting() {
  local start="$1" end="$2" file="$3" max_loss="$4" payload
  payload="$(curl -fsS -G -H "Authorization: Bearer $LIVE_API_TOKEN" --data-urlencode 'query="agent-live-seq"' --data-urlencode limit=1000 "$(live_ingest_http /api/search)")"
  jq -cn --argjson start "$start" --argjson end "$end" --argjson max_loss "$max_loss" --argjson logs "$(jq -c '.logs' <<<"$payload")" '
    [$logs[] | .message | capture("agent-live-seq-(?<n>[0-9]{8})").n | tonumber | select(.>$start and .<=$end)] as $seen |
    [range($start+1;$end+1)] as $expected |
    ($seen|unique) as $unique |
    {expected_sequence_ids:$expected,persisted_sequence_ids:$unique,expected_count:($expected|length),persisted_count:($unique|length),duplicates:(($seen|length)-($unique|length)),missing_sequence_ids:($expected-$unique),loss:(($expected-$unique)|length),loss_upper_bound:$max_loss} |
    .bounds_enforced=(.duplicates==0 and .loss<=.loss_upper_bound)' >"$file"
  jq -e '.bounds_enforced and .expected_count>0' "$file" >/dev/null
}
wait_marker_growth() {
  local baseline="$1" marker="${2:-agent-live-stdout-marker}" id="${3:-$fixture}" current=0 i
  # The production forwarder reconciles finished container followers on its
  # 30-second poll. Give one full reconciliation interval plus scheduling
  # margin, and prove recovery with a strictly advancing database watermark.
  for ((i=1; i<=45; i++)); do current="$(cortex_marker_watermark "$marker" "$id")"; (( current > baseline )) && { printf '%s\n' "$current"; return 0; }; sleep 1; done
  printf '%s\n' "$current"; return 1
}

before="$(checkpoint)"; dctl stop -t 2 "$fixture" >/dev/null
[[ "$(proxy_inspect "$fixture" | jq -r .State.Status)" == exited ]]
live_agent_observe_event container-die "$fixture" die 201
after="$(checkpoint)"; emit container-die "$before" "$after"
dctl start "$fixture" >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do [[ "$(proxy_inspect "$fixture" | jq -r .State.Running)" == true ]] && break; sleep .2; done
live_agent_observe_event container-restart "$fixture" start 202
emit container-restart "$after" "$(checkpoint)"

before="$(checkpoint)"; old_name="$(dctl inspect -f '{{.Name}}' "$fixture" | sed 's#^/##')"; renamed="live-renamed-${LIVE_RUN_ID#cortex-e2e-}"
dctl rename "$fixture" "$renamed"; [[ "$(proxy_inspect "$fixture" | jq -r '.Name|ltrimstr("/")')" == "$renamed" ]]
live_agent_observe_event container-rename "$fixture" rename 203
dctl rename "$fixture" "$old_name"; emit container-rename "$before" "$(checkpoint)"

unhealthy="$(dctl create --network none --label "cortex.live.run_id=$LIVE_RUN_ID" --health-cmd false --health-interval 100ms --health-retries 1 alpine:3.22 sleep 30)"
dctl start "$unhealthy" >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do [[ "$(proxy_inspect "$unhealthy" | jq -r '.State.Health.Status // ""')" == unhealthy ]] && break; sleep .2; done
[[ "$(proxy_inspect "$unhealthy" | jq -r .State.Health.Status)" == unhealthy ]]
live_agent_observe_event container-unhealthy "$unhealthy" health_status_unhealthy 204
dctl rm -f "$unhealthy" >/dev/null
if dctl inspect "$unhealthy" >/dev/null 2>&1; then exit 1; fi
emit container-unhealthy "$before" "$(checkpoint)" "[\"$unhealthy\"]"

before="$(checkpoint)"; pressure_before="$(cortex_marker_watermark)"; pressure_sequence_before="$(fixture_sequence)"; dctl pause "$fixture" >/dev/null; [[ "$(proxy_inspect "$fixture" | jq -r .State.Paused)" == true ]]; sleep 2
pressure_at_release="$(cortex_marker_watermark)"
dctl unpause "$fixture" >/dev/null; [[ "$(proxy_inspect "$fixture" | jq -r .State.Running)" == true ]]
backpressure_marker="agent-live-backpressure-${LIVE_RUN_ID#cortex-e2e-}"
  # Have PID 1 emit the marker through the container's configured stdout.
  # Docker does not guarantee that an exec process writing /proc/1/fd/1 is
  # attached to the container log driver on every daemon implementation.
  dctl exec "$fixture" sh -c 'printf "%s\n" "$1" >/tmp/live-marker' sh "$backpressure_marker"
  pressure_after="$(wait_marker_growth "$pressure_at_release" "$backpressure_marker")"; pressure_delta="$(marker_records_since "$pressure_at_release" "$backpressure_marker")"; (( pressure_delta >= 1 ))
  dctl exec "$fixture" sh -c ': >/tmp/live-marker'
live_agent_observe_log bounded-backpressure "$fixture" "$backpressure_marker" 205
pressure_sequence_after="$(fixture_sequence)"
sequence_accounting "$pressure_sequence_before" "$pressure_sequence_after" "$out/bounded-backpressure-sequences.json" 2
# The production parser deliberately filters unsupported exec lifecycle events.
# Prove that refusal and then rely on the marker above for recovery.
if live_ingest_mcp_search 'docker container event: exec_create' "$LIVE_RUN_ROOT/artifacts/agent-unsupported-event.json"; then
  echo 'unsupported Docker exec event was ingested' >&2; exit 1
fi
jq -cn --argjson before "$pressure_before" --argjson at_release "$pressure_at_release" --argjson after "$pressure_after" --argjson accepted "$pressure_delta" --slurpfile sequences "$out/bounded-backpressure-sequences.json" \
  '{schema:"cortex-live-agent-flow-accounting-v1",induced_pause_seconds:2,watermarks:{before:$before,at_release:$at_release,after_drain:$after},accepted_after_drain:$accepted,evicted:0,recovered:($accepted>0 and $after>$at_release),sequence_accounting:$sequences[0]}' \
  >"$out/bounded-backpressure-accounting.json"
emit bounded-backpressure "$before" "$(checkpoint)"

# Expanded by the controlled container shell.
# shellcheck disable=SC2016
rotation="$(dctl create --network none --label "cortex.live.run_id=$LIVE_RUN_ID" --log-driver json-file --log-opt max-size=1k --log-opt max-file=2 alpine:3.22 sh -c 'i=0; while [ $i -lt 500 ]; do echo rotation-fill-$i-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; i=$((i+1)); done; i=0; while [ $i -lt 30 ]; do echo agent-live-rotation-marker; i=$((i+1)); sleep 1; done; sleep 15')"
dctl start "$rotation" >/dev/null; sleep 2
curl -fsS --max-time 5 "$proxy/containers/$rotation/logs?stdout=1&tail=50" | strings | grep -F agent-live-rotation-marker >/dev/null
[[ "$(proxy_inspect "$rotation" | jq -r '.HostConfig.LogConfig.Config["max-size"]')" == 1k ]]
live_agent_observe_log log-rotation "$rotation" agent-live-rotation-marker 207
dctl rm -f "$rotation" >/dev/null
if dctl inspect "$rotation" >/dev/null 2>&1; then exit 1; fi
emit log-rotation "$before" "$(checkpoint)" "[\"$rotation\"]"

now="$(date +%s)"; dctl restart "$fixture" >/dev/null; sleep 1
curl -fsS --max-time 5 "$proxy/events?since=$now&until=$(date +%s)&filters=%7B%22container%22%3A%5B%22$fixture%22%5D%7D" >"$out/dedup-events.jsonl"
jq -e -s 'length>0 and (map([.timeNano,.Action,.Actor.ID]|join(":"))|length)==(map([.timeNano,.Action,.Actor.ID]|join(":"))|unique|length)' "$out/dedup-events.jsonl" >/dev/null
live_agent_observe_event duplicate-prevention "$fixture" restart 208
for artifact in "$LIVE_RUN_ROOT/artifacts/ingest-agent-duplicate-prevention-208-rest.json" "$LIVE_RUN_ROOT/artifacts/ingest-agent-duplicate-prevention-208-cli.json"; do
  jq -e --arg id "$fixture" '[.logs[]|select(((.metadata_json|fromjson).agent_docker.container_id==$id) and ((.metadata_json|fromjson).agent_docker.event_action=="restart"))]|length==1' "$artifact" >/dev/null
done
jq -e --arg id "$fixture" '[.result.structuredContent.logs[]|select(((.metadata_json|fromjson).agent_docker.container_id==$id) and ((.metadata_json|fromjson).agent_docker.event_action=="restart"))]|length==1' "$LIVE_RUN_ROOT/artifacts/ingest-agent-duplicate-prevention-208-mcp.json" >/dev/null
emit duplicate-prevention "$before" "$(checkpoint)"

if [[ -n "${LIVE_AGENT_PROXY_CONTAINER_ID:-}" ]]; then
  before="$(checkpoint)"; outage_before="$(cortex_marker_watermark)"; outage_sequence_before="$(fixture_sequence)"; outage_started="$(date +%s)"; docker stop "$LIVE_AGENT_PROXY_CONTAINER_ID" >/dev/null
  if curl -fsS --max-time 2 "$proxy/_ping" >/dev/null 2>&1; then exit 1; fi
  sleep 3; outage_at_restore="$(cortex_marker_watermark)"
  docker start "$LIVE_AGENT_PROXY_CONTAINER_ID" >/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10; do curl -fsS --max-time 1 "$proxy/_ping" >/dev/null 2>&1 && break; sleep .2; done
  [[ "$(curl -fsS "$proxy/info" | jq -r .ID)" == "$daemon_id" ]]
  outage_after="$(wait_marker_growth "$outage_at_restore")"; outage_delta="$(marker_records_since "$outage_at_restore")"; (( outage_delta >= 1 ))
  outage_sequence_after="$(fixture_sequence)"; sequence_accounting "$outage_sequence_before" "$outage_sequence_after" "$out/proxy-outage-sequences.json" 4
  live_agent_observe_log proxy-outage "$fixture" agent-live-stdout-marker 209
  outage_seconds=$(( $(date +%s)-outage_started )); (( outage_seconds >= 3 ))
  jq -cn --argjson seconds "$outage_seconds" --argjson before "$outage_before" --argjson at_restore "$outage_at_restore" --argjson after "$outage_after" --argjson accepted "$outage_delta" --slurpfile sequences "$out/proxy-outage-sequences.json" \
    '{schema:"cortex-live-agent-flow-accounting-v1",outage_seconds:$seconds,watermarks:{before:$before,at_restore:$at_restore,after_drain:$after},accepted_after_reconnect:$accepted,reconnected:($accepted>0 and $after>$at_restore),sequence_accounting:$sequences[0]}' \
    >"$out/proxy-outage-accounting.json"
  emit proxy-outage "$before" "$(checkpoint)"
fi

if [[ -n "${LIVE_COMPOSE_PROJECT:-}" && -n "${LIVE_HTTP_PORT:-}" ]]; then
  before="$(checkpoint)"; server_before="$(cortex_marker_watermark)"; server_sequence_before="$(fixture_sequence)"; server_started="$(date +%s)"
  docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/agent/compose.override.yaml" restart candidate >/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do curl -fsS --max-time 2 "http://127.0.0.1:$LIVE_HTTP_PORT/health" >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS --max-time 2 "http://127.0.0.1:$LIVE_HTTP_PORT/health" >/dev/null
  server_at_restore="$(cortex_marker_watermark)"
  server_after="$(wait_marker_growth "$server_at_restore")"; server_delta="$(marker_records_since "$server_at_restore")"; (( server_delta >= 1 ))
  server_sequence_after="$(fixture_sequence)"; sequence_accounting "$server_sequence_before" "$server_sequence_after" "$out/server-restart-sequences.json" 4
  live_agent_observe_log server-restart "$fixture" agent-live-stdout-marker 210
  server_seconds=$(( $(date +%s)-server_started ))
  jq -cn --argjson seconds "$server_seconds" --argjson before "$server_before" --argjson at_restore "$server_at_restore" --argjson after "$server_after" --argjson accepted "$server_delta" --slurpfile sequences "$out/server-restart-sequences.json" \
    '{schema:"cortex-live-agent-flow-accounting-v1",outage_seconds:$seconds,watermarks:{before:$before,at_restore:$at_restore,after_drain:$after},accepted_after_reconnect:$accepted,reconnected:($accepted>0 and $after>$at_restore),sequence_accounting:$sequences[0],durability:"lossy-syslog-bounded-observation"}' \
    >"$out/server-restart-accounting.json"
  emit server-restart "$before" "$(checkpoint)"
fi
