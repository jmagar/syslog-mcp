#!/usr/bin/env bash
set -euo pipefail

notification_mcp() {
  local args="$1" out="$2" status
  status="$(curl -sS --max-time 12 -o "$out" -w '%{http_code}' -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary "$(jq -cn --argjson a "$args" '{jsonrpc:"2.0",id:17,method:"tools/call",params:{name:"cortex",arguments:$a}}')" "http://127.0.0.1:$LIVE_HTTP_PORT/mcp")"
  [[ "$status" == 200 ]]
}
notification_control() {
  docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/notifications/compose.yaml" exec -T apprise wget -qO- --header="Authorization: Bearer $LIVE_APPRISE_CONTROL_TOKEN" --header='Content-Type: application/json' --post-data="$(jq -cn --argjson s "$1" '{sequence:$s}')" http://127.0.0.1:8000/control >/dev/null
}
notification_capture() {
  docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/notifications/compose.yaml" exec -T apprise wget -qO- --header="Authorization: Bearer $LIVE_APPRISE_CONTROL_TOKEN" http://127.0.0.1:8000/capture
}
notification_test_case() {
  local mode="$1" expected="$2" out="$3" body
  body="notify-$mode-$LIVE_RUN_ID"
  notification_control "[\"$mode\"]"
  notification_mcp "$(jq -cn --arg body "$body" '{action:"notifications_test",body:$body}')" "$out"
  if [[ "$expected" == pass ]]; then jq -e '.result.isError==false and (.result.structuredContent.result|contains("sent"))' "$out" >/dev/null
  else jq -e '.result.isError==true and (.result.content[0].text|contains("notifications_test"))' "$out" >/dev/null; fi
}
notification_phase_run() {
  local dir="$LIVE_RUN_ROOT/artifacts/notifications" before after marker host
  mkdir -p "$dir"; live_event phase_started '{"phase":"notifications"}'
  before="$(notification_capture | tee "$dir/capture-before.json" | jq -r .requests_total)"
  notification_test_case 202 pass "$dir/test-2xx.json"
  notification_test_case 400 fail "$dir/test-4xx.json"
  notification_test_case 503 fail "$dir/test-5xx.json"
  notification_test_case malformed fail "$dir/test-malformed.json"
  notification_test_case timeout fail "$dir/test-timeout.json"
  notification_test_case redirect fail "$dir/test-redirect.json"
  # Real evaluator -> durable outbox -> transient retry -> success.
  notification_control '["500","202"]'; host="notify-${LIVE_RUN_ID#cortex-e2e-}"; marker="Killed process 9911 (retry-${LIVE_RUN_ID#cortex-e2e-})"
  printf '<11>1 %s %s kernel - - - Out of memory: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "$host" "$marker" | nc -w 2 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  for _ in $(seq 1 20); do
    notification_capture >"$dir/capture-retry.json"
    [[ "$(jq --arg host "$host" '[.records[]|select(.payload.title|contains($host))]|length' "$dir/capture-retry.json")" -ge 2 ]] && break
    sleep 1
  done
  jq -e --arg host "$host" --arg run "$LIVE_RUN_ID" '
    .records as $records | [$records[]|select(.payload.title|contains($host))] as $r |
    ($r|length)==2 and $r[0].mode=="500" and $r[1].mode=="202" and
    $r[1].ordinal>$r[0].ordinal and ($r[1].at_ns-$r[0].at_ns)>=500000000 and
    all(["202","400","503","malformed","timeout","redirect"][];
      . as $mode | any($records[]; .mode==$mode and .payload.title=="Test Notification" and .payload.body==("notify-"+$mode+"-"+$run) and .payload.type=="info" and .payload.format=="markdown"))
  ' "$dir/capture-retry.json" >/dev/null
  # A repeat within the outage/dedup key must not deliver again.
  printf '<11>1 %s %s kernel - - - Out of memory: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "$host" "$marker" | nc -w 2 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  sleep 3; notification_capture >"$dir/capture-dedup.json"
  jq -e --arg host "$host" '[.records[]|select(.payload.title|contains($host))]|length==2' "$dir/capture-dedup.json" >/dev/null
  # Restart mock and prove delivery resumes without external redirect/egress.
  docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/notifications/compose.yaml" restart apprise >/dev/null
  notification_test_case 207 pass "$dir/test-after-restart.json"
  notification_capture >"$dir/capture-final.json"; after="$(jq -r .requests_total "$dir/capture-final.json")"
  jq -e '.external_canary==0 and (.records|length)<=128 and all(.records[];.path=="/notify/" and (.payload.urls==["json://run-owned.invalid"]) and .payload.format=="markdown")' "$dir/capture-final.json" >/dev/null
  (( after > before ))
  jq -cn --argjson before "$before" --argjson after "$after" --arg host "$host" '{schema:"cortex-live-notification-lifecycle-v1",before:$before,after:$after,retry_host:$host,cases:["2xx","4xx","5xx","timeout","malformed","redirect","retry","dedup","restart"],external_egress_requests:0,queue_bound:128,body_bound:65536}' >"$dir/result.json"
  live_terminal_disposition notifications pass artifacts/notifications/result.json
}
