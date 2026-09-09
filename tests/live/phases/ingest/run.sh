#!/usr/bin/env bash
set -euo pipefail

# A black-box ingest matrix: every positive assertion observes data through a
# supported Cortex surface and never reads the storage implementation directly.
live_ingest_identity() { printf 'li-%s-%s' "$(printf '%s' "${LIVE_RUN_ID:?}:$1:$2" | shasum -a 256 | cut -c1-16)" "$1"; }
live_ingest_marker() { printf '%s-%s-%04d' "$(live_ingest_identity "$1" "$2")" "$1" "$2"; }
live_ingest_case() { live_event ingest_case "$(jq -cn --arg case "$1" --arg result "$2" --arg evidence "${3:-}" '{case:$case,result:$result,evidence:$evidence}')"; }
live_ingest_bound_producer() {
  local type="$1" records="$2" bytes="$3" deadline="${4:-60}" plan
  plan="$LIVE_RUN_ROOT/${type//[^a-zA-Z0-9]/-}-producer-plan"
  local limits result; limits="$(jq -c --arg p isolated '.profiles[$p]' "$LIVE_PROJECT_ROOT/tests/live/contracts/profiles.json")"
  result="$(bash "$LIVE_PROJECT_ROOT/tests/live/phases/ingest/generate.sh" "$type" "$records" "$(jq -r .fixture_records <<<"$limits")" "$(jq -r .fixture_bytes <<<"$limits")" "$deadline" "$plan")"
  rm -f "$plan"; live_event producer_bound "$(jq -c --argjson planned_bytes "$bytes" '.+{planned_payload_bytes:$planned_bytes}' <<<"$result")"
}
live_ingest_account_file() {
  local records="$1" file="$2" bytes
  bytes="$(wc -c <"$file" | tr -d ' ')"
  live_budget_add fixture_records "$records"
  live_budget_add fixture_bytes "$bytes"
  live_event producer_actual "$(jq -cn --arg file "${file#"$LIVE_RUN_ROOT"/}" --argjson records "$records" --argjson bytes "$bytes" '{file:$file,records:$records,bytes:$bytes}')"
}
live_ingest_http() { printf 'http://127.0.0.1:%s%s' "${LIVE_HTTP_PORT:?}" "$1"; }

live_ingest_curl_status() {
  local output="$1"; shift
  curl -sS --max-time 10 -o "$output" -w '%{http_code}' -H 'Host: localhost' "$@"
}

live_ingest_mcp_search() {
  local marker="$1" output="$2"
  curl -fsS --max-time 8 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d "$(jq -cn --arg q "\"$marker\"" '{jsonrpc:"2.0",id:42,method:"tools/call",params:{name:"cortex",arguments:{action:"search",query:$q,limit:10}}}')" \
    "$(live_ingest_http /mcp)" >"$output"
  grep -F "$marker" "$output" >/dev/null
}

live_ingest_rest_search() {
  local marker="$1" output="$2"
  curl -fsS --max-time 8 -G -H 'Host: localhost' -H "Authorization: Bearer $LIVE_API_TOKEN" \
    --data-urlencode "query=\"$marker\"" --data-urlencode 'limit=10' "$(live_ingest_http /api/search)" >"$output"
  grep -F "$marker" "$output" >/dev/null
}

live_ingest_cli_search() {
  local marker="$1" output="$2" candidate
  candidate="$(docker ps -q --filter "label=com.docker.compose.project=$LIVE_COMPOSE_PROJECT" --filter label=com.docker.compose.service=candidate)"
  [[ -n "$candidate" ]]
  docker exec "$candidate" cortex search --http --server http://127.0.0.1:3100 \
    --grep "$marker" --limit 10 --json >"$output"
  grep -F "$marker" "$output" >/dev/null
}

live_ingest_wait_marker() {
  local marker="$1" kind="$2" sequence="$3" mcp rest cli
  mcp="$LIVE_RUN_ROOT/artifacts/ingest-${kind}-${sequence}-mcp.json"
  rest="$LIVE_RUN_ROOT/artifacts/ingest-${kind}-${sequence}-rest.json"
  cli="$LIVE_RUN_ROOT/artifacts/ingest-${kind}-${sequence}-cli.json"
  local deadline=$(( $(date +%s) + 30 ))
  while (( $(date +%s) < deadline )); do
    live_budget_add poll_attempts 1
    if live_ingest_mcp_search "$marker" "$mcp" && live_ingest_rest_search "$marker" "$rest" && live_ingest_cli_search "$marker" "$cli"; then return 0; fi
    sleep 1
  done
  return 1
}

live_ingest_syslog() {
  live_ingest_bound_producer syslog 16 10000 60
  local marker payload host app
  host="$(live_ingest_identity host-udp3164 1)"; app="$(live_ingest_identity app-udp3164 1)"
  marker="$(live_ingest_marker syslog-udp-rfc3164 1)"; payload="<134>Aug 27 12:00:00 $host ${app}[7]: $marker"
  printf '%s\n' "$payload" | nc -u -w 1 127.0.0.1 "$LIVE_SYSLOG_UDP_PORT"; live_budget_add fixture_records 1; live_budget_add fixture_bytes "${#payload}"
  live_ingest_wait_marker "$marker" syslog-udp-rfc3164 1
  jq -e --arg host "$host" --arg app "$app" '.count==1 and .logs[0].hostname==$host and .logs[0].app_name==$app and .logs[0].severity=="info" and (.logs[0].source_ip|length>0)' "$LIVE_RUN_ROOT/artifacts/ingest-syslog-udp-rfc3164-1-rest.json" >/dev/null
  live_ingest_case syslog.udp.rfc3164 pass artifacts/ingest-syslog-udp-rfc3164-1-rest.json
  host="$(live_ingest_identity host-udp5424 2)"; app="$(live_ingest_identity app-udp5424 2)"; marker="$(live_ingest_marker syslog-udp-rfc5424 2)"; payload="<134>1 2026-08-27T12:00:00Z $host $app 8 ID47 [live@32473 run=\"$LIVE_RUN_ID\"] $marker"
  printf '%s\n' "$payload" | nc -u -w 1 127.0.0.1 "$LIVE_SYSLOG_UDP_PORT"; live_budget_add fixture_records 1; live_budget_add fixture_bytes "${#payload}"
  live_ingest_wait_marker "$marker" syslog-udp-rfc5424 2
  jq -e --arg host "$host" --arg app "$app" '.logs[0].hostname==$host and .logs[0].app_name==$app and .logs[0].process_id=="8"' "$LIVE_RUN_ROOT/artifacts/ingest-syslog-udp-rfc5424-2-rest.json" >/dev/null
  live_ingest_case syslog.udp.rfc5424 pass artifacts/ingest-syslog-udp-rfc5424-2-rest.json
  host="$(live_ingest_identity host-tcp3164 3)"; app="$(live_ingest_identity app-tcp3164 3)"; marker="$(live_ingest_marker syslog-tcp-rfc3164 3)"; payload="<11>Aug 27 12:00:01 $host $app: $marker"
  printf '%s\n' "$payload" | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"; live_budget_add connections 1; live_budget_add fixture_records 1
  live_ingest_wait_marker "$marker" syslog-tcp-rfc3164 3
  jq -e --arg host "$host" --arg app "$app" '.logs[0].hostname==$host and .logs[0].app_name==$app and .logs[0].severity=="err"' "$LIVE_RUN_ROOT/artifacts/ingest-syslog-tcp-rfc3164-3-rest.json" >/dev/null
  live_ingest_case syslog.tcp.rfc3164 pass artifacts/ingest-syslog-tcp-rfc3164-3-rest.json
  host="$(live_ingest_identity host-tcp5424 4)"; app="$(live_ingest_identity app-tcp5424 4)"; marker="$(live_ingest_marker syslog-tcp-rfc5424 4)"; payload="<165>1 2026-08-27T12:00:02Z $host $app 9 ID48 - $marker"
  printf '%s\n' "$payload" | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"; live_budget_add connections 1; live_budget_add fixture_records 1
  live_ingest_wait_marker "$marker" syslog-tcp-rfc5424 4
  jq -e --arg host "$host" --arg app "$app" '.logs[0].hostname==$host and .logs[0].app_name==$app and .logs[0].severity=="notice"' "$LIVE_RUN_ROOT/artifacts/ingest-syslog-tcp-rfc5424-4-rest.json" >/dev/null
  live_ingest_case syslog.tcp.rfc5424 pass artifacts/ingest-syslog-tcp-rfc5424-4-rest.json
  # Newline framing is the compiled TCP contract. Fragmented writes and a
  # malformed neighbor prove buffering and per-line isolation.
  marker="$(live_ingest_marker syslog-tcp-framing 5)"
  { printf '<134>1 2026-08-27T12:00:03Z live app 10 ID49 - %s' "${marker:0:${#marker}/2}"; sleep 0.1; printf '%s\nmalformed-adversarial\n' "${marker:${#marker}/2}"; } | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  live_budget_add connections 1; live_budget_add fixture_records 2; live_ingest_wait_marker "$marker" syslog-tcp-framing 5
  live_ingest_case syslog.tcp.framing pass artifacts/ingest-syslog-tcp-framing-5-rest.json
  local first second duplicate rejected survivor
  first="$(live_ingest_marker syslog-tcp-reconnect 6)"; second="$(live_ingest_marker syslog-tcp-reconnect 7)"
  printf '<131>1 2026-08-27T12:00:04Z reconnect app 11 ID50 - %s\n' "$first" | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  printf '<131>1 2026-08-27T12:00:05Z reconnect app 12 ID51 - %s\n' "$second" | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  live_ingest_wait_marker "$first" syslog-tcp-reconnect 6; live_ingest_wait_marker "$second" syslog-tcp-reconnect 7
  duplicate="$(live_ingest_marker syslog-udp-duplicate 8)"
  printf '<134>1 2026-08-27T12:00:06Z duplicate app 13 ID52 - %s\n' "$duplicate" | nc -u -w 1 127.0.0.1 "$LIVE_SYSLOG_UDP_PORT"
  printf '<134>1 2026-08-27T12:00:06Z duplicate app 13 ID52 - %s\n' "$duplicate" | nc -u -w 1 127.0.0.1 "$LIVE_SYSLOG_UDP_PORT"
  live_ingest_wait_marker "$duplicate" syslog-udp-duplicate 8
  jq -e '.count==2 and (.logs|length)==2 and .logs[0].message==.logs[1].message' "$LIVE_RUN_ROOT/artifacts/ingest-syslog-udp-duplicate-8-rest.json" >/dev/null
  live_ingest_case syslog.retry-duplicate pass artifacts/ingest-syslog-udp-duplicate-8-rest.json
  rejected="$(live_ingest_marker syslog-oversize 9)"; survivor="$(live_ingest_marker syslog-survivor 10)"
  { printf '<134>'; printf '%9000s' "$rejected"; printf '\n<131>1 2026-08-27T12:00:07Z survivor app 14 ID53 - %s\n' "$survivor"; } | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT" || true
  printf '<134>invalid-utf8-\xff\xfe\n' | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT" || true
  live_ingest_wait_marker "$survivor" syslog-survivor 10
  if live_ingest_mcp_search "$rejected" "$LIVE_RUN_ROOT/artifacts/syslog-oversize-query.json"; then live_die 'oversized record was ingested'; return 1; fi
  live_budget_add fixture_records 7; live_budget_add connections 4; live_budget_add fixture_bytes 9400
  live_ingest_case syslog.adversarial pass artifacts/syslog-oversize-query.json
}

live_ingest_udp_relay_ready() {
  docker exec "$1" python -c '
import errno, socket, sys
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
    try:
        probe.bind(("0.0.0.0", 11514))
    except OSError as error:
        sys.exit(0 if error.errno == errno.EADDRINUSE else 1)
sys.exit(1)
'
}

live_ingest_downtime() {
  local candidate udp_redirector udp_lost udp_recovered tcp_retry http_retry status tcp_exit
  candidate="$(live_ingest_candidate_id)"; udp_lost="$(live_ingest_marker downtime-udp-loss 70)"; tcp_retry="$(live_ingest_marker downtime-tcp-retry 71)"; http_retry="$(live_ingest_marker downtime-http-retry 72)"
  udp_redirector="$(docker ps -q --filter "label=com.docker.compose.project=$LIVE_COMPOSE_PROJECT" --filter label=com.docker.compose.service=udp-redirector)"
  [[ -n "$udp_redirector" && "$udp_redirector" != *$'\n'* ]] || { live_die 'expected exactly one UDP redirector'; return 1; }
  # This is an ingress-outage test, not a promise that UDP can never queue.
  # Leaving the relay alive permits DNS/neighbor resolution or socket queues
  # to delay forwarding until the candidate returns, invalidating the probe.
  docker stop -t 5 "$udp_redirector" "$candidate" >/dev/null
  [[ "$(docker inspect -f '{{.State.Running}}' "$udp_redirector")" == false ]]
  [[ "$(docker inspect -f '{{.State.Running}}' "$candidate")" == false ]]
  printf '<134>1 2026-08-27T12:10:00Z down udp 70 ID70 - %s\n' "$udp_lost" | nc -u -w 1 127.0.0.1 "$LIVE_SYSLOG_UDP_PORT" || true
  set +e
  printf '<134>1 2026-08-27T12:10:01Z down tcp 71 ID71 - %s\n' "$tcp_retry" | nc -w 2 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  tcp_exit=$?
  set -e
  status="$(curl -sS --max-time 2 -o "$LIVE_RUN_ROOT/artifacts/downtime-http.stderr" -w '%{http_code}' -H 'Host: localhost' "$(live_ingest_http /health)" 2>/dev/null || true)"; [[ "$status" == 000 || -z "$status" ]]
  docker start "$candidate" >/dev/null; live_wait_until 30 downtime-health _live_http_health_ready; live_wait_until 30 downtime-mcp _live_mcp_ready
  docker start "$udp_redirector" >/dev/null
  live_wait_until 30 downtime-udp-ready live_ingest_udp_relay_ready "$udp_redirector"
  # Docker allocates a new ephemeral host port when this relay restarts.
  # The pre-outage binding is no longer an ingress endpoint.
  LIVE_SYSLOG_UDP_PORT="$(live_topology_port "" "$LIVE_COMPOSE_PROJECT" udp-redirector 11514 udp)"
  export LIVE_SYSLOG_UDP_PORT
  udp_recovered="$(live_ingest_marker downtime-udp-recovered 73)"
  printf '<134>1 2026-08-27T12:10:02Z retry udp 73 ID73 - %s\n' "$udp_recovered" | nc -u -w 1 127.0.0.1 "$LIVE_SYSLOG_UDP_PORT"
  live_ingest_wait_marker "$udp_recovered" downtime-udp-recovered 73
  # A TCP proxy may accept locally while its upstream is absent. Acceptance is
  # not durability: prove the first attempt was not stored before retrying.
  if live_ingest_mcp_search "$tcp_retry" "$LIVE_RUN_ROOT/artifacts/downtime-tcp-before-retry.json"; then live_die 'TCP attempt made during downtime was unexpectedly stored'; return 1; fi
  jq -cn --argjson tcp_exit "$tcp_exit" --arg http_status "${status:-000}" '{udp_ingress_while_down:"stopped",udp_recovery:"observed",tcp_proxy_exit:$tcp_exit,http_status_while_down:$http_status,tcp_contract:"retry_required_after_unconfirmed_delivery"}' >"$LIVE_RUN_ROOT/artifacts/downtime-transport.json"
  printf '<134>1 2026-08-27T12:10:02Z retry tcp 72 ID72 - %s\n' "$tcp_retry" | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"; live_ingest_wait_marker "$tcp_retry" downtime-tcp-retry 71
  local body; body="$(jq -cn --arg m "$http_retry" '[{started_at:"2026-08-27T12:10:03Z",finished_at:"2026-08-27T12:10:04Z",duration_ms:1000,exit_status:0,command:$m,cwd:null,agent:$m,command_surface:null,hostname:$m,user:null,pid:72,session_id:$m,schema_version:1,content_scrubbed:true}]')"
  [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/downtime-http-retry.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "$body" "$(live_ingest_http /v1/agent-commands)")" == 200 ]]; live_ingest_wait_marker "$http_retry" downtime-http-retry 72
  if live_ingest_mcp_search "$udp_lost" "$LIVE_RUN_ROOT/artifacts/downtime-udp-loss-query.json"; then live_die 'UDP datagram sent during downtime survived'; return 1; fi
  live_ingest_case downtime.udp-loss pass artifacts/downtime-udp-loss-query.json
  live_ingest_case downtime.tcp-retry pass artifacts/downtime-transport.json
  live_ingest_case downtime.http-retry pass artifacts/ingest-downtime-http-retry-72-rest.json
}

live_ingest_http_json_lanes() {
  live_ingest_bound_producer http-json 2021 9000000 90
  local marker body path response status seq=10 kind limit oversized
  for kind in heartbeat agent-command shell-history ai-transcript; do
    seq=$((seq+1)); marker="$(live_ingest_marker "$kind" "$seq")"
    case "$kind" in
      heartbeat) path=/v1/heartbeats; body="$(jq -cn --arg m "$marker" '{host:{host_id:$m,hostname:$m,os:"linux",kernel:"6.8-live",architecture:"x86_64",boot_id:$m,timezone:"UTC"},sample:{sequence:1,sampled_at:"2026-08-27T12:00:00Z",uptime_secs:1,monotonic_ms:1,collection_ms:1,partial:true,probe_errors:[],skipped_probes:[]},agent:{version:"3.15.0",mode:"always_on",interval_secs:30,push_latency_ms:1,retry_backlog:0},cpu:{load1:0.1,load5:0.1,load15:0.1,usage_pct:1,iowait_pct:0,steal_pct:0,core_count:1},memory:{mem_total_bytes:1000,mem_available_bytes:900,swap_total_bytes:0,swap_used_bytes:0},disks:[],network:[],processes:{total:1,running:1,sleeping:0,zombies:0,top:[]},containers:{runtime:"docker",reachable:true,running:0,exited:0,restarting:0,unhealthy:0,details:[]}}')";;
      agent-command) path=/v1/agent-commands; body="$(jq -cn --arg m "$marker" --arg agent "$(live_ingest_identity agent-command "$seq")" '[{started_at:"2026-08-27T12:00:00Z",finished_at:"2026-08-27T12:00:01Z",duration_ms:1000,exit_status:0,command:$m,cwd:null,agent:$agent,command_surface:null,hostname:$m,user:null,pid:42,session_id:$m,schema_version:1,content_scrubbed:true}]')";;
      shell-history) path=/v1/shell-history; body="$(jq -cn --arg m "$marker" '{records:[{source:"zsh",hostname:$m,timestamp:"2026-08-27T12:00:00Z",duration_ms:1,command:$m,cwd:null,exit_status:0,session_id:$m}]}')";;
      ai-transcript) path=/v1/ai-transcripts; body="$(jq -c --arg m "$marker" --arg digest "sha256:$(printf '%s' "$marker" | shasum -a 256 | cut -d ' ' -f 1)" 'walk(if . == "live-smoke-transcript" then $m elif (type == "string" and startswith("sha256:")) then $digest else . end)' "$LIVE_PROJECT_ROOT/tests/live/fixtures/ingest/transcript.json")";;
    esac
    response="$LIVE_RUN_ROOT/artifacts/ingest-${kind}-post.json"
    live_budget_add fixture_records 1; live_budget_add fixture_bytes "${#body}"
    status="$(live_ingest_curl_status "$response" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "$body" "$(live_ingest_http "$path")")"
    if [[ "$status" != 200 && "$status" != 202 ]]; then live_die "$kind ingest returned HTTP $status"; return 1; fi
    # Authentication and malformed-input semantics are part of every lane.
    [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/ingest-${kind}-unauth.json" -X POST -H 'Content-Type: application/json' --data-binary "$body" "$(live_ingest_http "$path")")" == 401 ]]
    [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/ingest-${kind}-malformed.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary '{' "$(live_ingest_http "$path")")" =~ ^(400|422)$ ]]
    # These agent ingest handlers intentionally deserialize bounded raw bytes,
    # so content type is not part of their wire contract. Malformed JSON,
    # invalid schemas, oversize bodies, authorization, and wrong methods cover
    # the supported negative semantics without inventing a 415 requirement.
    [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/ingest-${kind}-invalid-schema.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary '{}' "$(live_ingest_http "$path")")" =~ ^(400|422)$ ]]
    case "$kind" in heartbeat) limit=262144;; agent-command) limit=1048576;; shell-history) limit=2097152;; ai-transcript) limit=4194304;; esac
    oversized="$LIVE_RUN_ROOT/http-${kind}-oversized.json"; { printf '{"padding":"'; head -c "$limit" /dev/zero | tr '\0' x; printf '"}'; } >"$oversized"
    live_ingest_account_file 1 "$oversized"
    [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/ingest-${kind}-oversized.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "@$oversized" "$(live_ingest_http "$path")")" == 413 ]]; rm -f "$oversized"
    if [[ "$kind" != heartbeat ]]; then
      live_ingest_wait_marker "$marker" "$kind" "$seq"
      grep -F "$marker" "$LIVE_RUN_ROOT/artifacts/ingest-${kind}-${seq}-rest.json" >/dev/null
    fi
    live_ingest_case "http.$kind" pass "artifacts/ingest-${kind}-post.json"
  done
  local capacity="$LIVE_RUN_ROOT/http-shell-history-capacity.json"
  jq -cn '{records:[range(0;2001)|{source:"zsh",hostname:"capacity",timestamp:"2026-08-27T12:00:00Z",duration_ms:1,command:("c"+tostring),cwd:null,exit_status:0,session_id:null}]}' >"$capacity"
  live_ingest_account_file 2001 "$capacity"
  [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/ingest-shell-history-capacity.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "@$capacity" "$(live_ingest_http /v1/shell-history)")" == 413 ]]; rm -f "$capacity"
  live_ingest_case http.capacity pass artifacts/ingest-shell-history-capacity.json
  local heartbeat candidate
  heartbeat="$(live_ingest_marker heartbeat 11)"
  curl -fsS --max-time 8 -G -H 'Host: localhost' -H "Authorization: Bearer $LIVE_API_TOKEN" --data-urlencode "host=$heartbeat" "$(live_ingest_http /api/host-state)" >"$LIVE_RUN_ROOT/artifacts/heartbeat-host-state-rest.json"
  grep -F "$heartbeat" "$LIVE_RUN_ROOT/artifacts/heartbeat-host-state-rest.json" >/dev/null
  curl -fsS --max-time 8 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "$(jq -cn --arg h "$heartbeat" '{jsonrpc:"2.0",id:43,method:"tools/call",params:{name:"cortex",arguments:{action:"host_state",host:$h}}}')" "$(live_ingest_http /mcp)" >"$LIVE_RUN_ROOT/artifacts/heartbeat-host-state-mcp.json"
  grep -F "$heartbeat" "$LIVE_RUN_ROOT/artifacts/heartbeat-host-state-mcp.json" >/dev/null
  candidate="$(live_ingest_candidate_id)"
  docker exec "$candidate" cortex state host "$heartbeat" --http --server http://127.0.0.1:3100 --json >"$LIVE_RUN_ROOT/artifacts/heartbeat-host-state-cli.json"
  grep -F "$heartbeat" "$LIVE_RUN_ROOT/artifacts/heartbeat-host-state-cli.json" >/dev/null
  live_ingest_case heartbeat.state pass artifacts/heartbeat-host-state-rest.json
}

# Forwarded syslog is the replayable sibling of the best-effort TCP listener:
# it must commit the frame, echo a stable receipt, refuse a reused key that
# carries different content, and never store a second copy on retry.
live_ingest_syslog_forward() {
  local marker instance key body conflict response status
  marker="$(live_ingest_marker syslog-forward 15)"; instance="$(live_ingest_identity syslog-forward 15)"; key="$instance-1"
  body="$(jq -cn --arg instance "$instance" --arg key "$key" --arg m "$marker" '{records:[{source_instance:$instance,source_epoch:1,sequence:1,idempotency_key:$key,observed_at:"2026-08-27T12:00:08Z",line:("<134>1 2026-08-27T12:00:08Z "+$instance+" forwarder 15 ID54 - "+$m)}],gaps:[]}')"
  response="$LIVE_RUN_ROOT/artifacts/ingest-syslog-forward-post.json"
  live_budget_add fixture_records 1; live_budget_add fixture_bytes "${#body}"
  status="$(live_ingest_curl_status "$response" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "$body" "$(live_ingest_http /v1/syslog-forward)")"
  if [[ "$status" != 200 ]]; then live_die "syslog-forward ingest returned HTTP $status"; return 1; fi
  jq -e --arg key "$key" '.receipts==[$key]' "$response" >/dev/null
  live_ingest_wait_marker "$marker" syslog-forward 15
  # The forwarder identity is server-derived: a hostname claimed in the frame
  # never becomes the stored identity.
  jq -e --arg claimed "$instance" '.count==1 and .logs[0].hostname!=$claimed and (.logs[0].hostname|startswith("agent-"))' "$LIVE_RUN_ROOT/artifacts/ingest-syslog-forward-15-rest.json" >/dev/null
  # Replay is the point of the receipt: an identical batch is acknowledged
  # without a second row.
  [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/ingest-syslog-forward-replay.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "$body" "$(live_ingest_http /v1/syslog-forward)")" == 200 ]]
  jq -e --arg key "$key" '.receipts==[$key]' "$LIVE_RUN_ROOT/artifacts/ingest-syslog-forward-replay.json" >/dev/null
  live_ingest_rest_search "$marker" "$LIVE_RUN_ROOT/artifacts/ingest-syslog-forward-replay-search.json"
  jq -e '.count==1' "$LIVE_RUN_ROOT/artifacts/ingest-syslog-forward-replay-search.json" >/dev/null
  # A reused key carrying different content is a client defect, not a retry.
  conflict="$(jq -c '.records[0].line += "-conflict"' <<<"$body")"
  [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/ingest-syslog-forward-conflict.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "$conflict" "$(live_ingest_http /v1/syslog-forward)")" == 409 ]]
  [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/ingest-syslog-forward-unauth.json" -X POST -H 'Content-Type: application/json' --data-binary "$body" "$(live_ingest_http /v1/syslog-forward)")" == 401 ]]
  [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/ingest-syslog-forward-malformed.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary '{' "$(live_ingest_http /v1/syslog-forward)")" =~ ^(400|422)$ ]]
  live_budget_add fixture_records 3; live_budget_add connections 5
  live_ingest_case http.syslog-forward pass artifacts/ingest-syslog-forward-post.json
}

live_ingest_otlp() {
  live_ingest_bound_producer otlp 15 22000000 90
  local signal status fixture_dir="$LIVE_RUN_ROOT/otlp-fixtures" otlp_id baseline_logs baseline_metrics
  otlp_id="$(live_ingest_identity otlp 40)"
  cargo run --quiet --locked --manifest-path "$LIVE_PROJECT_ROOT/tests/live/fixtures/ingest/otlpgen/Cargo.toml" -- "$otlp_id" "$fixture_dir"
  curl -fsS --max-time 8 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" "$(live_ingest_http /health/full)" >"$LIVE_RUN_ROOT/artifacts/otlp-baseline-health.json"
  baseline_logs="$(jq -r .otlp_logs_received "$LIVE_RUN_ROOT/artifacts/otlp-baseline-health.json")"; baseline_metrics="$(jq -r .otlp_metrics_accepted "$LIVE_RUN_ROOT/artifacts/otlp-baseline-health.json")"
  for signal in logs metrics traces; do
    live_ingest_account_file 1 "$fixture_dir/$signal.pb"
    status="$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/otlp-${signal}-response.pb" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/x-protobuf' --data-binary "@$fixture_dir/$signal.pb" "$(live_ingest_http "/v1/$signal")")"; [[ "$status" == 200 ]]
    status="$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/otlp-${signal}-json.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary '{}' "$(live_ingest_http "/v1/$signal")")"
    # The legacy logs lane decodes bounded protobuf bytes regardless of the
    # media-type header, while the newer metrics/traces lanes require the OTLP
    # protobuf media type. Exercise and preserve both public contracts.
    if [[ "$signal" == logs ]]; then [[ "$status" == 400 ]]; else [[ "$status" == 415 ]]; fi
    [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/otlp-${signal}-unauth.json" -X POST -H 'Content-Type: application/x-protobuf' --data-binary '' "$(live_ingest_http "/v1/$signal")")" == 401 ]]
    [[ "$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/otlp-${signal}-malformed.json" -X POST -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/x-protobuf' --data-binary $'\x80' "$(live_ingest_http "/v1/$signal")")" == 400 ]]
    live_budget_add connections 4
    live_ingest_case "otlp.$signal" pass "artifacts/otlp-${signal}-response.pb"
  done
  local limit oversize
  for signal in logs metrics traces; do
    if [[ "$signal" == logs ]]; then limit=4194304; else limit=8388608; fi
    oversize="$LIVE_RUN_ROOT/otlp-fixtures/$signal-oversize.pb"; head -c "$((limit+1))" /dev/zero >"$oversize"
    live_ingest_account_file 1 "$oversize"
    status="$(curl -sS --max-time 15 -D "$LIVE_RUN_ROOT/artifacts/otlp-${signal}-oversize.headers" -o "$LIVE_RUN_ROOT/artifacts/otlp-${signal}-oversize.json" -w '%{http_code}' -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/x-protobuf' --data-binary "@$oversize" "$(live_ingest_http "/v1/$signal")")"
    [[ "$status" == 413 ]]; rm -f "$oversize"; live_ingest_case "otlp.$signal.oversize" pass "artifacts/otlp-${signal}-oversize.headers"
  done
  live_ingest_wait_marker "$otlp_id-otlp-log-0040" otlp-log 40
  curl -fsS --max-time 8 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" "$(live_ingest_http /health/full)" >"$LIVE_RUN_ROOT/artifacts/otlp-health.json"
  jq -e --argjson logs "$baseline_logs" --argjson metrics "$baseline_metrics" '.otlp_logs_received-$logs==1 and .otlp_metrics_accepted-$metrics==1 and .otlp_decode_errors >= 3' "$LIVE_RUN_ROOT/artifacts/otlp-health.json" >/dev/null
  jq -cn --arg run_id "$LIVE_RUN_ID" --arg identity "$otlp_id" --argjson before_logs "$baseline_logs" --argjson after_logs "$(jq -r .otlp_logs_received "$LIVE_RUN_ROOT/artifacts/otlp-health.json")" --argjson before_metrics "$baseline_metrics" --argjson after_metrics "$(jq -r .otlp_metrics_accepted "$LIVE_RUN_ROOT/artifacts/otlp-health.json")" '{run_id:$run_id,identity:$identity,logs_delta:($after_logs-$before_logs),metrics_delta:($after_metrics-$before_metrics),trace_public_read_surface:false,trace_attribution:"unique request plus successful ExportTrace response; no public row query exists"}' >"$LIVE_RUN_ROOT/artifacts/otlp-attribution.json"
}

live_ingest_candidate_id() {
  docker ps -q --filter "label=com.docker.compose.project=$LIVE_COMPOSE_PROJECT" --filter label=com.docker.compose.service=candidate
}

live_ingest_prepare_filetail_mount() {
  local base override
  LIVE_FILETAIL_ROOT="$LIVE_RUN_ROOT/file-tail-root"; export LIVE_FILETAIL_ROOT
  mkdir -p "$LIVE_FILETAIL_ROOT"; chmod 0777 "$LIVE_FILETAIL_ROOT"
  base="$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml"; override="$LIVE_PROJECT_ROOT/tests/live/phases/ingest/filetail-compose.yaml"
  docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" up -d --no-build --force-recreate candidate socket-maker
  live_wait_until 30 filetail-mount-health _live_http_health_ready; live_wait_until 30 filetail-mount-mcp _live_mcp_ready
  local deadline=$(( $(date +%s)+10 )); while [[ ! -S "$LIVE_FILETAIL_ROOT/hostile.sock" && $(date +%s) -lt $deadline ]]; do sleep .1; done
  [[ -S "$LIVE_FILETAIL_ROOT/hostile.sock" ]]
}

live_ingest_file_tail_api() {
  local body="$1" output="$2"
  curl -fsS --max-time 8 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_API_TOKEN" -H "X-Cortex-Admin-Token: $LIVE_ADMIN_TOKEN" -H 'Content-Type: application/json' -d "$body" "$(live_ingest_http /api/file-tails)" >"$output"
}

live_ingest_file_tail() {
  live_ingest_bound_producer filetail 12 10000 90
  local candidate id marker output pre_marker cleanup verify labels provider digest
  candidate="$(live_ingest_candidate_id)"; id="live-tail-${LIVE_RUN_ID#cortex-e2e-}"; marker="$(live_ingest_marker managed-file-tail 30)"
  # The container is the isolated test resource. Root only prepares the allowed
  # mount and hostile inode types; Cortex itself continues as its unprivileged UID.
  pre_marker="$(live_ingest_marker file-tail-preexisting 29)"; docker exec "$candidate" sh -c 'printf "%s\n" "$1" > /file-tail-root/live.log' sh "$pre_marker"
  provider="${LIVE_RESOURCE_PROVIDER:?}"; digest="$(printf '%s' "$LIVE_RUN_ID:$id:/file-tail-root/live.log" | shasum -a 256 | awk '{print $1}')"; cleanup="$(jq -cn --arg s "$LIVE_PROJECT_ROOT/tests/live/phases/ingest/filetail_resource.sh" --arg id "$id" --arg url "$(live_ingest_http '')" '["bash",$s,"cleanup",$id,$url]')"; verify="$(jq -cn --arg s "$LIVE_PROJECT_ROOT/tests/live/phases/ingest/filetail_resource.sh" --arg id "$id" --arg url "$(live_ingest_http '')" '["bash",$s,"verify",$id,$url]')"; labels="$(jq -cn --arg id "$id" '{file_tail_id:$id}')"
  live_resource_transition "filetail-$id" file-tail-registration PLANNED "$provider" "" '[]' "" "$labels" '[]'
  live_resource_transition "filetail-$id" file-tail-registration CREATING "$provider" "$id" '[]' "$digest" "$labels" '[]'
  live_resource_transition "filetail-$id" file-tail-registration IDENTIFIED "$provider" "$id" "$cleanup" "$digest" "$labels" "$verify"
  live_ingest_file_tail_api "$(jq -cn --arg id "$id" '{op:"add",id:$id,path:"/file-tail-root/live.log",tag:"cortex-live",start_at_end:false}')" "$LIVE_RUN_ROOT/artifacts/file-tail-add.json"
  live_resource_transition "filetail-$id" file-tail-registration CREATED "$provider" "$id" "$cleanup" "$digest" "$labels" "$verify"
  live_ingest_wait_marker "$pre_marker" file-tail-preexisting 29
  docker exec "$candidate" sh -c 'printf "%s\n" "$1" >> /file-tail-root/live.log' sh "$marker"
  live_budget_add fixture_records 1; live_ingest_wait_marker "$marker" managed-file-tail 30
  local rotated truncated checkpoint
  rotated="$(live_ingest_marker file-tail-rotate 32)"; truncated="$(live_ingest_marker file-tail-truncate 33)"; checkpoint="$(live_ingest_marker file-tail-checkpoint 34)"
  docker exec "$candidate" sh -c 'mv /file-tail-root/live.log /file-tail-root/live.log.1; : > /file-tail-root/live.log; printf "%s\n" "$1" >> /file-tail-root/live.log' sh "$rotated"
  live_ingest_wait_marker "$rotated" file-tail-rotate 32
  docker exec "$candidate" sh -c ': > /file-tail-root/live.log; printf "%s\n" "$1" >> /file-tail-root/live.log' sh "$truncated"
  live_ingest_wait_marker "$truncated" file-tail-truncate 33
  docker restart "$candidate" >/dev/null; live_wait_until 30 file-tail-restart-health _live_http_health_ready; live_wait_until 30 file-tail-restart-mcp _live_mcp_ready
  docker exec "$candidate" sh -c 'printf "%s\n" "$1" >> /file-tail-root/live.log' sh "$checkpoint"
  live_ingest_wait_marker "$checkpoint" file-tail-checkpoint 34
  live_ingest_case filetail.lifecycle pass artifacts/ingest-file-tail-checkpoint-34-rest.json
  live_ingest_file_tail_api "$(jq -cn --arg id "$id" '{op:"disable",id:$id}')" "$LIVE_RUN_ROOT/artifacts/file-tail-disable.json"
  live_ingest_file_tail_api "$(jq -cn --arg id "$id" '{op:"enable",id:$id}')" "$LIVE_RUN_ROOT/artifacts/file-tail-enable.json"
  local end_id="end-${LIVE_RUN_ID#cortex-e2e-}" end_pre end_post
  end_pre="$(live_ingest_marker file-tail-end-pre 36)"; end_post="$(live_ingest_marker file-tail-end-post 37)"
  docker exec "$candidate" sh -c 'printf "%s\n" "$1" > /file-tail-root/end.log' sh "$end_pre"
  live_ingest_file_tail_api "$(jq -cn --arg id "$end_id" '{op:"add",id:$id,path:"/file-tail-root/end.log",tag:"start-end",start_at_end:true}')" "$LIVE_RUN_ROOT/artifacts/file-tail-end-add.json"
  sleep 2; if live_ingest_mcp_search "$end_pre" "$LIVE_RUN_ROOT/artifacts/file-tail-end-pre-query.json"; then live_die 'start_at_end ingested preexisting line'; return 1; fi
  docker exec "$candidate" sh -c 'printf "%s\n" "$1" >> /file-tail-root/end.log' sh "$end_post"; live_ingest_wait_marker "$end_post" file-tail-end-post 37
  live_ingest_file_tail_api "$(jq -cn --arg id "$end_id" '{op:"remove",id:$id}')" /dev/null
  live_ingest_case filetail.start-position pass artifacts/ingest-file-tail-end-post-37-rest.json
  docker exec -u 0 "$candidate" sh -c 'ln -s live.log /file-tail-root/link.log; mkdir /file-tail-root/directory; mkfifo /file-tail-root/fifo'
  local hostile path
  for hostile in link directory fifo; do
    case "$hostile" in link) path=/file-tail-root/link.log;; directory) path=/file-tail-root/directory;; fifo) path=/file-tail-root/fifo;; esac
    if live_ingest_file_tail_api "$(jq -cn --arg id "hostile-$hostile" --arg path "$path" '{op:"add",id:$id,path:$path,tag:"hostile"}')" "$LIVE_RUN_ROOT/artifacts/file-tail-${hostile}.stdout" 2>"$LIVE_RUN_ROOT/artifacts/file-tail-${hostile}.stderr"; then
      live_die "file-tail accepted hostile $hostile path"; return 1
    fi
  done
  for hostile in proc sysfs device traversal socket; do
    case "$hostile" in proc) path=/proc/version;; sysfs) path=/sys/kernel/uevent_seqnum;; device) path=/dev/null;; traversal) path=/file-tail-root/../data/auth.db;; socket) path=/file-tail-root/hostile.sock;; esac
    if live_ingest_file_tail_api "$(jq -cn --arg id "hostile-$hostile" --arg path "$path" '{op:"add",id:$id,path:$path,tag:"hostile"}')" "$LIVE_RUN_ROOT/artifacts/file-tail-${hostile}.stdout" 2>"$LIVE_RUN_ROOT/artifacts/file-tail-${hostile}.stderr"; then
      live_die "file-tail accepted hostile $hostile path"; return 1
    fi
  done
  # A hardlink is still a regular inode under the allowed root. Exercise and
  # document that compiled policy explicitly rather than silently assuming it
  # is rejected like a symlink.
  local hard_id="hard-${LIVE_RUN_ID#cortex-e2e-}" hard_marker
  hard_marker="$(live_ingest_marker file-tail-hardlink 35)"
  docker exec "$candidate" sh -c ': > /file-tail-root/hard-target.log; ln /file-tail-root/hard-target.log /file-tail-root/hard-link.log'
  live_ingest_file_tail_api "$(jq -cn --arg id "$hard_id" '{op:"add",id:$id,path:"/file-tail-root/hard-link.log",tag:"hardlink",start_at_end:false}')" "$LIVE_RUN_ROOT/artifacts/file-tail-hardlink-add.json"
  docker exec "$candidate" sh -c 'printf "%s\n" "$1" >> /file-tail-root/hard-target.log' sh "$hard_marker"
  live_ingest_wait_marker "$hard_marker" file-tail-hardlink 35
  live_ingest_file_tail_api "$(jq -cn --arg id "$hard_id" '{op:"remove",id:$id}')" /dev/null
  live_ingest_case filetail.hardlink-regular-file pass artifacts/ingest-file-tail-hardlink-35-rest.json
  # Bounded swap race: alternate a regular file and symlink while Cortex
  # validates/opens it. The forbidden target marker must never be observable.
  local race_id="race-${LIVE_RUN_ID#cortex-e2e-}" forbidden
  forbidden="$(live_ingest_marker file-tail-toctou-target 31)"
  docker exec "$candidate" sh -c 'printf "%s\n" "$1" > /file-tail-root/target.log; : > /file-tail-root/race.log' sh "$forbidden"
  docker exec -u 0 "$candidate" sh -c 'i=0; while [ $i -lt 100 ]; do rm -f /file-tail-root/race.log; ln -s target.log /file-tail-root/race.log; rm -f /file-tail-root/race.log; : > /file-tail-root/race.log; chmod 0666 /file-tail-root/race.log; i=$((i+1)); done' &
  local swap_pid=$!
  live_ingest_file_tail_api "$(jq -cn --arg id "$race_id" '{op:"add",id:$id,path:"/file-tail-root/race.log",tag:"hostile",start_at_end:false}')" "$LIVE_RUN_ROOT/artifacts/file-tail-toctou.stdout" 2>"$LIVE_RUN_ROOT/artifacts/file-tail-toctou.stderr" || true
  wait "$swap_pid"
  sleep 2
  if live_ingest_mcp_search "$forbidden" "$LIVE_RUN_ROOT/artifacts/file-tail-toctou-query.json"; then live_die 'file-tail TOCTOU target was ingested'; return 1; fi
  live_ingest_file_tail_api "$(jq -cn --arg id "$race_id" '{op:"remove",id:$id}')" /dev/null 2>/dev/null || true
  live_ingest_file_tail_api "$(jq -cn --arg id "$id" '{op:"remove",id:$id}')" "$LIVE_RUN_ROOT/artifacts/file-tail-remove.json"
  live_resource_transition "filetail-$id" file-tail-registration CLEANING "$provider" "$id" "$cleanup" "$digest" "$labels" "$verify"
  live_resource_transition "filetail-$id" file-tail-registration REMOVED "$provider" "$id" "$cleanup" "$digest" "$labels" "$verify"
  live_ingest_file_tail_api '{"op":"list"}' "$LIVE_RUN_ROOT/artifacts/file-tail-list.json"
  if jq -e --arg id "$id" 'any(.sources[]?;.id==$id)' "$LIVE_RUN_ROOT/artifacts/file-tail-list.json" >/dev/null; then live_die 'file-tail removal was not durable'; return 1; fi
  live_resource_transition "filetail-$id" file-tail-registration VERIFIED "$provider" "$id" "$cleanup" "$digest" "$labels" "$verify"
  # Remove special inodes before the generic recursive secret scanner runs;
  # grep can block opening a FIFO even though it contains no artifact data.
  docker exec -u 0 "$candidate" sh -c 'rm -f /file-tail-root/fifo /file-tail-root/hostile.sock /file-tail-root/link.log /file-tail-root/race.log; rmdir /file-tail-root/directory 2>/dev/null || true'
  live_ingest_case filetail.security pass artifacts/file-tail-list.json
}

live_ingest_inventory_cli() {
  live_ingest_bound_producer inventory 1 4096 30
  local candidate inventory_marker inventory_sha
  candidate="$(live_ingest_candidate_id)"
  inventory_marker="$(live_ingest_marker inventory-input 60)"
  docker exec "$candidate" sh -c 'mkdir -p /data/live-inventory-project; printf "services:\n  %s:\n    image: alpine:3.20\n    labels:\n      cortex.live.marker: %s\n" "$1" "$1" > /data/live-inventory-project/compose.yaml' sh "$inventory_marker"
  docker exec -e CORTEX_INVENTORY_DIR=/data/live-inventory -e CORTEX_INVENTORY_PROJECT_ROOTS=/data/live-inventory-project -e CORTEX_INVENTORY_COMPOSE_PATHS=/data/live-inventory-project/compose.yaml "$candidate" cortex ingest inventory refresh --json >"$LIVE_RUN_ROOT/artifacts/inventory-refresh.json"
  docker exec -e CORTEX_INVENTORY_DIR=/data/live-inventory "$candidate" cortex ingest inventory status --json >"$LIVE_RUN_ROOT/artifacts/inventory-status.json"
  jq -e '.status|type=="string"' "$LIVE_RUN_ROOT/artifacts/inventory-refresh.json" >/dev/null
  jq -e '.status|type=="string"' "$LIVE_RUN_ROOT/artifacts/inventory-status.json" >/dev/null
  local normalized_path
  normalized_path="$(jq -r .normalized_path "$LIVE_RUN_ROOT/artifacts/inventory-refresh.json")"
  docker exec "$candidate" cat "$normalized_path" >"$LIVE_RUN_ROOT/artifacts/inventory-normalized.json"
  jq -e --arg marker "$inventory_marker" '.. | strings | select(. == $marker)' "$LIVE_RUN_ROOT/artifacts/inventory-normalized.json" >/dev/null
  inventory_sha="$(printf '%s\n' "$inventory_marker" | shasum -a 256 | awk '{print $1}')"
  jq -cn --arg run_id "$LIVE_RUN_ID" --arg marker "$inventory_marker" --arg sha256 "$inventory_sha" --arg inventory_run_id "$(jq -r .run_id "$LIVE_RUN_ROOT/artifacts/inventory-refresh.json")" --arg normalized "$normalized_path" '{run_id:$run_id,input:{marker:$marker,sha256:$sha256,path:"/data/live-inventory-project/compose.yaml"},inventory_run_id:$inventory_run_id,normalized_path:$normalized}' >"$LIVE_RUN_ROOT/artifacts/inventory-evidence.json"
  live_ingest_case inventory.status pass artifacts/inventory-normalized.json
}

live_ingest_legacy_docker() {
  live_ingest_bound_producer legacy-docker 2 4096 60
  local marker override base
  marker="$(live_ingest_marker legacy-docker 50)"; LIVE_LEGACY_MARKER="$marker"; export LIVE_LEGACY_MARKER
  base="$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml"; override="$LIVE_PROJECT_ROOT/tests/live/phases/ingest/legacy-compose.yaml"
  docker compose -f "$base" -f "$override" -p "$LIVE_COMPOSE_PROJECT" up -d --no-build --force-recreate legacy-docker candidate
  live_budget_add processes 2; live_budget_add connections 1; live_budget_add fixture_records 2
  live_wait_until 30 legacy-health _live_http_health_ready
  live_wait_until 30 legacy-mcp _live_mcp_ready
  live_ingest_wait_marker "$marker" legacy-docker 50
  curl -fsS --max-time 8 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" "$(live_ingest_http /health/full)" >"$LIVE_RUN_ROOT/artifacts/legacy-docker-health.json"
  jq -e '.ingest.docker_ingest_tasks_spawned >= 1 and .ingest.docker_ingest_log_entries_received >= 1' "$LIVE_RUN_ROOT/artifacts/legacy-docker-health.json" >/dev/null
  live_ingest_case legacy-docker.live pass artifacts/legacy-docker-health.json
}

live_ingest_matrix_run() {
  [[ -n "${LIVE_HTTP_PORT:-}" && -n "${LIVE_SYSLOG_TCP_PORT:-}" && -n "${LIVE_SYSLOG_UDP_PORT:-}" ]] || live_die 'ingest matrix requires isolated topology'
  live_event phase_started '{"phase":"ingest"}'
  live_ingest_prepare_filetail_mount
  live_ingest_syslog
  live_ingest_downtime
  live_ingest_http_json_lanes
  live_ingest_syslog_forward
  live_ingest_otlp
  live_ingest_file_tail
  live_ingest_inventory_cli
  live_ingest_legacy_docker
  status="$(live_ingest_curl_status "$LIVE_RUN_ROOT/artifacts/file-tail-unauth.json" -X POST -H 'Content-Type: application/json' --data-binary '{"op":"list"}' "$(live_ingest_http /api/file-tails)")"
  [[ "$status" == 401 ]]
  live_ingest_surface_results
  jq -s --slurpfile contract "$LIVE_PROJECT_ROOT/tests/live/contracts/ingest-cases.json" '
    ([.[]|select(.kind=="ingest_case" and .payload.result=="pass")|.payload.case]|unique) as $passed |
    ($contract[0].required-$passed) as $missing |
    if ($missing|length)==0 then {schema:"cortex-live-ingest-case-reconciliation-v1",passed:$passed,missing:[],green:true}
    else error("missing mandatory ingest cases: \($missing|join(","))") end' "$LIVE_RUN_ROOT/events.jsonl" >"$LIVE_RUN_ROOT/artifacts/ingest-case-reconciliation.json"
  jq -cn --arg run_id "$LIVE_RUN_ID" --slurpfile matrix "$LIVE_PROJECT_ROOT/tests/live/fixtures/ingest/matrix.json" '{schema:"cortex-live-ingest-result-v1",run_id:$run_id,matrix:$matrix[0],disposition:"pass",direct_db_seeding:false}' >"$LIVE_RUN_ROOT/artifacts/ingest-matrix.json"
  chmod 600 "$LIVE_RUN_ROOT/artifacts/ingest-matrix.json"
  live_event phase_finished '{"phase":"ingest","disposition":"pass"}'
}

live_ingest_surface_results() {
  local id case_kind evidence
  while IFS=$'\t' read -r id case_kind; do
    case "$id/$case_kind" in
      ingest.syslog-udp/semantic-positive) evidence=artifacts/ingest-syslog-udp-rfc5424-2-rest.json ;;
      ingest.syslog-udp/validation-negative) evidence=artifacts/syslog-oversize-query.json ;;
      ingest.syslog-tcp/semantic-positive) evidence=artifacts/ingest-syslog-tcp-rfc5424-4-rest.json ;;
      ingest.syslog-tcp/validation-negative) evidence=artifacts/ingest-syslog-tcp-framing-5-rest.json ;;
      ingest.file-tail/semantic-positive) evidence=artifacts/ingest-file-tail-checkpoint-34-rest.json ;;
      ingest.file-tail/validation-negative) evidence=artifacts/file-tail-traversal.stdout ;;
      ingest.file-tail/authorization) evidence=artifacts/file-tail-unauth.json ;;
      ingest.post-v1-heartbeats/semantic-positive) evidence=artifacts/ingest-heartbeat-post.json ;;
      ingest.post-v1-heartbeats/validation-negative) evidence=artifacts/ingest-heartbeat-malformed.json ;;
      ingest.post-v1-heartbeats/authorization) evidence=artifacts/ingest-heartbeat-unauth.json ;;
      ingest.post-v1-agent-commands/semantic-positive) evidence=artifacts/ingest-agent-command-post.json ;;
      ingest.post-v1-agent-commands/validation-negative) evidence=artifacts/ingest-agent-command-malformed.json ;;
      ingest.post-v1-agent-commands/authorization) evidence=artifacts/ingest-agent-command-unauth.json ;;
      ingest.post-v1-shell-history/semantic-positive) evidence=artifacts/ingest-shell-history-post.json ;;
      ingest.post-v1-shell-history/validation-negative) evidence=artifacts/ingest-shell-history-malformed.json ;;
      ingest.post-v1-shell-history/authorization) evidence=artifacts/ingest-shell-history-unauth.json ;;
      ingest.post-v1-ai-transcripts/semantic-positive) evidence=artifacts/ingest-ai-transcript-post.json ;;
      ingest.post-v1-ai-transcripts/validation-negative) evidence=artifacts/ingest-ai-transcript-malformed.json ;;
      ingest.post-v1-ai-transcripts/authorization) evidence=artifacts/ingest-ai-transcript-unauth.json ;;
      ingest.post-v1-syslog-forward/semantic-positive) evidence=artifacts/ingest-syslog-forward-post.json ;;
      ingest.post-v1-syslog-forward/validation-negative) evidence=artifacts/ingest-syslog-forward-malformed.json ;;
      ingest.post-v1-syslog-forward/authorization) evidence=artifacts/ingest-syslog-forward-unauth.json ;;
      ingest.post-v1-logs/semantic-positive) evidence=artifacts/otlp-logs-response.pb ;;
      ingest.post-v1-logs/validation-negative) evidence=artifacts/otlp-logs-malformed.json ;;
      ingest.post-v1-logs/authorization) evidence=artifacts/otlp-logs-unauth.json ;;
      ingest.post-v1-metrics/semantic-positive) evidence=artifacts/otlp-metrics-response.pb ;;
      ingest.post-v1-metrics/validation-negative) evidence=artifacts/otlp-metrics-malformed.json ;;
      ingest.post-v1-metrics/authorization) evidence=artifacts/otlp-metrics-unauth.json ;;
      ingest.post-v1-traces/semantic-positive) evidence=artifacts/otlp-traces-response.pb ;;
      ingest.post-v1-traces/validation-negative) evidence=artifacts/otlp-traces-malformed.json ;;
      ingest.post-v1-traces/authorization) evidence=artifacts/otlp-traces-unauth.json ;;
      *) live_ingest_direct_surface_case "$id" "$case_kind"; continue ;;
    esac
    [[ -f "$LIVE_RUN_ROOT/$evidence" ]]
    live_result "$id" "isolated-$case_kind" pass 0 "$evidence" "$case_kind"
  done < <(jq -r '.entries[]|select(.profiles|index("isolated")) as $e|$e.required_cases[]|[$e.id,.]|@tsv' "$LIVE_SURFACE_CONTRACT")
}

live_ingest_direct_surface_case() {
  local id="$1" case_kind="$2" method path status body=''
  local evidence="artifacts/${id}.${case_kind}.json"
  read -r method path < <(jq -r --arg id "$id" '.entries[]|select(.id==$id)|.spelling' "$LIVE_SURFACE_CONTRACT")
  if [[ "$case_kind" == validation-negative ]]; then
    [[ "$method" == GET ]] && method=POST || { method=GET; body=''; }
  elif [[ "$id" == ingest.post-mcp ]]; then
    body='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"live-isolated","version":"1"}}}'
  fi
  if [[ "$case_kind" == semantic-positive && "$id" == ingest.get-v1-agent-binary ]]; then
    path="$path?os=linux&arch=x86_64"
  elif [[ "$case_kind" == semantic-positive && "$id" == ingest.get-v1-agent-release ]]; then
    local candidate version
    candidate="$(live_ingest_candidate_id)"; version="$(docker exec "$candidate" cortex --version | awk '{print $2}')"
    path="$path?os=windows&arch=x86_64&version=$version&kind=checksum"
  fi
  local headers=(-H 'Host: localhost')
  [[ "$case_kind" == authorization ]] || headers+=(-H "Authorization: Bearer $LIVE_CORTEX_TOKEN")
  if [[ "$method" == POST ]]; then headers+=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream'); fi
  local request=(-sS --max-time 10 -o "$LIVE_RUN_ROOT/$evidence.body" -w '%{http_code}' -X "$method" "${headers[@]}")
  if [[ "$case_kind" == semantic-positive && "$id" == ingest.get-v1-agent-binary ]]; then
    request=(-sS --max-time 30 -D "$LIVE_RUN_ROOT/$evidence.headers" -o /dev/null -w '%{http_code}' -X GET "${headers[@]}")
  fi
  [[ -z "$body" ]] || request+=(--data-binary "$body")
  status="$(curl "${request[@]}" "$(live_ingest_http "$path")")"
  case "$case_kind" in
    authorization) if [[ "$status" != 401 && "$status" != 403 ]]; then live_die "$id authorization request returned $status"; return 1; fi ;;
    validation-negative) if [[ "$status" != 404 && "$status" != 405 ]]; then live_die "$id wrong method returned $status"; return 1; fi ;;
    semantic-positive)
      case "$id" in
        ingest.post-mcp) [[ "$status" == 200 ]] && jq -e '.result.protocolVersion and .result.serverInfo.name=="cortex"' "$LIVE_RUN_ROOT/$evidence.body" >/dev/null || { live_die "MCP initialize semantic probe failed"; return 1; } ;;
        ingest.get-v1-agent-binary) [[ "$status" == 200 ]] && grep -Eqi '^x-cortex-(version|sha256):' "$LIVE_RUN_ROOT/$evidence.headers" || { live_die "agent binary semantic probe failed"; return 1; } ;;
        ingest.get-v1-agent-release) [[ "$status" == 502 ]] && jq -e '.error=="release_artifact_unavailable"' "$LIVE_RUN_ROOT/$evidence.body" >/dev/null || { live_die "release isolated-egress refusal semantic failed"; return 1; } ;;
        *) if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then live_die "$id semantic request returned $status"; return 1; fi ;;
      esac ;;
  esac
  local response_bytes=0
  [[ ! -f "$LIVE_RUN_ROOT/$evidence.body" ]] || response_bytes="$(wc -c <"$LIVE_RUN_ROOT/$evidence.body" | tr -d ' ')"
  jq -n --arg surface "$id" --arg method "$method" --arg path "$path" --arg case_kind "$case_kind" --argjson status "$status" --argjson response_bytes "$response_bytes" '{surface_id:$surface,method:$method,path:$path,case_kind:$case_kind,status:$status,response_bytes:$response_bytes}' >"$LIVE_RUN_ROOT/$evidence"
  rm -f "$LIVE_RUN_ROOT/$evidence.body" "$LIVE_RUN_ROOT/$evidence.headers"
  live_result "$id" "isolated-direct-$case_kind" pass 0 "$evidence" "$case_kind"
}
