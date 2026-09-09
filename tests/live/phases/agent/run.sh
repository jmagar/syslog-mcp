#!/usr/bin/env bash
set -euo pipefail

agent_contract="${LIVE_PROJECT_ROOT:?}/tests/live/contracts/agent.json"

live_agent_binary() {
  if [[ -n "${LIVE_CORTEX_BIN:-}" ]]; then printf '%s\n' "$LIVE_CORTEX_BIN"; return; fi
  printf '%s/debug/cortex\n' "$(cargo metadata --no-deps --format-version 1 --manifest-path "$LIVE_PROJECT_ROOT/Cargo.toml" | jq -er .target_directory)"
}

live_agent_disposition() {
  local scenario="$1" disposition="$2" reason="$3" evidence="${4:-}"
  live_event agent_scenario "$(jq -cn --arg scenario "$scenario" --arg disposition "$disposition" --arg reason "$reason" --arg evidence "$evidence" \
    '{schema:"cortex-live-agent-scenario-v1",scenario:$scenario,disposition:$disposition,reason:$reason,evidence:$evidence}')"
  live_event agent_result "$(jq -cn --arg surface "agent.$scenario" --arg scenario "$scenario" --arg result "$([[ "$disposition" == pass ]] && echo pass || echo qualified)" --arg evidence "$evidence" '{surface_id:$surface,scenario:$scenario,case_kind:"semantic-positive",result:$result,evidence:$evidence,attempt_kind:"first_attempt"}')"
}

live_agent_assert_surface_semantics() {
  local file="$1" fixture="$2" expected="$3"
  jq -e --arg id "$fixture" --arg expected "$expected" '
    (if has("result") then .result.structuredContent else . end) as $v |
    ($v|type)=="object" and (($v|tostring)|contains($id)) and (($v|tostring)|contains($expected))
  ' "$file" >/dev/null
}

live_agent_validate_driver_evidence() {
  local evidence="$1" schema="$LIVE_PROJECT_ROOT/tests/live/contracts/agent-driver-evidence.schema.json"
  local validator=(python3)
  python3 -c 'import jsonschema' >/dev/null 2>&1 || {
    command -v uv >/dev/null 2>&1 || live_die "Python jsonschema validator is required"
    validator=(uv run --quiet --with jsonschema python)
  }
  "${validator[@]}" - "$schema" "$evidence" <<'PY'
import json, sys
from jsonschema import Draft202012Validator
with open(sys.argv[1], encoding="utf-8") as handle:
    schema = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    instance = json.load(handle)
Draft202012Validator(schema).validate(instance)
PY
}

live_agent_validate_dind_boundary() {
  local publication="$1"
  [[ "$publication" == unix-socket-only ]] || live_die "insecure DinD TCP publication is forbidden"
}

live_agent_dctl() {
  local control="${LIVE_AGENT_DOCKER_CONTROL_URL:?}"
  case "$control" in
    container-exec://*) docker exec "${control#container-exec://}" docker "$@" ;;
    *) docker -H "$control" "$@" ;;
  esac
}

live_agent_validate_authority() {
  local boundary="$LIVE_RUN_ROOT/artifacts/docker-boundary.json"
  [[ -f "$boundary" ]] || live_die "agent profile requires Docker-boundary evidence"
  jq -e '.schema=="cortex-live-docker-boundary-result-v1" and .disposition=="pass" and (.candidate=="linux-dind" or .candidate=="desktop-proxy") and (.details.daemon_id|type=="string" and length>0)' "$boundary" >/dev/null ||
    live_die "Docker boundary did not produce a passing, identified authority"
  LIVE_AGENT_BOUNDARY="$(jq -r .candidate "$boundary")"
  LIVE_AGENT_DAEMON_ID="$(jq -r .details.daemon_id "$boundary")"
  export LIVE_AGENT_BOUNDARY LIVE_AGENT_DAEMON_ID
  [[ "${LIVE_AGENT_DOCKER_URL:-}" =~ ^https?:// ]] || live_die "agent Docker URL must be the selected HTTP read proxy"
  case "$LIVE_AGENT_DOCKER_URL" in unix://*|npipe://*) live_die "unrestricted host Docker socket is forbidden";; esac
  local observed
  observed="$(curl -fsS --max-time 5 "${LIVE_AGENT_DOCKER_URL%/}/info" | jq -er .ID)"
  [[ "$observed" == "$LIVE_AGENT_DAEMON_ID" ]] || live_die "agent Docker authority identity changed"
  live_event agent_authority "$(jq -cn --arg candidate "$LIVE_AGENT_BOUNDARY" --arg daemon_id "$observed" --arg url "$LIVE_AGENT_DOCKER_URL" '{candidate:$candidate,daemon_id:$daemon_id,url:$url,unrestricted_socket:false}')"
}

live_agent_register_boundary_resources() {
  [[ "${LIVE_AGENT_BOUNDARY_REGISTERED:-0}" != 1 ]] || return 0
  [[ -n "${LIVE_AGENT_DAEMON_CONTAINER_ID:-}" && -n "${LIVE_AGENT_PROXY_CONTAINER_ID:-}" && -n "${LIVE_AGENT_SOCKET_VOLUME:-}" ]] || return 0
  local outer_id="${LIVE_RESOURCE_PROVIDER#docker-host:}" script="$LIVE_PROJECT_ROOT/tests/live/profiles/agent/boundary-resource.sh" spec key kind id control digest cleanup verify labels
  for spec in "socket|volume|$LIVE_AGENT_SOCKET_VOLUME|" "daemon|container|$LIVE_AGENT_DAEMON_CONTAINER_ID|" "proxy|container|$LIVE_AGENT_PROXY_CONTAINER_ID|" "fixture|inner-container|$LIVE_AGENT_FIXTURE_ID|$LIVE_AGENT_DOCKER_CONTROL_URL"; do
    IFS='|' read -r key kind id control <<<"$spec"
    digest="$(printf '%s' "$kind:$id:$LIVE_RUN_ID" | shasum -a 256 | awk '{print $1}')"
    cleanup="$(jq -cn --arg s "$script" --arg kind "$kind" --arg id "$id" --arg run "$LIVE_RUN_ID" --arg outer "$outer_id" --arg control "$control" '["bash",$s,"cleanup",$kind,$id,$run,$outer,$control]')"
    verify="$(jq -cn --arg s "$script" --arg kind "$kind" --arg id "$id" --arg run "$LIVE_RUN_ID" --arg outer "$outer_id" --arg control "$control" '["bash",$s,"verify",$kind,$id,$run,$outer,$control]')"
    labels="$(jq -cn --arg role "$key" '{role:$role}')"
    live_resource_transition "agent-boundary-$key" "$kind" PLANNED "$LIVE_RESOURCE_PROVIDER" "" '[]'
    live_resource_transition "agent-boundary-$key" "$kind" CREATING "$LIVE_RESOURCE_PROVIDER" "$id" '[]' "$digest" "$labels" '[]'
    live_resource_transition "agent-boundary-$key" "$kind" IDENTIFIED "$LIVE_RESOURCE_PROVIDER" "$id" "$cleanup" "$digest" "$labels" "$verify"
    live_resource_transition "agent-boundary-$key" "$kind" CREATED "$LIVE_RESOURCE_PROVIDER" "$id" "$cleanup" "$digest" "$labels" "$verify"
  done
}

live_agent_provision_portable() {
  [[ "${LIVE_AGENT_PORTABLE_PROVISION:-0}" == 1 ]] || return 0
  local outer_id="${LIVE_RESOURCE_PROVIDER#docker-host:}" volume="${LIVE_COMPOSE_PROJECT}-agent-socket" daemon_name="${LIVE_COMPOSE_PROJECT}-agent-daemon" proxy_name="${LIVE_COMPOSE_PROJECT}-agent-proxy"
  local proxy_port="${LIVE_AGENT_PROXY_PORT:-46100}" script="$LIVE_PROJECT_ROOT/tests/live/profiles/agent/boundary-resource.sh" key kind id control digest cleanup verify labels
  local daemon_image="docker:29.1.3-dind@sha256:173f284a4299164772a90f52b373e73e087583c0963f1334c9995f190ef6f3f5"
  local proxy_image="tecnativa/docker-socket-proxy:latest@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459"
  _agent_intent() { key="$1"; kind="$2"; id="$3"; control="${4:-}"; digest="$(printf '%s' "$kind:$id:$LIVE_RUN_ID" | shasum -a 256 | awk '{print $1}')"; labels="$(jq -cn --arg role "$key" '{role:$role}')"; live_resource_transition "agent-boundary-$key" "$kind" PLANNED "$LIVE_RESOURCE_PROVIDER" "" '[]'; live_resource_transition "agent-boundary-$key" "$kind" CREATING "$LIVE_RESOURCE_PROVIDER" "$id" '[]' "$digest" "$labels" '[]'; }
  _agent_identified() { cleanup="$(jq -cn --arg s "$script" --arg kind "$kind" --arg id "$id" --arg run "$LIVE_RUN_ID" --arg outer "$outer_id" --arg control "$control" '["bash",$s,"cleanup",$kind,$id,$run,$outer,$control]')"; verify="$(jq -cn --arg s "$script" --arg kind "$kind" --arg id "$id" --arg run "$LIVE_RUN_ID" --arg outer "$outer_id" --arg control "$control" '["bash",$s,"verify",$kind,$id,$run,$outer,$control]')"; live_resource_transition "agent-boundary-$key" "$kind" IDENTIFIED "$LIVE_RESOURCE_PROVIDER" "$id" "$cleanup" "$digest" "$labels" "$verify"; live_resource_transition "agent-boundary-$key" "$kind" CREATED "$LIVE_RESOURCE_PROVIDER" "$id" "$cleanup" "$digest" "$labels" "$verify"; }
  _agent_intent socket volume "$volume"; docker volume create --label "cortex.live.run_id=$LIVE_RUN_ID" "$volume" >/dev/null; _agent_identified
  live_agent_validate_dind_boundary unix-socket-only
  _agent_intent daemon container "$daemon_name"; LIVE_AGENT_DAEMON_CONTAINER_ID="$(docker run -d --name "$daemon_name" --privileged --label "cortex.live.run_id=$LIVE_RUN_ID" -e DOCKER_TLS_CERTDIR= -v "$volume:/var/run" "$daemon_image" dockerd --host=unix:///var/run/docker.sock --iptables=false --ip-forward=false)"; id="$LIVE_AGENT_DAEMON_CONTAINER_ID"; _agent_identified
  LIVE_AGENT_DOCKER_CONTROL_URL="container-exec://$LIVE_AGENT_DAEMON_CONTAINER_ID"
  local ready=0 attempt
  for ((attempt=1; attempt<=30; attempt++)); do live_agent_dctl info >/dev/null 2>&1 && { ready=1; break; }; sleep 1; done
  (( ready == 1 )) || live_die "run-owned Docker daemon did not become ready"
  _agent_intent proxy container "$proxy_name"; LIVE_AGENT_PROXY_CONTAINER_ID="$(docker run -d --name "$proxy_name" --label "cortex.live.run_id=$LIVE_RUN_ID" --entrypoint sh -e CONTAINERS=1 -e EVENTS=1 -e INFO=1 -e PING=1 -e POST=0 -e VERSION=1 -v "$volume:/var/run:ro" -p "127.0.0.1:$proxy_port:2375" "$proxy_image" -c 'sed -e "s|\${BIND_CONFIG}|:2375|g" -e "s|/run/haproxy.pid|/tmp/haproxy.pid|" /usr/local/etc/haproxy/haproxy.cfg.template >/tmp/haproxy.cfg; exec haproxy -W -db -f /tmp/haproxy.cfg')"; id="$LIVE_AGENT_PROXY_CONTAINER_ID"; _agent_identified
  LIVE_AGENT_DOCKER_URL="http://127.0.0.1:$proxy_port"; CORTEX_LIVE_DOCKER_PROXY_URL="$LIVE_AGENT_DOCKER_URL"; ready=0
  for ((attempt=1; attempt<=20; attempt++)); do curl -fsS --max-time 1 "$LIVE_AGENT_DOCKER_URL/_ping" >/dev/null 2>&1 && { ready=1; break; }; sleep .2; done
  (( ready == 1 )) || live_die "run-owned reduced Docker proxy did not become ready"
  docker image save alpine:3.22 | docker exec -i "$LIVE_AGENT_DAEMON_CONTAINER_ID" docker load >/dev/null
  _agent_intent fixture inner-container "${LIVE_COMPOSE_PROJECT}-agent-fixture" "$LIVE_AGENT_DOCKER_CONTROL_URL"; LIVE_AGENT_FIXTURE_ID="$(live_agent_dctl create --name "${LIVE_COMPOSE_PROJECT}-agent-fixture" --network none --label "cortex.live.run_id=$LIVE_RUN_ID" --health-cmd 'test -f /tmp/healthy' --health-interval 1s alpine:3.22 sh -c 'touch /tmp/healthy; i=0; while true; do i=$((i+1)); printf "%s\n" "$i" >/tmp/agent-seq; printf "agent-live-seq-%08d\n" "$i"; echo agent-live-stdout-marker; echo agent-live-stderr-marker >&2; if test -s /tmp/live-marker; then cat /tmp/live-marker; fi; sleep 1; done')"; id="$LIVE_AGENT_FIXTURE_ID"; digest="$(printf '%s' "$kind:$id:$LIVE_RUN_ID" | shasum -a 256 | awk '{print $1}')"; _agent_identified; live_agent_dctl start "$id" >/dev/null
  LIVE_AGENT_SOCKET_VOLUME="$volume" LIVE_AGENT_EXPECT_STDOUT=agent-live-stdout-marker LIVE_AGENT_EXPECT_STDERR=agent-live-stderr-marker LIVE_AGENT_EXPECT_HEALTH=healthy LIVE_AGENT_BOUNDARY_REGISTERED=1
  LIVE_AGENT_SCENARIO_EVIDENCE_DIR="${LIVE_AGENT_SCENARIO_EVIDENCE_DIR:-$LIVE_RUN_ROOT/agent-scenario-evidence}"
  mkdir -p "$LIVE_AGENT_SCENARIO_EVIDENCE_DIR"
  export LIVE_AGENT_DAEMON_CONTAINER_ID LIVE_AGENT_PROXY_CONTAINER_ID LIVE_AGENT_DOCKER_CONTROL_URL LIVE_AGENT_DOCKER_URL CORTEX_LIVE_DOCKER_PROXY_URL LIVE_AGENT_FIXTURE_ID LIVE_AGENT_SOCKET_VOLUME LIVE_AGENT_EXPECT_STDOUT LIVE_AGENT_EXPECT_STDERR LIVE_AGENT_EXPECT_HEALTH LIVE_AGENT_BOUNDARY_REGISTERED LIVE_AGENT_SCENARIO_EVIDENCE_DIR
}

live_agent_query_marker() {
  local marker="$1" name="$2"
  live_ingest_wait_marker "$marker" "agent-$name" 1
}

live_agent_observe_event() {
  local scenario="$1" container_id="$2" action="$3" sequence="$4" marker artifact
  marker="docker container event: $action"
  live_ingest_wait_marker "$marker" "agent-$scenario" "$sequence"
  artifact="$LIVE_RUN_ROOT/artifacts/ingest-agent-$scenario-$sequence-rest.json"
  jq -e --arg id "$container_id" --arg action "$action" '
    ([.logs[]|select(
      ((.metadata_json|fromjson).source_kind=="docker-event") and
      ((.metadata_json|fromjson).agent_docker.container_id==$id) and
      ((.metadata_json|fromjson).agent_docker.stream=="event") and
      ((.metadata_json|fromjson).agent_docker.event_action==$action))]|length)==1' "$artifact" >/dev/null
  grep -F "$container_id" "$LIVE_RUN_ROOT/artifacts/ingest-agent-$scenario-$sequence-mcp.json" >/dev/null
  grep -F "$container_id" "$LIVE_RUN_ROOT/artifacts/ingest-agent-$scenario-$sequence-cli.json" >/dev/null
}

live_agent_observe_log() {
  local scenario="$1" container_id="$2" marker="$3" sequence="$4" artifact
  live_ingest_wait_marker "$marker" "agent-$scenario" "$sequence"
  artifact="$LIVE_RUN_ROOT/artifacts/ingest-agent-$scenario-$sequence-rest.json"
  jq -e --arg id "$container_id" --arg marker "$marker" '
    (.count>=1) and any(.logs[];
      (.message|contains($marker)) and
      ((.metadata_json|fromjson) as $m |
        (($m.source_kind=="agent-docker" and $m.agent_docker.container_id==$id) or
         (.message|contains("\"source_kind\":\"agent-docker\"") and contains($id)))))' "$artifact" >/dev/null
}

live_agent_assert_identity() {
  local marker="$1" stream="$2" fixture="$3" artifact
  artifact="$LIVE_RUN_ROOT/artifacts/ingest-agent-$stream-1-rest.json"
  jq -e --arg marker "$marker" --arg stream "$stream" --arg fixture "$fixture" '
    (.count>=1) and any(.logs[];
      (.message|contains($marker)) and
      ((.metadata_json|fromjson) as $m |
        (($m.source_kind=="agent-docker" and $m.agent_docker.container_id==$fixture and $m.agent_docker.stream==$stream and (($m.agent_docker.host|length)>0)) or
         (.message|contains("\"source_kind\":\"agent-docker\"") and contains($fixture) and contains("\"stream\":\""+$stream+"\"")))))' "$artifact" >/dev/null
}

live_agent_start() {
  local host_id="$LIVE_RUN_ROOT/agent/host-id" stdout="$LIVE_RUN_ROOT/artifacts/agent.stdout" stderr="$LIVE_RUN_ROOT/artifacts/agent.stderr" key digest cleanup verify labels
  mkdir -p "$LIVE_RUN_ROOT/agent"
  : >"$stdout"; : >"$stderr"
  "$(live_agent_binary)" heartbeat agent \
    --target "http://127.0.0.1:${LIVE_HTTP_PORT:?}/v1/heartbeats" --token "$LIVE_CORTEX_TOKEN" \
    --syslog-target "127.0.0.1:${LIVE_SYSLOG_TCP_PORT:?}" --docker \
    --docker-url "$LIVE_AGENT_DOCKER_URL" --host-id-path "$host_id" --interval-secs 1 \
    --probe-deadline-ms 2000 --collection-deadline-ms 5000 --retry-buffer "$(jq -r .limits.retry_buffer "$agent_contract")" \
    --json >"$stdout" 2>"$stderr" &
  LIVE_AGENT_PID=$!; export LIVE_AGENT_PID
  key="agent-process-$LIVE_AGENT_PID"
  digest="$(ps -o lstart= -p "$LIVE_AGENT_PID" | shasum -a 256 | awk '{print $1}')"
  cleanup="$(jq -cn --arg script "$LIVE_PROJECT_ROOT/tests/live/phases/agent/process-resource.sh" --arg pid "$LIVE_AGENT_PID" --arg digest "$digest" --arg root "$LIVE_RUN_ROOT" '["bash",$script,"cleanup",$pid,$digest,$root]')"
  verify="$(jq -cn --arg script "$LIVE_PROJECT_ROOT/tests/live/phases/agent/process-resource.sh" --arg pid "$LIVE_AGENT_PID" --arg digest "$digest" --arg root "$LIVE_RUN_ROOT" '["bash",$script,"verify",$pid,$digest,$root]')"
  labels="$(jq -cn --arg run "$LIVE_RUN_ID" --arg role heartbeat-agent '{run_id:$run,role:$role}')"
  live_resource_transition "$key" process PLANNED "$LIVE_RESOURCE_PROVIDER" "" '[]'
  live_resource_transition "$key" process CREATING "$LIVE_RESOURCE_PROVIDER" "$LIVE_AGENT_PID" '[]' "$digest" "$labels" '[]'
  live_resource_transition "$key" process IDENTIFIED "$LIVE_RESOURCE_PROVIDER" "$LIVE_AGENT_PID" "$cleanup" "$digest" "$labels" "$verify"
  live_resource_transition "$key" process CREATED "$LIVE_RESOURCE_PROVIDER" "$LIVE_AGENT_PID" "$cleanup" "$digest" "$labels" "$verify"
  live_budget_add processes 1
  live_event agent_process "$(jq -cn --argjson pid "$LIVE_AGENT_PID" --arg host_id "${host_id#"$LIVE_RUN_ROOT/"}" '{pid:$pid,host_id_path:$host_id}')"
}

live_agent_stop() {
  [[ -z "${LIVE_AGENT_PID:-}" ]] || ! kill -0 "$LIVE_AGENT_PID" 2>/dev/null || kill -TERM "$LIVE_AGENT_PID"
  [[ -z "${LIVE_AGENT_PID:-}" ]] || wait "$LIVE_AGENT_PID" 2>/dev/null || true
  if [[ -n "${LIVE_AGENT_PID:-}" ]]; then
    local key="agent-process-$LIVE_AGENT_PID" last
    last="$(jq -sr --arg key "$key" '[.[]|select(.key==$key)]|last' "$LIVE_RUN_ROOT/resources.jsonl")"
    local verify_cmd=()
    while IFS= read -r argument; do verify_cmd+=("$argument"); done < <(jq -r '.verify_argv[]' <<<"$last")
    "${verify_cmd[@]}" || live_die "agent process cleanup verification failed"
    live_resource_transition "$key" process CLEANING "$LIVE_RESOURCE_PROVIDER" "$LIVE_AGENT_PID" "$(jq -c .cleanup_argv <<<"$last")" "$(jq -r .digest <<<"$last")" "$(jq -c .labels <<<"$last")" "$(jq -c .verify_argv <<<"$last")"
    live_resource_transition "$key" process REMOVED "$LIVE_RESOURCE_PROVIDER" "$LIVE_AGENT_PID" "$(jq -c .cleanup_argv <<<"$last")" "$(jq -r .digest <<<"$last")" "$(jq -c .labels <<<"$last")" "$(jq -c .verify_argv <<<"$last")"
    live_resource_transition "$key" process VERIFIED "$LIVE_RESOURCE_PROVIDER" "$LIVE_AGENT_PID" "$(jq -c .cleanup_argv <<<"$last")" "$(jq -r .digest <<<"$last")" "$(jq -c .labels <<<"$last")" "$(jq -c .verify_argv <<<"$last")"
  fi
  LIVE_AGENT_PID=""
}

live_agent_checkpoint() {
  local phase="$1" file="$LIVE_RUN_ROOT/agent/host-id" digest="" host_id mcp rest cli fleet sequence sampled_at candidate deadline docker_cursor cursor_file
  [[ -s "$file" ]] || live_die "agent host identity checkpoint missing"
  host_id="$(tr -d '\r\n' <"$file")"; [[ -n "$host_id" ]]
  digest="$(shasum -a 256 "$file" | awk '{print $1}')"
  mcp="$LIVE_RUN_ROOT/artifacts/agent-$phase-host-state-mcp.json"; rest="$LIVE_RUN_ROOT/artifacts/agent-$phase-host-state-rest.json"; cli="$LIVE_RUN_ROOT/artifacts/agent-$phase-host-state-cli.json"; fleet="$LIVE_RUN_ROOT/artifacts/agent-$phase-fleet-state-mcp.json"
  deadline=$(( $(date +%s)+20 ))
  while :; do
    curl -fsS --max-time 8 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
      -d "$(jq -cn --arg h "$host_id" '{jsonrpc:"2.0",id:74,method:"tools/call",params:{name:"cortex",arguments:{action:"host_state",host_id:$h}}}')" "$(live_ingest_http /mcp)" >"$mcp"
    if jq -e --arg h "$host_id" --arg phase "$phase" --arg minimum "${LIVE_AGENT_INITIAL_SAMPLED_AT:-}" '.error==null and .result.structuredContent.host_id==$h and (.result.structuredContent.latest.sequence|type=="number") and ($phase=="initial" or .result.structuredContent.latest.sampled_at>$minimum)' "$mcp" >/dev/null; then break; fi
    (( $(date +%s)<deadline )) || live_die "agent host_state checkpoint did not become visible"
    sleep 1
  done
  curl -fsS --max-time 8 -G -H 'Host: localhost' -H "Authorization: Bearer $LIVE_API_TOKEN" --data-urlencode "host_id=$host_id" "$(live_ingest_http /api/host-state)" >"$rest"
  candidate="$(live_ingest_candidate_id)"; docker exec "$candidate" cortex state host --host-id "$host_id" --http --server http://127.0.0.1:3100 --json >"$cli"
  curl -fsS --max-time 8 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":75,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"fleet_state"}}}' "$(live_ingest_http /mcp)" >"$fleet"
  sequence="$(jq -er '.result.structuredContent.latest.sequence' "$mcp")"; sampled_at="$(jq -er '.result.structuredContent.latest.sampled_at' "$mcp")"
  grep -F "$host_id" "$rest" >/dev/null; grep -F "$host_id" "$cli" >/dev/null
  jq -e --arg h "$host_id" '.error==null and (.result.structuredContent|tostring|contains($h))' "$fleet" >/dev/null
  cursor_file="$LIVE_RUN_ROOT/artifacts/agent-$phase-docker-cursor.json"
  curl -fsS -G -H "Authorization: Bearer $LIVE_API_TOKEN" --data-urlencode 'query="agent-live-stdout-marker"' --data-urlencode limit=100 "$(live_ingest_http /api/search)" >"$cursor_file"
  jq -e '[.logs[].id] as $ids | ($ids|length)>0 and ($ids|length)==($ids|unique|length)' "$cursor_file" >/dev/null
  docker_cursor="$(jq '[.logs[].id]|max' "$cursor_file")"
  if [[ "$phase" == initial ]]; then
    LIVE_AGENT_INITIAL_HOST_DIGEST="$digest"; LIVE_AGENT_INITIAL_SEQUENCE="$sequence"; LIVE_AGENT_INITIAL_SAMPLED_AT="$sampled_at"
    LIVE_AGENT_INITIAL_DOCKER_CURSOR="$docker_cursor"
    export LIVE_AGENT_INITIAL_HOST_DIGEST LIVE_AGENT_INITIAL_SEQUENCE LIVE_AGENT_INITIAL_SAMPLED_AT LIVE_AGENT_INITIAL_DOCKER_CURSOR
  else
    [[ "$digest" == "$LIVE_AGENT_INITIAL_HOST_DIGEST" && "$sampled_at" > "$LIVE_AGENT_INITIAL_SAMPLED_AT" ]] || live_die "agent checkpoint identity/observation did not progress after restart"
    [[ "$docker_cursor" -gt "$LIVE_AGENT_INITIAL_DOCKER_CURSOR" ]] || live_die "agent Docker cursor did not advance after restart"
  fi
  live_event agent_checkpoint "$(jq -cn --arg phase "$phase" --arg host_id "$host_id" --arg host_id_digest "$digest" --argjson sequence "$sequence" --arg sampled_at "$sampled_at" --argjson docker_cursor "$docker_cursor" --arg daemon_id "$LIVE_AGENT_DAEMON_ID" '{phase:$phase,host_id:$host_id,host_id_digest:$host_id_digest,sequence:$sequence,sampled_at:$sampled_at,docker_cursor:$docker_cursor,daemon_id:$daemon_id,jsonrpc_success:true,surfaces:["mcp","rest","cli"],fleet_observed:true}')"
}

live_agent_allowlist_experiment() {
  local candidate marker="agent-live-stdout-marker" denied="$LIVE_RUN_ROOT/artifacts/agent-allowlist-denied.json"
  candidate="$(live_ingest_candidate_id)"
  LIVE_AGENT_SOURCE_PREFIXES=203.0.113. docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/agent/compose.override.yaml" up -d --no-build --force-recreate candidate >/dev/null
  live_wait_until 30 agent-allowlist-deny-health _live_http_health_ready
  live_agent_start; sleep 3
  curl -fsS -G -H "Authorization: Bearer $LIVE_API_TOKEN" --data-urlencode "query=\"$marker\"" --data-urlencode limit=100 "$(live_ingest_http /api/search)" >"$denied"
  jq -e 'all(.logs[]?; ((.metadata_json // "{}" | fromjson).source_kind // "") != "agent-docker")' "$denied" >/dev/null
  live_agent_stop
  LIVE_AGENT_SOURCE_PREFIXES='10.,172.,192.168.' docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/agent/compose.override.yaml" up -d --no-build --force-recreate candidate >/dev/null
  live_wait_until 30 agent-allowlist-allow-health _live_http_health_ready
  live_wait_until 30 agent-allowlist-allow-mcp _live_mcp_ready
  jq -cn '{denied_before:true,allowed_after:true,wrong_prefix:"203.0.113.",allowed_prefixes:["10.","172.","192.168."]}' >"$LIVE_RUN_ROOT/artifacts/agent-allowlist.json"
}

live_agent_cli_sweep() {
  local bin out="$LIVE_RUN_ROOT/artifacts/agent-cli.jsonl" command status argv=()
  bin="$(live_agent_binary)"
  : >"$out"
  while IFS= read -r command; do
    # Help is the safe live grammar probe for install/deploy/update mutations;
    # actual mutation requires a run-owned service-manager host in fleet profiles.
    IFS=' ' read -r -a argv <<<"$command"
    if "$bin" "${argv[@]}" --help >"$LIVE_RUN_ROOT/agent-cli.out" 2>"$LIVE_RUN_ROOT/agent-cli.err"; then status=pass; else status=fail; fi
    jq -cn --arg command "$command" --arg status "$status" '{command:$command,status:$status}' >>"$out"
    [[ "$status" == pass ]] || live_die "agent CLI grammar failed: $command"
  done < <(jq -r '.agent_cli_commands[]' "$agent_contract")
  live_agent_disposition agent-cli pass "all agent command grammars exercised" artifacts/agent-cli.jsonl
}

live_agent_cli_execute() {
  local output="$LIVE_RUN_ROOT/artifacts/agent-cli-live.json"
  LIVE_CORTEX_BIN_REQUIRED="$(live_agent_binary)" LIVE_AGENT_CLI_OUTPUT="$output" \
    bash "$LIVE_PROJECT_ROOT/tests/live/profiles/agent/service-cli.sh"
  jq -e '.schema=="cortex-live-agent-cli-live-v1" and .actual_execution and .rollback and .transport_calls>0' "$output" >/dev/null
  live_event agent_cli_live "$(cat "$output")"
}

live_agent_portable_dispositions() {
  local scenario
  while IFS= read -r scenario; do live_agent_disposition "$scenario" platform-qualified "Docker Desktop read proxy cannot certify Linux daemon semantics"; done < <(jq -r '.portable_unsupported[]' "$agent_contract")
}

live_agent_external_scenarios() {
  local scenario evidence_dir="${LIVE_AGENT_SCENARIO_EVIDENCE_DIR:-}" file missing=0
  while IFS= read -r scenario; do
    case "$scenario" in initial-collection|agent-restart|checkpoint-resume|allowlist|container-oom|daemon-restart|socket-permission-loss) continue;; esac
    file="$evidence_dir/$scenario.json"
    if [[ -z "$evidence_dir" || ! -f "$file" ]]; then
      live_agent_disposition "$scenario" not-authorized "run-owned scenario driver evidence absent"
      missing=1
      continue
    fi
    live_agent_validate_driver_evidence "$file" || live_die "agent scenario evidence failed JSON Schema validation: $scenario"
    jq -e --arg scenario "$scenario" --arg daemon "$LIVE_AGENT_DAEMON_ID" '
      .schema=="cortex-live-agent-driver-evidence-v1" and .scenario==$scenario and
      .disposition=="pass" and .daemon_id==$daemon and .run_id==env.LIVE_RUN_ID and
      (.checkpoint_before|type=="string" and length>0) and
      (.checkpoint_after|type=="string" and length>0) and
      (.exact_fixture_ids|type=="array" and length>0) and .cleanup_evidence=="canonical-resource-manifest"' "$file" >/dev/null ||
      live_die "invalid or wrong-authority agent scenario evidence: $scenario"
    while IFS= read -r artifact; do
      [[ -s "$LIVE_RUN_ROOT/$artifact" ]] || live_die "agent scenario surface artifact missing: $artifact"
      local expected
      expected="$(jq -r 'if .expected_action=="log" then "agent-live" else .expected_action end' "$file")"
      live_agent_assert_surface_semantics "$LIVE_RUN_ROOT/$artifact" "$(jq -r '.exact_fixture_ids[0]' "$file")" "$expected" ||
        live_die "agent scenario surface lacks structured identity/action semantics: $scenario $artifact"
    done < <(jq -r '.surface_artifacts[]' "$file")
    cp "$file" "$LIVE_RUN_ROOT/artifacts/agent-$scenario.json"
    live_agent_disposition "$scenario" pass "run-owned driver evidence verified" "artifacts/agent-$scenario.json"
  done < <(jq -r '.scenarios[]' "$agent_contract")
  (( missing == 0 )) || return 1
}

live_agent_run() {
  jq -e '.schema=="cortex-live-agent-contract-v1" and (.scenarios|length)>=15 and (.surfaces|sort)==["cli","mcp","rest"]' "$agent_contract" >/dev/null
  live_agent_validate_authority
  local fixture="${LIVE_AGENT_FIXTURE_ID:?exact controlled agent fixture ID is required}" stdout_marker="${LIVE_AGENT_EXPECT_STDOUT:?}" stderr_marker="${LIVE_AGENT_EXPECT_STDERR:?}"
  [[ "$fixture" =~ ^[0-9a-f]{64}$ ]] || live_die "agent fixture must be an exact 64-character Docker ID"
  trap 'live_agent_stop' RETURN
  live_agent_allowlist_experiment
  live_agent_start
  live_agent_query_marker "$stdout_marker" stdout
  live_agent_assert_identity "$stdout_marker" stdout "$fixture"
  live_agent_query_marker "$stderr_marker" stderr
  live_agent_assert_identity "$stderr_marker" stderr "$fixture"
  live_agent_checkpoint initial
  live_agent_disposition initial-collection pass "stdout/stderr identity observed through MCP, REST, and CLI" artifacts/ingest-agent-stdout-1-rest.json
  live_agent_stop; live_agent_start; live_agent_checkpoint restart
  live_agent_disposition agent-restart pass "stable host identity and daemon watermark after restart"
  live_agent_disposition checkpoint-resume pass "persistent host ID and checkpoint watermark survived agent restart"
  live_agent_disposition allowlist pass "wrong-prefix metadata denial followed by isolated-prefix acceptance" artifacts/agent-allowlist.json
  if [[ "$LIVE_AGENT_BOUNDARY" == desktop-proxy ]]; then live_agent_portable_dispositions; fi
  if [[ -n "${LIVE_AGENT_DOCKER_CONTROL_URL:-}" ]]; then
    # shellcheck disable=SC1090
    source "$LIVE_PROJECT_ROOT/tests/live/profiles/agent/portable-driver.sh"
  fi
  live_agent_external_scenarios || live_die "agent scenario driver did not certify every required capability"
  if grep -F 'retry buffer full; oldest heartbeat evicted' "$LIVE_RUN_ROOT/artifacts/agent.stderr" >/dev/null; then live_die "agent retry buffer evicted data below the declared bounded load"; fi
  jq -e '.schema=="cortex-live-agent-flow-accounting-v1" and .induced_pause_seconds==2 and
    .watermarks.before==.watermarks.at_release and .watermarks.after_drain>.watermarks.at_release and
    .accepted_after_drain>0 and .evicted==0 and .recovered and
    .sequence_accounting.bounds_enforced and .sequence_accounting.duplicates==0 and
    .sequence_accounting.loss<=.sequence_accounting.loss_upper_bound' \
    "$LIVE_AGENT_SCENARIO_EVIDENCE_DIR/bounded-backpressure-accounting.json" >/dev/null
  for accounting in proxy-outage server-restart; do
    jq -e '.schema=="cortex-live-agent-flow-accounting-v1" and .outage_seconds>=1 and
      .watermarks.after_drain>.watermarks.at_restore and
      .accepted_after_reconnect>0 and .reconnected and
      .sequence_accounting.bounds_enforced and .sequence_accounting.duplicates==0 and
      .sequence_accounting.loss<=.sequence_accounting.loss_upper_bound' \
      "$LIVE_AGENT_SCENARIO_EVIDENCE_DIR/$accounting-accounting.json" >/dev/null
  done
  cp "$LIVE_AGENT_SCENARIO_EVIDENCE_DIR"/*-accounting.json "$LIVE_RUN_ROOT/artifacts/"
  live_event agent_queue_bounds "$(jq -cn --argjson heartbeat_limit "$(jq -r .limits.retry_buffer "$agent_contract")" --slurpfile measured "$LIVE_AGENT_SCENARIO_EVIDENCE_DIR/bounded-backpressure-accounting.json" '{heartbeat_retry_limit:$heartbeat_limit,heartbeat_evictions:$measured[0].evicted,syslog_channel_bound:2048,recovered:$measured[0].recovered,accepted_after_drain:$measured[0].accepted_after_drain,sequence_accounting:$measured[0].sequence_accounting}')"
  live_agent_cli_sweep
  live_agent_cli_execute
  live_agent_stop
  # Bind the owned contract surface to the raw observation/refusal evidence.
  # The allowlist denial is the negative policy case; the authorization case is
  # a real unauthenticated machine-ingest request against the same receiver.
  local agent_surface="ingest.agent-docker" agent_auth_status
  agent_auth_status="$(curl -sS --max-time 10 -o "$LIVE_RUN_ROOT/artifacts/agent-auth-denied.json" -w '%{http_code}' -H 'Host: localhost' -H 'Content-Type: application/json' --data-binary '{}' "$(live_ingest_http /v1/heartbeats)")"
  [[ "$agent_auth_status" == 401 ]]
  live_result "$agent_surface" agent-docker-forwarding pass 0 "artifacts/ingest-agent-stdout-1-rest.json" semantic-positive
  live_result "$agent_surface" agent-docker-unsupported-event-filter pass 0 "artifacts/agent-unsupported-event.json" validation-negative
  live_result "$agent_surface" agent-docker-source-authority-denial pass 0 "artifacts/agent-allowlist-denied.json" authorization
  local ledger="$LIVE_RUN_ROOT/artifacts/agent-capability-ledger.jsonl" scenario disposition
  : >"$ledger"
  while IFS= read -r scenario; do
    disposition="$(jq -sr --arg s "$scenario" '[.[]|select(.kind=="agent_scenario" and .payload.scenario==$s)]|last.payload.disposition' "$(live_event_file)")"
    jq -cn --arg scenario "$scenario" --arg disposition "$disposition" '{surface_id:("agent."+$scenario),case_kind:"semantic-positive",mandatory:true,outcome:{result:(if $disposition=="pass" then "pass" else "qualified" end),disposition:$disposition}}' >>"$ledger"
  done < <(jq -r '.scenarios[]' "$agent_contract")
  [[ "$(wc -l <"$ledger" | tr -d ' ')" == "$(jq '.scenarios|length' "$agent_contract")" ]]
  jq -e -s 'length==16 and ([.[].surface_id]|unique|length)==16 and all(.[];.outcome.result=="pass" or .outcome.result=="qualified")' "$ledger" >/dev/null
  live_event phase_finished "$(jq -cn --argjson total "$(wc -l <"$ledger")" '{phase:"agent",disposition:"pass",cases:$total,ledger:"artifacts/agent-capability-ledger.jsonl"}')"
  trap - RETURN
}
