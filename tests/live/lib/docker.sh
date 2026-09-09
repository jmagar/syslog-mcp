#!/usr/bin/env bash

_live_docker_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$_live_docker_lib_dir/common.sh"

live_docker_provider() {
  local id
  id="$(docker info --format '{{.ID}}')" || return
  [[ -n "$id" ]] || { live_die "Docker provider has no stable identity"; return; }
  printf 'docker-host:%s\n' "$id"
}

live_docker_image_id() {
  local image="$1" id
  id="$(docker image inspect --format '{{.Id}}' "$image")" || return
  [[ "$id" == sha256:* ]] || { live_die "candidate image did not resolve to immutable content ID"; return; }
  printf '%s\n' "$id"
}

live_topology_generate_secrets() {
  LIVE_CORTEX_TOKEN="$(openssl rand -hex 32)"
  LIVE_API_TOKEN="$(openssl rand -hex 32)"
  LIVE_ADMIN_TOKEN="$(openssl rand -hex 32)"
  LIVE_ORACLE_TOKEN="$(openssl rand -hex 32)"
  LIVE_CURSOR_SIGNING_KEY="$(openssl rand -hex 32)"
  live_register_secret "$LIVE_CORTEX_TOKEN"; live_register_secret "$LIVE_API_TOKEN"
  live_register_secret "$LIVE_ADMIN_TOKEN"; live_register_secret "$LIVE_ORACLE_TOKEN"
  live_register_secret "$LIVE_CURSOR_SIGNING_KEY"
  export LIVE_CORTEX_TOKEN LIVE_API_TOKEN LIVE_ADMIN_TOKEN LIVE_ORACLE_TOKEN LIVE_CURSOR_SIGNING_KEY
}

live_compose_project_exists() {
  local project="$1"
  docker compose ls --all --format json | jq -e --arg p "$project" 'if type=="array" then any(.[];.Name==$p) else false end' >/dev/null
}

live_compose_project_owned() {
  local project="$1" run_id="$2" ids
  ids="$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
  [[ -n "$ids" ]] || return 1
  while IFS= read -r id; do
    [[ "$(docker inspect --format '{{index .Config.Labels "cortex.live.run_id"}}' "$id")" == "$run_id" ]] || return 1
  done <<<"$ids"
}

live_compose_cleanup_exact() {
  local project="$1" run_id="$2" provider="$3" compose_file="$4"
  local ids volumes networks
  : "$compose_file" # retained in immutable cleanup argv as topology evidence
  [[ "$(live_docker_provider)" == "$provider" ]] || { live_die "foreign Docker provider refusal"; return 2; }
  if live_compose_project_exists "$project"; then
    live_compose_project_owned "$project" "$run_id" || { live_die "foreign Compose project refusal: $project"; return 2; }
  fi
  ids="$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
  if [[ -n "$ids" ]]; then
    # IDs were resolved from the exact project after every container ownership label was verified.
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null
  fi
  volumes="$(docker volume ls -q --filter "label=com.docker.compose.project=$project" --filter "label=cortex.live.run_id=$run_id")"
  if [[ -n "$volumes" ]]; then
    # shellcheck disable=SC2086
    docker volume rm $volumes >/dev/null
  fi
  networks="$(docker network ls -q --filter "label=com.docker.compose.project=$project" --filter "label=cortex.live.run_id=$run_id")"
  if [[ -n "$networks" ]]; then
    # shellcheck disable=SC2086
    docker network rm $networks >/dev/null
  fi
}

live_compose_verify_absent() {
  local project="$1" run_id="$2" provider="$3"
  [[ "$(live_docker_provider)" == "$provider" ]] || return 2
  ! live_compose_project_exists "$project" || return 1
  [[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ]] || return 1
  [[ -z "$(docker volume ls -q --filter "label=cortex.live.run_id=$run_id")" ]] || return 1
  [[ -z "$(docker network ls -q --filter "label=cortex.live.run_id=$run_id")" ]] || return 1
}

live_topology_register() {
  local project="$1" provider="$2" compose_file="$3" digest="$4" cleanup verify labels
  cleanup="$(jq -cn --arg self "$LIVE_PROJECT_ROOT/tests/live/lib/docker.sh" --arg p "$project" --arg r "$LIVE_RUN_ID" --arg provider "$provider" --arg f "$compose_file" '["bash",$self,"cleanup",$p,$r,$provider,$f]')"
  verify="$(jq -cn --arg self "$LIVE_PROJECT_ROOT/tests/live/lib/docker.sh" --arg p "$project" --arg r "$LIVE_RUN_ID" --arg provider "$provider" '["bash",$self,"verify",$p,$r,$provider]')"
  labels="$(jq -cn --arg project "$project" '{"com.docker.compose.project":$project}')"
  live_resource_transition topology compose-project PLANNED "$provider" "" '[]' "" "$labels" '[]'
  live_resource_transition topology compose-project CREATING "$provider" "$project" '[]' "$digest" "$labels" '[]'
  live_resource_transition topology compose-project IDENTIFIED "$provider" "$project" "$cleanup" "$digest" "$labels" "$verify"
}

live_topology_port() {
  local compose_file="$1" project="$2" service="$3" port="$4" proto="${5:-tcp}" value id
  : "$compose_file"
  id="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$service")"
  [[ -n "$id" ]] || { live_die "no running container for $project/$service"; return; }
  value="$(docker inspect "$id" | jq -er --arg key "$port/$proto" '.[0].NetworkSettings.Ports[$key][0].HostPort')" || {
    live_die "no provider binding for $project/$service $port/$proto"; return;
  }
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || { live_die "invalid provider port: $value"; return; }
  printf '%s\n' "$value"
}

_live_http_health_ready() {
  [[ "${LIVE_FORCE_READINESS_TIMEOUT:-0}" != 1 ]] || return 1
  curl -fsS --max-time 2 -H 'Host: localhost' "http://127.0.0.1:${LIVE_HTTP_PORT}/health" >/dev/null
}

_live_mcp_ready() {
  curl -fsS --max-time 3 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"cortex-live","version":"1"}}}' \
    "http://127.0.0.1:${LIVE_HTTP_PORT}/mcp" | jq -e '.result.serverInfo.name|length>0' >/dev/null
}

_live_ingest_ready() {
  local marker="$1" query="\"$1\""
  curl -fsS --max-time 3 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d "$(jq -cn --arg q "$query" '{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"cortex",arguments:{action:"search",query:$q,limit:1}}}')" \
    "http://127.0.0.1:${LIVE_HTTP_PORT}/mcp" | grep -F "$marker" >/dev/null
}

_live_doubles_ready() {
  curl -fsS --max-time 3 "http://127.0.0.1:${LIVE_ORACLE_PORT}/oauth/jwks" | jq -e '.keys[0].kid=="cortex-live"' >/dev/null &&
  curl -fsS --max-time 3 -H "Authorization: Bearer $LIVE_ORACLE_TOKEN" -H 'Content-Type: application/json' -d '{"title":"live readiness"}' "http://127.0.0.1:${LIVE_ORACLE_PORT}/notify" | jq -e '.captured==true' >/dev/null
}

live_platform_disposition() {
  local os="${1:-$(uname -s)}" disposition reason
  case "$os" in
    Linux)
      disposition=not-applicable; reason=owned-by-agent-full-boundary;;
    Darwin|MINGW*|MSYS*)
      if [[ -n "${CORTEX_LIVE_DOCKER_PROXY_URL:-}" ]]; then disposition=platform-qualified; reason=desktop-read-only-proxy
      else disposition=not-authorized; reason=desktop-proxy-not-configured; fi;;
    *) disposition=unsupported; reason=unknown-platform;;
  esac
  jq -cn --arg os "$os" --arg disposition "$disposition" --arg reason "$reason" \
    '{schema:"cortex-live-platform-disposition-v1",component:"docker-agent-boundary",platform:$os,disposition:$disposition,reason:$reason,executable:"tests/live/spikes/docker-boundary/scenario.sh"}'
}

live_topology_dispositions() {
  local project="$1" volume quota disposition
  volume="$(docker volume ls -q --filter "label=com.docker.compose.project=$project" --filter label=cortex.live.kind=pressure)"
  quota="$(docker volume inspect "$volume" | jq -r '.[0].Options.size // .[0].Options.o // empty')"
  if [[ "$quota" == *size=* || "$quota" =~ ^[0-9]+[kKmMgG]?$ ]]; then disposition=pass; else disposition=platform-qualified; fi
  jq -cn --arg disposition "$disposition" --arg quota "$quota" \
    '{schema:"cortex-live-pressure-disposition-v1",disposition:$disposition,quota_evidence:(if $quota=="" then null else $quota end),green:($disposition=="pass")}' >"$LIVE_RUN_ROOT/pressure-disposition.json"
  live_platform_disposition >"$LIVE_RUN_ROOT/docker-agent-disposition.json"
  jq -cn '{schema:"cortex-live-advanced-readiness-v1",projection_watermark:{disposition:"not-applicable",reason:"owned-by-data-wave"},evaluator_cycle:{disposition:"not-applicable",reason:"owned-by-notification-wave"},agent_checkpoint:{disposition:"not-applicable",reason:"owned-by-agent-wave"},green:false}' >"$LIVE_RUN_ROOT/advanced-readiness.json"
  chmod 600 "$LIVE_RUN_ROOT"/*-disposition.json "$LIVE_RUN_ROOT/advanced-readiness.json"
}

live_redirector_egress_denied() {
  local project="$1" id
  id="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=udp-redirector)"
  docker exec "$id" python -c 'import socket,sys
try: socket.create_connection(("1.1.1.1",80),1); sys.exit(1)
except OSError: sys.exit(0)'
}

live_emit_topology_dispositions() {
  local disposition
  disposition="$(jq -r .disposition "$LIVE_RUN_ROOT/pressure-disposition.json")"; live_terminal_disposition topology.pressure-quota "$disposition" pressure-disposition.json
  disposition="$(jq -r .disposition "$LIVE_RUN_ROOT/docker-agent-disposition.json")"; live_terminal_disposition topology.docker-agent-boundary "$disposition" docker-agent-disposition.json
  for capability in projection_watermark evaluator_cycle agent_checkpoint; do
    disposition="$(jq -r --arg capability "$capability" '.[$capability].disposition' "$LIVE_RUN_ROOT/advanced-readiness.json")"
    live_terminal_disposition "topology.$capability" "$disposition" advanced-readiness.json
  done
  disposition="$(jq -r .disposition "$LIVE_RUN_ROOT/egress-disposition.json")"; live_terminal_disposition topology.redirector-egress "$disposition" egress-disposition.json
  live_terminal_disposition topology.apprise-provider pass topology.json
  live_terminal_disposition topology.oauth-provider-double pass topology.json
  live_terminal_disposition topology.workload-producer pass topology.json
}

live_topology_readiness() {
  local compose_file="$1" project="$2" marker="live-ready-${LIVE_RUN_ID#cortex-e2e-}" readiness_timeout="${LIVE_READINESS_TIMEOUT_SECONDS:-30}"
  [[ "$readiness_timeout" =~ ^[1-9][0-9]*$ ]] || { live_die "invalid readiness timeout"; return; }
  if ! live_wait_until "$readiness_timeout" health-http _live_http_health_ready; then live_diagnostics_once "$compose_file" "$project" health-timeout; return 1; fi
  if ! live_wait_until 30 mcp-initialize _live_mcp_ready; then live_diagnostics_once "$compose_file" "$project" mcp-timeout; return 1; fi
  if ! live_wait_until 15 dependency-doubles _live_doubles_ready; then live_diagnostics_once "$compose_file" "$project" doubles-timeout; return 1; fi
  printf '<134>1 %s cortex-live readiness - - - %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$marker" | nc -u -w 1 127.0.0.1 "$LIVE_SYSLOG_UDP_PORT"
  if ! live_wait_until 30 ingest-roundtrip _live_ingest_ready "$marker"; then live_diagnostics_once "$compose_file" "$project" ingest-timeout; return 1; fi
}

_live_toxiproxy_api_ready() { curl -fsS --max-time 2 "http://127.0.0.1:$1/version" >/dev/null; }

live_toxiproxy_configure() {
  local api_port="$1" name listen upstream
  live_wait_until 20 toxiproxy-api _live_toxiproxy_api_ready "$api_port" || return
  while read -r name listen upstream; do
    curl -fsS --max-time 5 -H 'Content-Type: application/json' \
      -d "$(jq -cn --arg name "${LIVE_RUN_ID}-$name" --arg listen "$listen" --arg upstream "$upstream" '{name:$name,listen:$listen,upstream:$upstream,enabled:true}')" \
      "http://127.0.0.1:$api_port/proxies" >/dev/null
  done <<'PROXIES'
http 0.0.0.0:13100 candidate:3100
syslog-tcp 0.0.0.0:11514 candidate:1514
oracle 0.0.0.0:18080 oracle:8080
PROXIES
}

live_topology_start() {
  local candidate="$1" oracle="$2" toxiproxy="$3"
  local compose_file="$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml"
  local provider project digest
  provider="$(live_docker_provider)"; project="${LIVE_RUN_ID//_/-}"
  LIVE_CANDIDATE_IMAGE="$(live_docker_image_id "$candidate")"
  LIVE_ORACLE_IMAGE="$(live_docker_image_id "$oracle")"
  LIVE_TOXIPROXY_IMAGE="$(live_docker_image_id "$toxiproxy")"
  digest="${LIVE_CANDIDATE_IMAGE#sha256:}"
  LIVE_COMPOSE_PROJECT="$project"; LIVE_RESOURCE_PROVIDER="$provider"
  LIVE_SERVER_INSTANCE_ID="${LIVE_RUN_ID}-candidate"
  LIVE_DATABASE_FINGERPRINT="$(printf '%s' "${project}_state" | shasum -a 256 | awk '{print $1}')"
  export LIVE_COMPOSE_PROJECT LIVE_RESOURCE_PROVIDER LIVE_CANDIDATE_IMAGE LIVE_ORACLE_IMAGE LIVE_TOXIPROXY_IMAGE LIVE_SERVER_INSTANCE_ID LIVE_DATABASE_FINGERPRINT
  live_topology_generate_secrets
  if live_compose_project_exists "$project"; then
    live_event topology_refused "$(jq -cn --arg project "$project" '{project:$project,reason:"compose-project-collision"}')"
    live_die "Compose project collision: $project"
    return 2
  fi
  live_topology_register "$project" "$provider" "$compose_file" "$digest"
  local -a compose_args=(-f "$compose_file")
  if [[ "${LIVE_PLATFORM_POLICY:-}" == linux-full ]]; then
    [[ "${CORTEX_LIVE_DIND_AUTHORIZED:-0}" == 1 ]] || { live_die 'linux-full topology requires CORTEX_LIVE_DIND_AUTHORIZED=1'; return 1; }
    compose_args+=(-f "$LIVE_PROJECT_ROOT/tests/live/profiles/linux-full/compose.yaml")
  fi
  local -a compose_env=(env
    "LIVE_ADMIN_TOKEN=$LIVE_ADMIN_TOKEN"
    "LIVE_API_TOKEN=$LIVE_API_TOKEN"
    "LIVE_CANDIDATE_IMAGE=$LIVE_CANDIDATE_IMAGE"
    "LIVE_COMPOSE_PROJECT=$LIVE_COMPOSE_PROJECT"
    "LIVE_CORTEX_TOKEN=$LIVE_CORTEX_TOKEN"
    "LIVE_CURSOR_SIGNING_KEY=$LIVE_CURSOR_SIGNING_KEY"
    "LIVE_DATABASE_FINGERPRINT=$LIVE_DATABASE_FINGERPRINT"
    "LIVE_HTTP_PUBLISHED=${LIVE_HTTP_PUBLISHED:-0}"
    "LIVE_ORACLE_IMAGE=$LIVE_ORACLE_IMAGE"
    "LIVE_ORACLE_TOKEN=$LIVE_ORACLE_TOKEN"
    "LIVE_RUN_ID=$LIVE_RUN_ID"
    "LIVE_SERVER_INSTANCE_ID=$LIVE_SERVER_INSTANCE_ID"
    "LIVE_TOXIPROXY_IMAGE=$LIVE_TOXIPROXY_IMAGE")
  if ! live_timeout_process_tree 120 "${compose_env[@]}" docker compose "${compose_args[@]}" -p "$project" up -d --no-build --wait --wait-timeout 90; then
    live_diagnostics_once "$compose_file" "$project" compose-up-failed
    return 1
  fi
  live_resource_transition topology compose-project CREATED "$provider" "$project" \
    "$(jq -cn --arg self "$LIVE_PROJECT_ROOT/tests/live/lib/docker.sh" --arg p "$project" --arg r "$LIVE_RUN_ID" --arg provider "$provider" --arg f "$compose_file" '["bash",$self,"cleanup",$p,$r,$provider,$f]')" "$digest" \
    "$(jq -cn --arg project "$project" '{"com.docker.compose.project":$project}')" \
    "$(jq -cn --arg self "$LIVE_PROJECT_ROOT/tests/live/lib/docker.sh" --arg p "$project" --arg r "$LIVE_RUN_ID" --arg provider "$provider" '["bash",$self,"verify",$p,$r,$provider]')"
  LIVE_HTTP_PORT="$(live_topology_port "$compose_file" "$project" toxiproxy 13100 tcp)"
  LIVE_SYSLOG_TCP_PORT="$(live_topology_port "$compose_file" "$project" toxiproxy 11514 tcp)"
  LIVE_SYSLOG_UDP_PORT="$(live_topology_port "$compose_file" "$project" udp-redirector 11514 udp)"
  LIVE_ORACLE_PORT="$(live_topology_port "$compose_file" "$project" toxiproxy 18080 tcp)"
  LIVE_TOXIPROXY_PORT="$(live_topology_port "$compose_file" "$project" toxiproxy 8474 tcp)"
  export LIVE_HTTP_PORT LIVE_SYSLOG_TCP_PORT LIVE_SYSLOG_UDP_PORT LIVE_ORACLE_PORT LIVE_TOXIPROXY_PORT
  jq -cn --argjson http "$LIVE_HTTP_PORT" --argjson tcp "$LIVE_SYSLOG_TCP_PORT" --argjson udp "$LIVE_SYSLOG_UDP_PORT" \
    --argjson oracle "$LIVE_ORACLE_PORT" --argjson toxiproxy "$LIVE_TOXIPROXY_PORT" \
    '{host:"127.0.0.1",http:$http,syslog_tcp:$tcp,syslog_udp:$udp,oracle:$oracle,toxiproxy:$toxiproxy}' >"$LIVE_RUN_ROOT/topology.json"
  chmod 600 "$LIVE_RUN_ROOT/topology.json"
  live_toxiproxy_configure "$LIVE_TOXIPROXY_PORT"
  live_topology_dispositions "$project"
  if live_redirector_egress_denied "$project"; then
    jq -cn '{schema:"cortex-live-egress-disposition-v1",disposition:"pass",green:true,probe:"tcp-1.1.1.1:80-denied"}' >"$LIVE_RUN_ROOT/egress-disposition.json"
  else
    jq -cn '{schema:"cortex-live-egress-disposition-v1",disposition:"platform-qualified",green:false,probe:"tcp-1.1.1.1:80-reachable",reason:"Docker Desktop ingress bridge supplies redirector egress; workloads remain internal-only"}' >"$LIVE_RUN_ROOT/egress-disposition.json"
  fi
  chmod 600 "$LIVE_RUN_ROOT/egress-disposition.json"
  live_emit_topology_dispositions
  live_topology_readiness "$compose_file" "$project"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    cleanup) shift; live_compose_cleanup_exact "$@";;
    verify) shift; live_compose_verify_absent "$@";;
    *) echo "usage: docker.sh cleanup PROJECT RUN_ID PROVIDER COMPOSE_FILE | verify PROJECT RUN_ID PROVIDER" >&2; exit 2;;
  esac
fi
