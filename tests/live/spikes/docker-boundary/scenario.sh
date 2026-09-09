#!/usr/bin/env bash
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose="$here/../../services/docker-read-proxy/compose.yaml"
mode="${CORTEX_LIVE_DOCKER_BOUNDARY_MODE:-reduced}"
evidence="${LIVE_RUN_ROOT:?}/artifacts/docker-boundary.json"
started="$(date +%s)"

docker_boundary_main() {
record() {
  local disposition="$1" candidate="$2" reason="$3" details='{}'
  [[ $# -lt 4 ]] || details="$4"
  jq -cn --arg disposition "$disposition" --arg candidate "$candidate" --arg reason "$reason" \
    --argjson details "$details" --argjson duration "$(( $(date +%s) - started ))" \
    '{schema:"cortex-live-docker-boundary-result-v1",schema_version:1,candidate:$candidate,disposition:$disposition,reason:$reason,duration_seconds:$duration,details:$details}' |
    live_artifact_write docker-boundary.json 65536
  live_event docker_boundary_result_v1 "$(cat "$evidence")"
}

if [[ "$mode" == reduced ]]; then
  if [[ -z "${CORTEX_LIVE_DOCKER_PROXY_URL:-}" ]]; then
    record not-authorized desktop-proxy "explicit loopback proxy URL absent"
    return 1
  fi
  first="$LIVE_RUN_ROOT/reduced-first.json"
  if ! bash "$here/probe.sh" "$first"; then
    cp "$first" "$evidence"; live_event docker_boundary_result_v1 "$(cat "$first")"; return 1
  fi
  first_id="$(jq -er '.authority|sub("^proxy-read-only:";"")' "$first")"
  sleep 1
  second="$LIVE_RUN_ROOT/reduced-second.json"
  if ! bash "$here/probe.sh" "$second"; then
    record fail desktop-proxy "proxy outage after initial connection" "$(jq -cn --arg id "$first_id" --argjson retry "$(cat "$second")" '{initial_daemon_id:$id,recovery:$retry}')"
    return 1
  fi
  second_id="$(jq -er '.authority|sub("^proxy-read-only:";"")' "$second")"
  [[ "$first_id" == "$second_id" ]] || { record fail desktop-proxy "daemon identity changed between probes"; return 1; }
  fixture="${CORTEX_LIVE_DOCKER_FIXTURE_ID:-}"
  if [[ -z "$fixture" ]]; then record fail desktop-proxy "mandatory reduced profile requires an exact controlled fixture ID"; return 1; else
    [[ -n "${CORTEX_LIVE_DOCKER_EXPECT_STDOUT:-}" && -n "${CORTEX_LIVE_DOCKER_EXPECT_STDERR:-}" && -n "${CORTEX_LIVE_DOCKER_EXPECT_HEALTH:-}" ]] || { record fail desktop-proxy "controlled fixture markers and health are required"; return 1; }
    [[ "$fixture" =~ ^[0-9a-f]{64}$ ]] || { record fail desktop-proxy "fixture ID must be an exact 64-character Docker ID"; return 1; }
    curl_common=(--silent --show-error --fail --max-time 5 --connect-timeout 2 --max-filesize 65536 --noproxy '*' --proto '=http,https')
    curl "${curl_common[@]}" "$CORTEX_LIVE_DOCKER_PROXY_URL/containers/$fixture/logs?stdout=1&stderr=1&tail=10" >"$LIVE_RUN_ROOT/reduced-logs.txt"
    grep -F -q "$CORTEX_LIVE_DOCKER_EXPECT_STDOUT" "$LIVE_RUN_ROOT/reduced-logs.txt" || { record fail desktop-proxy "stdout marker missing through proxy"; return 1; }
    grep -F -q "$CORTEX_LIVE_DOCKER_EXPECT_STDERR" "$LIVE_RUN_ROOT/reduced-logs.txt" || { record fail desktop-proxy "stderr marker missing through proxy"; return 1; }
    curl "${curl_common[@]}" "$CORTEX_LIVE_DOCKER_PROXY_URL/containers/$fixture/json" >"$LIVE_RUN_ROOT/reduced-inspect.json"
    jq -e --arg health "$CORTEX_LIVE_DOCKER_EXPECT_HEALTH" '.State.Health.Status == $health' "$LIVE_RUN_ROOT/reduced-inspect.json" >/dev/null || { record fail desktop-proxy "health state mismatch through proxy"; return 1; }
    now="$(date +%s)"; curl "${curl_common[@]}" "$CORTEX_LIVE_DOCKER_PROXY_URL/events?since=$((now-2))&until=$now&filters=%7B%22container%22%3A%5B%22$fixture%22%5D%7D" >"$LIVE_RUN_ROOT/reduced-events.jsonl"
    jq -e -s 'length > 0 and all(.[]; type=="object" and .Type=="container" and (.Action|type=="string" and length>0))' "$LIVE_RUN_ROOT/reduced-events.jsonl" >/dev/null || { record fail desktop-proxy "no semantic container events through proxy"; return 1; }
    read_fidelity='{"stdout_stderr":"observed","events":"observed","health":"observed"}'
  fi
  record pass desktop-proxy "live reduced proxy boundary and controlled fixture passed" \
    "$(jq -cn --arg id "$first_id" --argjson fidelity "$read_fidelity" '{daemon_id:$id,read_fidelity:$fidelity,socket_denial:true,proxy_recovery:true,oom:"unsupported",daemon_restart:"unsupported",daemon_death_cleanup:"unsupported"}')"
  return 0
fi

if [[ "$mode" != full ]]; then record fail unknown "unknown Docker boundary mode"; return 1; fi
if [[ "${CORTEX_LIVE_DIND_AUTHORIZED:-0}" != 1 ]]; then
  record not-authorized linux-dind "privileged run-owned DinD authority absent"
  return 1
fi
[[ "$(uname -s)" == Linux ]] || { record platform-qualified linux-dind "full DinD certification is Linux-only"; return 1; }
live_require_tools docker curl jq || { record unsupported linux-dind "required executable unavailable"; return 1; }
project="cortex-live-${LIVE_RUN_ID#cortex-e2e-}"
export LIVE_RUN_ID
host_daemon_id="$(docker info --format '{{.ID}}')"
LIVE_RESOURCE_PROVIDER="docker-host:$host_daemon_id"; export LIVE_RESOURCE_PROVIDER
register_intent() { live_resource_transition "$1" "$2" PLANNED "$LIVE_RESOURCE_PROVIDER" '' '[]'; live_resource_transition "$1" "$2" CREATING "$LIVE_RESOURCE_PROVIDER" "$3" '[]' "$4" '{}' '[]'; }
register_exact() {
  local key="$1" kind="$2" id="$3" digest="$4" cleanup verify
  cleanup="$(jq -cn --arg script "$here/cleanup-host-resource.sh" --arg daemon "$host_daemon_id" --arg kind "$kind" --arg id "$id" '["bash",$script,$daemon,$kind,$id]')"
  verify="$(jq -cn --arg script "$here/verify-host-resource.sh" --arg daemon "$host_daemon_id" --arg kind "$kind" --arg id "$id" '["bash",$script,$daemon,$kind,$id]')"
  live_resource_transition "$key" "$kind" IDENTIFIED "$LIVE_RESOURCE_PROVIDER" "$id" "$cleanup" "$digest" '{}' "$verify"
  live_resource_transition "$key" "$kind" CREATED "$LIVE_RESOURCE_PROVIDER" "$id" "$cleanup" "$digest" '{}' "$verify"
}
reconcile_partial_compose() {
  local ids id kind key service count=0 labels
  [[ "$(docker info --format '{{.ID}}')" == "$host_daemon_id" ]] || return 2
  ids="$(live_timeout 10 docker ps -aq --no-trunc --filter "label=cortex.live.run_id=$LIVE_RUN_ID" --filter "label=com.docker.compose.project=$project")" || return 2
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue; labels="$(docker inspect "$id")" || return 2
    jq -e --arg run "$LIVE_RUN_ID" --arg project "$project" '.[0].Config.Labels["cortex.live.run_id"]==$run and .[0].Config.Labels["com.docker.compose.project"]==$project' <<<"$labels" >/dev/null || return 2
    service="$(jq -r '.[0].Config.Labels["com.docker.compose.service"]' <<<"$labels")"
    case "$service" in daemon) key=full-daemon;; proxy) key=full-proxy;; *) return 2;; esac
    register_exact "$key" container "$id" "$service-reconciled"; ((count+=1))
  done <<<"$ids"
  for kind in network volume; do
    if [[ "$kind" == network ]]; then ids="$(docker network ls -q --no-trunc --filter "label=cortex.live.run_id=$LIVE_RUN_ID" --filter "label=com.docker.compose.project=$project")"
    else ids="$(docker volume ls -q --filter "label=cortex.live.run_id=$LIVE_RUN_ID" --filter "label=com.docker.compose.project=$project")"; fi
    [[ "$(grep -c . <<<"$ids" || true)" -le 1 ]] || return 2
    while IFS= read -r id; do [[ -z "$id" ]] && continue; key="full-$kind"; register_exact "$key" "$kind" "$id" "$kind-reconciled"; ((count+=1)); done <<<"$ids"
  done
  (( count > 0 )) || return 2
}
register_intent full-network network "$project-control" network-request
register_intent full-volume volume "$project-dind-socket" volume-request
register_intent full-daemon container "$project-daemon" daemon-request
register_intent full-proxy container "$project-proxy" proxy-request
if [[ "${CORTEX_LIVE_DIND_FAULT_MID_UP:-0}" == 1 ]]; then
  live_timeout 60 docker compose -p "$project" -f "$compose" up -d daemon || true
  reconcile_partial_compose || { live_audit_write MANUAL_RECONCILIATION_REQUIRED "partial Compose resources ambiguous or provider changed"; return 1; }
  live_cleanup_resources "$LIVE_RESOURCE_PROVIDER" 30 || return 1
  record not-applicable linux-dind "injected mid-up fault reconciled exact resources"
  return 1
fi
if ! live_timeout 120 docker compose -p "$project" -f "$compose" up -d --wait --wait-timeout 60; then
  reconcile_partial_compose || { live_audit_write MANUAL_RECONCILIATION_REQUIRED "partial Compose resources ambiguous or provider changed"; return 1; }
  live_cleanup_resources "$LIVE_RESOURCE_PROVIDER" 30 || return 1
  record fail linux-dind "Compose up failed after exact reconciliation"
  return 1
fi
daemon_outer="$(docker compose -p "$project" -f "$compose" ps -q daemon)"; proxy_outer="$(docker compose -p "$project" -f "$compose" ps -q proxy)"
network_id="$(docker network inspect "${project}_control" --format '{{.ID}}')"; volume_id="$(docker volume inspect "${project}_dind-socket" --format '{{.Name}}')"
register_exact full-network network "$network_id" network-identified
register_exact full-volume volume "$volume_id" volume-identified
register_exact full-daemon container "$daemon_outer" daemon-identified
register_exact full-proxy container "$proxy_outer" proxy-identified
proxy_port="$(docker compose -p "$project" -f "$compose" port proxy 2375 | awk -F: '{print $NF}')"
proxy="http://127.0.0.1:$proxy_port"
inner_docker() { docker exec "$daemon_outer" docker "$@"; }
daemon_id=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do daemon_id="$(inner_docker info --format '{{.ID}}' 2>/dev/null || true)"; [[ -n "$daemon_id" ]] && break; sleep 1; done
[[ -n "$daemon_id" ]]
CORTEX_LIVE_DOCKER_PROXY_URL="$proxy" bash "$here/probe.sh" "$LIVE_RUN_ROOT/full-proxy.json"
# Verify actual outage and recovery without changing the daemon identity.
docker compose -p "$project" -f "$compose" stop proxy >/dev/null
if curl -fsS --max-time 2 "$proxy/_ping" >/dev/null 2>&1; then record fail linux-dind "stopped proxy remained reachable"; return 1; fi
docker compose -p "$project" -f "$compose" start proxy >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do curl -fsS --max-time 1 "$proxy/_ping" >/dev/null 2>&1 && break; sleep 0.5; done
CORTEX_LIVE_DOCKER_PROXY_URL="$proxy" bash "$here/probe.sh" "$LIVE_RUN_ROOT/full-proxy-recovered.json"
[[ "$(jq -r '.authority|sub("^proxy-read-only:";"")' "$LIVE_RUN_ROOT/full-proxy-recovered.json")" == "$daemon_id" ]]

# Preserve the topology's external-egress denial: preload via the control stream.
docker image inspect alpine:3.23 >/dev/null 2>&1 || docker pull alpine:3.23 >/dev/null
docker image save alpine:3.23 | docker exec -i "$daemon_outer" docker load >/dev/null
# A bind of the inner daemon's root must not reveal a marker from the outer host.
host_marker="$LIVE_RUN_ROOT/host-secret-$LIVE_RUN_ID"; : >"$host_marker"
inner_docker run --rm --network none --mount type=bind,src=/,dst=/host alpine:3.23 \
  test ! -e "/host$host_marker"
workload="$(inner_docker create --network none --label "cortex.live.run_id=$LIVE_RUN_ID" alpine:3.23 sh -c 'echo cortex-stdout; echo cortex-stderr >&2')"
inner_docker start -a "$workload" >"$LIVE_RUN_ROOT/workload.stdout" 2>"$LIVE_RUN_ROOT/workload.stderr"
grep -qx cortex-stdout "$LIVE_RUN_ROOT/workload.stdout"; grep -qx cortex-stderr "$LIVE_RUN_ROOT/workload.stderr"
curl -fsS --max-time 5 "$proxy/containers/$workload/logs?stdout=1&stderr=1&tail=10" >"$LIVE_RUN_ROOT/proxy-workload.logs"
grep -a -q cortex-stdout "$LIVE_RUN_ROOT/proxy-workload.logs"; grep -a -q cortex-stderr "$LIVE_RUN_ROOT/proxy-workload.logs"
now="$(date +%s)"; curl -fsS --max-time 5 "$proxy/events?since=$started&until=$now&filters=%7B%22container%22%3A%5B%22$workload%22%5D%7D" >"$LIVE_RUN_ROOT/proxy-events.jsonl"
event_count="$(wc -l <"$LIVE_RUN_ROOT/proxy-events.jsonl" | tr -d ' ')"
(( event_count > 0 ))
health="$(inner_docker create --network none --health-cmd false --health-interval 100ms --health-retries 1 alpine:3.23 sleep 5)"
inner_docker start "$health" >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10; do [[ "$(inner_docker inspect -f '{{.State.Health.Status}}' "$health")" == unhealthy ]] && break; sleep 0.2; done
[[ "$(inner_docker inspect -f '{{.State.Health.Status}}' "$health")" == unhealthy ]]
curl -fsS --max-time 5 "$proxy/containers/$health/json" | jq -e '.State.Health.Status == "unhealthy"' >/dev/null
oom="$(inner_docker create --network none --memory 16m alpine:3.23 awk 'BEGIN{s="x";while(length(s)<67108864)s=s s}')"
inner_docker start -a "$oom" >/dev/null 2>&1 || true
[[ "$(inner_docker inspect -f '{{.State.OOMKilled}}' "$oom")" == true ]]
# Network-none must reject egress without relying on external DNS availability.
egress="$(inner_docker run --rm --network none alpine:3.23 sh -c 'ip route | grep -q default'; printf '%s' "$?")" || true
[[ "${egress:-1}" != 0 ]]
before="$daemon_id"; docker compose -p "$project" -f "$compose" restart daemon >/dev/null
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do after="$(inner_docker info --format '{{.ID}}' 2>/dev/null || true)"; [[ -n "$after" ]] && break; sleep 1; done
[[ "$before" == "$after" ]]
inner_docker rm -f "$workload" "$health" "$oom" >/dev/null
! inner_docker inspect "$workload" >/dev/null 2>&1
# Killing the inner daemon must not broaden cleanup; outer exact run-owned IDs remain removable.
docker compose -p "$project" -f "$compose" kill daemon >/dev/null
live_cleanup_resources "$LIVE_RESOURCE_PROVIDER" 30
[[ "$(jq -r .state "$LIVE_RUN_ROOT/cleanup-audit.json")" == CLEAN ]]
record pass linux-dind "full live Docker boundary passed" \
  "$(jq -cn --arg id "$daemon_id" --argjson events "$event_count" '{daemon_id:$id,stdout:true,stderr:true,events:($events>0),health_unhealthy:true,oom:true,daemon_restart:true,socket_denial:true,daemon_death_cleanup:true,host_mount_isolation:true,egress_isolation:true}')"
}

( set -e; docker_boundary_main )
