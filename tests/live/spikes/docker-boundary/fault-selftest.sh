#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"; export LIVE_PROJECT_ROOT="$root"
# shellcheck disable=SC1090
for lib in common lock redact events command lease resources; do source "$root/tests/live/lib/$lib.sh"; done
docker image inspect hello-world:latest >/dev/null 2>&1 || { echo 'docker boundary fault selftest: SKIP (fixture image absent)'; exit 0; }
tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-docker-fault.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
live_init_run "$tmp/runs" >/dev/null
daemon="$(docker info --format '{{.ID}}')"; provider="docker-host:$daemon"; project="cortex-fault-${LIVE_RUN_ID#cortex-e2e-}"
register_intent() { live_resource_transition "$1" "$2" PLANNED "$provider" '' '[]'; live_resource_transition "$1" "$2" CREATING "$provider" "$3" '[]' "$4" '{}' '[]'; }
register_exact() {
  local cleanup verify
  cleanup="$(jq -cn --arg script "$here/cleanup-host-resource.sh" --arg daemon "$daemon" --arg kind "$2" --arg id "$3" '["bash",$script,$daemon,$kind,$id]')"
  verify="$(jq -cn --arg script "$here/verify-host-resource.sh" --arg daemon "$daemon" --arg kind "$2" --arg id "$3" '["bash",$script,$daemon,$kind,$id]')"
  live_resource_transition "$1" "$2" IDENTIFIED "$provider" "$3" "$cleanup" "$4" '{}' "$verify"
  live_resource_transition "$1" "$2" CREATED "$provider" "$3" "$cleanup" "$4" '{}' "$verify"
}
register_intent fault-network network "$project-fault-network" fault-network-request
register_intent fault-volume volume "$project-fault-volume" fault-volume-request
register_intent fault-daemon container "$project-fault-daemon" fault-daemon-request
register_intent fault-proxy container "$project-fault-proxy" fault-proxy-request
network="$(docker network create --label "cortex.live.run_id=$LIVE_RUN_ID" --label "com.docker.compose.project=$project" "$project-network")"
volume="$(docker volume create --label "cortex.live.run_id=$LIVE_RUN_ID" --label "com.docker.compose.project=$project" "$project-volume")"
container="$(docker create --network "$network" --label "cortex.live.run_id=$LIVE_RUN_ID" --label "com.docker.compose.project=$project" --label com.docker.compose.service=daemon hello-world:latest)"
register_exact fault-network network "$network" network-id
register_exact fault-volume volume "$volume" volume-id
register_exact fault-daemon container "$container" container-id
# Proxy creation fails: its unresolved CREATING intent forces manual reconciliation,
# while every exact resource that did exist is still removed and independently checked.
set +e; live_cleanup_resources "$provider" 20 >/dev/null 2>&1; status=$?; set -e
[[ "$status" == 2 ]] || exit 1
[[ -f "$LIVE_RUN_ROOT/cleanup-audit.json" ]] || exit 1
[[ "$(jq -r .state "$LIVE_RUN_ROOT/cleanup-audit.json")" == MANUAL_RECONCILIATION_REQUIRED ]] || exit 1
if docker container inspect "$container" >/dev/null 2>&1; then exit 1; fi
if docker network inspect "$network" >/dev/null 2>&1; then exit 1; fi
if docker volume inspect "$volume" >/dev/null 2>&1; then exit 1; fi
printf 'docker boundary fault selftest: PASS\n'
