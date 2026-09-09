#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
[[ $# -eq 3 ]] || { echo "usage: $0 CANDIDATE_IMAGE ORACLE_IMAGE TOXIPROXY_IMAGE" >&2; exit 2; }
export LIVE_PROJECT_ROOT="$root"
for lib in common lock redact events command lease resources report artifacts contracts budgets wait diagnostics docker; do
  # shellcheck disable=SC1090
  source "$root/tests/live/lib/$lib.sh"
done
runs="$(mktemp -d "${TMPDIR:-/tmp}/cortex-isolated-persist.XXXXXX")"
live_init_run "$runs" >/dev/null; live_budget_start; provider="$(live_docker_provider)"
trap 'live_cleanup_resources "$provider" >/dev/null 2>&1 || true' HUP INT TERM EXIT
live_topology_start "$1" "$2" "$3"; project="$LIVE_COMPOSE_PROJECT"
seed_marker="live-ready-${LIVE_RUN_ID#cortex-e2e-}"
state_before="$(docker volume ls -q --filter "label=com.docker.compose.project=$project" --filter label=cortex.live.kind=state)"
candidate_before="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=candidate)"
docker compose -f "$root/tests/live/profiles/isolated/compose.yaml" -p "$project" up -d --no-deps --force-recreate candidate >/dev/null
docker restart "$project-oracle-1" >/dev/null
healthy() { [[ "$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$1")" == healthy ]]; }
running() { [[ "$(docker inspect -f '{{.State.Running}}' "$1")" == true ]]; }
live_wait_until 30 candidate-replacement healthy "$project-candidate-1"
live_wait_until 30 oracle-replacement running "$project-oracle-1"
live_wait_until 30 persisted-marker-without-reinjection _live_ingest_ready "$seed_marker"
state_after="$(docker volume ls -q --filter "label=com.docker.compose.project=$project" --filter label=cortex.live.kind=state)"
candidate_after="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=candidate)"
[[ -n "$state_before" && "$state_before" == "$state_after" && "$candidate_before" != "$candidate_after" ]]
live_cleanup_resources "$provider"; trap - HUP INT TERM EXIT
jq -e '.state=="CLEAN"' "$LIVE_RUN_ROOT/cleanup-audit.json" >/dev/null
echo "isolated persistence selftest: PASS"
