#!/usr/bin/env bash
# Opt-in destructive-to-owned-resources validation. All three references must
# already exist locally; this script never pulls and never addresses foreign IDs.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
[[ $# -eq 3 ]] || { echo "usage: $0 CANDIDATE_IMAGE ORACLE_IMAGE TOXIPROXY_IMAGE" >&2; exit 2; }
runs="$(mktemp -d "${TMPDIR:-/tmp}/cortex-isolated-live.XXXXXX")"
cleanup() {
  "$root/tests/live/runner.sh" --janitor --runs-root "$runs" --provider "docker-host:$(docker info --format '{{.ID}}')" >/dev/null 2>&1 || true
}
trap cleanup HUP INT TERM EXIT

# Two simultaneous starts prove run/project/token/port separation and exact teardown.
for n in 1 2; do "$root/tests/live/runner.sh" --profile isolated --runs-root "$runs" \
  --candidate-image "$1" --oracle-image "$2" --toxiproxy-image "$3" >"$runs/parallel-$n.log" 2>&1 & pids[n]=$!; done
for n in 1 2; do status=0; wait "${pids[$n]}" || status=$?; [[ "$status" -ne 0 ]]; done
topology=()
while IFS= read -r path; do topology+=("$path"); done < <(find "$runs" -name topology.json -type f | sort)
[[ ${#topology[@]} -eq 2 ]]
[[ "$(jq -r .http "${topology[0]}")" != "$(jq -r .http "${topology[1]}")" ]]
for topology_path in "${topology[@]}"; do jq -e '.qualified>0 and .failed==0' "$(dirname "$topology_path")/summary.json" >/dev/null; done

# A missing immutable dependency is a partial-provision failure and must leave no residue.
if "$root/tests/live/runner.sh" --profile isolated --runs-root "$runs" --candidate-image "$1" \
  --oracle-image cortex-live-does-not-exist --toxiproxy-image "$3" >/dev/null 2>&1; then exit 1; fi

# A provider port collision must fail closed and clean the partial project.
collision_id="$(docker run -d --name "cortex-live-port-collision-$$" -e ORACLE_TOKEN=collision -p 127.0.0.1:38399:8080 "$2")"
collision_marker="$(mktemp "$runs/collision-marker.XXXXXX")"
if LIVE_HTTP_PUBLISHED=38399 "$root/tests/live/runner.sh" --profile isolated --runs-root "$runs" \
  --candidate-image "$1" --oracle-image "$2" --toxiproxy-image "$3" >/dev/null 2>&1; then docker rm -f "$collision_id" >/dev/null; exit 1; fi
docker rm -f "$collision_id" >/dev/null
collision_audit="$(find "$runs" -name cleanup-audit.json -type f -newer "$collision_marker" | tail -1)"
[[ -n "$collision_audit" ]]; jq -e '.state=="CLEAN"' "$collision_audit" >/dev/null

# Forced readiness timeout produces one and only one bounded diagnostic snapshot.
timeout_marker="$(mktemp "$runs/timeout-marker.XXXXXX")"
if LIVE_FORCE_READINESS_TIMEOUT=1 LIVE_READINESS_TIMEOUT_SECONDS=3 "$root/tests/live/runner.sh" --profile isolated --runs-root "$runs" \
  --candidate-image "$1" --oracle-image "$2" --toxiproxy-image "$3" >/dev/null 2>&1; then exit 1; fi
timeout_run="$(dirname "$(find "$runs" -name cleanup-audit.json -type f -newer "$timeout_marker" | tail -1)")"
[[ -f "$timeout_run/artifacts/diagnostics.txt" ]]
[[ "$(jq -s '[.[]|select(.kind=="diagnostic")]|length' "$timeout_run/events.jsonl")" -eq 1 ]]
jq -e '.state=="CLEAN"' "$timeout_run/cleanup-audit.json" >/dev/null
cleanup
[[ -z "$(docker ps -aq --filter label=cortex.live.run_id)" ]]
[[ -z "$(docker volume ls -q --filter label=cortex.live.run_id)" ]]
[[ -z "$(docker network ls -q --filter label=cortex.live.run_id)" ]]

# TERM during a live hold must execute the runner's exact-ID cleanup trap.
term_marker="$(mktemp "$runs/term-marker.XXXXXX")"
LIVE_ISOLATED_HOLD_SECONDS=120 "$root/tests/live/runner.sh" --profile isolated --runs-root "$runs" \
  --candidate-image "$1" --oracle-image "$2" --toxiproxy-image "$3" >"$runs/term.log" 2>&1 & term_pid=$!
ready=""
for _ in $(seq 1 180); do
  ready="$(find "$runs" -name poll-history.jsonl -type f -newer "$term_marker" -exec grep -l '"description":"ingest-roundtrip".*"result":"ready"' {} \; | tail -1)"
  [[ -n "$ready" ]] && break
  sleep .25
done
[[ -n "$ready" ]]
term_run="$(dirname "$(dirname "$ready")")"; term_project="$(basename "$term_run")"
# Replace the dependency proxy, rediscover provider ports, restore only the
# run-owned proxy definitions, and prove the candidate is reachable again.
secrets="$term_run/secrets.values"
LIVE_CORTEX_TOKEN="$(sed -n '1p' "$secrets")"; LIVE_API_TOKEN="$(sed -n '2p' "$secrets")"
LIVE_ADMIN_TOKEN="$(sed -n '3p' "$secrets")"; LIVE_ORACLE_TOKEN="$(sed -n '4p' "$secrets")"
LIVE_CANDIDATE_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$term_project-candidate-1")"
LIVE_ORACLE_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$term_project-oracle-1")"
LIVE_TOXIPROXY_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$term_project-toxiproxy-1")"
export LIVE_COMPOSE_PROJECT="$term_project" LIVE_RUN_ID="$term_project" LIVE_CORTEX_TOKEN LIVE_API_TOKEN LIVE_ADMIN_TOKEN LIVE_ORACLE_TOKEN LIVE_CANDIDATE_IMAGE LIVE_ORACLE_IMAGE LIVE_TOXIPROXY_IMAGE
old_proxy_id="$(docker ps -q --filter "label=com.docker.compose.project=$term_project" --filter label=com.docker.compose.service=toxiproxy)"
docker compose -f "$root/tests/live/profiles/isolated/compose.yaml" -p "$term_project" up -d --no-deps --force-recreate toxiproxy >/dev/null
new_proxy_id="$(docker ps -q --filter "label=com.docker.compose.project=$term_project" --filter label=com.docker.compose.service=toxiproxy)"
[[ -n "$new_proxy_id" && "$new_proxy_id" != "$old_proxy_id" ]]
api_port="$(docker inspect "$new_proxy_id" | jq -r '.[0].NetworkSettings.Ports["8474/tcp"][0].HostPort')"
http_port="$(docker inspect "$new_proxy_id" | jq -r '.[0].NetworkSettings.Ports["13100/tcp"][0].HostPort')"
for _ in $(seq 1 80); do curl -fsS --max-time 1 "http://127.0.0.1:$api_port/version" >/dev/null 2>&1 && break; sleep .25; done
for spec in 'http 0.0.0.0:13100 candidate:3100' 'syslog-tcp 0.0.0.0:11514 candidate:1514' 'oracle 0.0.0.0:18080 oracle:8080'; do
  read -r proxy_name proxy_listen proxy_upstream <<<"$spec"
  curl -fsS -H 'Content-Type: application/json' -d "$(jq -cn --arg name "$term_project-$proxy_name" --arg listen "$proxy_listen" --arg upstream "$proxy_upstream" '{name:$name,listen:$listen,upstream:$upstream,enabled:true}')" "http://127.0.0.1:$api_port/proxies" >/dev/null
done
curl -fsS -H 'Host: localhost' "http://127.0.0.1:$http_port/health" >/dev/null
kill -TERM "$term_pid"; term_status=0; wait "$term_pid" || term_status=$?
[[ "$term_status" -ne 0 ]]
jq -e '.state=="CLEAN"' "$term_run/cleanup-audit.json" >/dev/null
bash "$root/tests/live/lib/docker.sh" verify "$term_project" "$term_project" "docker-host:$(docker info --format '{{.ID}}')"
trap - HUP INT TERM EXIT
rm -rf "$runs"
echo "isolated live fault selftest: PASS"
