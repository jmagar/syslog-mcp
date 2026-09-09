#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
contract="$here/../../contracts/docker-platforms.json"
decision="$here/decision.json"
compose="$here/../../services/docker-read-proxy/compose.yaml"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-docker-boundary.XXXXXX")"
server_pid=""
cleanup() { [[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM HUP

jq -e '
  .profiles["linux-dind"].certification == "full" and
  .profiles["desktop-proxy"].disposition == "platform-qualified" and
  .cleanup.labels_are_evidence_not_authority == true and
  (.probe.denied_paths | length >= 7)
' "$contract" >/dev/null
jq -e '.linux_dind.host_socket == false and .desktop_proxy.disposition == "platform-qualified" and (.fail_closed|index("identity-change"))' "$decision" >/dev/null

if rg -n '/var/run/docker.sock:/var/run/docker.sock|/run/docker.sock:/var/run/docker.sock' "$compose" >/dev/null; then exit 1; fi
rg -n 'dind-socket:/var/run:ro' "$compose" >/dev/null
rg -n 'internal: true' "$compose" >/dev/null
daemon_ports="$(docker compose -f "$compose" config --format json | jq -c '.services.daemon.ports // []')"
[[ "$daemon_ports" == '[]' ]]
docker compose -f "$compose" config --format json | jq -e '.services.daemon.expose == ["2375"] and (.services.proxy.ports|length)==1' >/dev/null

set +e
env -u CORTEX_LIVE_DOCKER_PROXY_URL bash "$here/probe.sh" "$tmp/missing.json"
status=$?
set -e
[[ "$status" == 3 ]]
jq -e '.disposition == "not-authorized" and .authority == "none"' "$tmp/missing.json" >/dev/null

CORTEX_LIVE_DOCKER_PROXY_URL=http://127.0.0.1:9 bash "$here/probe.sh" "$tmp/dead.json" && exit 1 || status=$?
[[ "$status" == 4 ]]
jq -e '.disposition == "platform-qualified" and .authority == "unreachable"' "$tmp/dead.json" >/dev/null

python3 "$here/mock_server.py" >"$tmp/server.out" 2>"$tmp/server.err" &
server_pid=$!
for _ in 1 2 3 4 5; do
  port="$(lsof -nP -a -p "$server_pid" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR==2{sub(/.*:/,"",$9);print $9}' || true)"
  [[ -n "$port" ]] && break
  sleep 0.1
done
[[ -n "${port:-}" ]]
status=0
CORTEX_LIVE_DOCKER_PROXY_URL="http://127.0.0.1:$port" bash "$here/probe.sh" "$tmp/pass.json" || status=$?
[[ "$status" == 0 ]]
jq -e '.disposition == "platform-qualified" and .authority == "proxy-read-only:mock-daemon"' "$tmp/pass.json" >/dev/null
# A connected proxy outage is observable and recovery on the same endpoint is requalified.
kill "$server_pid"; wait "$server_pid" 2>/dev/null || true; server_pid=""
CORTEX_LIVE_DOCKER_PROXY_URL="http://127.0.0.1:$port" bash "$here/probe.sh" "$tmp/outage.json" && exit 1 || status=$?
[[ "$status" == 4 ]]
python3 "$here/mock_server.py" "$port" >"$tmp/restarted.out" 2>"$tmp/restarted.err" & server_pid=$!
for _ in 1 2 3 4 5; do curl -fsS --max-time 1 "http://127.0.0.1:$port/_ping" >/dev/null 2>&1 && break; sleep 0.1; done
CORTEX_LIVE_DOCKER_PROXY_URL="http://127.0.0.1:$port" bash "$here/probe.sh" "$tmp/recovered.json"
jq -e '.authority == "proxy-read-only:mock-daemon"' "$tmp/recovered.json" >/dev/null
# Replacement at the same endpoint derives a different identity; callers can never reuse authority.
kill "$server_pid"; wait "$server_pid" 2>/dev/null || true; server_pid=""
python3 "$here/mock_server.py" "$port" replacement-daemon >"$tmp/replaced.out" 2>"$tmp/replaced.err" & server_pid=$!
for _ in 1 2 3 4 5; do curl -fsS --max-time 1 "http://127.0.0.1:$port/_ping" >/dev/null 2>&1 && break; sleep 0.1; done
CORTEX_LIVE_DOCKER_PROXY_URL="http://127.0.0.1:$port" bash "$here/probe.sh" "$tmp/replaced.json"
jq -e '.authority == "proxy-read-only:replacement-daemon"' "$tmp/replaced.json" >/dev/null
[[ "$(jq -r .authority "$tmp/recovered.json")" != "$(jq -r .authority "$tmp/replaced.json")" ]]

# Cleanup independently rechecks live daemon authority before any destructive argv.
fake_bin="$tmp/fake-bin"; mkdir "$fake_bin"; daemon_delete_marker="$tmp/daemon-delete-called"
cat >"$fake_bin/docker" <<'DOCKER'
#!/usr/bin/env bash
if [[ "$1" == info ]]; then printf '%s\n' replacement-daemon; exit 0; fi
touch "${DAEMON_DELETE_MARKER:?}"
DOCKER
chmod +x "$fake_bin/docker"
set +e
PATH="$fake_bin:$PATH" DAEMON_DELETE_MARKER="$daemon_delete_marker" bash "$here/cleanup-host-resource.sh" sealed-daemon container aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null 2>&1
status=$?
set -e
[[ "$status" == 2 && ! -e "$daemon_delete_marker" ]]

# Exercise the foundation's exact-identity cleanup rules used by both profiles.
export LIVE_PROJECT_ROOT="$root"
# shellcheck disable=SC1090
for lib in common lock redact events command lease resources; do source "$root/tests/live/lib/$lib.sh"; done
live_init_run "$tmp/runs" >/dev/null
provider=daemon:fixture-v1
marker="$tmp/owned-container"; touch "$marker"
remove_argv="$(jq -cn --arg path "$marker" '["rm","-f",$path]')"
verify_argv="$(jq -cn --arg path "$marker" '["sh","-c","test ! -e \"$1\"","_",$path]')"
live_resource_transition workload container PLANNED "$provider" '' '[]'
live_resource_transition workload container CREATING "$provider" requested-name '[]' request-digest '{}' '[]'
live_resource_transition workload container IDENTIFIED "$provider" "$marker" "$remove_argv" provider-digest '{}' "$verify_argv"
live_resource_transition workload container CREATED "$provider" "$marker" "$remove_argv" provider-digest '{}' "$verify_argv"
if live_cleanup_resources daemon:fixture-v2 2 >/dev/null 2>&1; then exit 1; fi
[[ -e "$marker" ]]
jq -e '.state == "MANUAL_RECONCILIATION_REQUIRED"' "$LIVE_RUN_ROOT/cleanup-audit.json" >/dev/null
live_cleanup_resources "$provider" 2
[[ ! -e "$marker" ]]

# Daemon death between request and provider identification cannot trigger broad cleanup.
partial_marker="$tmp/partial-never-owned"; touch "$partial_marker"
live_resource_transition partial container PLANNED "$provider" '' '[]'
live_resource_transition partial container CREATING "$provider" requested-partial '[]' partial-digest '{}' '[]'
if live_cleanup_resources "$provider" 2 >/dev/null 2>&1; then exit 1; fi
[[ -e "$partial_marker" ]]
jq -e '.state == "MANUAL_RECONCILIATION_REQUIRED"' "$LIVE_RUN_ROOT/cleanup-audit.json" >/dev/null

# A forged ownership label without valid state history is corruption, never authority.
forged="$tmp/forged-runs"; live_init_run "$forged" >/dev/null
printf '%s\n' '{"run_id":"forged","key":"victim","state":"CREATED","provider":"daemon:fixture-v1","canonical_id":"victim","labels":{"cortex.live.run_id":"forged"}}' >"$(live_resource_file)"
chmod 600 "$(live_resource_file)"
if live_cleanup_resources daemon:fixture-v1 2 >/dev/null 2>&1; then exit 1; fi
jq -e '.state == "MANUAL_RECONCILIATION_REQUIRED"' "$LIVE_RUN_ROOT/cleanup-audit.json" >/dev/null

printf 'docker boundary selftest: PASS\n'
