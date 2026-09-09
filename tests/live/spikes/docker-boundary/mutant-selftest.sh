#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-docker-mutants.XXXXXX")"
server_pid=""
cleanup() { [[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT INT TERM HUP
fixture=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

run_variant() {
  local variant="$1" expected="$2" port status latest
  python3 "$here/mock_server.py" 0 mock-daemon "$variant" >"$tmp/$variant.out" 2>"$tmp/$variant.err" & server_pid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    port="$(lsof -nP -a -p "$server_pid" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR==2{sub(/.*:/,"",$9);print $9}' || true)"
    [[ -n "$port" ]] && break; sleep 0.1
  done
  [[ -n "${port:-}" ]]
  set +e
  CORTEX_LIVE_DOCKER_PROXY_URL="http://127.0.0.1:$port" CORTEX_LIVE_DOCKER_FIXTURE_ID="$fixture" \
    CORTEX_LIVE_DOCKER_EXPECT_STDOUT=cortex-fixture-stdout CORTEX_LIVE_DOCKER_EXPECT_STDERR=cortex-fixture-stderr \
    CORTEX_LIVE_DOCKER_EXPECT_HEALTH=healthy bash "$root/tests/live/runner.sh" --profile docker-boundary-reduced --runs-root "$tmp/runs-$variant" >/dev/null 2>&1
  status=$?
  set -e
  kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; server_pid=""
  latest="$(find "$tmp/runs-$variant" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
  if [[ "$expected" == pass ]]; then
    [[ "$status" == 0 ]]; jq -e '.disposition=="pass"' "$latest/artifacts/docker-boundary.json" >/dev/null
  else
    [[ "$status" != 0 ]]
    if jq -e '.disposition=="pass"' "$latest/artifacts/docker-boundary.json" >/dev/null; then return 1; fi
    if jq -e -n 'any(inputs; .kind=="docker_boundary_result_v1" and .payload.disposition=="pass")' "$latest/events.jsonl" >/dev/null; then return 1; fi
  fi
}

run_variant normal pass
for mutant in missing-stdout missing-stderr events-empty wrong-health identity-drift; do run_variant "$mutant" fail; done
printf 'docker boundary mutant selftest: PASS\n'
