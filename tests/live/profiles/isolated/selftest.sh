#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
compose="$root/tests/live/profiles/isolated/compose.yaml"
contract="$root/tests/live/contracts/topology.json"
profiles="$root/tests/live/contracts/profiles.json"

fail() { printf 'isolated topology selftest: %s\n' "$*" >&2; exit 1; }
for tool in bash jq docker openssl awk; do command -v "$tool" >/dev/null || fail "missing $tool"; done
bash -n "$root/tests/live/lib/docker.sh" "$root/tests/live/lib/platform.sh" "$root/tests/live/lib/wait.sh" "$root/tests/live/lib/diagnostics.sh" "$root/tests/live/runner.sh"
jq -e '.network.workload_internal == true and .network.workload_external_egress == false and .network.redirectors_on_ingress == true and
  (.ports|to_entries|all(.value.host=="provider-assigned-loopback")) and
  (.volumes|keys|sort == ["oracle","pressure","state"]) and
  (.readiness == ["compose-running","health-http","mcp-initialize","ingest-roundtrip"])' "$contract" >/dev/null
jq -e '.profiles.isolated.mandatory == true and .profiles.isolated.wall_seconds <= 900' "$profiles" >/dev/null
! grep -Eq '/var/run/docker.sock|network_mode:[[:space:]]*host|CORTEX_NOTIFICATIONS_URLS:[[:space:]]*\$\{' "$compose" || fail "unsafe host authority or inherited notification URL"
[[ "$(grep -c 'host_ip: 127.0.0.1' "$compose")" -eq 5 ]] || fail "all five ports must be provider assigned on loopback"
[[ "$(grep -c 'published:' "$compose")" -eq 5 ]] || fail "provider-assigned ports must use five disjoint bounded ranges"
grep -q 'NetworkSettings.Ports' "$root/tests/live/lib/docker.sh" || fail "runtime binding discovery must use provider state"
grep -q 'invalid provider port' "$root/tests/live/lib/docker.sh" || fail "missing/null provider bindings must fail closed"
[[ "$(grep -c 'cortex.live.run_id:' "$compose")" -ge 6 ]] || fail "services and resources must carry run ownership"

export LIVE_COMPOSE_PROJECT=cortex-e2e-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa LIVE_RUN_ID=cortex-e2e-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export LIVE_CANDIDATE_IMAGE=sha256:aaaaaaaa LIVE_ORACLE_IMAGE=sha256:bbbbbbbb LIVE_TOXIPROXY_IMAGE=sha256:cccccccc
export LIVE_CORTEX_TOKEN=x LIVE_API_TOKEN=y LIVE_ADMIN_TOKEN=z LIVE_ORACLE_TOKEN=o LIVE_CURSOR_SIGNING_KEY=cursor-signing-test-key
export LIVE_SERVER_INSTANCE_ID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa LIVE_DATABASE_FINGERPRINT=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb LIVE_HTTP_PUBLISHED=127.0.0.1
docker compose -f "$compose" config --quiet

# Parallel identities and tokens are collision resistant without touching Docker state.
# shellcheck disable=SC1091
source "$root/tests/live/lib/common.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/redact.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/events.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/report.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/lock.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/budgets.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/wait.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/docker.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/platform.sh"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-topology-selftest.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
for n in 1 2; do (live_init_run "$tmp" >"$tmp/id$n"; source "$root/tests/live/lib/docker.sh"; live_topology_generate_secrets; printf '%s %s\n' "$LIVE_RUN_ID" "$LIVE_CORTEX_TOKEN" >"$tmp/value$n") & done
wait
[[ "$(cut -d' ' -f1 "$tmp/value1")" != "$(cut -d' ' -f1 "$tmp/value2")" ]] || fail "parallel run ID collision"
[[ "$(cut -d' ' -f2 "$tmp/value1")" != "$(cut -d' ' -f2 "$tmp/value2")" ]] || fail "parallel token collision"

# A permanently failing probe must back off, account every attempt, and remain bounded.
live_init_run "$tmp" >/dev/null; live_budget_start
started="$(date +%s)"; code=0
live_wait_until 3 deliberate-failure false || code=$?
elapsed=$(( $(date +%s) - started ))
[[ "$code" -eq 124 && "$elapsed" -ge 3 && "$elapsed" -le 6 ]] || fail "failed readiness probe was unbounded or busy-looped"
attempts="$(jq -r .poll_attempts "$LIVE_BUDGET_METRICS")"
[[ "$attempts" -ge 3 && "$attempts" -le 8 ]] || fail "poll attempts were not paced/accounted: $attempts"
live_platform_disposition Linux | jq -e '.platform=="Linux" and .disposition=="not-applicable" and (.executable|endswith("scenario.sh"))' >/dev/null
jq -e '.pressure_quota.green_without_verified_quota==false and ((.advanced_readiness.agent_checkpoint|type)=="string")' "$contract" >/dev/null

# Portable qualification accepts only the exact, contract-approved Darwin
# dispositions. Linux full qualification fails closed if a required pass is
# absent; neither path converts missing coverage into a pass.
LIVE_PROJECT_ROOT="$root" LIVE_PLATFORM=darwin LIVE_PLATFORM_POLICY=portable LIVE_PLATFORM_CONTRACT="$root/tests/live/contracts/platform-coverage.json"
export LIVE_PROJECT_ROOT LIVE_PLATFORM LIVE_PLATFORM_POLICY LIVE_PLATFORM_CONTRACT
live_init_run "$tmp" >/dev/null
printf '{}\n' >"$LIVE_RUN_ROOT/portable.json"
for item in 'pressure-quota platform-qualified' 'docker-agent-boundary not-authorized' 'projection_watermark not-applicable' 'evaluator_cycle not-applicable' 'agent_checkpoint not-applicable' 'redirector-egress platform-qualified'; do
  set -- $item
  live_terminal_disposition "topology.$1" "$2" portable.json
done
live_platform_coverage_write isolated
jq -e '.platform=="darwin" and .policy=="portable" and .accepted and .approved_count==6 and .unapproved_count==0' "$LIVE_RUN_ROOT/platform-coverage.json" >/dev/null

LIVE_PLATFORM=linux LIVE_PLATFORM_POLICY=linux-full; export LIVE_PLATFORM LIVE_PLATFORM_POLICY
live_platform_coverage_write isolated
jq -e '.accepted==false and (.missing_required_passes|sort)==["topology.pressure-quota","topology.redirector-egress"]' "$LIVE_RUN_ROOT/platform-coverage.json" >/dev/null
live_init_run "$tmp" >/dev/null; printf '{}\n' >"$LIVE_RUN_ROOT/linux.json"
for capability in pressure-quota docker-agent-boundary redirector-egress; do live_terminal_disposition "topology.$capability" pass linux.json; done
for capability in projection_watermark evaluator_cycle agent_checkpoint; do live_terminal_disposition "topology.$capability" not-applicable linux.json; done
live_platform_coverage_write isolated
jq -e '.accepted and .missing_required_passes==[] and .unapproved_count==0' "$LIVE_RUN_ROOT/platform-coverage.json" >/dev/null
printf 'isolated topology selftest: PASS\n'
