#!/usr/bin/env bash
set -euo pipefail

# Every Compose project is run-owned and cleanup-registered. Keep all lifecycle
# operations non-interactive so unattended qualification can never block on a
# provider reconciliation prompt.
export COMPOSE_ASSUME_YES=true COMPOSE_MENU=false
LIVE_PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; export LIVE_PROJECT_ROOT
# shellcheck disable=SC1090
for lib in common lock redact events command lease resources report artifacts contracts budgets wait diagnostics docker platform; do source "$LIVE_PROJECT_ROOT/tests/live/lib/$lib.sh"; done
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/ingest/run.sh"
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/agent/run.sh"
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/mcp/run.sh"
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/auth/run.sh"
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/stateful/run.sh"
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/artifacts/run.sh"
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/notifications/run.sh"
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/incidents/run.sh"
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/security/run.sh"
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/upgrade/run.sh"

usage() { echo "usage: tests/live/runner.sh [--profile noop|smoke|full|storage|soak|isolated|agent|legacy-central-pull|mcp|auth|stateful|artifacts|notifications|security|upgrade|compose-isolated|fleet-read-only|fleet-mutating|docker-boundary-reduced|docker-boundary-full] [--platform-policy portable|linux-full] [--candidate-image IMAGE --oracle-image IMAGE --toxiproxy-image IMAGE] [--runs-root DIR] [--janitor] [--provider ID] [--target ID] [--legacy ARGS...]"; }
profile=smoke; boundary_status=0; runs_root="${TMPDIR:-/tmp}/cortex-live-runs"; janitor=false; provider="local:$LIVE_PROJECT_ROOT"; target="local"; legacy=false; legacy_args=(); legacy_runner="${LIVE_LEGACY_RUNNER:-$LIVE_PROJECT_ROOT/tests/test_live.sh}"; candidate_image="${LIVE_CANDIDATE_IMAGE_REF:-}"; oracle_image="${LIVE_ORACLE_IMAGE_REF:-}"; toxiproxy_image="${LIVE_TOXIPROXY_IMAGE_REF:-}"
while (($#)); do case "$1" in --profile) profile="$2"; shift 2;; --platform-policy) LIVE_PLATFORM_POLICY="$2"; export LIVE_PLATFORM_POLICY; shift 2;; --candidate-image) candidate_image="$2"; shift 2;; --oracle-image) oracle_image="$2"; shift 2;; --toxiproxy-image) toxiproxy_image="$2"; shift 2;; --runs-root) runs_root="$2"; shift 2;; --provider) provider="$2"; shift 2;; --target) target="$2"; shift 2;; --janitor) janitor=true; shift;; --legacy) legacy=true; shift; legacy_args=("$@"); break;; -h|--help) usage; exit;; *) usage >&2; exit 2;; esac; done
LIVE_PROFILE="$profile"; export LIVE_PROFILE
live_require_tools bash jq openssl cargo shasum ps pgrep find stat sed awk || live_die "live harness prerequisites unavailable"
jq -e --arg p "$profile" '.profiles[$p]' "$LIVE_PROJECT_ROOT/tests/live/contracts/profiles.json" >/dev/null || live_die "unknown profile: $profile"
if $janitor; then live_janitor "$runs_root" "$provider"; exit; fi
live_platform_init
if [[ -n "${LIVE_RUN_ROOT:-}" ]]; then
  live_validate_run_id "${LIVE_RUN_ID:?}" || live_die "invalid pre-created run id"
  [[ "$LIVE_RUN_ROOT" == "$runs_root/$LIVE_RUN_ID" && -d "$LIVE_RUN_ROOT" && ! -L "$LIVE_RUN_ROOT" ]] || live_die "unsafe pre-created run root"
else
  live_init_run "$runs_root" "${LIVE_RUN_ID_OVERRIDE:-}" >/dev/null
fi
live_runner_cleanup() {
  local status=$? cleanup_provider="${LIVE_RESOURCE_PROVIDER:-$provider}" resource_file="$LIVE_RUN_ROOT/resources.jsonl"
  trap - HUP INT TERM EXIT
  live_lease_heartbeat_stop
  if [[ -f "$resource_file" ]] && jq -e -s 'length>0 and ([.[].provider]|unique|length)==1' "$resource_file" >/dev/null 2>&1; then
    cleanup_provider="$(jq -sr '.[0].provider' "$resource_file")"
  fi
  if [[ "$cleanup_provider" == docker-host:* ]]; then
    current_docker_id="$(docker info --format '{{.ID}}' 2>/dev/null || true)"
    [[ "docker-host:$current_docker_id" == "$cleanup_provider" ]] || cleanup_provider="docker-host:identity-mismatch"
  fi
  live_cleanup_resources "$cleanup_provider" >/dev/null 2>&1 || status=$?
  exit "$status"
}
trap live_runner_cleanup HUP INT TERM EXIT
live_contract_export "$LIVE_RUN_ROOT/surface-contract.json"
live_run_manifest_write "$profile" "$provider" "$target" "$LIVE_SURFACE_CONTRACT"
live_budget_start
live_lease_write 180
live_lease_heartbeat_start 180 30
live_event run_started "$(jq -cn --arg profile "$profile" '{profile:$profile}')"
case "$profile" in
  smoke)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "smoke profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    live_ingest_matrix_run
    source "$LIVE_PROJECT_ROOT/tests/live/phases/surfaces/run.sh"
    ;;
  full)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "full profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    live_ingest_matrix_run
    source "$LIVE_PROJECT_ROOT/tests/live/phases/surfaces/run.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/retention.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/db-size.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/cleanup-faults.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/run.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/lifecycle/run.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/pressure.sh"
    ;;
  compose-isolated)
    source "$LIVE_PROJECT_ROOT/tests/live/phases/compose/run.sh"
    ;;
  fleet-read-only)
    [[ -n "${LIVE_TARGET_MANIFEST:-}" && -n "${LIVE_FLEET_READ_TOKEN:-}" && -n "${LIVE_FLEET_ADMIN_TOKEN:-}" ]] || live_die "fleet-read-only requires target manifest and read/admin role tokens"
    source "$LIVE_PROJECT_ROOT/tests/live/profiles/fleet/target.sh"
    fleet_target_validate "$LIVE_TARGET_MANIFEST"
    fleet_roles_assert "$LIVE_TARGET_MANIFEST" "$LIVE_FLEET_READ_TOKEN" "$LIVE_FLEET_ADMIN_TOKEN"
    fleet_target_snapshot "$LIVE_TARGET_MANIFEST" "$LIVE_FLEET_READ_TOKEN" "$LIVE_RUN_ROOT/fleet-pre.json" pre
    fleet_target_snapshot "$LIVE_TARGET_MANIFEST" "$LIVE_FLEET_READ_TOKEN" "$LIVE_RUN_ROOT/fleet-admin.json" admin-role-observed
    fleet_target_snapshot "$LIVE_TARGET_MANIFEST" "$LIVE_FLEET_READ_TOKEN" "$LIVE_RUN_ROOT/fleet-post.json" post
    fleet_snapshot_assert_allowed_diff "$LIVE_RUN_ROOT/fleet-pre.json" "$LIVE_RUN_ROOT/fleet-post.json"
    live_terminal_disposition fleet-read-only pass fleet-post.json
    live_event fleet_target_verified "$(jq -c '{target_id,profile,server_instance_id,deployment_id,database_fingerprint,compose}' "$LIVE_TARGET_MANIFEST")"
    ;;
  fleet-mutating)
    [[ -n "${LIVE_TARGET_MANIFEST:-}" && -d "${LIVE_MUTATION_GRANTS_DIR:-}" && -n "${LIVE_MUTATION_GRANT_KEY:-}" ]] || live_die "fleet-mutating requires explicit target and per-operation grants directory"
    source "$LIVE_PROJECT_ROOT/tests/live/profiles/fleet/target.sh"; source "$LIVE_PROJECT_ROOT/tests/live/profiles/fleet/grant.sh"; source "$LIVE_PROJECT_ROOT/tests/live/profiles/fleet/mutations.sh"
    fleet_target_snapshot "$LIVE_TARGET_MANIFEST" "${LIVE_FLEET_READ_TOKEN:?}" "$LIVE_RUN_ROOT/fleet-pre.json" pre
    "$LIVE_PROJECT_ROOT/tests/live/profiles/fleet/run-mutations.sh"
    fleet_target_snapshot "$LIVE_TARGET_MANIFEST" "$LIVE_FLEET_READ_TOKEN" "$LIVE_RUN_ROOT/fleet-post.json" post
    fleet_snapshot_assert_allowed_diff "$LIVE_RUN_ROOT/fleet-pre.json" "$LIVE_RUN_ROOT/fleet-post.json"
    live_terminal_disposition fleet-mutating pass fleet-residual.json
    ;;
  storage)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "storage profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/retention.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/db-size.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/cleanup-faults.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/run.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/lifecycle/run.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/storage/pressure.sh"
    ;;
  isolated)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "isolated profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    live_ingest_matrix_run
    if [[ "${LIVE_ISOLATED_HOLD_SECONDS:-0}" =~ ^[1-9][0-9]*$ ]]; then
      hold_until=$(( $(date +%s) + LIVE_ISOLATED_HOLD_SECONDS ))
      while (( $(date +%s) < hold_until )); do sleep 1; done
    fi
    ;;
  mcp)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "mcp profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    [[ "${LIVE_MCP_SKIP_INGEST:-false}" == true ]] || live_ingest_matrix_run
    mcp_read_scope_precheck
    LIVE_MCP_FILETAIL_ROOT="$LIVE_RUN_ROOT/mcp-filetail"; export LIVE_MCP_FILETAIL_ROOT; mkdir -p "$LIVE_MCP_FILETAIL_ROOT"; chmod 0777 "$LIVE_MCP_FILETAIL_ROOT"
    docker compose -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp/compose.yaml" -p "$LIVE_COMPOSE_PROJECT" up -d --no-build --force-recreate candidate
    live_wait_until 30 mcp-admin-health _live_http_health_ready
    live_wait_until 30 mcp-admin-ready _live_mcp_ready
    mcp_phase_run
    ;;
  auth)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "auth profile requires three explicit image references"
    cargo build --quiet --manifest-path "$LIVE_PROJECT_ROOT/tests/live/services/oauth/Cargo.toml"
    LIVE_OAUTH_FIXTURE_BIN="$(cargo metadata --no-deps --format-version 1 --manifest-path "$LIVE_PROJECT_ROOT/tests/live/services/oauth/Cargo.toml" | jq -r .target_directory)/debug/cortex-live-oauth"; export LIVE_OAUTH_FIXTURE_BIN
    [[ -x "$LIVE_OAUTH_FIXTURE_BIN" ]] || live_die "OAuth fixture build did not produce executable"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    auth_phase_run
    ;;
  stateful)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "stateful profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    LIVE_MCP_FILETAIL_ROOT="$LIVE_RUN_ROOT/stateful-filetail"; export LIVE_MCP_FILETAIL_ROOT; mkdir -p "$LIVE_MCP_FILETAIL_ROOT"; chmod 0777 "$LIVE_MCP_FILETAIL_ROOT"
    mkdir -p "$LIVE_RUN_ROOT/artifacts/stateful"
    docker exec "$(live_ingest_candidate_id)" cortex graph status --json >"$LIVE_RUN_ROOT/artifacts/stateful/projection-disabled.json"
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$(live_ingest_candidate_id)" | grep -E '^CORTEX_(INVENTORY_GRAPH_PROJECTION_ENABLED|GRAPH_REFRESH_INTERVAL_SECS)=' >"$LIVE_RUN_ROOT/artifacts/stateful/projection-disabled-env.txt" || true
    ! grep -q '^CORTEX_INVENTORY_GRAPH_PROJECTION_ENABLED=true$' "$LIVE_RUN_ROOT/artifacts/stateful/projection-disabled-env.txt"
    jq -e '.projection_status=="never_built" and .source_watermark==""' "$LIVE_RUN_ROOT/artifacts/stateful/projection-disabled.json" >/dev/null
    docker compose -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/stateful/compose.yaml" -p "$LIVE_COMPOSE_PROJECT" up -d --no-build --force-recreate candidate
    live_wait_until 30 stateful-health _live_http_health_ready
    live_wait_until 30 stateful-mcp _live_mcp_ready
    LIVE_MCP_SEMANTIC_SWEEP_ONLY=true stateful_phase_run
    ;;
  artifacts)
    [[ -n "${LIVE_ARTIFACT_MANIFEST:-}" ]] || live_die "artifacts profile requires LIVE_ARTIFACT_MANIFEST"
    artifact_qualify_manifest "$LIVE_ARTIFACT_MANIFEST"
    ;;
  notifications)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "notifications profile requires three explicit image references"
    LIVE_APPRISE_CONTROL_TOKEN="$(openssl rand -hex 24)"; export LIVE_APPRISE_CONTROL_TOKEN
    live_register_secret "$LIVE_APPRISE_CONTROL_TOKEN"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/notifications/compose.yaml" up -d --no-build --force-recreate apprise candidate
    live_wait_until 30 notifications-health _live_http_health_ready
    live_wait_until 30 notifications-mcp _live_mcp_ready
    notification_phase_run
    incident_phase_run
    ;;
  mutation)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "mutation profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    "$LIVE_PROJECT_ROOT/tests/live/phases/mutation/selftest.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/concurrency/run.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/concurrency/live.sh"
    live_terminal_disposition mutation pass artifacts/concurrency-live/accounting.json
    ;;
  soak)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "soak profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    "$LIVE_PROJECT_ROOT/tests/live/phases/concurrency/run.sh"
    "$LIVE_PROJECT_ROOT/tests/live/phases/concurrency/live.sh"
    LIVE_SOAK_CONTAINER="$(live_ingest_candidate_id)"; export LIVE_SOAK_CONTAINER
    "$LIVE_PROJECT_ROOT/tests/live/profiles/soak/run.sh"
    live_terminal_disposition soak pass artifacts/soak/analysis.json
    ;;
  security)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "security profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    LIVE_MCP_FILETAIL_ROOT="$LIVE_RUN_ROOT/security-tail"; export LIVE_MCP_FILETAIL_ROOT; mkdir -p "$LIVE_MCP_FILETAIL_ROOT"; chmod 0777 "$LIVE_MCP_FILETAIL_ROOT"
    docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/security/compose.yaml" up -d --no-build --force-recreate candidate security-probe
    live_wait_until 30 security-health _live_http_health_ready
    live_wait_until 30 security-mcp _live_mcp_ready
    security_phase_run
    ;;
  upgrade)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "upgrade profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    LIVE_MCP_FILETAIL_ROOT="$LIVE_RUN_ROOT/upgrade-tail"; export LIVE_MCP_FILETAIL_ROOT; mkdir -p "$LIVE_MCP_FILETAIL_ROOT"; chmod 0777 "$LIVE_MCP_FILETAIL_ROOT"
    docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp/compose.yaml" up -d --no-build --force-recreate candidate
    live_wait_until 30 upgrade-initial-health _live_http_health_ready
    live_wait_until 30 upgrade-initial-mcp _live_mcp_ready
    upgrade_phase_run
    ;;
  agent)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "agent profile requires three explicit image references"
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" \
      -f "$LIVE_PROJECT_ROOT/tests/live/profiles/agent/compose.override.yaml" up -d --no-build --force-recreate candidate
    live_wait_until 30 agent-candidate-health _live_http_health_ready
    live_wait_until 30 agent-candidate-mcp _live_mcp_ready
    live_agent_provision_portable
    live_agent_register_boundary_resources
    export CORTEX_LIVE_DOCKER_FIXTURE_ID="${CORTEX_LIVE_DOCKER_FIXTURE_ID:-${LIVE_AGENT_FIXTURE_ID:-}}"
    export CORTEX_LIVE_DOCKER_EXPECT_STDOUT="${CORTEX_LIVE_DOCKER_EXPECT_STDOUT:-${LIVE_AGENT_EXPECT_STDOUT:-}}"
    export CORTEX_LIVE_DOCKER_EXPECT_STDERR="${CORTEX_LIVE_DOCKER_EXPECT_STDERR:-${LIVE_AGENT_EXPECT_STDERR:-}}"
    export CORTEX_LIVE_DOCKER_EXPECT_HEALTH="${CORTEX_LIVE_DOCKER_EXPECT_HEALTH:-${LIVE_AGENT_EXPECT_HEALTH:-}}"
    export LIVE_AGENT_DOCKER_URL="${LIVE_AGENT_DOCKER_URL:-${CORTEX_LIVE_DOCKER_PROXY_URL:-}}"
    set +e
    CORTEX_LIVE_DOCKER_BOUNDARY_MODE="${LIVE_AGENT_BOUNDARY_MODE:-reduced}" source "$LIVE_PROJECT_ROOT/tests/live/spikes/docker-boundary/scenario.sh"
    boundary_status=$?; set -e
    (( boundary_status == 0 )) || live_die "agent profile Docker boundary did not pass"
    live_terminal_disposition topology.docker-agent-boundary pass artifacts/docker-boundary.json
    live_agent_run
    ;;
  legacy-central-pull)
    [[ -n "$candidate_image" && -n "$oracle_image" && -n "$toxiproxy_image" ]] || live_die "legacy-central-pull profile requires three explicit image references"
    jq -e '.schema=="cortex-live-legacy-central-pull-v1" and .compatibility_only and .mandatory_case=="legacy-docker.live"' "$LIVE_PROJECT_ROOT/tests/live/contracts/legacy-central-pull.json" >/dev/null
    live_topology_start "$candidate_image" "$oracle_image" "$toxiproxy_image"
    live_ingest_legacy_docker
    ;;
  docker-boundary-reduced)
    set +e
    # shellcheck disable=SC1091
    CORTEX_LIVE_DOCKER_BOUNDARY_MODE=reduced source "$LIVE_PROJECT_ROOT/tests/live/spikes/docker-boundary/scenario.sh"
    boundary_status=$?; set -e
    ;;
  docker-boundary-full)
    set +e
    # shellcheck disable=SC1091
    CORTEX_LIVE_DOCKER_BOUNDARY_MODE=full source "$LIVE_PROJECT_ROOT/tests/live/spikes/docker-boundary/scenario.sh"
    boundary_status=$?; set -e
    ;;
esac
if [[ "$profile" == storage || "$profile" == full ]]; then
  obligation="$LIVE_RUN_ROOT/artifacts/storage/otlp-storage-blocked.json"
  pressure="$LIVE_RUN_ROOT/artifacts/storage/pressure.json"
  disposition="$(jq -r '.disposition // empty' "$pressure")"
  if [[ "$disposition" == pass ]]; then
    [[ -f "$obligation" ]] || live_die "$profile profile lacks mandatory otlp-storage-blocked evidence"
    jq -e '.case=="otlp-storage-blocked" and .write_blocked and .logs.exact_count_after_recovery==1 and .metrics.blocked_status==503 and .traces.rejected_spans==1' "$obligation" >/dev/null || live_die "invalid otlp-storage-blocked evidence"
    [[ "$(jq -r 'select(.kind=="ingest_case" and .payload.case=="otlp-storage-blocked" and .payload.result=="pass" and .payload.cross_bead_required==true)|1' "$LIVE_RUN_ROOT/events.jsonl" | wc -l | tr -d ' ')" == 1 ]] || live_die "$profile profile did not reconcile otlp-storage-blocked exactly once"
  elif [[ "$disposition" == platform-qualified || "$disposition" == not-authorized ]]; then
    [[ ! -e "$obligation" ]] || live_die "$profile profile emitted OTLP pressure evidence without executing the pressure capability"
  else
    live_die "$profile profile has invalid storage pressure disposition: ${disposition:-missing}"
  fi
fi
if [[ "$profile" == docker-boundary-* || "$profile" == agent ]]; then
  boundary_evidence="$LIVE_RUN_ROOT/artifacts/docker-boundary.json"
  if [[ ! -f "$boundary_evidence" ]] || ! jq -e '.schema=="cortex-live-docker-boundary-result-v1" and .disposition=="pass"' "$boundary_evidence" >/dev/null; then boundary_status=1; fi
fi
if $legacy; then
  live_run_bounded "$(jq -r --arg p "$profile" '.profiles[$p].wall_seconds' "$LIVE_PROJECT_ROOT/tests/live/contracts/profiles.json")" \
    "$LIVE_RUN_ROOT/artifacts/legacy.stdout" "$LIVE_RUN_ROOT/artifacts/legacy.stderr" "$legacy_runner" "${legacy_args[@]}" && result=pass || result=fail
  live_event legacy_result "$(jq -cn --arg result "$result" --arg stdout artifacts/legacy.stdout --arg stderr artifacts/legacy.stderr '{schema:"cortex-live-legacy-result-v1",isolated_from_capability_ledger:true,result:$result,stdout:$stdout,stderr:$stderr}')"
fi
live_budget_check "$profile" "$LIVE_PROJECT_ROOT/tests/live/contracts/profiles.json"
live_platform_coverage_write "$profile"
live_report
live_secret_scan "$LIVE_RUN_ROOT"
live_run_manifest_verify
live_ledger_validate "$LIVE_SURFACE_CONTRACT" "$profile"
live_summary_accepts_profile "$profile" "$LIVE_PROJECT_ROOT/tests/live/contracts/profiles.json" "$LIVE_RUN_ROOT/summary.json" || live_die "mandatory profile failed or produced a qualified/non-green outcome"
(( boundary_status == 0 )) || live_die "mandatory Docker boundary scenario did not pass"
