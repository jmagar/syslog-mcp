#!/usr/bin/env bash
# =============================================================================
# test-tools.sh — Integration smoke-test for cortex MCP server tools
#
# Exercises broad non-destructive checks for the action-based cortex MCP tool.
# Action inventory reference (not every action is exercised below):
#   cortex search, cortex filter, cortex tail, cortex errors, cortex hosts, cortex map, cortex host_state, cortex fleet_state, cortex correlate_state, cortex sessions,
#   cortex search_sessions, cortex evidence_scope, cortex abuse, cortex ai_correlate, cortex usage_blocks, cortex project_context,
#   cortex list_ai_tools, cortex list_ai_projects, cortex correlate, cortex stats, cortex status, cortex apps,
#   cortex source_ips, cortex timeline, cortex patterns, cortex context,
#   cortex get, cortex ingest_rate, cortex silent_hosts, cortex clock_skew,
#   cortex anomalies, cortex compare, cortex compose_status,
#   cortex compose_doctor, cortex unaddressed_errors, cortex ack_error,
#   cortex unack_error, cortex notifications_recent, cortex file_tails, cortex notifications_test,
#   cortex llm_invocations,
#   cortex similar_incidents, cortex ask_history, cortex incident_context, cortex graph,
#   cortex artifact_evidence, cortex artifact_evidence_record,
#   cortex skill_events, cortex skill_incidents, cortex skill_investigate,
#   cortex mcp_events, cortex mcp_incidents, cortex mcp_investigate,
#   cortex hook_events, cortex hook_incidents, cortex hook_investigate,
#   cortex help
#
# The server runs as a Docker container over HTTP. No stdio launch needed.
# Credentials are sourced from ~/.claude-homelab/.env:
#   CORTEX_HOST  (default: localhost)
#   CORTEX_PORT  (default: 3100)
#   CORTEX_TOKEN (optional; CORTEX_API_TOKEN is accepted as a deprecated alias)
#
# Usage:
#   ./tests/mcporter/test-tools.sh [--timeout-ms N] [--parallel] [--verbose]
#
# Options:
#   --timeout-ms N   Per-call timeout in milliseconds (default: 25000)
#   --parallel       Run independent test groups in parallel (default: off)
#   --verbose        Print raw mcporter output for each call
#
# Exit codes:
#   0 — all tests passed or skipped
#   1 — one or more tests failed
#   2 — prerequisite check failed (mcporter not found, server unreachable)
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
readonly TS_START="$(date +%s%N)"
readonly LOG_FILE="${TMPDIR:-/tmp}/${SCRIPT_NAME%.sh}.$(date +%Y%m%d-%H%M%S).log"
readonly ENV_FILE="${HOME}/.claude-homelab/.env"
readonly AI_SMOKE_FIXTURE="${PROJECT_DIR}/tests/fixtures/ai-session-smoke.jsonl"
readonly AI_SMOKE_PROJECT="/tmp/cortex-ai-smoke"
readonly AI_SMOKE_QUERY='"ai-smoke-authentication"'

# Colours (disabled automatically when stdout is not a terminal)
if [[ -t 1 ]]; then
  C_RESET='\033[0m'
  C_BOLD='\033[1m'
  C_GREEN='\033[0;32m'
  C_RED='\033[0;31m'
  C_YELLOW='\033[0;33m'
  C_CYAN='\033[0;36m'
  C_DIM='\033[2m'
else
  C_RESET='' C_BOLD='' C_GREEN='' C_RED='' C_YELLOW='' C_CYAN='' C_DIM=''
fi

# ---------------------------------------------------------------------------
# Defaults (overridable via flags)
# ---------------------------------------------------------------------------
CALL_TIMEOUT_MS=25000
USE_PARALLEL=false
VERBOSE=false

# ---------------------------------------------------------------------------
# Counters (updated by run_test / skip_test)
# ---------------------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
declare -a FAIL_NAMES=()

# Runtime globals — populated after ENV load
MCP_URL=''
MCPORTER_HEADER_ARGS=()
AI_SEEDED=false

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --timeout-ms)
        CALL_TIMEOUT_MS="${2:?--timeout-ms requires a value}"
        shift 2
        ;;
      --parallel)
        USE_PARALLEL=true
        shift
        ;;
      --verbose)
        VERBOSE=true
        shift
        ;;
      -h|--help)
        printf 'Usage: %s [--timeout-ms N] [--parallel] [--verbose]\n' "${SCRIPT_NAME}"
        exit 0
        ;;
      *)
        printf '[ERROR] Unknown argument: %s\n' "$1" >&2
        exit 2
        ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { printf "${C_CYAN}[INFO]${C_RESET}  %s\n" "$*" | tee -a "${LOG_FILE}"; }
log_warn()  { printf "${C_YELLOW}[WARN]${C_RESET}  %s\n" "$*" | tee -a "${LOG_FILE}"; }
log_error() { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$*" | tee -a "${LOG_FILE}" >&2; }

elapsed_ms() {
  local now
  now="$(date +%s%N)"
  printf '%d' "$(( (now - TS_START) / 1000000 ))"
}

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------
cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    log_warn "Script exited with rc=${rc}. Log: ${LOG_FILE}"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Load environment and build MCP URL + auth headers
# ---------------------------------------------------------------------------
load_env() {
  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "${ENV_FILE}"
    set +a
    log_info "Loaded credentials from ${ENV_FILE}"
  else
    log_warn "${ENV_FILE} not found — using defaults / environment"
  fi

  local host="${CORTEX_HOST:-localhost}"
  # CORTEX_HOST in .env is set to "0.0.0.0" (bind address), not the access address.
  # Remap 0.0.0.0 → localhost for outbound connections.
  if [[ "${host}" == "0.0.0.0" ]]; then
    host="localhost"
  fi
  local port="${CORTEX_PORT:-3100}"
  MCP_URL="http://${host}:${port}/mcp"

  # Auth is enabled by the server only when CORTEX_TOKEN is configured.
  local token="${CORTEX_TOKEN:-${CORTEX_API_TOKEN:-}}"

  MCPORTER_HEADER_ARGS=()
  if [[ -n "${token}" ]]; then
    MCPORTER_HEADER_ARGS+=(--header "Authorization: Bearer ${token}")
  fi

  log_info "MCP URL: ${MCP_URL}"
  if [[ ${#MCPORTER_HEADER_ARGS[@]} -gt 0 ]]; then
    log_info "Auth: Bearer token configured"
  else
    log_info "Auth: none (CORTEX_TOKEN unset)"
  fi
}

run_local_syslog_ai_add() {
  local db_path="$1"
  local fixture="$2"
  if [[ -x "${PROJECT_DIR}/target/debug/syslog" ]]; then
    CORTEX_DB_PATH="${db_path}" "${PROJECT_DIR}/target/debug/syslog" sessions add --file "${fixture}" --json
  else
    (cd "${PROJECT_DIR}" && CORTEX_DB_PATH="${db_path}" cargo run --quiet -- sessions add --file "${fixture}" --json)
  fi
}

seed_ai_fixture() {
  [[ -f "${AI_SMOKE_FIXTURE}" ]] || return 1
  local db_path="${CORTEX_SMOKE_DB_PATH:-${CORTEX_DB_PATH:-${PROJECT_DIR}/data/cortex.db}}"
  run_local_syslog_ai_add "${db_path}" "${AI_SMOKE_FIXTURE}" >/dev/null || return $?
  AI_SEEDED=true
}

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
check_prerequisites() {
  local missing=false

  if ! command -v mcporter &>/dev/null; then
    log_error "mcporter not found in PATH. Install it and re-run."
    missing=true
  fi

  if ! command -v python3 &>/dev/null; then
    log_error "python3 not found in PATH."
    missing=true
  fi

  if ! command -v curl &>/dev/null; then
    log_error "curl not found in PATH."
    missing=true
  fi

  if [[ "${missing}" == true ]]; then
    return 2
  fi
}

# ---------------------------------------------------------------------------
# Server connectivity smoke-test
#   Hits /health (unauthenticated) then verifies MCP tools/list responds.
# ---------------------------------------------------------------------------
smoke_test_server() {
  log_info "Smoke-testing server connectivity..."

  local base_url="${MCP_URL%/mcp}"

  # 1. Health endpoint (no auth required)
  local health_status
  health_status="$(
    curl -sf --max-time 10 "${base_url}/health" 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null
  )" || health_status=''

  if [[ "${health_status}" != "ok" ]]; then
    log_error "Health endpoint at ${base_url}/health did not return status=ok (got: '${health_status}')"
    log_error "Is the cortex container running?  docker ps | grep cortex"
    return 2
  fi
  log_info "Health endpoint OK"

  # 2. tools/list to confirm MCP layer responds
  local tool_count
  tool_count="$(
    curl -sf --max-time 10 \
      -X POST "${MCP_URL}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      ${MCPORTER_HEADER_ARGS[@]+"${MCPORTER_HEADER_ARGS[@]}"} \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' 2>/dev/null | \
    python3 -c "
import sys, json
d = json.load(sys.stdin)
tools = d.get('result', {}).get('tools', [])
print(len(tools))
" 2>/dev/null
  )" || tool_count=0

  if [[ "${tool_count}" -lt 1 ]] 2>/dev/null; then
    log_error "tools/list returned ${tool_count} tools — expected at least 1"
    return 2
  fi

  log_info "Server OK — ${tool_count} tools available"
  return 0
}

# ---------------------------------------------------------------------------
# mcporter call wrapper
#   Usage: mcporter_call <tool_name> <args_json>
# ---------------------------------------------------------------------------
mcporter_call() {
  local tool="${1:?tool required}"
  shift
  local args_json="${1:?args_json required}"
  local action=''

  if [[ "${tool}" == "cortex" && "${args_json}" != \{* ]]; then
    action="${args_json}"
    args_json="${2:?args_json required}"
  else
    case "${tool}" in
      search_logs) action='search' ;;
      tail_logs) action='tail' ;;
      get_errors) action='errors' ;;
      list_hosts) action='hosts' ;;
      correlate_events) action='correlate' ;;
      get_stats) action='stats' ;;
      syslog_help) action='help' ;;
    esac
  fi

  if [[ -n "${action}" ]]; then
    args_json="$(printf '%s' "${args_json}" | jq -c --arg action "${action}" '. + {action: $action}')"
    tool="cortex"
  fi

  mcporter call \
    --http-url "${MCP_URL}" \
    --allow-http \
    ${MCPORTER_HEADER_ARGS[@]+"${MCPORTER_HEADER_ARGS[@]}"} \
    --tool "${tool}" \
    --args "${args_json}" \
    --timeout "${CALL_TIMEOUT_MS}" \
    --output json \
    2>>"${LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Test runner
#   Usage: run_test <label> <tool_name> <args_json> [expected_key]
# ---------------------------------------------------------------------------
run_test() {
  local label="${1:?label required}"
  local tool="${2:?tool required}"
  local args="${3:?args required}"
  local expected_key="${4:-}"
  local action=''

  if [[ "${tool}" == "cortex" && "${args}" != \{* ]]; then
    action="${args}"
    args="${4:?args required}"
    expected_key="${5:-}"
  fi

  local t0
  t0="$(date +%s%N)"

  local output
  if [[ -n "${action}" ]]; then
    output="$(mcporter_call "${tool}" "${action}" "${args}")" || true
  else
    output="$(mcporter_call "${tool}" "${args}")" || true
  fi

  local elapsed_ms
  elapsed_ms="$(( ( $(date +%s%N) - t0 ) / 1000000 ))"

  if [[ "${VERBOSE}" == true ]]; then
    printf '%s\n' "${output}" | tee -a "${LOG_FILE}"
  else
    printf '%s\n' "${output}" >> "${LOG_FILE}"
  fi

  # Validate JSON is parseable and not an error payload
  local json_check
  json_check="$(
    printf '%s' "${output}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if isinstance(d, dict) and ('error' in d or d.get('kind') == 'error'):
        print('error: ' + str(d.get('error', d.get('message', 'unknown error'))))
    else:
        print('ok')
except Exception as e:
    print('invalid_json: ' + str(e))
" 2>/dev/null
  )" || json_check="parse_error"

  if [[ "${json_check}" != "ok" ]]; then
    printf "${C_RED}[FAIL]${C_RESET} %-60s ${C_DIM}%dms${C_RESET}\n" \
      "${label}" "${elapsed_ms}" | tee -a "${LOG_FILE}"
    printf '       response validation failed: %s\n' "${json_check}" | tee -a "${LOG_FILE}"
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    FAIL_NAMES+=("${label}")
    return 1
  fi

  # Validate optional key presence (dot-notation e.g. "hosts" or "logs.0")
  if [[ -n "${expected_key}" ]]; then
    local key_check
    key_check="$(
      printf '%s' "${output}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    keys = '${expected_key}'.split('.')
    node = d
    for k in keys:
        if k:
            node = node[int(k)] if (isinstance(node, list) and k.isdigit()) else node[k]
    print('ok')
except Exception as e:
    print('missing: ' + str(e))
" 2>/dev/null
    )" || key_check="parse_error"

    if [[ "${key_check}" != "ok" ]]; then
      printf "${C_RED}[FAIL]${C_RESET} %-60s ${C_DIM}%dms${C_RESET}\n" \
        "${label}" "${elapsed_ms}" | tee -a "${LOG_FILE}"
      printf '       expected key .%s not found: %s\n' "${expected_key}" "${key_check}" | tee -a "${LOG_FILE}"
      FAIL_COUNT=$(( FAIL_COUNT + 1 ))
      FAIL_NAMES+=("${label}")
      return 1
    fi
  fi

  printf "${C_GREEN}[PASS]${C_RESET} %-60s ${C_DIM}%dms${C_RESET}\n" \
    "${label}" "${elapsed_ms}" | tee -a "${LOG_FILE}"
  PASS_COUNT=$(( PASS_COUNT + 1 ))
  return 0
}

pass_test() {
  local label="${1:?label required}"
  printf "${C_GREEN}[PASS]${C_RESET} %-60s\n" "${label}" | tee -a "${LOG_FILE}"
  PASS_COUNT=$(( PASS_COUNT + 1 ))
}

fail_test() {
  local label="${1:?label required}"
  local reason="${2:-check failed}"
  printf "${C_RED}[FAIL]${C_RESET} %-60s\n" "${label}" | tee -a "${LOG_FILE}"
  printf '       %s\n' "${reason}" | tee -a "${LOG_FILE}"
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  FAIL_NAMES+=("${label}")
}

# ---------------------------------------------------------------------------
# Skip helper
# ---------------------------------------------------------------------------
skip_test() {
  local label="${1:?label required}"
  local reason="${2:-prerequisite returned empty}"
  printf "${C_YELLOW}[SKIP]${C_RESET} %-60s %s\n" "${label}" "${reason}" | tee -a "${LOG_FILE}"
  SKIP_COUNT=$(( SKIP_COUNT + 1 ))
}

mcp_admin_scope_available() {
  local token="${CORTEX_TOKEN:-${CORTEX_API_TOKEN:-}}"
  token="${token//[[:space:]]/}"
  [[ -n "${token}" \
    && ( "${CORTEX_STATIC_TOKEN_ADMIN:-false}" == "true" \
      || "${CORTEX_SMOKE_ADMIN:-false}" == "true" ) ]]
}

file_tail_smoke_available() {
  [[ -n "${CORTEX_FILE_TAIL_SMOKE_PATH:-}" && -n "${CORTEX_FILE_TAIL_SMOKE_WRITE_PATH:-${CORTEX_FILE_TAIL_SMOKE_PATH:-}}" ]]
}

# ---------------------------------------------------------------------------
# Safe JSON payload builder
#   Usage: _json_payload '<jq-template>' key1=value1 key2=value2 ...
# ---------------------------------------------------------------------------
_json_payload() {
  local template="${1:?template required}"; shift
  local jq_args=()
  local pair k v
  for pair in "$@"; do
    k="${pair%%=*}"
    v="${pair#*=}"
    jq_args+=(--arg "$k" "$v")
  done
  jq -n "${jq_args[@]}" "$template"
}

# ---------------------------------------------------------------------------
# ID / value extractors  (used for parameterised tests)
# ---------------------------------------------------------------------------

# Returns the hostname with the highest log_count (most data = best for testing)
get_primary_host() {
  local raw
  raw="$(mcporter_call cortex hosts '{}'  2>/dev/null)" || return 0
  printf '%s' "${raw}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    hosts = sorted(d.get('hosts', []), key=lambda h: h.get('log_count', 0), reverse=True)
    # Filter out malformed hostnames (timestamp-like strings)
    for h in hosts:
        name = h.get('hostname','')
        if name and 'T' not in name and ':' not in name:
            print(name)
            break
except Exception:
    pass
" 2>/dev/null || true
}

# Returns a recent error timestamp from cortex errors, used for cortex correlate
get_recent_error_time() {
  local raw
  raw="$(mcporter_call cortex errors '{}'  2>/dev/null)" || return 0
  # cortex stats has newest_log which is more reliable
  local stats
  stats="$(mcporter_call cortex stats '{}' 2>/dev/null)" || return 0
  printf '%s' "${stats}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ts = d.get('newest_log', '')
    if ts:
        print(ts)
except Exception:
    pass
" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

suite_meta() {
  printf '\n%b== meta (help + health) ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"
  run_test "cortex help: returns documentation"    cortex help '{}'
  run_test "cortex status: returns lightweight status" cortex status '{}' "status"
  run_test "cortex status: db_ok field present"        cortex status '{}' "db_ok"
  run_test "cortex status: runtime observability"      cortex status '{}' "runtime_observability"
  run_test "cortex status: otlp counters present"      cortex status '{}' "otlp"
  run_test "cortex stats: returns database statistics" cortex stats   '{}' "total_logs"
  run_test "cortex stats: write_blocked field present" cortex stats   '{}' "write_blocked"
  run_test "cortex stats: free_disk_mb field present"  cortex stats   '{}' "free_disk_mb"
  if mcp_admin_scope_available; then
    run_test "cortex file_tails: returns registry status" cortex file_tails '{"op":"status"}' "sources"
    local missing_op
    if missing_op="$(mcporter_call cortex file_tails '{}' 2>&1)"; then
      fail_test "cortex file_tails: missing op rejected" "request unexpectedly succeeded: ${missing_op}"
    elif [[ "${missing_op}" == *"op"* || "${missing_op}" == *"missing"* || "${missing_op}" == *"required"* ]]; then
      pass_test "cortex file_tails: missing op rejected"
    else
      fail_test "cortex file_tails: missing op rejected" "response did not mention op: ${missing_op}"
    fi
    if file_tail_smoke_available; then
      local server_path write_path source_id tag marker add_output search_output count attempt
      server_path="${CORTEX_FILE_TAIL_SMOKE_PATH}"
      write_path="${CORTEX_FILE_TAIL_SMOKE_WRITE_PATH:-${server_path}}"
      source_id="smoke-$(date +%s)-$$"
      tag="file-tail-smoke"
      marker="file-tail-smoke-${source_id}"
      touch "${write_path}" || fail_test "cortex file_tails: smoke file writable" "could not write ${write_path}"
      add_output="$(mcporter_call cortex file_tails "$(jq -nc \
        --arg id "${source_id}" \
        --arg path "${server_path}" \
        --arg tag "${tag}" \
        '{"op":"add","id":$id,"path":$path,"tag":$tag,"hostname":"mcporter-smoke","facility":"local7","severity":"info","start_at_end":true}')")" || add_output=""
      if printf '%s' "${add_output}" | jq -e '.sources | type == "array"' >/dev/null 2>&1; then
        pass_test "cortex file_tails: add smoke source"
      else
        fail_test "cortex file_tails: add smoke source" "${add_output}"
      fi
      printf '%s\n' "${marker}" >> "${write_path}"
      count=0
      for attempt in {1..20}; do
        search_output="$(mcporter_call cortex search "$(jq -nc \
          --arg q "\"${marker}\"" \
          --arg tag "${tag}" \
          '{"query":$q,"source_kind":"file-tail","app_name":$tag,"limit":5}')")" || search_output=""
        count="$(printf '%s' "${search_output}" | jq -r '.count // 0' 2>/dev/null)" || count=0
        [[ "${count}" -ge 1 ]] && break
        sleep 0.5
      done
      if [[ "${count}" -ge 1 ]]; then
        pass_test "cortex file_tails: add append query ingest"
      else
        fail_test "cortex file_tails: add append query ingest" "marker was not queryable"
      fi
      mcporter_call cortex file_tails "$(jq -nc --arg id "${source_id}" '{"op":"remove","id":$id}')" >/dev/null 2>&1 || true
    else
      skip_test "cortex file_tails: add append query ingest" "requires CORTEX_FILE_TAIL_SMOKE_PATH"
    fi
  else
    skip_test "cortex file_tails: returns registry status" "requires cortex:admin (set CORTEX_STATIC_TOKEN_ADMIN=true or CORTEX_SMOKE_ADMIN=true)"
  fi
  run_test "cortex compose_status: redacted diagnostics" cortex compose_status '{}' "runtime_state"

  local compose_status compose_runtime compose_ownership
  compose_status="$(mcporter_call cortex compose_status '{}')" || compose_status=""
  compose_runtime="$(printf '%s' "${compose_status}" | jq -r '.runtime_state // "unknown"' 2>/dev/null)" || compose_runtime="unknown"
  compose_ownership="$(printf '%s' "${compose_status}" | jq -r '.ownership // "unknown"' 2>/dev/null)" || compose_ownership="unknown"
  if [[ "${compose_runtime}" != "docker_unavailable" && "${compose_ownership}" == "compose_owned" ]]; then
    run_test "cortex compose_doctor: redacted diagnostics" cortex compose_doctor '{}' "ownership"
    run_test "cortex compose_doctor: published ports present" cortex compose_doctor '{}' "published_ports"
  else
    skip_test "cortex compose_doctor: redacted diagnostics" "runtime=${compose_runtime}, ownership=${compose_ownership}"
    skip_test "cortex compose_doctor: published ports present" "runtime=${compose_runtime}, ownership=${compose_ownership}"
  fi
}

suite_hosts() {
  printf '\n%b== cortex hosts ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"
  run_test "cortex hosts: returns hosts array"     cortex hosts '{}' "hosts"
  run_test "cortex hosts: hosts have hostname key" cortex hosts '{}' "hosts.0.hostname"
  run_test "cortex hosts: hosts have log_count"    cortex hosts '{}' "hosts.0.log_count"
  run_test "cortex hosts: hosts have first_seen"   cortex hosts '{}' "hosts.0.first_seen"
  run_test "cortex hosts: hosts have last_seen"    cortex hosts '{}' "hosts.0.last_seen"
  run_test "cortex map: returns schema"             cortex map '{}' "schema"
  run_test "cortex map: returns nodes array"        cortex map '{}' "nodes"
  run_test "cortex map: returns cache status"       cortex map '{}' "cache_status"
  run_test "cortex map: returns artifact refs"      cortex map '{}' "artifact_refs"
  run_test "cortex map: returns collection errors"  cortex map '{}' "collection_errors"
  run_test "cortex map: returns cortex overlay"     cortex map '{}' "cortex_overlay"
}

suite_sessions() {
  printf '\n%b== cortex sessions ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"
  run_test "cortex sessions: returns sessions array"     cortex sessions '{"limit":10}' "sessions"
  run_test "cortex sessions: count field present"         cortex sessions '{"limit":5}' "count"
  run_test "cortex search_sessions: returns sessions array" \
    cortex search_sessions "$(jq -nc --arg q "${AI_SMOKE_QUERY}" '{"query":$q,"limit":10}')" "sessions"
  run_test "cortex search_sessions: total_candidates present" \
    cortex search_sessions "$(jq -nc --arg q "${AI_SMOKE_QUERY}" '{"query":$q,"limit":10}')" "total_candidates"
  run_test "cortex abuse: returns matches array" \
    cortex abuse "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" --arg term "ai-smoke-authentication" '{"project":$project,"terms":$term,"limit":5,"before":1,"after":1}')" "matches"
  run_test "cortex abuse_incidents: returns incidents array" \
    cortex abuse_incidents "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" '{"project":$project,"limit":5}')" "incidents"
  run_test "cortex abuse_investigate: returns evidence array" \
    cortex abuse_investigate "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" '{"project":$project,"limit":1}')" "evidence"
  run_test "cortex ai_correlate: returns anchors array" \
    cortex ai_correlate "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" '{"project":$project,"limit":2,"events_per_anchor":3}')" "anchors"
  run_test "cortex topic_correlate: returns timeline array" \
    cortex topic_correlate "$(jq -nc --arg topic "${AI_SMOKE_PROJECT}" '{"topic":$topic,"limit":5}')" "timeline"
  run_test "cortex usage_blocks: returns blocks array" \
    cortex usage_blocks '{}' "blocks"
  run_test "cortex project_context: returns project field" \
    cortex project_context "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" '{"project":$project,"limit":5}')" "project"
  run_test "cortex list_ai_tools: returns tools array" \
    cortex list_ai_tools '{}' "tools"
  run_test "cortex list_ai_projects: returns projects array" \
    cortex list_ai_projects '{}' "projects"
  if [[ "${AI_SEEDED}" == true ]]; then
    run_test "cortex search_sessions: seeded fixture searchable" \
      cortex search_sessions "$(jq -nc --arg q "${AI_SMOKE_QUERY}" '{"query":$q,"limit":10}')" "sessions.0.project"
    run_test "cortex abuse: custom detector finds seeded fixture" \
      cortex abuse "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" --arg term "ai-smoke-authentication" '{"project":$project,"terms":$term,"limit":5,"before":1,"after":1}')" "matches.0.entry.message"
    run_test "cortex project_context: seeded fixture entries" \
      cortex project_context "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" '{"project":$project,"limit":5}')" "recent_entries.0.message"
  fi
}

suite_tail() {
  printf '\n%b== cortex tail ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"
  run_test "cortex tail: default (50 entries)"  cortex tail '{}' "logs"
  run_test "cortex tail: count field present"   cortex tail '{}' "count"
  run_test "cortex tail: n=10 returns entries"  cortex tail '{"n":10}' "logs"
  run_test "cortex tail: log entry has message" cortex tail '{"n":5}' "logs.0.message"
  run_test "cortex tail: log entry has hostname" cortex tail '{"n":5}' "logs.0.hostname"
  run_test "cortex tail: log entry has severity" cortex tail '{"n":5}' "logs.0.severity"
  run_test "cortex tail: log entry has timestamp" cortex tail '{"n":5}' "logs.0.timestamp"

  # Host-scoped tail
  local primary_host
  primary_host="$(get_primary_host)" || primary_host=''
  if [[ -n "${primary_host}" ]]; then
    run_test "cortex tail: host=${primary_host} filter" \
      cortex tail \
      "$(_json_payload '{"hostname":$h,"n":10}' h="${primary_host}")" \
      "logs"
  else
    skip_test "cortex tail: host-scoped" "no usable hostname found"
  fi
}

suite_search() {
  printf '\n%b== cortex search ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"

  run_test "cortex search: basic query (error)"         cortex search '{"query":"error","limit":10}' "logs"
  run_test "cortex search: count field present"         cortex search '{"query":"error","limit":5}' "count"
  run_test "cortex search: severity filter (err)"       cortex search '{"severity":"err","limit":10}' "logs"
  run_test "cortex search: severity filter (warning)"   cortex search '{"severity":"warning","limit":10}' "logs"
  run_test "cortex search: limit respected"             cortex search '{"query":"info","limit":3}' "logs"
  run_test "cortex search: no query (list recent)"      cortex search '{"limit":20}' "logs"
  run_test "cortex filter: structured list recent"      cortex filter '{"limit":20}' "logs"
  run_test "cortex filter: severity filter (warning)"   cortex filter '{"severity":"warning","limit":10}' "logs"

  # App-name filter — discover real app name from tail first
  local app_name
  app_name="$(
    mcporter_call cortex tail '{"n":20}' 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    apps = [l.get('app_name','') for l in d.get('logs',[]) if l.get('app_name','')]
    # Pick first non-empty, reasonably short app name
    for a in apps:
        if a and len(a) < 30 and ' ' not in a:
            print(a)
            break
except Exception:
    pass
" 2>/dev/null
  )" || app_name=''

  if [[ -n "${app_name}" ]]; then
    run_test "cortex search: app_name=${app_name} filter" \
      cortex search \
      "$(_json_payload '{"app_name":$a,"limit":10}' a="${app_name}")" \
      "logs"
  else
    skip_test "cortex search: app_name filter" "no usable app_name found in recent logs"
  fi

  # Host-scoped search
  local primary_host
  primary_host="$(get_primary_host)" || primary_host=''
  if [[ -n "${primary_host}" ]]; then
    run_test "cortex search: hostname=${primary_host} filter" \
      cortex search \
      "$(_json_payload '{"hostname":$h,"limit":10}' h="${primary_host}")" \
      "logs"
  else
    skip_test "cortex search: hostname filter" "no usable hostname found"
  fi

  # FTS5 phrase matching
  run_test "cortex search: FTS5 phrase query"    cortex search '{"query":"\"connection refused\"","limit":10}' "logs"
  # Prefix matching
  run_test "cortex search: FTS5 prefix query"    cortex search '{"query":"kernel*","limit":10}' "logs"
  # Time-bounded search — last 24 hours
  local since
  since="$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
  if [[ -n "${since}" ]]; then
    run_test "cortex search: time range (last 24h)" \
      cortex search \
      "$(_json_payload '{"from":$f,"limit":20}' f="${since}")" \
      "logs"
  else
    skip_test "cortex search: time range filter" "could not compute timestamp"
  fi
}

suite_errors() {
  printf '\n%b== cortex errors ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"

  run_test "cortex errors: all time"       cortex errors '{}' "summary"
  run_test "cortex errors: summary has hostname" cortex errors '{}' "summary.0.hostname"
  run_test "cortex errors: summary has severity" cortex errors '{}' "summary.0.severity"
  run_test "cortex errors: summary has count"    cortex errors '{}' "summary.0.count"

  # Time-bounded cortex errors (last 1 hour)
  local since
  since="$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
  local until_now
  until_now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ -n "${since}" ]]; then
    run_test "cortex errors: time range (last 1h)" \
      cortex errors \
      "$(_json_payload '{"from":$f,"to":$t}' f="${since}" t="${until_now}")" \
      "summary"
  else
    skip_test "cortex errors: time range filter" "could not compute timestamp"
  fi
}

suite_correlate() {
  printf '\n%b== cortex correlate ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"

  # cortex correlate requires reference_time (the only required field)
  local ref_time
  ref_time="$(get_recent_error_time)" || ref_time=''

  if [[ -z "${ref_time}" ]]; then
    # Fallback: use current time
    ref_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi

  run_test "cortex correlate: default window (5m)" \
    cortex correlate \
    "$(_json_payload '{"reference_time":$t}' t="${ref_time}")"

  run_test "cortex correlate: wider window (15m)" \
    cortex correlate \
    "$(_json_payload '{"reference_time":$t,"window_minutes":15}' t="${ref_time}")"

  run_test "cortex correlate: severity_min=err" \
    cortex correlate \
    "$(_json_payload '{"reference_time":$t,"severity_min":"err"}' t="${ref_time}")"

  run_test "cortex correlate: severity_min=debug (all)" \
    cortex correlate \
    "$(_json_payload '{"reference_time":$t,"window_minutes":2,"severity_min":"debug","limit":50}' t="${ref_time}")"

  run_test "cortex correlate: with FTS query" \
    cortex correlate \
    "$(_json_payload '{"reference_time":$t,"query":"error*","window_minutes":10}' t="${ref_time}")"

  # Host-scoped correlation
  local primary_host
  primary_host="$(get_primary_host)" || primary_host=''
  if [[ -n "${primary_host}" ]]; then
    run_test "cortex correlate: host=${primary_host} scoped" \
      cortex correlate \
      "$(_json_payload '{"reference_time":$t,"hostname":$h,"window_minutes":5}' t="${ref_time}" h="${primary_host}")"
  else
    skip_test "cortex correlate: host-scoped" "no usable hostname found"
  fi
}

# ---------------------------------------------------------------------------
# Auth enforcement tests (only run when CORTEX_TOKEN is set)
# ---------------------------------------------------------------------------
suite_auth() {
  if [[ -z "${CORTEX_TOKEN:-${CORTEX_API_TOKEN:-}}" ]]; then
    printf '\n%b== auth (skipped — token unset) ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"
    skip_test "auth: unauthenticated request returns 401" "CORTEX_TOKEN unset"
    skip_test "auth: bad token returns 401"                "CORTEX_TOKEN unset"
    return
  fi

  printf '\n%b== auth enforcement ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"

  local base_url="${MCP_URL%/mcp}"
  local label status

  label="auth: unauthenticated /mcp returns 401"
  status="$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
    "${MCP_URL}" -X POST -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' 2>/dev/null)" || status=0
  if [[ "${status}" == "401" ]]; then
    printf "${C_GREEN}[PASS]${C_RESET} %-60s\n" "${label}" | tee -a "${LOG_FILE}"
    PASS_COUNT=$(( PASS_COUNT + 1 ))
  else
    printf "${C_RED}[FAIL]${C_RESET} %-60s (got HTTP %s)\n" "${label}" "${status}" | tee -a "${LOG_FILE}"
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    FAIL_NAMES+=("${label}")
  fi

  label="auth: bad token returns 401"
  status="$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
    "${MCP_URL}" -X POST \
    -H "Authorization: Bearer bad-token-intentionally-invalid" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' 2>/dev/null)" || status=0
  if [[ "${status}" == "401" ]]; then
    printf "${C_GREEN}[PASS]${C_RESET} %-60s\n" "${label}" | tee -a "${LOG_FILE}"
    PASS_COUNT=$(( PASS_COUNT + 1 ))
  else
    printf "${C_RED}[FAIL]${C_RESET} %-60s (got HTTP %s)\n" "${label}" "${status}" | tee -a "${LOG_FILE}"
    FAIL_COUNT=$(( FAIL_COUNT + 1 ))
    FAIL_NAMES+=("${label}")
  fi
}

# ---------------------------------------------------------------------------
# Print final summary
# ---------------------------------------------------------------------------
print_summary() {
  local total_ms="$(( ( $(date +%s%N) - TS_START ) / 1000000 ))"
  local total=$(( PASS_COUNT + FAIL_COUNT + SKIP_COUNT ))

  printf '\n%b%s%b\n' "${C_BOLD}" "$(printf '=%.0s' {1..65})" "${C_RESET}"
  printf '%b%-20s%b  %b%d%b\n' "${C_BOLD}" "PASS" "${C_RESET}" "${C_GREEN}" "${PASS_COUNT}" "${C_RESET}"
  printf '%b%-20s%b  %b%d%b\n' "${C_BOLD}" "FAIL" "${C_RESET}" "${C_RED}"   "${FAIL_COUNT}" "${C_RESET}"
  printf '%b%-20s%b  %b%d%b\n' "${C_BOLD}" "SKIP" "${C_RESET}" "${C_YELLOW}" "${SKIP_COUNT}" "${C_RESET}"
  printf '%b%-20s%b  %d\n' "${C_BOLD}" "TOTAL" "${C_RESET}" "${total}"
  printf '%b%-20s%b  %ds (%dms)\n' "${C_BOLD}" "ELAPSED" "${C_RESET}" \
    "$(( total_ms / 1000 ))" "${total_ms}"
  printf '%b%s%b\n' "${C_BOLD}" "$(printf '=%.0s' {1..65})" "${C_RESET}"

  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    printf '\n%bFailed tests:%b\n' "${C_RED}" "${C_RESET}"
    local name
    for name in "${FAIL_NAMES[@]}"; do
      printf '  • %s\n' "${name}"
    done
    printf '\nFull log: %s\n' "${LOG_FILE}"
  fi
}

# ---------------------------------------------------------------------------
# Parallel runner
# ---------------------------------------------------------------------------
run_parallel() {
  log_warn "--parallel mode: per-suite counters aggregated via temp files."

  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf -- "${tmp_dir}"' RETURN

  local suites=(
    suite_meta
    suite_hosts
    suite_sessions
    suite_tail
    suite_search
    suite_errors
    suite_correlate
    suite_auth
  )

  local pids=()
  local suite
  for suite in "${suites[@]}"; do
    (
      PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAIL_NAMES=()
      "${suite}"
      printf '%d %d %d\n' "${PASS_COUNT}" "${FAIL_COUNT}" "${SKIP_COUNT}" \
        > "${tmp_dir}/${suite}.counts"
      printf '%s\n' "${FAIL_NAMES[@]:-}" > "${tmp_dir}/${suite}.fails"
    ) &
    pids+=($!)
  done

  local pid
  for pid in "${pids[@]}"; do
    wait "${pid}" || true
  done

  local f
  for f in "${tmp_dir}"/*.counts; do
    [[ -f "${f}" ]] || continue
    local p fl s
    read -r p fl s < "${f}"
    PASS_COUNT=$(( PASS_COUNT + p ))
    FAIL_COUNT=$(( FAIL_COUNT + fl ))
    SKIP_COUNT=$(( SKIP_COUNT + s ))
  done

  for f in "${tmp_dir}"/*.fails; do
    [[ -f "${f}" ]] || continue
    while IFS= read -r line; do
      [[ -n "${line}" ]] && FAIL_NAMES+=("${line}")
    done < "${f}"
  done
}

# ---------------------------------------------------------------------------
# Sequential runner
# ---------------------------------------------------------------------------
run_sequential() {
  suite_auth
  suite_meta
  suite_hosts
  suite_sessions
  suite_tail
  suite_search
  suite_errors
  suite_correlate
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  parse_args "$@"
  load_env

  printf '%b%s%b\n' "${C_BOLD}" "$(printf '=%.0s' {1..65})" "${C_RESET}"
  printf '%b  cortex integration smoke-test%b\n' "${C_BOLD}" "${C_RESET}"
  printf '%b  Project:  %s%b\n' "${C_BOLD}" "${PROJECT_DIR}" "${C_RESET}"
  printf '%b  MCP URL:  %s%b\n' "${C_BOLD}" "${MCP_URL}" "${C_RESET}"
  printf '%b  Timeout:  %dms/call | Parallel: %s%b\n' \
    "${C_BOLD}" "${CALL_TIMEOUT_MS}" "${USE_PARALLEL}" "${C_RESET}"
  printf '%b  Log:      %s%b\n' "${C_BOLD}" "${LOG_FILE}" "${C_RESET}"
  printf '%b%s%b\n\n' "${C_BOLD}" "$(printf '=%.0s' {1..65})" "${C_RESET}"

  check_prerequisites || exit 2

  smoke_test_server || {
    log_error ""
    log_error "Server connectivity check failed. Aborting — no tests will run."
    log_error ""
    log_error "To diagnose:"
    log_error "  docker ps | grep cortex"
    log_error "  curl http://localhost:3100/health"
    log_error "  curl -X POST http://localhost:3100/mcp -H 'Content-Type: application/json' \\"
    log_error "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}'"
    exit 2
  }

  seed_ai_fixture || {
    log_error "AI transcript fixture seed failed"
    exit 2
  }
  log_info "Seeded AI transcript fixture"

  if [[ "${USE_PARALLEL}" == true ]]; then
    run_parallel
  else
    run_sequential
  fi

  print_summary

  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

main "$@"
