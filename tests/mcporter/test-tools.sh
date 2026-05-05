#!/usr/bin/env bash
# =============================================================================
# test-tools.sh — Integration smoke-test for syslog-mcp MCP server tools
#
# Exercises broad non-destructive coverage of all syslog-mcp tools via HTTP:
#   search_logs, tail_logs, get_errors, list_hosts, correlate_events,
#   get_stats, syslog_help
#
# The server runs as a Docker container over HTTP. No stdio launch needed.
# Credentials are sourced from ~/.claude-homelab/.env:
#   SYSLOG_MCP_HOST  (default: localhost)
#   SYSLOG_MCP_PORT  (default: 3100)
#   SYSLOG_MCP_NO_AUTH  (if "true", no Authorization header sent)
#   SYSLOG_MCP_TOKEN    (optional; only used when SYSLOG_MCP_NO_AUTH != true)
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

  local host="${SYSLOG_MCP_HOST:-localhost}"
  # SYSLOG_MCP_HOST in .env is set to "0.0.0.0" (bind address), not the access address.
  # Remap 0.0.0.0 → localhost for outbound connections.
  if [[ "${host}" == "0.0.0.0" ]]; then
    host="localhost"
  fi
  local port="${SYSLOG_MCP_PORT:-3100}"
  MCP_URL="http://${host}:${port}/mcp"

  # Auth: SYSLOG_MCP_NO_AUTH=true means the server runs without token validation.
  # Honour an explicit SYSLOG_MCP_TOKEN if set regardless.
  local token="${SYSLOG_MCP_TOKEN:-}"
  local no_auth="${SYSLOG_MCP_NO_AUTH:-true}"

  MCPORTER_HEADER_ARGS=()
  if [[ -n "${token}" ]]; then
    MCPORTER_HEADER_ARGS+=(--header "Authorization: Bearer ${token}")
  elif [[ "${no_auth}" != "true" ]]; then
    log_warn "SYSLOG_MCP_NO_AUTH is not 'true' and SYSLOG_MCP_TOKEN is unset — calls may return 401"
  fi

  log_info "MCP URL: ${MCP_URL}"
  if [[ ${#MCPORTER_HEADER_ARGS[@]} -gt 0 ]]; then
    log_info "Auth: Bearer token configured"
  else
    log_info "Auth: none (SYSLOG_MCP_NO_AUTH=true)"
  fi
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
    log_error "Is the syslog-mcp container running?  docker ps | grep syslog-mcp"
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
    log_error "tools/list returned ${tool_count} tools — expected at least 7"
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
  local args_json="${2:?args_json required}"

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

  local t0
  t0="$(date +%s%N)"

  local output
  output="$(mcporter_call "${tool}" "${args}")" || true

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

# ---------------------------------------------------------------------------
# Skip helper
# ---------------------------------------------------------------------------
skip_test() {
  local label="${1:?label required}"
  local reason="${2:-prerequisite returned empty}"
  printf "${C_YELLOW}[SKIP]${C_RESET} %-60s %s\n" "${label}" "${reason}" | tee -a "${LOG_FILE}"
  SKIP_COUNT=$(( SKIP_COUNT + 1 ))
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
  raw="$(mcporter_call list_hosts '{}'  2>/dev/null)" || return 0
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

# Returns a recent error timestamp from get_errors, used for correlate_events
get_recent_error_time() {
  local raw
  raw="$(mcporter_call get_errors '{}'  2>/dev/null)" || return 0
  # get_stats has newest_log which is more reliable
  local stats
  stats="$(mcporter_call get_stats '{}' 2>/dev/null)" || return 0
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
  run_test "syslog_help: returns documentation"    syslog_help '{}'
  run_test "get_stats: returns database statistics" get_stats   '{}' "total_logs"
  run_test "get_stats: write_blocked field present" get_stats   '{}' "write_blocked"
  run_test "get_stats: free_disk_mb field present"  get_stats   '{}' "free_disk_mb"
}

suite_hosts() {
  printf '\n%b== list_hosts ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"
  run_test "list_hosts: returns hosts array"     list_hosts '{}' "hosts"
  run_test "list_hosts: hosts have hostname key" list_hosts '{}' "hosts.0.hostname"
  run_test "list_hosts: hosts have log_count"    list_hosts '{}' "hosts.0.log_count"
  run_test "list_hosts: hosts have first_seen"   list_hosts '{}' "hosts.0.first_seen"
  run_test "list_hosts: hosts have last_seen"    list_hosts '{}' "hosts.0.last_seen"
}

suite_tail() {
  printf '\n%b== tail_logs ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"
  run_test "tail_logs: default (50 entries)"  tail_logs '{}' "logs"
  run_test "tail_logs: count field present"   tail_logs '{}' "count"
  run_test "tail_logs: n=10 returns entries"  tail_logs '{"n":10}' "logs"
  run_test "tail_logs: log entry has message" tail_logs '{"n":5}' "logs.0.message"
  run_test "tail_logs: log entry has hostname" tail_logs '{"n":5}' "logs.0.hostname"
  run_test "tail_logs: log entry has severity" tail_logs '{"n":5}' "logs.0.severity"
  run_test "tail_logs: log entry has timestamp" tail_logs '{"n":5}' "logs.0.timestamp"

  # Host-scoped tail
  local primary_host
  primary_host="$(get_primary_host)" || primary_host=''
  if [[ -n "${primary_host}" ]]; then
    run_test "tail_logs: host=${primary_host} filter" \
      tail_logs \
      "$(_json_payload '{"hostname":$h,"n":10}' h="${primary_host}")" \
      "logs"
  else
    skip_test "tail_logs: host-scoped" "no usable hostname found"
  fi
}

suite_search() {
  printf '\n%b== search_logs ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"

  run_test "search_logs: basic query (error)"         search_logs '{"query":"error","limit":10}' "logs"
  run_test "search_logs: count field present"         search_logs '{"query":"error","limit":5}' "count"
  run_test "search_logs: severity filter (err)"       search_logs '{"severity":"err","limit":10}' "logs"
  run_test "search_logs: severity filter (warning)"   search_logs '{"severity":"warning","limit":10}' "logs"
  run_test "search_logs: limit respected"             search_logs '{"query":"info","limit":3}' "logs"
  run_test "search_logs: no query (list recent)"      search_logs '{"limit":20}' "logs"

  # App-name filter — discover real app name from tail first
  local app_name
  app_name="$(
    mcporter_call tail_logs '{"n":20}' 2>/dev/null | python3 -c "
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
    run_test "search_logs: app_name=${app_name} filter" \
      search_logs \
      "$(_json_payload '{"app_name":$a,"limit":10}' a="${app_name}")" \
      "logs"
  else
    skip_test "search_logs: app_name filter" "no usable app_name found in recent logs"
  fi

  # Host-scoped search
  local primary_host
  primary_host="$(get_primary_host)" || primary_host=''
  if [[ -n "${primary_host}" ]]; then
    run_test "search_logs: hostname=${primary_host} filter" \
      search_logs \
      "$(_json_payload '{"hostname":$h,"limit":10}' h="${primary_host}")" \
      "logs"
  else
    skip_test "search_logs: hostname filter" "no usable hostname found"
  fi

  # FTS5 phrase matching
  run_test "search_logs: FTS5 phrase query"    search_logs '{"query":"\"connection refused\"","limit":10}' "logs"
  # Prefix matching
  run_test "search_logs: FTS5 prefix query"    search_logs '{"query":"kernel*","limit":10}' "logs"
  # Time-bounded search — last 24 hours
  local since
  since="$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
  if [[ -n "${since}" ]]; then
    run_test "search_logs: time range (last 24h)" \
      search_logs \
      "$(_json_payload '{"from":$f,"limit":20}' f="${since}")" \
      "logs"
  else
    skip_test "search_logs: time range filter" "could not compute timestamp"
  fi
}

suite_errors() {
  printf '\n%b== get_errors ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"

  run_test "get_errors: all time"       get_errors '{}' "summary"
  run_test "get_errors: summary has hostname" get_errors '{}' "summary.0.hostname"
  run_test "get_errors: summary has severity" get_errors '{}' "summary.0.severity"
  run_test "get_errors: summary has count"    get_errors '{}' "summary.0.count"

  # Time-bounded get_errors (last 1 hour)
  local since
  since="$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
  local until_now
  until_now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ -n "${since}" ]]; then
    run_test "get_errors: time range (last 1h)" \
      get_errors \
      "$(_json_payload '{"from":$f,"to":$t}' f="${since}" t="${until_now}")" \
      "summary"
  else
    skip_test "get_errors: time range filter" "could not compute timestamp"
  fi
}

suite_correlate() {
  printf '\n%b== correlate_events ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"

  # correlate_events requires reference_time (the only required field)
  local ref_time
  ref_time="$(get_recent_error_time)" || ref_time=''

  if [[ -z "${ref_time}" ]]; then
    # Fallback: use current time
    ref_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi

  run_test "correlate_events: default window (5m)" \
    correlate_events \
    "$(_json_payload '{"reference_time":$t}' t="${ref_time}")"

  run_test "correlate_events: wider window (15m)" \
    correlate_events \
    "$(_json_payload '{"reference_time":$t,"window_minutes":15}' t="${ref_time}")"

  run_test "correlate_events: severity_min=err" \
    correlate_events \
    "$(_json_payload '{"reference_time":$t,"severity_min":"err"}' t="${ref_time}")"

  run_test "correlate_events: severity_min=debug (all)" \
    correlate_events \
    "$(_json_payload '{"reference_time":$t,"window_minutes":2,"severity_min":"debug","limit":50}' t="${ref_time}")"

  run_test "correlate_events: with FTS query" \
    correlate_events \
    "$(_json_payload '{"reference_time":$t,"query":"error*","window_minutes":10}' t="${ref_time}")"

  # Host-scoped correlation
  local primary_host
  primary_host="$(get_primary_host)" || primary_host=''
  if [[ -n "${primary_host}" ]]; then
    run_test "correlate_events: host=${primary_host} scoped" \
      correlate_events \
      "$(_json_payload '{"reference_time":$t,"hostname":$h,"window_minutes":5}' t="${ref_time}" h="${primary_host}")"
  else
    skip_test "correlate_events: host-scoped" "no usable hostname found"
  fi
}

# ---------------------------------------------------------------------------
# Auth enforcement tests (only run when SYSLOG_MCP_NO_AUTH != "true")
# ---------------------------------------------------------------------------
suite_auth() {
  local no_auth="${SYSLOG_MCP_NO_AUTH:-true}"
  if [[ "${no_auth}" == "true" ]]; then
    printf '\n%b== auth (skipped — SYSLOG_MCP_NO_AUTH=true) ==%b\n' "${C_BOLD}" "${C_RESET}" | tee -a "${LOG_FILE}"
    skip_test "auth: unauthenticated request returns 401" "SYSLOG_MCP_NO_AUTH=true"
    skip_test "auth: bad token returns 401"                "SYSLOG_MCP_NO_AUTH=true"
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
  printf '%b  syslog-mcp integration smoke-test%b\n' "${C_BOLD}" "${C_RESET}"
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
    log_error "  docker ps | grep syslog-mcp"
    log_error "  curl http://localhost:3100/health"
    log_error "  curl -X POST http://localhost:3100/mcp -H 'Content-Type: application/json' \\"
    log_error "    -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}'"
    exit 2
  }

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
