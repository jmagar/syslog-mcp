#!/usr/bin/env bash
# =============================================================================
# tests/test_live.sh — Canonical integration test for cortex
#
# Modes:
#   --mode docker  Build image, start container, run all test phases, teardown
#   --mode http    Test against an already-running server (requires --url)
#   --mode all     Alias for docker (default)
#
# Flags:
#   --url URL        Base URL of the MCP server (default: http://localhost:3100)
#   --token TOKEN    Bearer token (also read from CORTEX_TOKEN env var)
#   --verbose        Print raw JSON responses for every call
#   --help           Show this help
#
# Environment variables:
#   CORTEX_TOKEN       Bearer token for auth (optional — server may run without it)
#   CORTEX_API_ADMIN_TOKEN Admin token for /api/file-tails live REST smoke
#   PORT                   Override server port (default: 3100)
#
# Action inventory reference (not every action is exercised by this live test):
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
# Exit codes:
#   0 — all tests passed (SKIPs do not count as failures)
#   1 — one or more tests failed
#   2 — prerequisite check failed or docker build/start failed
#
# Examples:
#   # Docker mode (default — builds image, runs tests, tears down)
#   CORTEX_TOKEN=ci-integration-value bash tests/test_live.sh
#
#   # HTTP mode — test an already-running server
#   bash tests/test_live.sh --mode http --url http://192.168.1.10:3100
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
MODE="all"          # all | docker | http
BASE_URL=""         # populated after arg parsing
TOKEN=""            # populated from args or env
VERBOSE=false
PORT="${PORT:-3100}"
CONTAINER_NAME="cortex-test-$$"
IMAGE_NAME="cortex-test"
AI_SMOKE_FIXTURE="tests/fixtures/ai-session-smoke.jsonl"
AI_SMOKE_PROJECT="/tmp/cortex-ai-smoke"
AI_SMOKE_QUERY='"ai-smoke-authentication"'
AI_SEEDED=false
CLI_PARITY_CONTAINER=""
FILE_TAIL_SMOKE_DIR=""
FILE_TAIL_SMOKE_HOST_PATH=""
FILE_TAIL_SMOKE_SERVER_PATH="/file-tail-root/smoke.log"

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
declare -a FAIL_NAMES=()

# ---------------------------------------------------------------------------
# Colours (disabled when stdout is not a terminal or NO_COLOR is set)
# ---------------------------------------------------------------------------
if [[ -t 1 && "${NO_COLOR:-}" == "" ]]; then
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
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { printf "${C_CYAN}[INFO]${C_RESET}  %s\n" "$*"; }
log_warn()  { printf "${C_YELLOW}[WARN]${C_RESET}  %s\n" "$*"; }
log_error() { printf "${C_RED}[ERROR]${C_RESET} %s\n" "$*" >&2; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        MODE="${2:?--mode requires a value: docker|http|all}"
        shift 2
        ;;
      --url)
        BASE_URL="${2:?--url requires a value}"
        shift 2
        ;;
      --token)
        TOKEN="${2:?--token requires a value}"
        shift 2
        ;;
      --verbose)
        VERBOSE=true
        shift
        ;;
      -h|--help)
        sed -n '2,30p' "$0" | sed 's/^# \?//'
        exit 0
        ;;
      *)
        log_error "Unknown argument: $1"
        exit 2
        ;;
    esac
  done

  # Normalise "all" → "docker"
  if [[ "${MODE}" == "all" ]]; then
    MODE="docker"
  fi

  # Env var fallback for token
  if [[ -z "${TOKEN}" ]]; then
    TOKEN="${CORTEX_TOKEN:-${CORTEX_API_TOKEN:-}}"
  fi

  # Default BASE_URL
  if [[ -z "${BASE_URL}" ]]; then
    BASE_URL="http://localhost:${PORT}"
  fi
}

# ---------------------------------------------------------------------------
# Test result helpers
# ---------------------------------------------------------------------------
_pass() {
  local label="$1"
  printf "${C_GREEN}[PASS]${C_RESET} %s\n" "${label}"
  PASS_COUNT=$(( PASS_COUNT + 1 ))
}

_fail() {
  local label="$1"
  local reason="${2:-}"
  printf "${C_RED}[FAIL]${C_RESET} %s\n" "${label}"
  if [[ -n "${reason}" ]]; then
    printf "       %s\n" "${reason}"
  fi
  FAIL_COUNT=$(( FAIL_COUNT + 1 ))
  FAIL_NAMES+=("${label}")
}

_skip() {
  local label="$1"
  local reason="${2:-}"
  printf "${C_YELLOW}[SKIP]${C_RESET} %s" "${label}"
  if [[ -n "${reason}" ]]; then
    printf " — %s" "${reason}"
  fi
  printf '\n'
  SKIP_COUNT=$(( SKIP_COUNT + 1 ))
}

mcp_admin_scope_available() {
  local token="${TOKEN:-}"
  token="${token//[[:space:]]/}"
  [[ -n "${token}" \
    && ( "${CORTEX_STATIC_TOKEN_ADMIN:-false}" == "true" \
      || "${CORTEX_SMOKE_ADMIN:-false}" == "true" ) ]]
}

file_tail_smoke_available() {
  [[ -n "${CORTEX_FILE_TAIL_SMOKE_PATH:-${FILE_TAIL_SMOKE_SERVER_PATH:-}}" \
    && -n "${CORTEX_FILE_TAIL_SMOKE_WRITE_PATH:-${FILE_TAIL_SMOKE_HOST_PATH:-${CORTEX_FILE_TAIL_SMOKE_PATH:-}}}" ]]
}

section() {
  printf '\n%b=== %s ===%b\n' "${C_BOLD}" "$*" "${C_RESET}"
}

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
check_prerequisites() {
  local missing=false

  if ! command -v curl &>/dev/null; then
    log_error "curl not found in PATH"
    missing=true
  fi

  if ! command -v jq &>/dev/null; then
    log_error "jq not found in PATH"
    missing=true
  fi

  if [[ "${MODE}" == "docker" ]]; then
    if ! command -v docker &>/dev/null; then
      log_error "docker not found in PATH (required for --mode docker)"
      missing=true
    fi
  fi

  if [[ "${missing}" == "true" ]]; then
    return 2
  fi
}

# ---------------------------------------------------------------------------
# Build auth header array for curl
# Usage: build_auth_args
# Sets AUTH_ARGS global array
# ---------------------------------------------------------------------------
AUTH_ARGS=()
build_auth_args() {
  AUTH_ARGS=()
  if [[ -n "${TOKEN}" ]]; then
    AUTH_ARGS=(-H "Authorization: Bearer ${TOKEN}")
  fi
}

run_local_syslog_ai_add() {
  local db_path="$1"
  local fixture="$2"
  if [[ -x "target/debug/cortex" ]]; then
    CORTEX_DB_PATH="${db_path}" target/debug/cortex sessions add --file "${fixture}" --json
  else
    CORTEX_DB_PATH="${db_path}" cargo run --quiet -- sessions add --file "${fixture}" --json
  fi
}

seed_ai_fixture_local() {
  [[ -f "${AI_SMOKE_FIXTURE}" ]] || return 1
  local db_path="${CORTEX_SMOKE_DB_PATH:-${CORTEX_DB_PATH:-data/cortex.db}}"
  run_local_syslog_ai_add "${db_path}" "${AI_SMOKE_FIXTURE}" >/dev/null || return $?
  AI_SEEDED=true
}

seed_ai_fixture_container() {
  local project_dir="$1"
  local container_fixture="/tmp/ai-session-smoke.jsonl"
  docker cp "${project_dir}/${AI_SMOKE_FIXTURE}" "${CONTAINER_NAME}:${container_fixture}" >/dev/null || return $?
  docker exec "${CONTAINER_NAME}" cortex sessions add --file "${container_fixture}" --json >/dev/null || return $?
  AI_SEEDED=true
}

# ---------------------------------------------------------------------------
# Raw MCP JSON-RPC POST
# Usage: mcp_post <json-body>
# Returns raw JSON response on stdout; returns non-zero on curl failure
# ---------------------------------------------------------------------------
mcp_post() {
  local body="$1"
  curl -sf --max-time 15 \
    -X POST "${BASE_URL}/mcp" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
    -d "${body}"
}

# ---------------------------------------------------------------------------
# assert_jq — validate a jq expression on a JSON value
# Usage: assert_jq <label> <json> <jq-expr> [expected-value]
#
# If expected-value is omitted, just checks the expression is not null/false/empty.
# If expected-value is provided, checks the expression equals that string.
# ---------------------------------------------------------------------------
assert_jq() {
  local label="$1"
  local json="$2"
  local expr="$3"
  local expected="${4:-}"

  local actual
  actual="$(printf '%s' "${json}" | jq -r "${expr}" 2>/dev/null)" || actual=""

  if [[ -n "${expected}" ]]; then
    if [[ "${actual}" == "${expected}" ]]; then
      _pass "${label}"
      return 0
    else
      _fail "${label}" "expected '${expected}', got '${actual}'"
      return 1
    fi
  else
    # No expected — just verify not null / not empty string / not "false"
    if [[ -n "${actual}" && "${actual}" != "null" && "${actual}" != "false" ]]; then
      _pass "${label}"
      return 0
    else
      _fail "${label}" "expression '${expr}' returned '${actual}' (null/false/empty)"
      return 1
    fi
  fi
}

# ---------------------------------------------------------------------------
# call_tool — call a tool via MCP JSON-RPC and return the result JSON
# Usage: result=$(call_tool <tool_name> <args_json>)
# The returned JSON is the value of .result.content[0].text (parsed from JSON-in-JSON)
# ---------------------------------------------------------------------------
_req_id=0
call_tool() {
  local tool="$1"
  local args="${2:-{\}}"
  _req_id=$(( _req_id + 1 ))

  local body
  body="$(jq -nc \
    --arg tool "${tool}" \
    --argjson args "${args}" \
    --argjson id "${_req_id}" \
    '{"jsonrpc":"2.0","id":$id,"method":"tools/call","params":{"name":$tool,"arguments":$args}}')"

  local raw
  raw="$(mcp_post "${body}")" || { log_error "curl failed for tool ${tool}"; return 1; }

  if [[ "${VERBOSE}" == "true" ]]; then
    printf '%b[VERBOSE] %s response:%b\n%s\n' "${C_DIM}" "${tool}" "${C_RESET}" "${raw}"
  fi

  # Extract text content (tools return content[0].text as a JSON string)
  local text
  text="$(printf '%s' "${raw}" | jq -r '.result.content[0].text // empty' 2>/dev/null)" || text=""

  if [[ -z "${text}" ]]; then
    # Check if it's an error response
    local err
    err="$(printf '%s' "${raw}" | jq -r '.error.message // .result.content[0].text // "unknown"' 2>/dev/null)"
    log_error "call_tool ${tool}: no text content in response (error: ${err})"
    printf '%s' "${raw}"
    return 1
  fi

  # text itself is a JSON string — parse it
  printf '%s' "${text}"
}

# ---------------------------------------------------------------------------
# Phase 1 — Health check
# ---------------------------------------------------------------------------
phase_health() {
  section "Phase 1 — Health"

  local response
  response="$(curl -sf --max-time 10 \
    -H "Accept: application/json, text/event-stream" \
    "${BASE_URL}/health" 2>/dev/null)" || response=""

  if [[ -z "${response}" ]]; then
    _fail "GET /health returns 200" "curl failed or no response"
    return 1
  fi

  assert_jq "GET /health — status is ok" "${response}" '.status' "ok"
}

# ---------------------------------------------------------------------------
# Phase 2 — Auth enforcement
# ---------------------------------------------------------------------------
phase_auth() {
  section "Phase 2 — Auth"

  if [[ -z "${TOKEN}" ]]; then
    _skip "auth: unauthenticated /mcp returns 401" "CORTEX_TOKEN not set — auth assumed disabled"
    _skip "auth: bad token returns 401"             "CORTEX_TOKEN not set — auth assumed disabled"
    return 0
  fi

  local status

  # Test: no token → 401
  status="$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
    -X POST "${BASE_URL}/mcp" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' 2>/dev/null)" || status=0

  if [[ "${status}" == "401" ]]; then
    _pass "auth: unauthenticated /mcp returns 401"
  else
    _fail "auth: unauthenticated /mcp returns 401" "got HTTP ${status}"
  fi

  # Test: wrong token → 401
  status="$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
    -X POST "${BASE_URL}/mcp" \
    -H "Authorization: Bearer intentionally-wrong-value-for-testing" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' 2>/dev/null)" || status=0

  if [[ "${status}" == "401" ]]; then
    _pass "auth: bad token returns 401"
  else
    _fail "auth: bad token returns 401" "got HTTP ${status}"
  fi
}

# ---------------------------------------------------------------------------
# Phase 3 — Protocol (initialize + tools/list)
# ---------------------------------------------------------------------------
phase_protocol() {
  section "Phase 3 — Protocol"

  local expected_tools=("cortex")

  # initialize
  local init_resp
  init_resp="$(mcp_post '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test_live.sh","version":"1.0.0"}}}')" || init_resp=""

  assert_jq "initialize — protocolVersion present"    "${init_resp}" '.result.protocolVersion'
  assert_jq "initialize — serverInfo.name present"    "${init_resp}" '.result.serverInfo.name'
  assert_jq "initialize — capabilities.tools present" "${init_resp}" '.result.capabilities.tools'

  # tools/list
  local list_resp
  list_resp="$(mcp_post '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')" || list_resp=""

  local tool_count
  tool_count="$(printf '%s' "${list_resp}" | jq '.result.tools | length' 2>/dev/null)" || tool_count=0

  if [[ "${tool_count}" -eq 1 ]]; then
    _pass "tools/list — returns ${tool_count} tool (expected 1)"
  else
    _fail "tools/list — returns ${tool_count} tools (expected 1)"
  fi

  # Verify each expected tool is present by name
  local tool
  for tool in "${expected_tools[@]}"; do
    local found
    found="$(printf '%s' "${list_resp}" | jq -r --arg name "${tool}" '.result.tools[] | select(.name == $name) | .name' 2>/dev/null)" || found=""
    if [[ "${found}" == "${tool}" ]]; then
      _pass "tools/list — tool '${tool}' present"
    else
      _fail "tools/list — tool '${tool}' present" "not found in tools list"
    fi
  done
}

# ---------------------------------------------------------------------------
# Phase 4 — Tool calls
# ---------------------------------------------------------------------------
phase_tools() {
  section "Phase 4 — Tool calls"

  # --- cortex help ---
  section "  cortex help"
  local help_result
  help_result="$(call_tool cortex '{"action":"help"}')" || help_result=""

  assert_jq "cortex help — help field present"          "${help_result}" '.help'
  assert_jq "cortex help — help text is non-empty"      "${help_result}" '.help | length > 0'
  assert_jq "cortex help — help text contains 'syslog'" "${help_result}" '.help | ascii_downcase | contains("syslog")'

  # --- cortex status ---
  section "  cortex status"
  local status_result
  status_result="$(call_tool cortex '{"action":"status"}')" || status_result=""

  assert_jq "cortex status — status is ok"                    "${status_result}" '.status' "ok"
  assert_jq "cortex status — db_ok field present"             "${status_result}" '.db_ok != null'
  assert_jq "cortex status — runtime_observability present"   "${status_result}" '.runtime_observability'
  assert_jq "cortex status — otlp counters present"           "${status_result}" '.otlp'

  # --- cortex stats ---
  section "  cortex stats"
  local stats_result
  stats_result="$(call_tool cortex '{"action":"stats"}')" || stats_result=""

  assert_jq "cortex stats — total_logs field present"         "${stats_result}" '.total_logs != null'
  assert_jq "cortex stats — total_hosts field present"        "${stats_result}" '.total_hosts != null'
  assert_jq "cortex stats — logical_db_size_mb present"       "${stats_result}" '.logical_db_size_mb'
  assert_jq "cortex stats — physical_db_size_mb present"      "${stats_result}" '.physical_db_size_mb'
  assert_jq "cortex stats — write_blocked field present"      "${stats_result}" '.write_blocked != null'
  assert_jq "cortex stats — total_logs is a number >= 0"      "${stats_result}" '.total_logs >= 0'
  assert_jq "cortex stats — total_hosts is a number >= 0"     "${stats_result}" '.total_hosts >= 0'

  # --- cortex file_tails ---
  section "  cortex file_tails"
  if mcp_admin_scope_available; then
    local file_tails_result
    file_tails_result="$(call_tool cortex '{"action":"file_tails","op":"status"}')" || file_tails_result=""
    assert_jq "cortex file_tails — sources array present"       "${file_tails_result}" '.sources | type == "array"'
    assert_jq "cortex file_tails — statuses array present"      "${file_tails_result}" '.statuses | type == "array"'
    # Invalid params now come back as a structured tool-level error
    # (isError result with a JSON body), not a JSON-RPC-level failure —
    # see fix(mcp): return structured validation errors.
    local file_tails_missing_op
    file_tails_missing_op="$(call_tool cortex '{"action":"file_tails"}')" || file_tails_missing_op=""
    assert_jq "cortex file_tails — missing op rejected"             "${file_tails_missing_op}" '.kind' "invalid_param"
    assert_jq "cortex file_tails — missing op rejected mentions op" "${file_tails_missing_op}" '.message | contains("op")' "true"
    if file_tail_smoke_available; then
      local server_path write_path source_id tag marker add_result search_result count attempt
      server_path="${CORTEX_FILE_TAIL_SMOKE_PATH:-${FILE_TAIL_SMOKE_SERVER_PATH}}"
      write_path="${CORTEX_FILE_TAIL_SMOKE_WRITE_PATH:-${FILE_TAIL_SMOKE_HOST_PATH:-${server_path}}}"
      source_id="smoke-${CONTAINER_NAME:-$$}"
      tag="file-tail-smoke"
      marker="file-tail-smoke-${CONTAINER_NAME:-$$}"
      touch "${write_path}" || _fail "cortex file_tails — smoke file writable" "could not write ${write_path}"
      add_result="$(call_tool cortex "$(jq -nc \
        --arg id "${source_id}" \
        --arg path "${server_path}" \
        --arg tag "${tag}" \
        '{"action":"file_tails","op":"add","id":$id,"path":$path,"tag":$tag,"host":"live-smoke","facility":"local7","severity":"info","start_at_end":true}')")" || add_result=""
      assert_jq "cortex file_tails — add smoke source" "${add_result}" '.sources | type == "array"'
      printf '%s\n' "${marker}" >> "${write_path}"
      count=0
      for attempt in {1..20}; do
        search_result="$(call_tool cortex "$(jq -nc \
          --arg q "\"${marker}\"" \
          --arg tag "${tag}" \
          '{"action":"search","query":$q,"source_kind":"file-tail","app":$tag,"limit":5}')")" || search_result=""
        count="$(printf '%s' "${search_result}" | jq -r '.count // 0' 2>/dev/null)" || count=0
        [[ "${count}" -ge 1 ]] && break
        sleep 0.5
      done
      if [[ "${count}" -ge 1 ]]; then
        _pass "cortex file_tails — add append query ingest"
      else
        _fail "cortex file_tails — add append query ingest" "marker was not queryable"
      fi
      call_tool cortex "$(jq -nc --arg id "${source_id}" '{"action":"file_tails","op":"remove","id":$id}')" >/dev/null 2>&1 || true
    else
      _skip "cortex file_tails — add append query ingest" "requires CORTEX_FILE_TAIL_SMOKE_PATH"
    fi
  else
    _skip "cortex file_tails — registry status" "requires cortex:admin (set CORTEX_STATIC_TOKEN_ADMIN=true or CORTEX_SMOKE_ADMIN=true)"
  fi

  # --- compose diagnostics ---
  section "  cortex compose diagnostics"
  local compose_status_result
  compose_status_result="$(call_tool cortex '{"action":"compose_status"}')" || compose_status_result=""
  assert_jq "cortex compose_status — runtime_state present" "${compose_status_result}" '.runtime_state'
  assert_jq "cortex compose_status — no host working dir leaks" "${compose_status_result}" 'has("compose_working_dir") | not'
  assert_jq "cortex compose_status — no image id leaks" "${compose_status_result}" 'has("image_id") | not'
  local compose_runtime compose_ownership
  compose_runtime="$(printf '%s' "${compose_status_result}" | jq -r '.runtime_state // "unknown"' 2>/dev/null)" || compose_runtime="unknown"
  compose_ownership="$(printf '%s' "${compose_status_result}" | jq -r '.ownership // "unknown"' 2>/dev/null)" || compose_ownership="unknown"
  if [[ "${compose_runtime}" != "docker_unavailable" && "${compose_ownership}" == "compose_owned" ]]; then
    assert_jq "cortex compose_status — ownership known" "${compose_status_result}" '.ownership != "unknown"'
    assert_jq "cortex compose_status — no unsafe diagnostics" "${compose_status_result}" '[.diagnostics[]?.severity] | all(. != "error" and . != "unsafe")'

    local compose_doctor_result
    compose_doctor_result="$(call_tool cortex '{"action":"compose_doctor"}')" || compose_doctor_result=""
    assert_jq "cortex compose_doctor — ownership present" "${compose_doctor_result}" '.ownership'
    assert_jq "cortex compose_doctor — runtime_state present" "${compose_doctor_result}" '.runtime_state'
    assert_jq "cortex compose_doctor — no unsafe diagnostics" "${compose_doctor_result}" '[.diagnostics[]?.severity] | all(. != "error" and . != "unsafe")'
  else
    _skip "cortex compose_status strict diagnostics" "runtime=${compose_runtime}, ownership=${compose_ownership}"
    _skip "cortex compose_doctor strict diagnostics" "runtime=${compose_runtime}, ownership=${compose_ownership}"
  fi

  # --- cortex hosts ---
  section "  cortex hosts"
  local hosts_result
  hosts_result="$(call_tool cortex '{"action":"hosts"}')" || hosts_result=""

  assert_jq "cortex hosts — hosts field is an array"       "${hosts_result}" '.hosts | type' "array"

  # Structure check (only if hosts are present — may be empty in CI with no cortex data)
  local host_count
  host_count="$(printf '%s' "${hosts_result}" | jq '.hosts | length' 2>/dev/null)" || host_count=0

  if [[ "${host_count}" -gt 0 ]]; then
    assert_jq "cortex hosts — entry has hostname field"  "${hosts_result}" '.hosts[0].hostname'
    assert_jq "cortex hosts — entry has log_count field" "${hosts_result}" '.hosts[0].log_count != null'
    assert_jq "cortex hosts — entry has first_seen field" "${hosts_result}" '.hosts[0].first_seen'
    assert_jq "cortex hosts — entry has last_seen field"  "${hosts_result}" '.hosts[0].last_seen'
  else
    _skip "cortex hosts — entry field validation" "no hosts in DB (no cortex data ingested)"
  fi

  # --- cortex map ---
  section "  cortex map"
  local map_result
  map_result="$(call_tool cortex '{"action":"map"}')" || map_result=""

  assert_jq "cortex map — schema is v2" "${map_result}" '.schema' "cortex.homelab_map.v2"
  assert_jq "cortex map — summary field present" "${map_result}" '.summary'
  assert_jq "cortex map — nodes field is array" "${map_result}" '.nodes | type' "array"
  assert_jq "cortex map — cache status field present" "${map_result}" '.cache_status'
  assert_jq "cortex map — services field is array" "${map_result}" '.services | type' "array"
  assert_jq "cortex map — compose projects field is array" "${map_result}" '.compose_projects | type' "array"
  assert_jq "cortex map — reverse proxies field is array" "${map_result}" '.reverse_proxies | type' "array"
  assert_jq "cortex map — networks field is array" "${map_result}" '.networks | type' "array"
  assert_jq "cortex map — storage field is array" "${map_result}" '.storage | type' "array"
  assert_jq "cortex map — media services field is array" "${map_result}" '.media_services | type' "array"
  assert_jq "cortex map — projects field is array" "${map_result}" '.projects | type' "array"
  assert_jq "cortex map — artifact refs field is array" "${map_result}" '.artifact_refs | type' "array"
  assert_jq "cortex map — collection errors field is array" "${map_result}" '.collection_errors | type' "array"
  assert_jq "cortex map — cortex overlay field present" "${map_result}" '.cortex_overlay'

  # --- cortex sessions ---
  section "  cortex sessions"
  local sessions_result
  sessions_result="$(call_tool cortex '{"action":"sessions","limit":10}')" || sessions_result=""

  assert_jq "cortex sessions — count field present" "${sessions_result}" '.count != null'
  assert_jq "cortex sessions — sessions field is array" "${sessions_result}" '.sessions | type' "array"
  if [[ "${AI_SEEDED}" == true ]]; then
    # The unbounded sessions action intentionally reads a periodically refreshed
    # rollup. Query the seeded fixture through an explicit time window so this
    # assertion uses the exact live path instead of racing rollup refresh timing.
    local seeded_sessions_result
    seeded_sessions_result="$(call_tool cortex "$(jq -nc \
      --arg project "${AI_SMOKE_PROJECT}" \
      '{"action":"sessions","project":$project,"since":"2026-05-11T00:00:00Z","until":"2026-05-13T00:00:00Z","limit":10}')")" \
      || seeded_sessions_result=""
    assert_jq "cortex sessions — seeded AI project appears" "${seeded_sessions_result}" \
      "any(.sessions[]?; .project == \"${AI_SMOKE_PROJECT}\")" "true"
  fi

  local search_sessions_result
  search_sessions_result="$(call_tool cortex "$(jq -nc --arg q "${AI_SMOKE_QUERY}" '{"action":"search_sessions","query":$q,"limit":10}')")" || search_sessions_result=""
  assert_jq "cortex search_sessions — total_candidates present" "${search_sessions_result}" '.total_candidates != null'
  assert_jq "cortex search_sessions — sessions field is array" "${search_sessions_result}" '.sessions | type' "array"
  if [[ "${AI_SEEDED}" == true ]]; then
    assert_jq "cortex search_sessions — seeded fixture is searchable" "${search_sessions_result}" '.total_candidates >= 1' "true"
  fi

  local abuse_result
  abuse_result="$(call_tool cortex "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" --arg term "ai-smoke-authentication" '{"action":"abuse","project":$project,"terms":[$term],"limit":5,"before":1,"after":1}')")" || abuse_result=""
  assert_jq "cortex abuse — terms field is array" "${abuse_result}" '.terms | type' "array"
  assert_jq "cortex abuse — matches field is array" "${abuse_result}" '.matches | type' "array"
  if [[ "${AI_SEEDED}" == true ]]; then
    assert_jq "cortex abuse — custom detector finds seeded fixture" "${abuse_result}" '.matches | length >= 1' "true"
  fi

  local abuse_incidents_result
  abuse_incidents_result="$(call_tool cortex "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" '{"action":"abuse_incidents","project":$project,"limit":5}')")" || abuse_incidents_result=""
  assert_jq "cortex abuse_incidents — incidents field is array" "${abuse_incidents_result}" '.incidents | type' "array"
  assert_jq "cortex abuse_incidents — total_incidents present" "${abuse_incidents_result}" '.total_incidents != null'

  local abuse_investigate_result
  abuse_investigate_result="$(call_tool cortex "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" '{"action":"abuse_investigate","project":$project,"limit":1}')")" || abuse_investigate_result=""
  assert_jq "cortex abuse_investigate — evidence field is array" "${abuse_investigate_result}" '.evidence | type' "array"
  assert_jq "cortex abuse_investigate — total_incidents present" "${abuse_investigate_result}" '.total_incidents != null'

  local ai_correlate_result
  ai_correlate_result="$(call_tool cortex "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" '{"action":"ai_correlate","project":$project,"limit":2,"events_per_anchor":3}')")" || ai_correlate_result=""
  assert_jq "cortex ai_correlate — anchors field is array" "${ai_correlate_result}" '.anchors | type' "array"
  assert_jq "cortex ai_correlate — total_related_events present" "${ai_correlate_result}" '.total_related_events != null'

  local topic_correlate_result
  topic_correlate_result="$(call_tool cortex "$(jq -nc --arg topic "${AI_SMOKE_PROJECT}" '{"action":"topic_correlate","topic":$topic,"limit":5}')")" || topic_correlate_result=""
  assert_jq "cortex topic_correlate — timeline field is array" "${topic_correlate_result}" '.timeline | type' "array"
  assert_jq "cortex topic_correlate — resolved_entities present" "${topic_correlate_result}" '.resolved_entities != null'

  local usage_blocks_result
  usage_blocks_result="$(call_tool cortex '{"action":"usage_blocks"}')" || usage_blocks_result=""
  assert_jq "cortex usage_blocks — blocks field is array" "${usage_blocks_result}" '.blocks | type' "array"
  assert_jq "cortex usage_blocks — truncated field present" "${usage_blocks_result}" '.truncated != null'

  local project_context_result
  project_context_result="$(call_tool cortex "$(jq -nc --arg project "${AI_SMOKE_PROJECT}" '{"action":"project_context","project":$project,"limit":5}')")" || project_context_result=""
  assert_jq "cortex project_context — project field present" "${project_context_result}" '.project' "${AI_SMOKE_PROJECT}"
  assert_jq "cortex project_context — recent_entries field is array" "${project_context_result}" '.recent_entries | type' "array"
  if [[ "${AI_SEEDED}" == true ]]; then
    assert_jq "cortex project_context — seeded fixture has entries" "${project_context_result}" '.recent_entries | length >= 1' "true"
  fi

  local ai_tools_result
  ai_tools_result="$(call_tool cortex '{"action":"list_ai_tools"}')" || ai_tools_result=""
  assert_jq "cortex list_ai_tools — tools field is array" "${ai_tools_result}" '.tools | type' "array"

  local ai_projects_result
  ai_projects_result="$(call_tool cortex '{"action":"list_ai_projects"}')" || ai_projects_result=""
  assert_jq "cortex list_ai_projects — projects field is array" "${ai_projects_result}" '.projects | type' "array"

  # --- cortex search ---
  section "  cortex search"
  local search_result
  search_result="$(call_tool cortex '{"action":"search","query":"error","limit":10}')" || search_result=""

  assert_jq "cortex search — count field present"   "${search_result}" '.count != null'
  assert_jq "cortex search — logs field is array"   "${search_result}" '.logs | type' "array"
  assert_jq "cortex search — count is number >= 0"  "${search_result}" '.count >= 0'

  local log_count
  log_count="$(printf '%s' "${search_result}" | jq '.logs | length' 2>/dev/null)" || log_count=0
  if [[ "${log_count}" -gt 0 ]]; then
    assert_jq "cortex search — log entry has message field"   "${search_result}" '.logs[0].message'
    assert_jq "cortex search — log entry has hostname field"  "${search_result}" '.logs[0].hostname'
    assert_jq "cortex search — log entry has severity field"  "${search_result}" '.logs[0].severity'
    assert_jq "cortex search — log entry has timestamp field" "${search_result}" '.logs[0].timestamp'
  else
    _skip "cortex search — log entry field validation" "no matching logs (empty DB)"
  fi

  # cortex search with no query (list recent)
  local search_noq
  search_noq="$(call_tool cortex '{"action":"search","limit":5}')" || search_noq=""
  assert_jq "cortex search (no query) — count field present" "${search_noq}" '.count != null'
  assert_jq "cortex search (no query) — logs field is array" "${search_noq}" '.logs | type' "array"

  # --- cortex filter ---
  section "  cortex filter"
  local filter_result
  filter_result="$(call_tool cortex '{"action":"filter","limit":5}')" || filter_result=""
  assert_jq "cortex filter — count field present" "${filter_result}" '.count != null'
  assert_jq "cortex filter — logs field is array" "${filter_result}" '.logs | type' "array"

  # --- cortex errors ---
  section "  cortex errors"
  local errors_result
  errors_result="$(call_tool cortex '{"action":"errors"}')" || errors_result=""

  assert_jq "cortex errors — summary field is array" "${errors_result}" '.summary | type' "array"

  local err_count
  err_count="$(printf '%s' "${errors_result}" | jq '.summary | length' 2>/dev/null)" || err_count=0
  if [[ "${err_count}" -gt 0 ]]; then
    assert_jq "cortex errors — entry has hostname field" "${errors_result}" '.summary[0].hostname'
    assert_jq "cortex errors — entry has severity field" "${errors_result}" '.summary[0].severity'
    assert_jq "cortex errors — entry has count field"    "${errors_result}" '.summary[0].count != null'
  else
    _skip "cortex errors — entry field validation" "no error-level logs in DB"
  fi

  # --- cortex tail ---
  section "  cortex tail"
  local tail_result
  tail_result="$(call_tool cortex '{"action":"tail","n":10}')" || tail_result=""

  assert_jq "cortex tail — count field present"   "${tail_result}" '.count != null'
  assert_jq "cortex tail — logs field is array"   "${tail_result}" '.logs | type' "array"
  assert_jq "cortex tail — count is number >= 0"  "${tail_result}" '.count >= 0'

  local tail_count
  tail_count="$(printf '%s' "${tail_result}" | jq '.logs | length' 2>/dev/null)" || tail_count=0
  if [[ "${tail_count}" -gt 0 ]]; then
    assert_jq "cortex tail — entry has message field"   "${tail_result}" '.logs[0].message'
    assert_jq "cortex tail — entry has hostname field"  "${tail_result}" '.logs[0].hostname'
    assert_jq "cortex tail — entry has severity field"  "${tail_result}" '.logs[0].severity'
    assert_jq "cortex tail — entry has timestamp field" "${tail_result}" '.logs[0].timestamp'
  else
    _skip "cortex tail — entry field validation" "no logs in DB"
  fi

  # --- cortex correlate ---
  section "  cortex correlate"
  local ref_time
  ref_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local correlate_result
  correlate_result="$(call_tool cortex \
    "$(jq -nc --arg t "${ref_time}" '{"action":"correlate","reference_time":$t,"window_minutes":5,"severity_min":"debug","limit":50}')")" \
    || correlate_result=""

  assert_jq "cortex correlate — reference_time present"  "${correlate_result}" '.reference_time'
  assert_jq "cortex correlate — window_minutes present"  "${correlate_result}" '.window_minutes != null'
  assert_jq "cortex correlate — window_from present"     "${correlate_result}" '.window_from'
  assert_jq "cortex correlate — window_to present"       "${correlate_result}" '.window_to'
  assert_jq "cortex correlate — hosts field is array"    "${correlate_result}" '.hosts | type' "array"
  assert_jq "cortex correlate — total_events >= 0"       "${correlate_result}" '.total_events >= 0'
  assert_jq "cortex correlate — truncated field present" "${correlate_result}" '.truncated != null'
}

# ---------------------------------------------------------------------------
# Docker mode — build, start, test, teardown
# ---------------------------------------------------------------------------
docker_cleanup() {
  if docker inspect "${CONTAINER_NAME}" &>/dev/null 2>&1; then
    log_info "Removing test container ${CONTAINER_NAME}..."
    docker rm -f "${CONTAINER_NAME}" &>/dev/null || true
  fi
  if [[ -n "${FILE_TAIL_SMOKE_DIR}" && -d "${FILE_TAIL_SMOKE_DIR}" ]]; then
    rm -rf "${FILE_TAIL_SMOKE_DIR}"
  fi
}

run_docker_mode() {
  local project_dir
  project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

  log_info "Project dir: ${project_dir}"
  log_info "Image:       ${IMAGE_NAME}"
  log_info "Container:   ${CONTAINER_NAME}"

  # Register cleanup on exit
  trap docker_cleanup EXIT INT TERM

  # Build image
  section "Docker — Build"
  log_info "Building Docker image ${IMAGE_NAME}..."
  if ! docker build -f "${project_dir}/config/Dockerfile" -t "${IMAGE_NAME}" "${project_dir}"; then
    log_error "Docker build failed"
    return 2
  fi
  log_info "Docker build succeeded"

  # Start container
  section "Docker — Start"
  local docker_args=(
    "--name" "${CONTAINER_NAME}"
    "--detach"
    "--rm"
    # Expose MCP HTTP port
    "-p" "0:3100"
    # Use a tmpfs for SQLite (no volume needed for CI)
    # uid=1000,gid=1000 matches the 'syslog' user in the container image
    "--tmpfs" "/data:rw,noexec,nosuid,size=64m,uid=1000,gid=1000"
  )
  FILE_TAIL_SMOKE_DIR="$(mktemp -d /tmp/cortex-file-tail-smoke.XXXXXX)"
  FILE_TAIL_SMOKE_HOST_PATH="${FILE_TAIL_SMOKE_DIR}/smoke.log"
  : > "${FILE_TAIL_SMOKE_HOST_PATH}"
  chmod 755 "${FILE_TAIL_SMOKE_DIR}"
  chmod 644 "${FILE_TAIL_SMOKE_HOST_PATH}"
  docker_args+=("-v" "${FILE_TAIL_SMOKE_DIR}:/file-tail-root:ro")
  CORTEX_FILE_TAIL_SMOKE_PATH="${FILE_TAIL_SMOKE_SERVER_PATH}"
  CORTEX_FILE_TAIL_SMOKE_WRITE_PATH="${FILE_TAIL_SMOKE_HOST_PATH}"

  # /api/* is always mounted post-v0.26, so the container will refuse to
  # start without CORTEX_API_TOKEN. Fail fast here with a clear message
  # instead of leaving the user to debug a crash inside docker run.
  if [[ -z "${TOKEN}" ]]; then
    log_error "TOKEN must be set for docker-mode live tests (the server requires CORTEX_API_TOKEN to start)"
    return 2
  fi
  docker_args+=("-e" "CORTEX_HOST=0.0.0.0")
  docker_args+=("-e" "CORTEX_TOKEN=${TOKEN}")
  docker_args+=("-e" "CORTEX_API_TOKEN=${TOKEN}")
  docker_args+=("-e" "CORTEX_API_ADMIN_TOKEN=${TOKEN}")
  docker_args+=("-e" "CORTEX_STATIC_TOKEN_ADMIN=true")
  CORTEX_STATIC_TOKEN_ADMIN=true
  CORTEX_API_ADMIN_TOKEN="${TOKEN}"

  # Remove storage budget env vars that conflict with tmpfs size limits
  docker_args+=(
    "-e" "CORTEX_MAX_DB_SIZE_MB=0"
    "-e" "CORTEX_RECOVERY_DB_SIZE_MB=0"
    "-e" "CORTEX_MIN_FREE_DISK_MB=0"
    "-e" "CORTEX_RECOVERY_FREE_DISK_MB=0"
  )

  log_info "Starting container..."
  if ! docker run "${docker_args[@]}" "${IMAGE_NAME}"; then
    log_error "docker run failed"
    return 2
  fi
  CLI_PARITY_CONTAINER="${CONTAINER_NAME}"

  # Discover the mapped port (since we used -p 0:3100)
  local mapped_port
  mapped_port="$(docker inspect "${CONTAINER_NAME}" \
    --format '{{(index (index .NetworkSettings.Ports "3100/tcp") 0).HostPort}}' 2>/dev/null)" || mapped_port=""

  if [[ -z "${mapped_port}" ]]; then
    log_warn "Could not detect mapped port — falling back to ${PORT}"
    mapped_port="${PORT}"
  fi

  BASE_URL="http://localhost:${mapped_port}"
  log_info "MCP server at ${BASE_URL}"

  # Poll /health until ready (30 attempts × 1s)
  section "Docker — Wait for health"
  local attempt=0
  local max_attempts=30
  while [[ ${attempt} -lt ${max_attempts} ]]; do
    attempt=$(( attempt + 1 ))
    local health_status
    health_status="$(curl -sf --max-time 3 \
      -H "Accept: application/json, text/event-stream" \
      "${BASE_URL}/health" 2>/dev/null | jq -r '.status' 2>/dev/null)" || health_status=""
    if [[ "${health_status}" == "ok" ]]; then
      log_info "Server healthy after ${attempt}s"
      break
    fi
    if [[ ${attempt} -eq ${max_attempts} ]]; then
      log_error "Server did not become healthy after ${max_attempts}s"
      docker logs "${CONTAINER_NAME}" 2>&1 | tail -30
      return 2
    fi
    sleep 1
  done

  if ! docker exec "${CONTAINER_NAME}" test -r "${FILE_TAIL_SMOKE_SERVER_PATH}"; then
    log_error "file-tail smoke path is not readable in container: ${FILE_TAIL_SMOKE_SERVER_PATH}"
    docker exec "${CONTAINER_NAME}" sh -c 'id; ls -ld /file-tail-root; ls -l /file-tail-root' 2>&1 || true
    return 2
  fi

  section "Docker — Seed AI transcript fixture"
  seed_ai_fixture_container "${project_dir}" || {
    log_error "AI transcript fixture seed failed"
    return 2
  }
  log_info "Seeded AI transcript fixture"

  # Run all test phases
  build_auth_args
  run_test_phases

  # Print summary (trap handles container cleanup)
  print_summary
}

# ---------------------------------------------------------------------------
# HTTP mode — test against already-running server
# ---------------------------------------------------------------------------
run_http_mode() {
  log_info "HTTP mode — testing against ${BASE_URL}"
  build_auth_args
  if [[ "${BASE_URL}" == http://localhost:* || "${BASE_URL}" == http://127.0.0.1:* ]]; then
    seed_ai_fixture_local || {
      log_error "AI transcript fixture seed failed"
      return 2
    }
    log_info "Seeded AI transcript fixture"
  else
    AI_SEEDED=false
    log_info "Skipping local AI fixture seed for non-local HTTP target"
  fi
  run_test_phases
  print_summary
}

# ---------------------------------------------------------------------------
# Wait for the eager hourly timeline rollup before comparing local and HTTP
# transports. The server intentionally performs its first refresh 10 seconds
# after startup; without this gate, the local call can observe the empty rollup
# immediately before the HTTP call observes the freshly populated one.
# ---------------------------------------------------------------------------
wait_for_timeline_rollup() {
  local token="$1"
  local response=""
  local attempt
  for attempt in {1..120}; do
    response="$(curl -sf --max-time 3 \
      -H "Authorization: Bearer ${token}" \
      "${BASE_URL}/api/timeline?bucket=hour" 2>/dev/null || true)"
    if jq -e '.rollup_as_of | select(type == "string" and length > 0)' \
      <<<"${response}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# ---------------------------------------------------------------------------
# Phase 5 — CLI parity (bead cortex-0p8r.10)
# For each HTTP-supported CLI command, run both local + --http transports
# and assert their JSON shapes agree after filtering volatile fields. This
# is the load-bearing check that the cutover (default → HTTP) does not
# silently change query output.
#
# We only run this phase when:
#   - the `syslog` binary is on PATH (host CLI installed)
#   - a CORTEX_API_TOKEN value is available (env or --token arg)
# Otherwise the phase is skipped cleanly with a single SKIP entry.
# ---------------------------------------------------------------------------
phase_cli_parity() {
  section "Phase 5 — CLI parity (local vs --http)"

  local cli_token="${CORTEX_API_TOKEN:-${TOKEN:-}}"
  if [[ -z "${cli_token}" ]]; then
    _skip "cli parity phase" "no CORTEX_API_TOKEN / TOKEN available"
    return 0
  fi

  local cli_bin=""
  if [[ -z "${CLI_PARITY_CONTAINER}" ]]; then
    if ! cli_bin="$(command -v "${CORTEX_BIN:-syslog}" 2>/dev/null)"; then
      _skip "cli parity phase" "cortex binary not on PATH (set CORTEX_BIN)"
      return 0
    fi
  fi

  # jq filter that strips fields known to vary between calls:
  #   - timestamps/dates (server-side `now()`-style fields)
  #   - elapsed_ms / duration counters
  #   - request-scoped ids (run_id, request_id)
  #   - live cgroup counters sampled from transport-specific runtimes
  # Recursively walks the structure, deleting volatile non-contract keys and
  # replacing volatile cgroup values with sentinels so field presence/type
  # drift still fails parity.
  local jq_strip='
    def strip:
      if type == "object" then
        with_entries(
          select(.key | test("^(generated_at|elapsed_ms|duration_ms|started_at|finished_at|request_id|run_id|timestamp|ts|now|free_disk_mb|physical_db_size_mb)$") | not)
          | if (.key | test("^cgroup_memory_(current|peak)_bytes$")) then .value = "__volatile_number_or_null__" else . end
        ) | map_values(strip)
      elif type == "array" then map(strip)
      else . end;
    strip
  '

  # Pair: (label, args...). Each command is run twice and the filtered JSON
  # is diffed. `hosts` is the simplest command and is the canary.
  local pairs=(
    "hosts|hosts"
    "stats|stats"
    "tail -n 1|tail -n 1"
    "analysis errors|analysis errors"
    "search --limit 1|search --limit 1"
    "sessions --limit 1|sessions --limit 1"
    "db status|db status"
    # Surface parity (2026-05-21)
    "hosts sources --limit 3|hosts sources --limit 3"
    "timeline --bucket hour|timeline --bucket hour"
    "analysis patterns --top-n 5|analysis patterns --top-n 5"
    "stats ingestrate|stats ingestrate"
    "alerts signatures --limit 5|alerts signatures --limit 5"
    "alerts notifications --limit 5|alerts notifications --limit 5"
  )

  local pair label args local_out http_out filtered_local filtered_http diff
  for pair in "${pairs[@]}"; do
    label="${pair%%|*}"
    args="${pair#*|}"
    if [[ "${label}" == "timeline --bucket hour" ]] \
      && ! wait_for_timeline_rollup "${cli_token}"; then
      _fail "cli parity: ${label} (timeline rollup not ready after 120s)"
      continue
    fi
    if [[ -n "${CLI_PARITY_CONTAINER}" ]]; then
      # shellcheck disable=SC2086  # word splitting on $args is intentional
      local_out="$(docker exec "${CLI_PARITY_CONTAINER}" env -u CORTEX_USE_HTTP RUST_LOG=off cortex ${args} --json 2>&1)"
    else
      # shellcheck disable=SC2086  # word splitting on $args is intentional
      local_out="$(env -u CORTEX_USE_HTTP RUST_LOG=off "${cli_bin}" ${args} --json 2>&1)"
    fi
    if [[ $? -ne 0 ]]; then
      _fail "cli parity: local ${label} (exit non-zero)"
      printf '  stderr: %s\n' "${local_out:0:300}" >&2
      continue
    fi
    if [[ -n "${CLI_PARITY_CONTAINER}" ]]; then
      # shellcheck disable=SC2086  # word splitting on $args is intentional
      http_out="$(docker exec "${CLI_PARITY_CONTAINER}" env RUST_LOG=off cortex --http --server "http://127.0.0.1:3100" --token "${cli_token}" ${args} --json 2>&1)"
    else
      # shellcheck disable=SC2086
      http_out="$(RUST_LOG=off "${cli_bin}" --http --server "${BASE_URL}" --token "${cli_token}" ${args} --json 2>&1)"
    fi
    if [[ $? -ne 0 ]]; then
      _fail "cli parity: http ${label} (exit non-zero)"
      printf '  stderr: %s\n' "${http_out:0:300}" >&2
      continue
    fi
    if ! filtered_local="$(jq -S "${jq_strip}" <<<"${local_out}" 2>/dev/null)"; then
      _fail "cli parity: local ${label} (stdout not JSON)"
      continue
    fi
    if ! filtered_http="$(jq -S "${jq_strip}" <<<"${http_out}" 2>/dev/null)"; then
      _fail "cli parity: http ${label} (stdout not JSON)"
      continue
    fi
    if diff="$(diff <(printf '%s\n' "${filtered_local}") <(printf '%s\n' "${filtered_http}"))"; then
      _pass "cli parity: ${label}"
    else
      _fail "cli parity: ${label} (filtered JSON differs)"
      printf '  diff (truncated):\n%s\n' "$(printf '%s\n' "${diff}" | head -20)" >&2
    fi
  done
}

# ---------------------------------------------------------------------------
# Phase 6 — Surface parity REST routes
#
# Smoke-checks the routes added by the 2026-05-21 surface-parity plan. Just
# verifies each route returns 200 with a well-formed JSON body — the cli-
# parity phase already proves the body matches the local SQLite path.
# ---------------------------------------------------------------------------
phase_surface_parity_rest() {
  section "Phase 6 — Surface parity REST routes"

  if [[ -z "${TOKEN}" ]]; then
    _skip "surface parity REST phase" "no TOKEN configured"
    return 0
  fi

  build_auth_args

  # Error-signature mutation and notification-test routes require seeded
  # signatures or external service availability and stay covered by unit tests
  # in src/api_tests.rs and src/app/service.rs. The file-tail route is a
  # deterministic admin POST path, so smoke covers status/list when
  # CORTEX_API_ADMIN_TOKEN is available.
  local routes=(
    "GET /api/source-ips?limit=3|source_ips"
    "GET /api/timeline?bucket=hour|points"
    "GET /api/patterns?top_n=5|patterns"
    "GET /api/ingest-rate|buckets"
    "GET /api/get?id=1|log"
    "GET /api/errors/unaddressed?limit=5|signatures"
    "GET /api/notifications/recent?limit=5|"
    # 2026-05-22 surface-parity gap closure
    "GET /api/silent-hosts?silent_minutes=60|hosts"
    "GET /api/clock-skew|hosts"
    "GET /api/anomalies|hosts"
    "GET /api/apps?limit=10|apps"
    "GET /api/similar-incidents?query=test&window_minutes=30|clusters"
    "GET /api/incident-context?since=2026-01-01T00:00:00Z&until=2026-12-31T23:59:59Z|error_logs"
    "GET /api/sessions/incidents?limit=5|incidents"
    "GET /api/sessions/investigate?limit=5|evidence"
  )

  local route_pair label path field response
  for route_pair in "${routes[@]}"; do
    label="${route_pair%%|*}"
    field="${route_pair##*|}"
    path="${label#GET }"
    response="$(curl -sf --max-time 10 "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" "${BASE_URL}${path}" 2>&1)" || {
      _fail "${label}" "curl failed: ${response:0:200}"
      continue
    }
    if ! printf '%s' "${response}" | jq -e '.' >/dev/null 2>&1; then
      _fail "${label}" "response not valid JSON: ${response:0:200}"
      continue
    fi
    if [[ -n "${field}" ]]; then
      assert_jq "${label} — ${field} field present" "${response}" ".${field} != null"
    else
      # /api/notifications/recent returns a JSON array directly
      assert_jq "${label} — response is array" "${response}" 'type' "array"
    fi
  done

  local removed_path status
  for removed_path in \
    "/api/ai/ask-history?query=test" \
    "/api/ai/incidents?limit=5" \
    "/api/ai/investigate?limit=5"; do
    status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" "${BASE_URL}${removed_path}" 2>/dev/null || true)"
    if [[ "${status}" == "404" ]]; then
      _pass "clean break: ${removed_path} returns 404"
    else
      _fail "clean break: ${removed_path} returns 404" "got HTTP ${status}"
    fi
  done

  if [[ -n "${CORTEX_API_ADMIN_TOKEN:-}" ]]; then
    local admin_body admin_response
    for admin_body in '{"op":"status"}' '{"op":"list"}'; do
      admin_response="$(curl -sf --max-time 10 \
        "${AUTH_ARGS[@]+"${AUTH_ARGS[@]}"}" \
        -H "X-Cortex-Admin-Token: ${CORTEX_API_ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "${admin_body}" \
        "${BASE_URL}/api/file-tails" 2>&1)" || {
          _fail "POST /api/file-tails ${admin_body}" "curl failed: ${admin_response:0:200}"
          continue
        }
      assert_jq "POST /api/file-tails ${admin_body} — sources array present" "${admin_response}" '.sources | type' "array"
      assert_jq "POST /api/file-tails ${admin_body} — statuses array present" "${admin_response}" '.statuses | type' "array"
    done
  else
    _skip "POST /api/file-tails admin smoke" "requires CORTEX_API_ADMIN_TOKEN"
  fi
}

# ---------------------------------------------------------------------------
# Run all test phases
# ---------------------------------------------------------------------------
run_test_phases() {
  phase_health
  phase_auth
  phase_protocol
  phase_tools
  phase_cli_parity
  phase_surface_parity_rest
}

# ---------------------------------------------------------------------------
# Print final summary
# ---------------------------------------------------------------------------
print_summary() {
  local total=$(( PASS_COUNT + FAIL_COUNT + SKIP_COUNT ))
  printf '\n%b%s%b\n' "${C_BOLD}" "$(printf '=%.0s' {1..65})" "${C_RESET}"
  printf '%b%-20s%b  %b%d%b\n' "${C_BOLD}" "PASS"  "${C_RESET}" "${C_GREEN}"  "${PASS_COUNT}"  "${C_RESET}"
  printf '%b%-20s%b  %b%d%b\n' "${C_BOLD}" "FAIL"  "${C_RESET}" "${C_RED}"    "${FAIL_COUNT}"  "${C_RESET}"
  printf '%b%-20s%b  %b%d%b\n' "${C_BOLD}" "SKIP"  "${C_RESET}" "${C_YELLOW}" "${SKIP_COUNT}"  "${C_RESET}"
  printf '%b%-20s%b  %d\n'     "${C_BOLD}" "TOTAL" "${C_RESET}"               "${total}"
  printf '%b%s%b\n' "${C_BOLD}" "$(printf '=%.0s' {1..65})" "${C_RESET}"

  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    printf '\n%bFailed tests:%b\n' "${C_RED}" "${C_RESET}"
    local name
    for name in "${FAIL_NAMES[@]}"; do
      printf '  • %s\n' "${name}"
    done
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  parse_args "$@"

  printf '%b%s%b\n'                 "${C_BOLD}" "$(printf '=%.0s' {1..65})" "${C_RESET}"
  printf '%b  cortex integration tests%b\n' "${C_BOLD}" "${C_RESET}"
  printf '%b  Mode:    %s%b\n'      "${C_BOLD}" "${MODE}" "${C_RESET}"
  printf '%b  URL:     %s%b\n'      "${C_BOLD}" "${BASE_URL}" "${C_RESET}"
  printf '%b  Token:   %s%b\n'      "${C_BOLD}" "${TOKEN:+(set)}" "${C_RESET}"
  printf '%b%s%b\n\n'               "${C_BOLD}" "$(printf '=%.0s' {1..65})" "${C_RESET}"

  check_prerequisites || exit 2

  case "${MODE}" in
    docker) run_docker_mode || exit 2 ;;
    http)   run_http_mode              ;;
    *)
      log_error "Unknown mode '${MODE}' — use docker|http|all"
      exit 2
      ;;
  esac

  if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

main "$@"
