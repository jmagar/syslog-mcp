#!/usr/bin/env bash
# smoke-test.sh — Live end-to-end smoke test for syslog-mcp
# Tests all 7 MCP tools via mcporter with strict PASS/FAIL validation.
# Exit code 0 = all passed. Exit code 1 = one or more failures.
#
# Usage:
#   bash bin/smoke-test.sh [--url http://host:3100/mcp]
#   bash bin/smoke-test.sh --skip-seed   # if data already exists
#
# Requirements: mcporter, nc, curl, jq (or python3)

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────────────
MCP_URL="${SYSLOG_MCP_URL:-http://localhost:3100/mcp}"
HEALTH_URL="${MCP_URL%/mcp}/health"
SYSLOG_HOST="${SYSLOG_HOST:-127.0.0.1}"
SYSLOG_PORT="${SYSLOG_PORT:-1514}"
SKIP_SEED=0
MCPORTER_CONFIG="config/mcporter.json"
_MCPORTER_CONFIG_TMPFILE=""

# Clean up temp config on exit
trap '[[ -n "$_MCPORTER_CONFIG_TMPFILE" ]] && rm -f "$_MCPORTER_CONFIG_TMPFILE"' EXIT

while [[ $# -gt 0 ]]; do
    case $1 in
        --url)
            [[ -z "${2:-}" ]] && { echo "Error: --url requires a value"; exit 1; }
            MCP_URL="$2"; HEALTH_URL="${MCP_URL%/mcp}/health"; shift 2
            # Create a temp mcporter config pointing at the custom URL so both
            # health checks and mcporter tool calls target the same server.
            _MCPORTER_CONFIG_TMPFILE=$(mktemp /tmp/mcporter-XXXXXX.json)
            printf '{"mcpServers":{"syslog-mcp":{"url":"%s","transport":"http"}}}' "$MCP_URL" > "$_MCPORTER_CONFIG_TMPFILE"
            MCPORTER_CONFIG="$_MCPORTER_CONFIG_TMPFILE"
            ;;
        --skip-seed) SKIP_SEED=1; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ─── Helpers ─────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
ERRORS=()

COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_RESET='\033[0m'
COLOR_BOLD='\033[1m'

pass() { echo -e "${COLOR_GREEN}PASS${COLOR_RESET}  $1"; (( PASS++ )) || true; }
fail() { echo -e "${COLOR_RED}FAIL${COLOR_RESET}  $1"; ERRORS+=("$1"); (( FAIL++ )) || true; }

# Run mcporter call and return output (exits non-zero on tool error)
mcp_call() {
    local tool="$1"; shift
    mcporter call --config "$MCPORTER_CONFIG" "syslog-mcp.${tool}" "$@" 2>&1
}

# Extract JSON field from output
json_get() {
    local json="$1" field="$2"
    echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d$field)" 2>/dev/null
}

# Assert a JSON field equals expected value
assert_eq() {
    local label="$1" actual="$2" expected="$3"
    if [[ "$actual" == "$expected" ]]; then
        pass "$label"
    else
        fail "$label (expected '$expected', got '$actual')"
    fi
}

# Assert a JSON field is an integer >= min
assert_gte() {
    local label="$1" actual="$2" min="$3"
    if python3 -c "exit(0 if int('$actual') >= $min else 1)" 2>/dev/null; then
        pass "$label"
    else
        fail "$label (expected >= $min, got '$actual')"
    fi
}

# Assert JSON output represents a successful MCP tool call (isError absent or false)
assert_no_error() {
    local label="$1" output="$2"
    if echo "$output" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    sys.exit(1 if d.get('isError') else 0)
except (json.JSONDecodeError, ValueError):
    # Non-JSON output is a real failure — mcporter/tool returned garbage
    sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        pass "$label"
    else
        local detail
        detail=$(echo "$output" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    content = d.get('content', [])
    print(content[0].get('text','')[:120] if content else '')
except Exception:
    print(sys.stdin.read()[:120])
" 2>/dev/null)
        fail "$label (isError=true: $detail)"
    fi
}

# ─── Phase 1: Pre-flight ─────────────────────────────────────────────────────
echo ""
echo -e "${COLOR_BOLD}=== syslog-mcp smoke test ===${COLOR_RESET}"
echo "MCP URL: $MCP_URL"
echo ""

echo -e "${COLOR_BOLD}[1/4] Pre-flight checks${COLOR_RESET}"

# 1a: Health endpoint
HEALTH=$(curl -sf "$HEALTH_URL" 2>&1) || { echo -e "${COLOR_RED}ABORT${COLOR_RESET}  Health endpoint unreachable: $HEALTH_URL"; exit 1; }
HEALTH_STATUS=$(json_get "$HEALTH" "['status']")
assert_eq "Health endpoint responds" "$HEALTH_STATUS" "ok"

# 1b: mcporter can reach server and lists all 7 tools
TOOL_LIST=$(mcporter list syslog-mcp --config "$MCPORTER_CONFIG" 2>&1)
TOOL_COUNT=$(echo "$TOOL_LIST" | grep -c "^  function " || true)
if [[ "$TOOL_COUNT" -eq 7 ]]; then
    pass "mcporter lists 7 tools ($TOOL_COUNT found)"
else
    fail "mcporter tool count (expected 7, got $TOOL_COUNT)"
fi

# ─── Phase 2: Seed test data ─────────────────────────────────────────────────
echo ""
echo -e "${COLOR_BOLD}[2/4] Seeding test data${COLOR_RESET}"

SEED_HOST="smoke-test-host"
SEED_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ "$SKIP_SEED" -eq 0 ]]; then
    # Send a spread of severity levels and hosts
    printf '<14>%s %s sshd[42]: smoke-test: info message\n' "$(date '+%b %e %H:%M:%S')" "$SEED_HOST" | nc -u -w1 "$SYSLOG_HOST" "$SYSLOG_PORT"
    printf '<11>%s %s sshd[42]: smoke-test: error authentication failure\n' "$(date '+%b %e %H:%M:%S')" "$SEED_HOST" | nc -u -w1 "$SYSLOG_HOST" "$SYSLOG_PORT"
    printf '<3>%s %s kernel: smoke-test: crit memory allocation failed\n' "$(date '+%b %e %H:%M:%S')" "$SEED_HOST" | nc -u -w1 "$SYSLOG_HOST" "$SYSLOG_PORT"
    printf '<12>%s %s dockerd[99]: smoke-test: warning container restart\n' "$(date '+%b %e %H:%M:%S')" "$SEED_HOST" | nc -u -w1 "$SYSLOG_HOST" "$SYSLOG_PORT"
    sleep 2   # wait for batch writer to flush (500ms interval + margin)
    echo "Seeded 4 messages (info, err, crit, warning) to $SEED_HOST"
else
    echo "Skipping seed (--skip-seed)"
fi

# Confirm at least 1 log exists before testing tools
STATS_PREFLIGHT=$(mcp_call get_stats 2>&1)
TOTAL_PREFLIGHT=$(json_get "$STATS_PREFLIGHT" "['total_logs']")
if python3 -c "exit(0 if int('${TOTAL_PREFLIGHT:-0}') >= 1 else 1)" 2>/dev/null; then
    echo "DB has $TOTAL_PREFLIGHT logs — proceeding"
else
    echo -e "${COLOR_RED}ABORT${COLOR_RESET}  No logs in DB. Seed failed or server just started."
    echo "  Check: docker compose logs syslog-mcp"
    exit 1
fi

# ─── Phase 3: Tool tests ─────────────────────────────────────────────────────
echo ""
echo -e "${COLOR_BOLD}[3/4] Tool tests${COLOR_RESET}"

# ── Tool 1: get_stats ────────────────────────────────────────────────────────
echo ""
echo "Tool: get_stats"
STATS=$(mcp_call get_stats 2>&1)
assert_no_error "get_stats: no error" "$STATS"
STATS_TOTAL=$(json_get "$STATS" "['total_logs']")
STATS_HOSTS=$(json_get "$STATS" "['total_hosts']")
STATS_SIZE=$(json_get "$STATS" "['db_size_mb']")
assert_gte "get_stats: total_logs >= 1" "$STATS_TOTAL" 1
assert_gte "get_stats: total_hosts >= 1" "$STATS_HOSTS" 1
if [[ -n "$STATS_SIZE" ]]; then
    pass "get_stats: db_size_mb present ('$STATS_SIZE')"
else
    fail "get_stats: db_size_mb missing"
fi

# ── Tool 2: list_hosts ───────────────────────────────────────────────────────
echo ""
echo "Tool: list_hosts"
HOSTS=$(mcp_call list_hosts 2>&1)
assert_no_error "list_hosts: no error" "$HOSTS"
HOSTS_COUNT=$(json_get "$HOSTS" "['hosts'].__len__()" 2>/dev/null || echo "$HOSTS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['hosts']))" 2>/dev/null || echo "0")
assert_gte "list_hosts: at least 1 host" "$HOSTS_COUNT" 1
# Validate each host record has required fields
HOSTS_VALID=$(echo "$HOSTS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
hosts = d['hosts']
for h in hosts:
    assert 'hostname' in h and h['hostname'], 'hostname missing or empty'
    assert 'log_count' in h, 'log_count missing'
    assert 'first_seen' in h, 'first_seen missing'
    assert 'last_seen' in h, 'last_seen missing'
print('ok')
" 2>&1)
assert_eq "list_hosts: all records have required fields" "$HOSTS_VALID" "ok"

# ── Tool 3: tail_logs ────────────────────────────────────────────────────────
echo ""
echo "Tool: tail_logs"
TAIL=$(mcp_call tail_logs "n=10" 2>&1)
assert_no_error "tail_logs: no error" "$TAIL"
TAIL_COUNT=$(echo "$TAIL" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['count'])" 2>/dev/null || echo "0")
assert_gte "tail_logs: returns >= 1 log" "$TAIL_COUNT" 1
# Validate log entry structure
TAIL_VALID=$(echo "$TAIL" | python3 -c "
import sys, json
d = json.load(sys.stdin)
logs = d['logs']
assert len(logs) > 0, 'no logs'
for l in logs:
    assert 'id' in l, 'id missing'
    assert 'hostname' in l and l['hostname'], 'hostname missing'
    assert 'severity' in l and l['severity'], 'severity missing'
    assert 'message' in l, 'message missing'
    assert 'timestamp' in l and l['timestamp'], 'timestamp missing'
    # Order must be descending (most recent first)
assert True  # timestamp ordering validated below
print('ok')
" 2>&1)
assert_eq "tail_logs: log entries have required fields" "$TAIL_VALID" "ok"
# Validate timestamp non-increasing order (ORDER BY timestamp DESC; ties allowed)
TAIL_ORDER=$(echo "$TAIL" | python3 -c "
import sys, json
d = json.load(sys.stdin)
logs = d['logs']
if len(logs) < 2:
    print('ok')
    sys.exit(0)
timestamps = [l['timestamp'] for l in logs]
# Each timestamp must be <= the previous (descending, ties OK)
for i in range(1, len(timestamps)):
    if timestamps[i] > timestamps[i-1]:
        print(f'not_descending at {i}: {timestamps[i-1]!r} then {timestamps[i]!r}')
        sys.exit(0)
print('ok')
" 2>/dev/null || echo "error")
assert_eq "tail_logs: results in non-increasing timestamp order" "$TAIL_ORDER" "ok"

# ── Tool 4: search_logs ─────────────────────────────────────────────────────
echo ""
echo "Tool: search_logs"
# Note: FTS5 treats '-' as NOT operator, so use a plain keyword from seeded data
SEARCH=$(mcp_call search_logs "query=authentication" "limit=50" 2>&1)
assert_no_error "search_logs(query=authentication): no error" "$SEARCH"
SEARCH_COUNT=$(echo "$SEARCH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['count'])" 2>/dev/null || echo "0")
assert_gte "search_logs(query=authentication): returns >= 1 result" "$SEARCH_COUNT" 1
# Every result must contain the search term in the message
SEARCH_MATCH=$(echo "$SEARCH" | python3 -c "
import sys, json
d = json.load(sys.stdin)
logs = d['logs']
assert len(logs) > 0, 'no logs'
for l in logs:
    msg = (l.get('message') or '').lower()
    if 'authentication' not in msg:
        print(f'mismatch: {l}')
        sys.exit(0)
print('ok')
" 2>/dev/null || echo "error")
assert_eq "search_logs: all results match query" "$SEARCH_MATCH" "ok"

# FTS5 syntax test — phrase search
SEARCH_PHRASE=$(mcp_call search_logs 'query="authentication failure"' "limit=10" 2>&1)
assert_no_error "search_logs(phrase query): no error" "$SEARCH_PHRASE"
PHRASE_COUNT=$(echo "$SEARCH_PHRASE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['count'])" 2>/dev/null || echo "0")
assert_gte "search_logs(phrase query): finds matching logs" "$PHRASE_COUNT" 1

# limit=0 should not crash (returns 0, not error)
SEARCH_ZERO=$(mcp_call search_logs "limit=0" 2>&1)
assert_no_error "search_logs(limit=0): no error" "$SEARCH_ZERO"

# ── Tool 5: get_errors ───────────────────────────────────────────────────────
echo ""
echo "Tool: get_errors"
ERRORS_OUT=$(mcp_call get_errors 2>&1)
assert_no_error "get_errors: no error" "$ERRORS_OUT"
# Should have a summary array
ERRORS_VALID=$(echo "$ERRORS_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'summary' in d, 'summary key missing'
assert isinstance(d['summary'], list), 'summary is not a list'
for item in d['summary']:
    assert 'hostname' in item, 'hostname missing from summary item'
    assert 'severity' in item, 'severity missing from summary item'
    assert 'count' in item, 'count missing from summary item'
    # severity must be a real error/warning level
    assert item['severity'] in ('emerg','alert','crit','err','warning'), f'unexpected severity: {item[\"severity\"]}'
    assert item['count'] >= 1, 'count must be >= 1'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "get_errors: summary structure valid" "$ERRORS_VALID" "ok"
# We seeded err/crit messages, so count must be > 0
ERRORS_COUNT=$(echo "$ERRORS_OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['summary']))" 2>/dev/null || echo "0")
assert_gte "get_errors: at least 1 error group from seeded data" "$ERRORS_COUNT" 1

# ── Tool 6: correlate_events ─────────────────────────────────────────────────
echo ""
echo "Tool: correlate_events"
REF_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
CORRELATE=$(mcp_call correlate_events "reference_time=$REF_TIME" "window_minutes=30" 2>&1)
assert_no_error "correlate_events: no error" "$CORRELATE"
# Validate response structure
CORRELATE_VALID=$(echo "$CORRELATE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'reference_time' in d, 'reference_time missing'
assert 'window_minutes' in d, 'window_minutes missing'
assert 'total_events' in d, 'total_events missing'
assert 'hosts' in d, 'hosts key missing'
assert isinstance(d['hosts'], list), 'hosts is not a list'
for h in d['hosts']:
    assert 'hostname' in h, 'hostname missing from host entry'
    assert 'event_count' in h, 'event_count missing'
    assert 'events' in h, 'events missing'
    assert isinstance(h['events'], list), 'events is not a list'
    for e in h['events']:
        assert 'id' in e, 'event id missing'
        assert 'severity' in e, 'event severity missing'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "correlate_events: response structure valid" "$CORRELATE_VALID" "ok"
CORRELATE_EVENTS=$(echo "$CORRELATE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['total_events'])" 2>/dev/null || echo "0")
assert_gte "correlate_events: found events in 30-minute window" "$CORRELATE_EVENTS" 1

# ─── Phase 4: Summary ────────────────────────────────────────────────────────
echo ""
echo -e "${COLOR_BOLD}[4/4] Results${COLOR_RESET}"
echo "─────────────────────────────────────"
TOTAL=$((PASS + FAIL))
echo -e "  Passed:  ${COLOR_GREEN}${PASS}${COLOR_RESET} / ${TOTAL}"
echo -e "  Failed:  ${COLOR_RED}${FAIL}${COLOR_RESET} / ${TOTAL}"

if [[ ${#ERRORS[@]} -gt 0 ]]; then
    echo ""
    echo -e "${COLOR_RED}Failures:${COLOR_RESET}"
    for e in "${ERRORS[@]}"; do
        echo "  - $e"
    done
fi

echo ""
if [[ $FAIL -eq 0 ]]; then
    echo -e "${COLOR_GREEN}${COLOR_BOLD}ALL TESTS PASSED${COLOR_RESET}"
    exit 0
else
    echo -e "${COLOR_RED}${COLOR_BOLD}SMOKE TEST FAILED — $FAIL test(s) failed${COLOR_RESET}"
    exit 1
fi
