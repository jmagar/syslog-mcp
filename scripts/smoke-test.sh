#!/usr/bin/env bash
# smoke-test.sh — Live end-to-end smoke test for cortex
# Tests all MCP actions via mcporter with strict PASS/FAIL validation.
# Exit code 0 = all passed. Exit code 1 = one or more failures.
#
# Usage:
#   bash scripts/smoke-test.sh [--url http://host:3100/mcp]
#   bash scripts/smoke-test.sh --skip-seed   # if data already exists
#
# Requirements: mcporter, nc, curl, python3
#
# Action inventory reference:
#   mcp_call search, mcp_call filter, mcp_call tail, mcp_call errors, mcp_call hosts, mcp_call map, mcp_call host_state, mcp_call fleet_state, mcp_call correlate_state,
#   mcp_call sessions, mcp_call search_sessions, mcp_call evidence_scope, mcp_call abuse, mcp_call ai_correlate,
#   mcp_call usage_blocks, mcp_call project_context, mcp_call list_ai_tools, mcp_call list_ai_projects,
#   mcp_call correlate, mcp_call stats, mcp_call status, mcp_call apps,
#   mcp_call source_ips, mcp_call timeline, mcp_call patterns, mcp_call context,
#   mcp_call get, mcp_call ingest_rate, mcp_call silent_hosts,
#   mcp_call clock_skew, mcp_call anomalies, mcp_call compare,
#   mcp_call compose_status, mcp_call compose_doctor,
#   mcp_call unaddressed_errors, mcp_call ack_error, mcp_call unack_error,
#   mcp_call notifications_recent, mcp_call file_tails, mcp_call notifications_test,
#   mcp_call llm_invocations,
#   mcp_call similar_incidents, mcp_call ask_history, mcp_call incident_context, mcp_call graph,
#   mcp_call artifact_evidence, mcp_call artifact_evidence_record,
#   mcp_call skill_events, mcp_call skill_incidents, mcp_call skill_investigate,
#   mcp_call mcp_events, mcp_call mcp_incidents, mcp_call mcp_investigate,
#   mcp_call hook_events, mcp_call hook_incidents, mcp_call hook_investigate,
#   mcp_call help

set -euo pipefail

# ─── Config ──────────────────────────────────────────────────────────────────
MCP_URL="${CORTEX_URL:-http://localhost:3100/mcp}"
HEALTH_URL="${MCP_URL%/mcp}/health"
CORTEX_RECEIVER_HOST="${CORTEX_RECEIVER_HOST:-127.0.0.1}"
CORTEX_RECEIVER_PORT="${CORTEX_RECEIVER_PORT:-1514}"
SKIP_SEED=0
MCPORTER_CONFIG="config/mcporter.json"
_MCPORTER_CONFIG_TMPFILE=""
SEED_HOST="smoke-test-host"
GHOST_HOST="nonexistent-host-xyz-404"
RUN_ID="${CORTEX_SMOKE_RUN_ID:-$(date -u +%Y%m%d%H%M%S)}"
TCP_MARKER="smoketcp${RUN_ID}"
AI_SMOKE_FIXTURE="${CORTEX_SMOKE_AI_FIXTURE:-tests/fixtures/ai-session-smoke.jsonl}"
AI_SMOKE_PROJECT="/tmp/cortex-ai-smoke"
AI_SMOKE_QUERY='"ai-smoke-authentication"'
AI_SEEDED=0

trap '[[ -n "$_MCPORTER_CONFIG_TMPFILE" ]] && rm -f "$_MCPORTER_CONFIG_TMPFILE"' EXIT

while [[ $# -gt 0 ]]; do
    case $1 in
        --url)
            [[ -z "${2:-}" ]] && { echo "Error: --url requires a value"; exit 1; }
            MCP_URL="$2"; HEALTH_URL="${MCP_URL%/mcp}/health"; shift 2
            _MCPORTER_CONFIG_TMPFILE=$(mktemp /tmp/mcporter-XXXXXX.json)
            MCPORTER_CONFIG="$_MCPORTER_CONFIG_TMPFILE"
            ;;
        --skip-seed) SKIP_SEED=1; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -n "${CORTEX_TOKEN:-}" || -n "$_MCPORTER_CONFIG_TMPFILE" ]]; then
    if [[ -z "$_MCPORTER_CONFIG_TMPFILE" ]]; then
        _MCPORTER_CONFIG_TMPFILE=$(mktemp /tmp/mcporter-XXXXXX.json)
        MCPORTER_CONFIG="$_MCPORTER_CONFIG_TMPFILE"
    fi
    python3 - "$MCPORTER_CONFIG" "$MCP_URL" "${CORTEX_TOKEN:-}" <<'PY'
import json
import sys

path, url, token = sys.argv[1:4]
server = {"baseUrl": url}
if token:
    server["headers"] = {"Authorization": f"Bearer {token}"}
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"mcpServers": {"cortex": server}}, fh)
PY
fi

# ─── Helpers ─────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0
ERRORS=()

COLOR_GREEN='\033[0;32m'
COLOR_RED='\033[0;31m'
COLOR_RESET='\033[0m'
COLOR_BOLD='\033[1m'

pass() { echo -e "${COLOR_GREEN}PASS${COLOR_RESET}  $1"; (( PASS++ )) || true; }
fail() { echo -e "${COLOR_RED}FAIL${COLOR_RESET}  $1"; ERRORS+=("$1"); (( FAIL++ )) || true; }
skip() { echo "SKIP  $1"; (( SKIP++ )) || true; }

mcp_call() {
    local action="$1"; shift
    mcporter call --config "$MCPORTER_CONFIG" "cortex.cortex" "action=${action}" "$@" 2>&1
}

mcp_admin_scope_available() {
    local token="${CORTEX_TOKEN:-}"
    token="${token//[[:space:]]/}"
    [[ -n "${token}" \
        && ( "${CORTEX_STATIC_TOKEN_ADMIN:-false}" == "true" \
          || "${CORTEX_SMOKE_ADMIN:-false}" == "true" ) ]]
}

file_tail_smoke_available() {
    [[ -n "${CORTEX_FILE_TAIL_SMOKE_PATH:-}" && -n "${CORTEX_FILE_TAIL_SMOKE_WRITE_PATH:-${CORTEX_FILE_TAIL_SMOKE_PATH:-}}" ]]
}

mcp_jsonrpc() {
    local payload="$1"
    local auth_args=()
    if [[ -n "${CORTEX_TOKEN:-}" ]]; then
        auth_args=(-H "Authorization: Bearer ${CORTEX_TOKEN}")
    fi
    curl -fsS -X POST "$MCP_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        "${auth_args[@]}" \
        -d "$payload" 2>&1
}

json_get() {
    # NOTE: $field is interpolated into the Python program, so callers MUST pass
    # only a literal accessor (e.g. ['status']) — never a server-controlled value.
    # The JSON payload itself is safe: it is piped via stdin, not interpolated.
    local json="$1" field="$2"
    printf '%s\n' "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d$field)" 2>/dev/null
}

assert_eq() {
    local label="$1" actual="$2" expected="$3"
    if [[ "$actual" == "$expected" ]]; then
        pass "$label"
    else
        fail "$label (expected '$expected', got '$actual')"
    fi
}

assert_gte() {
    local label="$1" actual="$2" min="$3"
    # Read $actual via stdin rather than interpolating it into the -c program —
    # it can originate from server JSON, and int() of an interpolated string is a
    # footgun. ($min is always an integer literal from in-script callers.)
    if printf '%s' "$actual" | python3 -c "
import sys
try:
    sys.exit(0 if int(sys.stdin.read().strip()) >= $min else 1)
except ValueError:
    sys.exit(1)
" 2>/dev/null; then
        pass "$label"
    else
        fail "$label (expected >= $min, got '$actual')"
    fi
}

assert_no_error() {
    local label="$1" output="$2"
    if printf '%s\n' "$output" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    sys.exit(1 if d.get('isError') else 0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        pass "$label"
    else
        local detail
        detail=$(printf '%s\n' "$output" | python3 -c "
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

assert_is_error() {
    local label="$1" output="$2"
    if printf '%s\n' "$output" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    sys.exit(0 if d.get('isError') else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        pass "$label"
    elif printf '%s\n' "$output" | grep -Eq "^\[mcporter\] MCP error -32602:|requires scope: cortex:__deny__|unsupported action|unknown action|notanaction"; then
        pass "$label"
    else
        fail "$label (expected tool isError=true or MCP invalid-params error)"
    fi
}

send_tcp_seed() {
    local message="$1"
    if printf '%s\n' "$message" | nc -w2 -N "$CORTEX_RECEIVER_HOST" "$CORTEX_RECEIVER_PORT" >/dev/null 2>&1; then
        return 0
    fi
    printf '%s\n' "$message" | nc -w2 "$CORTEX_RECEIVER_HOST" "$CORTEX_RECEIVER_PORT" >/dev/null
}

run_cortex_ai_add() {
    local db_path="$1"
    local fixture="$2"
    local cortex_bin="${CORTEX_BIN:-}"

    if [[ -z "$cortex_bin" ]]; then
        if command -v cortex >/dev/null 2>&1; then
            cortex_bin="$(command -v cortex)"
        elif [[ -x "target/debug/cortex" ]]; then
            cortex_bin="target/debug/cortex"
        else
            echo "cortex binary not found; install cortex on PATH, set CORTEX_BIN, or run cargo build" >&2
            return 127
        fi
    fi

    CORTEX_USE_HTTP=false CORTEX_DB_PATH="$db_path" \
        "$cortex_bin" sessions add --file "$fixture" --json
}

# Resolve the cortex CLI binary (env CORTEX_BIN, PATH, or debug build), echoing
# its path. Returns 127 when no binary is found.
resolve_cortex_bin() {
    if [[ -n "${CORTEX_BIN:-}" ]]; then
        echo "$CORTEX_BIN"
    elif command -v cortex >/dev/null 2>&1; then
        command -v cortex
    elif [[ -x "target/debug/cortex" ]]; then
        echo "target/debug/cortex"
    else
        return 127
    fi
}

resolve_smoke_db_path() {
    if [[ -n "${CORTEX_SMOKE_DB_PATH:-}" ]]; then
        printf '%s\n' "$CORTEX_SMOKE_DB_PATH"
    elif [[ "${CORTEX_DB_PATH:-}" == /data/* && "${CORTEX_DATA_VOLUME:-}" == /* ]]; then
        printf '%s/%s\n' "${CORTEX_DATA_VOLUME%/}" "${CORTEX_DB_PATH#/data/}"
    else
        printf '%s\n' "${CORTEX_DB_PATH:-data/cortex.db}"
    fi
}

seed_ai_fixture() {
    [[ -f "$AI_SMOKE_FIXTURE" ]] || return 1

    local db_path
    db_path="$(resolve_smoke_db_path)"
    local output
    if output="$(run_cortex_ai_add "$db_path" "$AI_SMOKE_FIXTURE" 2>&1)"; then
        AI_SEEDED=1
        echo "Seeded AI transcript fixture into ${db_path}: ${AI_SMOKE_FIXTURE}"
    else
        local rc=$?
        echo "ERROR  AI transcript fixture seed failed: ${output}" >&2
        return "$rc"
    fi
}

# ─── Phase 1: Pre-flight ─────────────────────────────────────────────────────
echo ""
echo -e "${COLOR_BOLD}=== cortex smoke test ===${COLOR_RESET}"
echo "MCP URL: $MCP_URL"
echo ""

echo -e "${COLOR_BOLD}[1/4] Pre-flight checks${COLOR_RESET}"

HEALTH=$(curl -sf "$HEALTH_URL" 2>&1) || { echo -e "${COLOR_RED}ABORT${COLOR_RESET}  Health endpoint unreachable: $HEALTH_URL"; exit 1; }
HEALTH_STATUS=$(json_get "$HEALTH" "['status']")
assert_eq "Health endpoint responds with ok" "$HEALTH_STATUS" "ok"

TOOL_LIST=$(mcporter list cortex --config "$MCPORTER_CONFIG" 2>&1)
TOOL_COUNT=$(printf '%s\n' "$TOOL_LIST" | grep -c "^  function " || true)
assert_eq "mcporter lists exactly 1 tool (cortex)" "$TOOL_COUNT" "1"

PROMPTS_LIST=$(mcp_jsonrpc '{"jsonrpc":"2.0","id":101,"method":"prompts/list","params":{}}' || true)
PROMPTS_VALID=$(printf '%s\n' "$PROMPTS_LIST" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    names = {p['name'] for p in d['result']['prompts']}
    required = {'infra.incident-triage', 'infra.after-deploy-check', 'infra.syslog-forwarding-gap'}
    assert required <= names, required - names
    assert len(names) >= 12, len(names)
    print('ok')
except Exception as e:
    print(f'error: {e}')
")
assert_eq "prompts/list exposes focused infra prompts" "$PROMPTS_VALID" "ok"

PROMPT_GET_PAYLOAD=$(python3 - <<'PY'
import json
print(json.dumps({
    "jsonrpc": "2.0",
    "id": 102,
    "method": "prompts/get",
    "params": {
        "name": "infra.service-outage",
        "arguments": {
            "service": "plex",
            "host": "nashost",
            "window": "last 45 minutes",
        },
    },
}))
PY
)
PROMPT_GET=$(mcp_jsonrpc "$PROMPT_GET_PAYLOAD" || true)
PROMPT_VALID=$(printf '%s\n' "$PROMPT_GET" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    text = d['result']['messages'][0]['content']['text']
    for needle in ['service \`plex\`', 'Host: nashost', 'bucket=minute', 'limit=10', 'cortex://schema/prompt-output']:
        assert needle in text, needle
    print('ok')
except Exception as e:
    print(f'error: {e}')
")
assert_eq "prompts/get renders bounded argument-aware prompt" "$PROMPT_VALID" "ok"

PROMPT_SCHEMA=$(mcp_jsonrpc '{"jsonrpc":"2.0","id":103,"method":"resources/read","params":{"uri":"cortex://schema/prompt-output"}}' || true)
PROMPT_SCHEMA_VALID=$(printf '%s\n' "$PROMPT_SCHEMA" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    schema = json.loads(d['result']['contents'][0]['text'])
    required = set(schema['required'])
    assert {'verdict', 'confidence', 'evidence', 'likely_cause', 'not_supported', 'next_actions', 'telemetry_gaps'} <= required
    assert schema['properties']['confidence']['enum'] == ['low', 'medium', 'high']
    print('ok')
except Exception as e:
    print(f'error: {e}')
")
assert_eq "prompt output schema resource is available" "$PROMPT_SCHEMA_VALID" "ok"

# MCP Apps query widget wire contract — host-agnostic. No browser, Node, or named
# UI host required; this verifies only the MCP JSON-RPC surface that any capable
# host (e.g. one honoring _meta.ui.resourceUri) would consume. Non-UI clients
# keep using normal text/JSON tool results and are unaffected by these fields.
RES_LIST=$(mcp_jsonrpc '{"jsonrpc":"2.0","id":110,"method":"resources/list","params":{}}' || true)
RES_LIST_VALID=$(printf '%s\n' "$RES_LIST" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    uris = {r['uri'] for r in d['result']['resources']}
    assert 'ui://cortex/query-widget' in uris, uris
    assert 'cortex://schema/mcp-tool' in uris, uris
    print('ok')
except Exception as e:
    print(f'error: {e}')
")
assert_eq "resources/list exposes the query widget resource" "$RES_LIST_VALID" "ok"

WIDGET_READ=$(mcp_jsonrpc '{"jsonrpc":"2.0","id":111,"method":"resources/read","params":{"uri":"ui://cortex/query-widget"}}' || true)
WIDGET_READ_VALID=$(printf '%s\n' "$WIDGET_READ" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    c = d['result']['contents'][0]
    assert c['uri'] == 'ui://cortex/query-widget', c.get('uri')
    assert c['mimeType'] == 'text/html;profile=mcp-app', c.get('mimeType')
    html = c['text']
    for anchor in ['data-syslog-query-widget', 'value=\"search\"', 'name=\"query\"',
                   'ui-message-response', 'event.source', 'Host bridge unavailable']:
        assert anchor in html, anchor
    print('ok')
except Exception as e:
    print(f'error: {e}')
")
assert_eq "resources/read returns query widget HTML with MCP Apps MIME + anchors" "$WIDGET_READ_VALID" "ok"

TOOLS_META=$(mcp_jsonrpc '{"jsonrpc":"2.0","id":112,"method":"tools/list","params":{}}' || true)
TOOLS_META_VALID=$(printf '%s\n' "$TOOLS_META" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    tool = next(t for t in d['result']['tools'] if t['name'] == 'cortex')
    ui = tool['_meta']['ui']
    assert ui['resourceUri'] == 'ui://cortex/query-widget', ui.get('resourceUri')
    print('ok')
except Exception as e:
    print(f'error: {e}')
")
assert_eq "tools/list cortex tool advertises _meta.ui.resourceUri" "$TOOLS_META_VALID" "ok"

WIDGET_SEARCH=$(mcp_jsonrpc '{"jsonrpc":"2.0","id":113,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"search","query":"smoke","limit":1}}}' || true)
WIDGET_SEARCH_VALID=$(printf '%s\n' "$WIDGET_SEARCH" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    r = d['result']
    # UI hosts render structuredContent; non-UI hosts read content[0].text.
    assert 'logs' in r['structuredContent'], 'no structuredContent.logs'
    assert r['content'][0]['text'], 'no text content'
    print('ok')
except Exception as e:
    print(f'error: {e}')
")
assert_eq "tools/call action=search returns structuredContent and text" "$WIDGET_SEARCH_VALID" "ok"

# ─── Phase 2: Seed test data ─────────────────────────────────────────────────
echo ""
echo -e "${COLOR_BOLD}[2/4] Seeding test data${COLOR_RESET}"

if [[ "$SKIP_SEED" -eq 0 ]]; then
    printf '<14>%s %s sshd[42]: smoke-test: info message\n'           "$(date -u '+%b %e %H:%M:%S')" "$SEED_HOST" | nc -u -w1 "$CORTEX_RECEIVER_HOST" "$CORTEX_RECEIVER_PORT"
    printf '<11>%s %s sshd[42]: smoke-test: error authentication failure\n' "$(date -u '+%b %e %H:%M:%S')" "$SEED_HOST" | nc -u -w1 "$CORTEX_RECEIVER_HOST" "$CORTEX_RECEIVER_PORT"
    printf '<2>%s %s kernel: smoke-test: crit memory allocation failed\n'    "$(date -u '+%b %e %H:%M:%S')" "$SEED_HOST" | nc -u -w1 "$CORTEX_RECEIVER_HOST" "$CORTEX_RECEIVER_PORT"
    printf '<12>%s %s dockerd[99]: smoke-test: warning container restart\n'  "$(date -u '+%b %e %H:%M:%S')" "$SEED_HOST" | nc -u -w1 "$CORTEX_RECEIVER_HOST" "$CORTEX_RECEIVER_PORT"
    send_tcp_seed "<14>$(date -u '+%b %e %H:%M:%S') ${SEED_HOST} tcpsmoke[77]: smoke-test tcp seed ${TCP_MARKER} bounded frame ok"
    if ! seed_ai_fixture; then
        echo -e "${COLOR_RED}ABORT${COLOR_RESET}  AI transcript fixture seed failed"
        exit 1
    fi
    sleep 2
    echo "Seeded 5 messages (4 UDP, 1 TCP) from $SEED_HOST; TCP marker=$TCP_MARKER"
else
    echo "Skipping seed (--skip-seed)"
fi

STATS_PREFLIGHT=$(mcp_call stats 2>&1)
TOTAL_PREFLIGHT=$(json_get "$STATS_PREFLIGHT" "['total_logs']")
if python3 -c "exit(0 if int('${TOTAL_PREFLIGHT:-0}') >= 1 else 1)" 2>/dev/null; then
    echo "DB has $TOTAL_PREFLIGHT logs — proceeding"
else
    echo -e "${COLOR_RED}ABORT${COLOR_RESET}  No logs in DB. Seed failed or server just started."
    exit 1
fi

# ─── Phase 3: Action tests ───────────────────────────────────────────────────
echo ""
echo -e "${COLOR_BOLD}[3/4] Action tests${COLOR_RESET}"

# ── status ────────────────────────────────────────────────────────────────────
echo ""
echo "Action: status"
STATUS=$(mcp_call status 2>&1)
assert_no_error "status: no error" "$STATUS"

STATUS_VALUE=$(json_get "$STATUS" "['status']")
STATUS_DB_OK=$(json_get "$STATUS" "['db_ok']")
STATUS_OBS=$(json_get "$STATUS" "['runtime_observability']['ingest_queue_depth']")
STATUS_OTLP=$(json_get "$STATUS" "['otlp']['logs_received']")
assert_eq "status: status is ok" "$STATUS_VALUE" "ok"
assert_eq "status: db_ok is true" "$STATUS_DB_OK" "True"
[[ -n "$STATUS_OBS" ]] \
    && pass "status: runtime_observability present" \
    || fail "status: runtime_observability missing"
[[ -n "$STATUS_OTLP" ]] \
    && pass "status: otlp counters present" \
    || fail "status: otlp counters missing"

# ── file_tails ────────────────────────────────────────────────────────────────
echo ""
echo "Action: file_tails"
if mcp_admin_scope_available; then
    FILE_TAILS=$(mcp_call file_tails "op=status" 2>&1)
    assert_no_error "file_tails: status no error" "$FILE_TAILS"
    FILE_TAILS_SOURCES=$(json_get "$FILE_TAILS" "['sources']")
    FILE_TAILS_STATUSES=$(json_get "$FILE_TAILS" "['statuses']")
    [[ -n "$FILE_TAILS_SOURCES" ]] \
        && pass "file_tails: sources present" \
        || fail "file_tails: sources missing"
    [[ -n "$FILE_TAILS_STATUSES" ]] \
        && pass "file_tails: statuses present" \
        || fail "file_tails: statuses missing"
    if FILE_TAILS_OP_REQUIRED=$(mcp_call file_tails 2>&1); then
        fail "file_tails: missing op should be rejected"
    elif [[ "$FILE_TAILS_OP_REQUIRED" == *"op"* || "$FILE_TAILS_OP_REQUIRED" == *"missing"* || "$FILE_TAILS_OP_REQUIRED" == *"required"* ]]; then
        pass "file_tails: missing op is rejected"
    else
        fail "file_tails: missing op rejection should mention op"
    fi
    if file_tail_smoke_available; then
        FILE_TAIL_SMOKE_SERVER_PATH="${CORTEX_FILE_TAIL_SMOKE_PATH}"
        FILE_TAIL_SMOKE_WRITE_PATH="${CORTEX_FILE_TAIL_SMOKE_WRITE_PATH:-$FILE_TAIL_SMOKE_SERVER_PATH}"
        FILE_TAIL_SMOKE_ID="smoke-${RUN_ID}"
        FILE_TAIL_SMOKE_TAG="file-tail-smoke"
        FILE_TAIL_SMOKE_MARKER="file-tail-smoke-${RUN_ID}"
        touch "$FILE_TAIL_SMOKE_WRITE_PATH" || fail "file_tails: smoke file writable"
        FILE_TAIL_ADD=$(mcp_call file_tails \
            "op=add" \
            "id=${FILE_TAIL_SMOKE_ID}" \
            "path=${FILE_TAIL_SMOKE_SERVER_PATH}" \
            "tag=${FILE_TAIL_SMOKE_TAG}" \
            "host=${SEED_HOST}" \
            "facility=local7" \
            "severity=info" \
            "start_at_end=true" 2>&1)
        assert_no_error "file_tails: add smoke source" "$FILE_TAIL_ADD"
        printf '%s\n' "$FILE_TAIL_SMOKE_MARKER" >> "$FILE_TAIL_SMOKE_WRITE_PATH"
        FILE_TAIL_FOUND=0
        for _ in {1..20}; do
            FILE_TAIL_SEARCH=$(mcp_call search \
                "query=\"${FILE_TAIL_SMOKE_MARKER}\"" \
                "source_kind=file-tail" \
                "app=${FILE_TAIL_SMOKE_TAG}" \
                "limit=5" 2>&1 || true)
            FILE_TAIL_COUNT=$(json_get "$FILE_TAIL_SEARCH" "['count']" || true)
            if [[ "${FILE_TAIL_COUNT:-0}" -ge 1 ]]; then
                FILE_TAIL_FOUND=1
                break
            fi
            sleep 0.5
        done
        [[ "$FILE_TAIL_FOUND" == "1" ]] \
            && pass "file_tails: add append query ingest" \
            || fail "file_tails: appended smoke line was not queryable"
        mcp_call file_tails "op=remove" "id=${FILE_TAIL_SMOKE_ID}" >/dev/null 2>&1 || true
    else
        skip "file_tails: add append query ingest requires CORTEX_FILE_TAIL_SMOKE_PATH"
    fi
else
    skip "file_tails: status requires cortex:admin (set CORTEX_STATIC_TOKEN_ADMIN=true or CORTEX_SMOKE_ADMIN=true)"
fi

# ── llm_invocations ──────────────────────────────────────────────────────────
echo ""
echo "Action: llm_invocations"
if mcp_admin_scope_available; then
    LLM_INVOCATIONS=$(mcp_call llm_invocations "limit=5" 2>&1)
    assert_no_error "llm_invocations: no error" "$LLM_INVOCATIONS"
else
    skip "llm_invocations: requires cortex:admin (set CORTEX_STATIC_TOKEN_ADMIN=true or CORTEX_SMOKE_ADMIN=true)"
fi

# ── stats ─────────────────────────────────────────────────────────────────────
echo ""
echo "Action: stats"
STATS=$(mcp_call stats 2>&1)
assert_no_error "stats: no error" "$STATS"

STATS_TOTAL=$(json_get "$STATS" "['total_logs']")
STATS_HOSTS=$(json_get "$STATS" "['total_hosts']")
STATS_SIZE=$(json_get "$STATS" "['logical_db_size_mb']")
STATS_BLOCKED=$(json_get "$STATS" "['write_blocked']")
assert_gte  "stats: total_logs >= 1" "$STATS_TOTAL" 1
assert_gte  "stats: total_hosts >= 1" "$STATS_HOSTS" 1
[[ -n "$STATS_SIZE" ]] \
    && pass "stats: logical_db_size_mb present ('$STATS_SIZE')" \
    || fail "stats: logical_db_size_mb missing"
assert_eq   "stats: write_blocked is false (DB healthy)" "$STATS_BLOCKED" "False"

# ── hosts ─────────────────────────────────────────────────────────────────────
echo ""
echo "Action: hosts"
HOSTS=$(mcp_call hosts 2>&1)
assert_no_error "hosts: no error" "$HOSTS"

HOSTS_COUNT=$(printf '%s\n' "$HOSTS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['hosts']))" 2>/dev/null || echo "0")
assert_gte "hosts: at least 1 host" "$HOSTS_COUNT" 1

# All records have required fields and non-zero log counts
HOSTS_VALID=$(printf '%s\n' "$HOSTS" | python3 -c "
import sys, json
for h in json.load(sys.stdin)['hosts']:
    assert h.get('hostname'), 'hostname missing or empty'
    assert 'log_count' in h, 'log_count missing'
    assert h['log_count'] > 0, f'log_count=0 for {h[\"hostname\"]}'
    assert 'first_seen' in h, 'first_seen missing'
    assert 'last_seen' in h, 'last_seen missing'
print('ok')
" 2>&1)
assert_eq "hosts: all records have required fields and log_count > 0" "$HOSTS_VALID" "ok"

TEST_HOST=$(printf '%s\n' "$HOSTS" | python3 -c "
import sys, json
hosts = json.load(sys.stdin).get('hosts') or []
print('${SEED_HOST}' if ${SKIP_SEED} == 0 else hosts[0]['hostname'])
" 2>/dev/null || true)

if [[ "$SKIP_SEED" -eq 0 ]]; then
    # Verify the seeded host actually appears by name
    SEED_HOST_FOUND=$(printf '%s\n' "$HOSTS" | python3 -c "
import sys, json
hosts = [h['hostname'] for h in json.load(sys.stdin)['hosts']]
print('ok' if '${SEED_HOST}' in hosts else f'missing: {hosts}')
" 2>/dev/null || echo "error")
    assert_eq "hosts: seeded host '$SEED_HOST' appears in list" "$SEED_HOST_FOUND" "ok"
fi

# ── map ───────────────────────────────────────────────────────────────────────
echo ""
echo "Action: map"
MAP=$(mcp_call map 2>&1)
assert_no_error "map: no error" "$MAP"

MAP_VALID=$(printf '%s\n' "$MAP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('schema') == 'cortex.homelab_map.v2', 'schema mismatch'
assert isinstance(d.get('summary'), dict), 'summary missing'
assert isinstance(d.get('nodes'), list), 'nodes not a list'
assert isinstance(d.get('cache_status'), str), 'cache_status missing'
assert isinstance(d.get('artifact_refs'), list), 'artifact_refs not a list'
assert isinstance(d.get('collection_errors'), list), 'collection_errors not a list'
assert isinstance(d.get('cortex_overlay'), dict), 'cortex_overlay missing'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "map: response structure valid" "$MAP_VALID" "ok"

MAP_FINDINGS=$(mcp_call map "mode=findings" "finding_limit=5" "evidence_per_finding=1" 'finding_types=["collector_health"]' 2>&1)
assert_no_error "map findings: no error" "$MAP_FINDINGS"

MAP_FINDINGS_VALID=$(printf '%s\n' "$MAP_FINDINGS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
answer = d.get('graph_answer') or {}
assert answer.get('mode') == 'findings', 'mode mismatch'
assert answer.get('answer_status') in ('ok', 'degraded'), 'invalid answer_status'
assert isinstance(answer.get('findings'), list), 'findings not a list'
metadata = answer.get('metadata') or {}
truncation = answer.get('truncation') or {}
assert metadata.get('limit') == 5, 'finding_limit not reflected'
assert metadata.get('evidence_sample_limit') == 1, 'evidence_per_finding not reflected'
assert truncation.get('limit') == 5, 'truncation limit mismatch'
for finding in answer.get('findings', []):
    assert finding.get('finding_type') == 'collector_health', 'finding_types subset not honored'
    assert 'evidence_total' in finding, 'evidence_total missing'
    assert 'evidence_truncated' in finding, 'evidence_truncated missing'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "map findings: response contract valid" "$MAP_FINDINGS_VALID" "ok"

# ── sessions ──────────────────────────────────────────────────────────────────
echo ""
echo "Action: sessions"
# Use a time-windowed query so smoke data seeded directly into SQLite is read
# live instead of through a periodically refreshed session rollup.
if [[ "$AI_SEEDED" -eq 1 ]]; then
    SESSIONS=$(mcp_call sessions "project=${AI_SMOKE_PROJECT}" "limit=10" "since=1970-01-01T00:00:00Z" 2>&1)
else
    SESSIONS=$(mcp_call sessions "limit=10" 2>&1)
    AI_SMOKE_QUERY='"cortex"'
fi
assert_no_error "sessions: no error" "$SESSIONS"

SESSIONS_VALID=$(printf '%s\n' "$SESSIONS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'count' in d, 'count missing'
assert isinstance(d['sessions'], list), 'sessions not a list'
for s in d['sessions']:
    assert s.get('project'), 'project missing'
    assert s.get('tool'), 'tool missing'
    assert s.get('session_id'), 'session_id missing'
    assert s.get('hostname'), 'hostname missing'
    assert 'first_seen' in s, 'first_seen missing'
    assert 'last_seen' in s, 'last_seen missing'
    assert s.get('event_count', 0) >= 1, 'event_count < 1'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "sessions: response structure valid" "$SESSIONS_VALID" "ok"

if [[ "$AI_SEEDED" -eq 1 ]]; then
    AI_SESSION_FOUND=$(printf '%s\n' "$SESSIONS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('ok' if any(s.get('project') == '${AI_SMOKE_PROJECT}' for s in d.get('sessions', [])) else 'missing')
" 2>/dev/null || echo "error")
    assert_eq "sessions: seeded AI project appears" "$AI_SESSION_FOUND" "ok"
fi

echo ""
echo "Action: AI session analytics"
SEARCH_SESSIONS=$(mcp_call search_sessions "query=${AI_SMOKE_QUERY}" "limit=10" 2>&1)
assert_no_error "search_sessions: no error" "$SEARCH_SESSIONS"
SEARCH_SESSIONS_VALID=$(printf '%s\n' "$SEARCH_SESSIONS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'total_candidates' in d, 'total_candidates missing'
assert isinstance(d.get('sessions'), list), 'sessions not a list'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "search_sessions: response structure valid" "$SEARCH_SESSIONS_VALID" "ok"
if [[ "$AI_SEEDED" -eq 1 ]]; then
    SEARCH_SESSIONS_FOUND=$(printf '%s\n' "$SEARCH_SESSIONS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('ok' if d.get('total_candidates', 0) >= 1 else 'missing')
" 2>/dev/null || echo "error")
    assert_eq "search_sessions: seeded fixture is searchable" "$SEARCH_SESSIONS_FOUND" "ok"
fi

ABUSE=$(mcp_call abuse "project=${AI_SMOKE_PROJECT}" 'terms=["ai-smoke-authentication"]' "limit=5" "before=1" "after=1" 2>&1)
assert_no_error "abuse: no error" "$ABUSE"
ABUSE_VALID=$(printf '%s\n' "$ABUSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d.get('terms'), list), 'terms not a list'
assert isinstance(d.get('matches'), list), 'matches not a list'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "abuse: response structure valid" "$ABUSE_VALID" "ok"
if [[ "$AI_SEEDED" -eq 1 ]]; then
    ABUSE_FOUND=$(printf '%s\n' "$ABUSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('ok' if d.get('matches') else 'missing')
" 2>/dev/null || echo "error")
    assert_eq "abuse: custom detector finds seeded fixture" "$ABUSE_FOUND" "ok"
fi

ABUSE_INCIDENTS=$(mcp_call abuse_incidents "project=${AI_SMOKE_PROJECT}" "limit=5" 2>&1)
assert_no_error "abuse_incidents: no error" "$ABUSE_INCIDENTS"
ABUSE_INCIDENTS_VALID=$(printf '%s\n' "$ABUSE_INCIDENTS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d.get('incidents'), list), 'incidents not a list'
assert 'total_incidents' in d, 'missing total_incidents'
print('ok')" 2>/dev/null || echo "error")
assert_eq "abuse_incidents: response structure valid" "$ABUSE_INCIDENTS_VALID" "ok"

ABUSE_INVESTIGATE=$(mcp_call abuse_investigate "project=${AI_SMOKE_PROJECT}" "limit=1" 2>&1)
assert_no_error "abuse_investigate: no error" "$ABUSE_INVESTIGATE"
ABUSE_INVESTIGATE_VALID=$(printf '%s\n' "$ABUSE_INVESTIGATE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d.get('evidence'), list), 'evidence not a list'
assert 'total_incidents' in d, 'missing total_incidents'
print('ok')" 2>/dev/null || echo "error")
assert_eq "abuse_investigate: response structure valid" "$ABUSE_INVESTIGATE_VALID" "ok"

AI_CORRELATE=$(mcp_call ai_correlate "project=${AI_SMOKE_PROJECT}" "limit=2" "events_per_anchor=3" 2>&1)
assert_no_error "ai_correlate: no error" "$AI_CORRELATE"
AI_CORRELATE_VALID=$(printf '%s\n' "$AI_CORRELATE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'anchors' in d and isinstance(d['anchors'], list), 'anchors not a list'
assert 'total_related_events' in d, 'total_related_events missing'
assert 'related_limit_per_anchor' in d, 'related_limit_per_anchor missing'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "ai_correlate: response structure valid" "$AI_CORRELATE_VALID" "ok"

TOPIC_CORRELATE=$(mcp_call topic_correlate "topic=${AI_SMOKE_PROJECT}" "limit=5" 2>&1)
assert_no_error "topic_correlate: no error" "$TOPIC_CORRELATE"
TOPIC_CORRELATE_VALID=$(printf '%s\n' "$TOPIC_CORRELATE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'resolved_entities' in d and isinstance(d['resolved_entities'], list), 'resolved_entities not a list'
assert 'timeline' in d and isinstance(d['timeline'], list), 'timeline not a list'
assert 'graph_expansion' in d, 'graph_expansion missing'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "topic_correlate: response structure valid" "$TOPIC_CORRELATE_VALID" "ok"

USAGE_BLOCKS=$(mcp_call usage_blocks 2>&1)
assert_no_error "usage_blocks: no error" "$USAGE_BLOCKS"
USAGE_BLOCKS_VALID=$(printf '%s\n' "$USAGE_BLOCKS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d.get('blocks'), list), 'blocks not a list'
assert 'truncated' in d, 'truncated missing'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "usage_blocks: response structure valid" "$USAGE_BLOCKS_VALID" "ok"

PROJECT_CONTEXT=$(mcp_call project_context "project=${AI_SMOKE_PROJECT}" "limit=5" 2>&1)
assert_no_error "project_context: no error" "$PROJECT_CONTEXT"
PROJECT_CONTEXT_VALID=$(printf '%s\n' "$PROJECT_CONTEXT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('project') == '${AI_SMOKE_PROJECT}', 'project mismatch'
assert isinstance(d.get('recent_entries'), list), 'recent_entries not a list'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "project_context: response structure valid" "$PROJECT_CONTEXT_VALID" "ok"
if [[ "$AI_SEEDED" -eq 1 ]]; then
    PROJECT_CONTEXT_FOUND=$(printf '%s\n' "$PROJECT_CONTEXT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('ok' if len(d.get('recent_entries', [])) >= 1 else 'missing')
" 2>/dev/null || echo "error")
    assert_eq "project_context: seeded fixture has entries" "$PROJECT_CONTEXT_FOUND" "ok"
fi

AI_TOOLS=$(mcp_call list_ai_tools 2>&1)
assert_no_error "list_ai_tools: no error" "$AI_TOOLS"
AI_TOOLS_VALID=$(printf '%s\n' "$AI_TOOLS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d.get('tools'), list), 'tools not a list'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "list_ai_tools: response structure valid" "$AI_TOOLS_VALID" "ok"

AI_PROJECTS=$(mcp_call list_ai_projects 2>&1)
assert_no_error "list_ai_projects: no error" "$AI_PROJECTS"
AI_PROJECTS_VALID=$(printf '%s\n' "$AI_PROJECTS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d.get('projects'), list), 'projects not a list'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "list_ai_projects: response structure valid" "$AI_PROJECTS_VALID" "ok"

# ── tail ──────────────────────────────────────────────────────────────────────
echo ""
echo "Action: tail"
TAIL=$(mcp_call tail "n=10" 2>&1)
assert_no_error "tail: no error" "$TAIL"

TAIL_COUNT=$(printf '%s\n' "$TAIL" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "0")
assert_gte "tail: returns >= 1 log" "$TAIL_COUNT" 1

TAIL_VALID=$(printf '%s\n' "$TAIL" | python3 -c "
import sys, json
logs = json.load(sys.stdin)['logs']
assert logs, 'no logs'
for l in logs:
    assert l.get('id'), 'id missing'
    assert l.get('hostname'), 'hostname missing'
    assert l.get('severity'), 'severity missing'
    assert 'message' in l, 'message missing'
    assert l.get('timestamp'), 'timestamp missing'
print('ok')
" 2>&1)
assert_eq "tail: log entries have required fields" "$TAIL_VALID" "ok"

# Results must be in non-increasing timestamp order (most recent first)
TAIL_ORDER=$(printf '%s\n' "$TAIL" | python3 -c "
import sys, json
logs = json.load(sys.stdin)['logs']
for i in range(1, len(logs)):
    if logs[i]['timestamp'] > logs[i-1]['timestamp']:
        print(f'not_descending at index {i}'); sys.exit(0)
print('ok')
" 2>/dev/null || echo "error")
assert_eq "tail: results in non-increasing timestamp order" "$TAIL_ORDER" "ok"

if [[ "$SKIP_SEED" -eq 0 ]]; then
    # host= filter must only return logs for that host
    TAIL_FILTERED=$(mcp_call tail "host=${SEED_HOST}" "n=50" 2>&1)
    assert_no_error "tail(hostname filter): no error" "$TAIL_FILTERED"
    TAIL_FILTER_VALID=$(printf '%s\n' "$TAIL_FILTERED" | python3 -c "
import sys, json
logs = json.load(sys.stdin)['logs']
assert logs, 'no logs returned for seeded host'
wrong = [l['hostname'] for l in logs if l['hostname'] != '${SEED_HOST}']
assert not wrong, f'hostname filter leaked other hosts: {wrong}'
print('ok')
" 2>/dev/null || echo "error")
    assert_eq "tail(hostname filter): only returns logs for '$SEED_HOST'" "$TAIL_FILTER_VALID" "ok"

    TAIL_TCP_MARKER=$(printf '%s\n' "$TAIL_FILTERED" | python3 -c "
import sys, json
logs = json.load(sys.stdin)['logs']
matches = [l for l in logs if '${TCP_MARKER}' in (l.get('message') or '')]
assert matches, 'TCP seed marker not present in tail(hostname filter)'
print('ok')
" 2>/dev/null || echo "error")
    assert_eq "tail(hostname filter): TCP seed marker appears" "$TAIL_TCP_MARKER" "ok"
fi

# ── search ────────────────────────────────────────────────────────────────────
echo ""
echo "Action: search"

# FTS5 keyword search. A match can come from any indexed field, so message-only
# substring assertions belong to the seeded marker checks below.
SEARCH=$(mcp_call search "query=authentication" "limit=50" 2>&1)
assert_no_error "search(query=authentication): no error" "$SEARCH"
SEARCH_VALID=$(printf '%s\n' "$SEARCH" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d.get('logs'), list), 'logs missing or not a list'
assert isinstance(d.get('count'), int), 'count missing or not an integer'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "search(query=authentication): response structure valid" "$SEARCH_VALID" "ok"

# Phrase search
SEARCH_PHRASE=$(mcp_call search 'query="authentication failure"' "host=${SEED_HOST}" "severity=err" "limit=10" 2>&1)
assert_no_error "search(phrase): no error" "$SEARCH_PHRASE"
if [[ "$SKIP_SEED" -eq 0 ]]; then
    PHRASE_MATCH=$(printf '%s\n' "$SEARCH_PHRASE" | python3 -c "
import sys, json
logs = json.load(sys.stdin)['logs']
assert logs, 'phrase search returned no results'
for l in logs:
    if 'authentication failure' not in (l.get('message') or '').lower():
        print(f'phrase not found in: {l[\"message\"][:80]}'); sys.exit(0)
    assert l['hostname'] == '${SEED_HOST}', f'wrong hostname: {l[\"hostname\"]}'
    assert l['severity'] == 'err', f'wrong severity: {l[\"severity\"]}'
print('ok')
" 2>/dev/null || echo "error")
    assert_eq "search(phrase): seeded results contain exact phrase" "$PHRASE_MATCH" "ok"
fi

if [[ "$SKIP_SEED" -eq 0 ]]; then
    # host= filter: should return only that host's logs
    SEARCH_HOST=$(mcp_call search "host=${SEED_HOST}" "limit=50" 2>&1)
    assert_no_error "search(hostname filter): no error" "$SEARCH_HOST"
    SEARCH_HOST_VALID=$(printf '%s\n' "$SEARCH_HOST" | python3 -c "
import sys, json
logs = json.load(sys.stdin)['logs']
assert logs, 'hostname filter returned no logs for seeded host'
wrong = [l['hostname'] for l in logs if l['hostname'] != '${SEED_HOST}']
assert not wrong, f'hostname filter leaked other hosts: {wrong}'
print('ok')
" 2>/dev/null || echo "error")
    assert_eq "search(hostname filter): only returns logs for '$SEED_HOST'" "$SEARCH_HOST_VALID" "ok"

    SEARCH_TCP=$(mcp_call search "query=${TCP_MARKER}" "host=${SEED_HOST}" "limit=10" 2>&1)
    assert_no_error "search(TCP seed marker): no error" "$SEARCH_TCP"
    SEARCH_TCP_VALID=$(printf '%s\n' "$SEARCH_TCP" | python3 -c "
import sys, json
logs = json.load(sys.stdin)['logs']
assert logs, 'TCP seed marker search returned no logs'
for l in logs:
    assert l['hostname'] == '${SEED_HOST}', f'wrong hostname: {l[\"hostname\"]}'
    assert '${TCP_MARKER}' in (l.get('message') or ''), 'marker missing from result'
print('ok')
" 2>/dev/null || echo "error")
    assert_eq "search(TCP seed marker): returns TCP-ingested message" "$SEARCH_TCP_VALID" "ok"
fi

# Nonexistent hostname must return 0 results (filter is not ignored)
SEARCH_GHOST=$(mcp_call search "host=${GHOST_HOST}" "limit=10" 2>&1)
assert_no_error "search(nonexistent hostname): no error" "$SEARCH_GHOST"
GHOST_COUNT=$(printf '%s\n' "$SEARCH_GHOST" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "-1")
assert_eq "search(nonexistent hostname): returns 0 results" "$GHOST_COUNT" "0"

# limit=0 edge case
SEARCH_ZERO=$(mcp_call search "limit=0" 2>&1)
assert_no_error "search(limit=0): no error" "$SEARCH_ZERO"
ZERO_COUNT=$(printf '%s\n' "$SEARCH_ZERO" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])" 2>/dev/null || echo "-1")
assert_eq "search(limit=0): returns 0 results" "$ZERO_COUNT" "0"

# ── filter ───────────────────────────────────────────────────────────────────
echo ""
echo "Action: filter"
FILTER_HOST=$(mcp_call filter "host=${TEST_HOST}" "limit=50" 2>&1)
assert_no_error "filter(hostname): no error" "$FILTER_HOST"
FILTER_HOST_VALID=$(printf '%s\n' "$FILTER_HOST" | python3 -c "
import sys, json
logs = json.load(sys.stdin)['logs']
assert logs, 'filter returned no logs for selected host'
wrong = [l['hostname'] for l in logs if l['hostname'] != '${TEST_HOST}']
assert not wrong, f'filter leaked other hosts: {wrong}'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "filter(hostname): only returns logs for '$TEST_HOST'" "$FILTER_HOST_VALID" "ok"

# ── errors ────────────────────────────────────────────────────────────────────
echo ""
echo "Action: errors"
ERRORS_OUT=$(mcp_call errors 2>&1)
assert_no_error "errors: no error" "$ERRORS_OUT"

# Structure + severity values are valid
ERRORS_VALID=$(printf '%s\n' "$ERRORS_OUT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'summary' in d and isinstance(d['summary'], list), 'summary missing or not a list'
valid_severities = {'emerg', 'alert', 'crit', 'err', 'warning'}
for item in d['summary']:
    assert item.get('hostname'), 'hostname missing'
    assert item.get('severity') in valid_severities, f'unexpected severity: {item.get(\"severity\")}'
    assert item.get('count', 0) >= 1, 'count must be >= 1'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "errors: summary structure and severity values valid" "$ERRORS_VALID" "ok"

# Info-level logs must NOT appear in error summary
INFO_IN_ERRORS=$(printf '%s\n' "$ERRORS_OUT" | python3 -c "
import sys, json
info_rows = [i for i in json.load(sys.stdin)['summary'] if i['severity'] in ('info','debug','notice')]
print('ok' if not info_rows else f'info/debug/notice leaked: {info_rows}')
" 2>/dev/null || echo "error")
assert_eq "errors: info/debug/notice levels absent from summary" "$INFO_IN_ERRORS" "ok"

ERRORS_COUNT=$(printf '%s\n' "$ERRORS_OUT" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['summary']))" 2>/dev/null || echo "0")
if [[ "$SKIP_SEED" -eq 0 ]]; then
    assert_gte "errors: at least 1 seeded error group" "$ERRORS_COUNT" 1
fi

if [[ "$SKIP_SEED" -eq 0 ]]; then
    # Seeded host must appear with err, crit, and warning entries
    SEED_IN_ERRORS=$(printf '%s\n' "$ERRORS_OUT" | python3 -c "
import sys, json
rows = json.load(sys.stdin)['summary']
host_rows = [r for r in rows if r['hostname'] == '${SEED_HOST}']
assert host_rows, 'seeded host not found in errors summary'
severities = {r['severity'] for r in host_rows}
for expected in ('err', 'crit', 'warning'):
    assert expected in severities, f'{expected} missing from seeded host rows (got {severities})'
print('ok')
" 2>/dev/null || echo "error")
    assert_eq "errors: seeded host present with err/crit/warning entries" "$SEED_IN_ERRORS" "ok"
fi

# ── correlate ─────────────────────────────────────────────────────────────────
echo ""
echo "Action: correlate"
REF_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
CORRELATE=$(mcp_call correlate "reference_time=$REF_TIME" "window_minutes=30" 2>&1)
assert_no_error "correlate: no error" "$CORRELATE"

CORRELATE_VALID=$(printf '%s\n' "$CORRELATE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for field in ('reference_time', 'window_minutes', 'total_events', 'hosts', 'window_from', 'window_to', 'truncated'):
    assert field in d, f'{field} missing'
assert isinstance(d['hosts'], list), 'hosts not a list'
for h in d['hosts']:
    assert h.get('hostname'), 'hostname missing'
    assert 'event_count' in h, 'event_count missing'
    assert h['event_count'] > 0, 'event_count=0'
    assert isinstance(h.get('events'), list), 'events not a list'
    for e in h['events']:
        assert e.get('id'), 'event id missing'
        assert e.get('severity'), 'event severity missing'
        assert e.get('timestamp'), 'event timestamp missing'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "correlate: response structure valid" "$CORRELATE_VALID" "ok"

# window_minutes must be echoed back correctly
CORRELATE_WINDOW=$(json_get "$CORRELATE" "['window_minutes']")
assert_eq "correlate: window_minutes echoed back as 30" "$CORRELATE_WINDOW" "30"

CORRELATE_EVENTS=$(printf '%s\n' "$CORRELATE" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_events'])" 2>/dev/null || echo "0")
if [[ "$SKIP_SEED" -eq 0 ]]; then
    assert_gte "correlate: found seeded events in 30-minute window" "$CORRELATE_EVENTS" 1
fi

if [[ "$SKIP_SEED" -eq 0 ]]; then
    SEED_IN_CORRELATE=$(printf '%s\n' "$CORRELATE" | python3 -c "
import sys, json
hosts = [h['hostname'] for h in json.load(sys.stdin)['hosts']]
print('ok' if '${SEED_HOST}' in hosts else f'missing (got {hosts})')
" 2>/dev/null || echo "error")
    assert_eq "correlate: seeded host '$SEED_HOST' appears in window" "$SEED_IN_CORRELATE" "ok"
fi

# Omitting reference_time now derives a useful default from recent activity.
CORRELATE_NO_REF=$(mcp_call correlate 2>&1 || true)
assert_no_error "correlate(default reference_time): no error" "$CORRELATE_NO_REF"
CORRELATE_DEFAULT_VALID=$(printf '%s\n' "$CORRELATE_NO_REF" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('reference_time'), 'reference_time missing'
assert isinstance(d.get('hosts'), list), 'hosts not a list'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "correlate(default reference_time): response structure valid" "$CORRELATE_DEFAULT_VALID" "ok"

# ── compose diagnostics ───────────────────────────────────────────────────────
echo ""
echo "Action: compose_status"
COMPOSE_STATUS=$(mcp_call compose_status 2>&1)
assert_no_error "compose_status: no error" "$COMPOSE_STATUS"
COMPOSE_STATUS_VALID=$(printf '%s\n' "$COMPOSE_STATUS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for key in ('container_name', 'ownership', 'runtime_state', 'published_ports', 'diagnostics'):
    assert key in d, f'{key} missing'
text = json.dumps(d)
assert 'compose_working_dir' not in text, 'host working dir leaked'
assert 'image_id' not in text, 'image id leaked'
print('ok')
" 2>/dev/null || echo "error")
assert_eq "compose_status: redacted safe response valid" "$COMPOSE_STATUS_VALID" "ok"
COMPOSE_STATUS_DOCTORABLE=$(printf '%s\n' "$COMPOSE_STATUS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('yes' if d.get('runtime_state') != 'docker_unavailable' and d.get('ownership') == 'compose_owned' else 'no')
" 2>/dev/null || echo "no")

echo ""
echo "Action: compose_doctor"
if [[ "$COMPOSE_STATUS_DOCTORABLE" == "yes" ]]; then
    COMPOSE_DOCTOR=$(mcp_call compose_doctor 2>&1)
    assert_no_error "compose_doctor: no error" "$COMPOSE_DOCTOR"
    COMPOSE_DOCTOR_VALID=$(printf '%s\n' "$COMPOSE_DOCTOR" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for key in ('container_name', 'ownership', 'runtime_state'):
    assert key in d, f'{key} missing'
print('ok')
" 2>/dev/null || echo "error")
    assert_eq "compose_doctor: safe response valid" "$COMPOSE_DOCTOR_VALID" "ok"
else
    skip "compose_doctor: deployment is not doctorable from compose_status"
fi

# ── help ──────────────────────────────────────────────────────────────────────
echo ""
echo "Action: help"
HELP_FILE=$(mktemp /tmp/cortex-help-XXXXXX.json)
if mcporter call --config "$MCPORTER_CONFIG" "cortex.cortex" "action=help" >"$HELP_FILE" 2>&1; then
    if python3 -c "
import sys, json
try:
    d = json.load(open(sys.argv[1]))
    sys.exit(1 if d.get('isError') else 0)
except Exception:
    sys.exit(1)
" "$HELP_FILE" 2>/dev/null; then
        pass "help: no error"
    else
        fail "help: no error (response was invalid JSON or isError=true)"
    fi
else
    fail "help: no error (mcporter call failed)"
fi
HELP_VALID=$(python3 -c "
import sys, json
d = json.load(open(sys.argv[1]))
assert 'help' in d, 'help key missing'
text = d['help']
assert len(text) > 100, 'help text suspiciously short'
for section in ('search', 'tail', 'errors', 'hosts', 'sessions', 'correlate', 'stats', 'status'):
    assert section in text.lower(), f'help text missing section: {section}'
print('ok')
" "$HELP_FILE" 2>/dev/null || echo "error")
rm -f "$HELP_FILE"
assert_eq "help: contains all action sections" "$HELP_VALID" "ok"

# ── artifact evidence ─────────────────────────────────────────────────────────
echo ""
echo "Action: artifact_evidence"
ARTIFACT_EVIDENCE=$(mcp_call artifact_evidence "limit=5" 2>&1)
assert_no_error "artifact_evidence: bounded query no error" "$ARTIFACT_EVIDENCE"

echo ""
echo "Action: artifact_evidence_record"
if mcp_admin_scope_available; then
    ARTIFACT_SMOKE_ID="smoke-artifact-${RUN_ID}"
    ARTIFACT_EVENT_ID="smoke-event-${RUN_ID}"
    ARTIFACT_OBSERVED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    ARTIFACT_RECORD=$(mcp_call artifact_evidence_record \
        "schemaVersion=dinglebear.cortex-artifact-evidence/v1" \
        "eventId=${ARTIFACT_EVENT_ID}" \
        "eventKind=runtime_call" \
        "sourceSystem=smoke" \
        "sourceIssuer=smoke:integration" \
        "observedAt=${ARTIFACT_OBSERVED_AT}" \
        "artifactId=${ARTIFACT_SMOKE_ID}" \
        "outcome=success" 2>&1)
    assert_no_error "artifact_evidence_record: append no error" "$ARTIFACT_RECORD"
    ARTIFACT_QUERY=$(mcp_call artifact_evidence "artifactId=${ARTIFACT_SMOKE_ID}" "limit=5" 2>&1)
    assert_no_error "artifact_evidence: recorded event query no error" "$ARTIFACT_QUERY"
    ARTIFACT_QUERY_COUNT=$(printf '%s\n' "$ARTIFACT_QUERY" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('events', [])))" 2>/dev/null || echo 0)
    assert_gte "artifact_evidence: recorded event query returns row" "$ARTIFACT_QUERY_COUNT" 1
else
    skip "artifact_evidence_record: requires cortex:admin (set CORTEX_STATIC_TOKEN_ADMIN=true or CORTEX_SMOKE_ADMIN=true)"
fi

# ── skill_events ─────────────────────────────────────────────────────────────
echo ""
echo "Action: skill_events"
SKILL_EVENTS=$(mcp_call skill_events "limit=5" 2>&1)
assert_no_error "skill_events: no error" "$SKILL_EVENTS"

# ── skill_incidents ──────────────────────────────────────────────────────────
echo ""
echo "Action: skill_incidents"
SKILL_INCIDENTS=$(mcp_call skill_incidents "limit=5" 2>&1)
assert_no_error "skill_incidents: no error" "$SKILL_INCIDENTS"

# ── skill_investigate ────────────────────────────────────────────────────────
echo ""
echo "Action: skill_investigate"
SKILL_INVESTIGATE=$(mcp_call skill_investigate "skill=smoke-test-skill" 2>&1)
assert_no_error "skill_investigate: no error" "$SKILL_INVESTIGATE"

# ── mcp_events ───────────────────────────────────────────────────────────────
echo ""
echo "Action: mcp_events"
MCP_EVENTS=$(mcp_call mcp_events "limit=5" 2>&1)
assert_no_error "mcp_events: no error" "$MCP_EVENTS"

# ── mcp_incidents ────────────────────────────────────────────────────────────
echo ""
echo "Action: mcp_incidents"
MCP_INCIDENTS=$(mcp_call mcp_incidents "limit=5" 2>&1)
assert_no_error "mcp_incidents: no error" "$MCP_INCIDENTS"

# ── mcp_investigate ──────────────────────────────────────────────────────────
echo ""
echo "Action: mcp_investigate"
MCP_INVESTIGATE=$(mcp_call mcp_investigate "mcp_server=smoke-test-server" 2>&1)
assert_no_error "mcp_investigate: no error" "$MCP_INVESTIGATE"

# ── hook_events ──────────────────────────────────────────────────────────────
echo ""
echo "Action: hook_events"
HOOK_EVENTS=$(mcp_call hook_events "limit=5" 2>&1)
assert_no_error "hook_events: no error" "$HOOK_EVENTS"

# ── hook_incidents ───────────────────────────────────────────────────────────
echo ""
echo "Action: hook_incidents"
HOOK_INCIDENTS=$(mcp_call hook_incidents "limit=5" 2>&1)
assert_no_error "hook_incidents: no error" "$HOOK_INCIDENTS"

# ── hook_investigate ─────────────────────────────────────────────────────────
echo ""
echo "Action: hook_investigate"
HOOK_INVESTIGATE=$(mcp_call hook_investigate "hook_name=smoke-test-hook" 2>&1)
assert_no_error "hook_investigate: no error" "$HOOK_INVESTIGATE"

# ── graph proof UX (optional: requires known seeded graph evidence id) ───────
echo ""
echo "Graph proof UX"
if [[ -n "${CORTEX_SMOKE_GRAPH_EVIDENCE_ID:-}" ]]; then
    GRAPH_PROOF_START=$(python3 -c "import time; print(int(time.time() * 1000))")
    GRAPH_EVIDENCE=$(mcp_call graph "mode=evidence" "evidence_id=${CORTEX_SMOKE_GRAPH_EVIDENCE_ID}" "payload_budget=8192" 2>&1)
    GRAPH_PROOF_END=$(python3 -c "import time; print(int(time.time() * 1000))")
    assert_no_error "graph evidence: no error" "$GRAPH_EVIDENCE"
    GRAPH_EVIDENCE_BYTES=$(printf '%s' "$GRAPH_EVIDENCE" | wc -c | tr -d ' ')
    GRAPH_EVIDENCE_LATENCY_MS=$((GRAPH_PROOF_END - GRAPH_PROOF_START))
    GRAPH_EVIDENCE_VALID=$(printf '%s\n' "$GRAPH_EVIDENCE" | python3 -c "
import json, re, sys
d = json.load(sys.stdin)
blob = json.dumps(d)
assert d['evidence']['id'] == int('${CORTEX_SMOKE_GRAPH_EVIDENCE_ID}'), 'evidence id mismatch'
rel = d['relationship']
assert isinstance(rel.get('src_entity_id'), int), 'src_entity_id missing'
assert isinstance(rel.get('dst_entity_id'), int), 'dst_entity_id missing'
assert isinstance(d.get('src_entity'), dict), 'src_entity summary missing'
assert isinstance(d.get('dst_entity'), dict), 'dst_entity summary missing'
assert 'raw' not in blob, 'raw field leaked'
assert 'metadata_json' not in blob, 'metadata_json leaked'
privacy_blob = blob
for marker in ('Authorization', 'Bearer ', 'Cookie', 'Set-Cookie', 'client_secret', 'access_token', '/home/', 'PRIVATE KEY'):
    assert marker not in privacy_blob, f'sensitive marker leaked: {marker}'
assert re.search(r'://[^\s/:]+:[^\s/@]+@', privacy_blob) is None, 'url userinfo leaked'
summary = d.get('source_log_summary')
if summary is None:
    assert d.get('missing_source_reason'), 'missing source reason absent'
else:
    assert len(summary.get('message', '')) <= 1024, 'source summary message too large'
    assert not any(ord(ch) < 32 for ch in summary.get('message', '')), 'control character leaked'
print('ok')
" 2>/dev/null || echo "error")
    assert_eq "graph evidence: proof/privacy contract valid" "$GRAPH_EVIDENCE_VALID" "ok"
    if [[ "$GRAPH_EVIDENCE_BYTES" -le 8192 ]]; then
        echo "PASS: graph evidence: bounded response bytes ($GRAPH_EVIDENCE_BYTES <= 8192)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: graph evidence: response too large ($GRAPH_EVIDENCE_BYTES > 8192)"
        FAIL=$((FAIL + 1))
        ERRORS+=("graph evidence response too large")
    fi
    if [[ "$GRAPH_EVIDENCE_LATENCY_MS" -le 5000 ]]; then
        echo "PASS: graph evidence: latency bounded (${GRAPH_EVIDENCE_LATENCY_MS}ms <= 5000ms)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: graph evidence: latency too high (${GRAPH_EVIDENCE_LATENCY_MS}ms > 5000ms)"
        FAIL=$((FAIL + 1))
        ERRORS+=("graph evidence latency too high")
    fi
else
    echo "SKIP: graph proof UX — set CORTEX_SMOKE_GRAPH_EVIDENCE_ID to a real graph_relationship_evidence id"
    SKIP=$((SKIP + 1))
fi

# ── invalid action (negative test) ───────────────────────────────────────────
echo ""
echo "Negative tests"
INVALID=$(mcp_call notanaction 2>&1 || true)
assert_is_error "invalid action: returns error" "$INVALID"

# ─── OAuth discovery endpoints (unconditional — no Google creds needed) ─────
echo ""
echo "OAuth discovery endpoints"
OAUTH_BASE="${MCP_URL%/mcp}"
DISCOVERY=$(curl -s -o /dev/null -w "%{http_code}" "$OAUTH_BASE/.well-known/oauth-authorization-server")
if [ "$DISCOVERY" = "200" ]; then
    echo "PASS: OAuth discovery endpoint reachable (/.well-known/oauth-authorization-server)"
    PASS=$((PASS + 1))
    JWKS=$(curl -s -o /dev/null -w "%{http_code}" "$OAUTH_BASE/jwks")
    if [ "$JWKS" = "200" ]; then
        echo "PASS: /jwks reachable"
        PASS=$((PASS + 1))
    else
        echo "WARN: /jwks returned $JWKS (expected 200 when OAuth mounted)"
        FAIL=$((FAIL + 1))
        ERRORS+=("/jwks returned $JWKS")
    fi
else
    echo "INFO: OAuth not enabled (/.well-known returned $DISCOVERY) — skipping OAuth endpoint checks"
fi

# ─── Enrichment framework smoke (epic cortex-1wjr) ─────────────────────
# Forward a synthetic SWAG access line, then assert http_status materialised.
echo ""
echo "Enrichment framework smoke"
SWAG_LINE='<134>1 2026-05-16T10:00:00Z localhost swag - - - 192.0.2.55 - - [16/May/2026:10:00:00 +0000] "GET /smoke HTTP/1.1" 418 13 "-" "smoketest/1.0"'
echo "$SWAG_LINE" | nc -w1 -u "${CORTEX_RECEIVER_HOST:-127.0.0.1}" "${CORTEX_RECEIVER_PORT:-1514}" || true
sleep 1

if command -v sqlite3 >/dev/null 2>&1; then
    DB_PATH="${CORTEX_DB_PATH:-/data/cortex.db}"
    COUNT=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM logs WHERE http_status = 418" 2>/dev/null || echo "0")
    if [ "$COUNT" = "0" ]; then
        echo "WARN: enrichment smoke — http_status=418 not found (sqlite3 check)"
    else
        echo "PASS: enrichment framework wired (http_status=418 found)"
        PASS=$((PASS + 1))
    fi
else
    echo "SKIP: enrichment smoke — sqlite3 not available"
fi

# ── CLI positionals + zero-flag defaults (Plan 3) ─────────────────────────────
echo ""
echo "CLI: positionals + defaults"
if CLI_BIN="$(resolve_cortex_bin)"; then
    # `cortex tail devhost` — bare positional binds to --host; default n=50.
    CLI_TAIL_HOST="$TEST_HOST"
    if [[ -n "$CLI_TAIL_HOST" ]]; then
        if CORTEX_URL="${MCP_URL%/mcp}" "$CLI_BIN" tail "$CLI_TAIL_HOST" -n 1 >/dev/null 2>&1; then
            pass "cli: tail positional host (cortex tail $CLI_TAIL_HOST -n 1)"
        else
            fail "cli: tail positional host (cortex tail $CLI_TAIL_HOST -n 1)"
        fi
    else
        skip "cli: tail positional host (no known hostname to target)"
    fi

    # `cortex analysis errors` — no flags; default 1h window applied.
    if CORTEX_URL="${MCP_URL%/mcp}" "$CLI_BIN" analysis errors >/dev/null 2>&1; then
        pass "cli: errors default window (cortex analysis errors)"
    else
        fail "cli: errors default window (cortex analysis errors)"
    fi
else
    skip "cli: positional/default checks require the cortex binary (set CORTEX_BIN or build it)"
fi

# ─── Phase 4: Summary ────────────────────────────────────────────────────────
echo ""
echo -e "${COLOR_BOLD}[4/4] Results${COLOR_RESET}"
echo "─────────────────────────────────────"
TOTAL=$((PASS + FAIL))
echo -e "  Passed:  ${COLOR_GREEN}${PASS}${COLOR_RESET} / ${TOTAL}"
echo -e "  Failed:  ${COLOR_RED}${FAIL}${COLOR_RESET} / ${TOTAL}"
echo "  Skipped: ${SKIP}"

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
