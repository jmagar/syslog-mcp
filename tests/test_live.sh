#!/usr/bin/env bash
# test_live.sh -- Live end-to-end test for syslog-mcp
# Tests auth enforcement and health endpoint.
# Exit code 0 = all passed. Exit code 1 = one or more failures.
#
# Usage:
#   SYSLOG_MCP_TOKEN=<token> bash tests/test_live.sh
#   SYSLOG_MCP_TOKEN=<token> SYSLOG_MCP_URL=http://host:3100 bash tests/test_live.sh
set -euo pipefail

TOKEN="${SYSLOG_MCP_TOKEN:-}"
BASE_URL="${SYSLOG_MCP_URL:-http://localhost:3100}"

PASS=0
FAIL=0
ERRORS=()

pass() { echo "PASS  $1"; (( PASS++ )) || true; }
fail() { echo "FAIL  $1"; ERRORS+=("$1"); (( FAIL++ )) || true; }

echo "=== syslog-mcp live tests ==="
echo "URL: $BASE_URL"
echo ""

if [ -n "$TOKEN" ]; then
  echo "Testing unauthenticated rejection..."
  status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/mcp" \
    -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')
  if [ "$status" = "401" ]; then
    pass "Unauthenticated /mcp returns 401"
  else
    fail "Unauthenticated /mcp: expected 401, got $status"
  fi

  echo "Testing bad token rejection..."
  status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/mcp" \
    -X POST -H "Authorization: Bearer bad-token" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')
  if [ "$status" = "401" ]; then
    pass "Bad token /mcp returns 401"
  else
    fail "Bad token /mcp: expected 401, got $status"
  fi
else
  echo "Skipping auth rejection tests (SYSLOG_MCP_TOKEN not set — auth assumed disabled)"
fi

echo "Testing health endpoint (no auth)..."
health=$(curl -sf "$BASE_URL/health" 2>&1) || { fail "Health endpoint unreachable"; health="{}"; }
health_status=$(echo "$health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
if [ "$health_status" = "ok" ]; then
  pass "Health endpoint returns status=ok"
else
  fail "Health endpoint: expected status=ok, got '$health_status'"
fi

echo "Testing tools/list..."
if [ -n "$TOKEN" ]; then
  response=$(curl -s "$BASE_URL/mcp" \
    -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')
else
  response=$(curl -s "$BASE_URL/mcp" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}')
fi
tool_count=$(echo "$response" | python3 -c "
import sys, json
d = json.load(sys.stdin)
tools = d.get('result', {}).get('tools', [])
print(len(tools))
" 2>/dev/null || echo "0")
if [ "$tool_count" -ge 1 ] 2>/dev/null; then
  pass "tools/list returns $tool_count tool(s)"
else
  fail "tools/list: expected at least 1 tool, got $tool_count"
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
if [ ${#ERRORS[@]} -gt 0 ]; then
  echo "Failures:"
  for e in "${ERRORS[@]}"; do
    echo "  - $e"
  done
fi

echo ""
if [ $FAIL -eq 0 ]; then
  echo "ALL TESTS PASSED"
  exit 0
else
  echo "TESTS FAILED -- $FAIL test(s) failed"
  exit 1
fi
