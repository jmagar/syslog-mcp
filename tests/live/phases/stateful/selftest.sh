#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
jq -e '.profiles.stateful.mandatory and .profiles.stateful.poll_attempts>=1000' "$root/tests/live/contracts/profiles.json" >/dev/null
grep -q 'mcp_phase_run' "$root/tests/live/phases/stateful/run.sh"
grep -q 'poll_count' "$root/tests/live/phases/stateful/run.sh"
grep -q 'CORTEX_LLM_ENABLED: "false"' "$root/tests/live/profiles/stateful/compose.yaml"
grep -q 'cmp .*llm-row-before' "$root/tests/live/phases/stateful/run.sh"
grep -q 'exact-log-after' "$root/tests/live/phases/stateful/run.sh"
grep -q 'dependency-failure' "$root/tests/live/phases/stateful/run.sh"
grep -q 'projection watermark did not advance' "$root/tests/live/phases/stateful/run.sh"
grep -q 'timeline-empty' "$root/tests/live/phases/stateful/run.sh"
grep -q 'live_terminal_disposition stateful pass' "$root/tests/live/phases/stateful/run.sh"
! grep -q 'live_result "stateful\.' "$root/tests/live/phases/stateful/run.sh"
echo 'stateful selftest: PASS'
