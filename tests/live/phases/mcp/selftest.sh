#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
jq -e '.version==1 and (.admin_actions|length)==6' "$root/tests/live/phases/mcp/scenarios.json" >/dev/null
rg -q 'length==58' "$root/tests/live/phases/mcp/run.sh"
rg -q 'unique|length' "$root/tests/live/phases/mcp/run.sh"
# shellcheck disable=SC1090
source "$root/tests/live/phases/mcp/run.sh"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
printf '%s\n' '{"result":{"isError":false,"structuredContent":{"logs":[]}}}' >"$tmp/good.json"
printf '%s\n' '{"result":{"isError":false,"structuredContent":{"count":0}}}' >"$tmp/mutant.json"
mcp_semantic_oracle "$tmp/good.json" logs
if mcp_semantic_oracle "$tmp/mutant.json" logs; then echo 'semantic-oracle mutant survived' >&2; exit 1; fi
jq -e --slurpfile discovery "$root/tests/live/phases/mcp/discovery.json" '(.required_key|keys|length)+(.allowed_not_found|length)==58 and ($discovery[0]|length)==4' "$root/tests/live/phases/mcp/scenarios.json" >/dev/null
echo 'mcp phase selftest passed'
