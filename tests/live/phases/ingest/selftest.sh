#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
bash -n "$root/tests/live/phases/ingest/run.sh"
bash -n "$root/tests/live/phases/ingest/generate.sh"
jq -e '.schema=="cortex-live-ingest-matrix-v1" and (.lanes|length)==16 and ([.lanes[].id]|unique|length)==16 and all(.lanes[];.durability|length>0)' "$root/tests/live/fixtures/ingest/matrix.json" >/dev/null
grep -q 'live_ingest_mcp_search' "$root/tests/live/phases/ingest/run.sh"
grep -q 'live_ingest_rest_search' "$root/tests/live/phases/ingest/run.sh"
if grep -Eq 'sqlite3|cortex\.db' "$root/tests/live/phases/ingest/run.sh"; then echo 'direct DB access is forbidden' >&2; exit 1; fi
bytes="$(xxd -r -p "$root/tests/live/fixtures/ingest/legacy-docker-multiplex.hex" | wc -c | tr -d ' ')"
[[ "$bytes" -gt 16 ]]
jq -e . "$root/tests/live/fixtures/ingest/legacy-docker-events.jsonl" >/dev/null
jq -e '.case=="otlp-storage-blocked" and (.required_evidence|length)==6' "$root/tests/live/contracts/ingest-storage-obligation.json" >/dev/null
jq -e '(.required|length)>=28 and (.required|unique|length)==(.required|length)' "$root/tests/live/contracts/ingest-cases.json" >/dev/null
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
result="$(bash "$root/tests/live/phases/ingest/generate.sh" fixture 3 3 100 5 "$tmp/out")"
jq -e '.count==3 and .bytes>0' <<<"$result" >/dev/null
[[ "$(wc -l <"$tmp/out" | tr -d ' ')" == 3 ]]
if bash "$root/tests/live/phases/ingest/generate.sh" fixture 4 3 100 5 "$tmp/records" >/dev/null 2>&1; then echo 'generator accepted record overflow' >&2; exit 1; fi
if bash "$root/tests/live/phases/ingest/generate.sh" fixture 3 3 5 5 "$tmp/bytes" >/dev/null 2>&1; then echo 'generator accepted byte overflow' >&2; exit 1; fi
for required in syslog-tcp-reconnect syslog-oversize invalid-utf8 file-tail-rotate file-tail-truncate file-tail-checkpoint legacy-docker; do grep -q "$required" "$root/tests/live/phases/ingest/run.sh"; done
for required in producer_bound file-tail-registration downtime.udp-loss ingest-case-reconciliation; do grep -q "$required" "$root/tests/live/phases/ingest/run.sh"; done
grep -F 'Accept: application/json, text/event-stream' "$root/tests/live/phases/ingest/run.sh" >/dev/null
grep -F '?os=linux&arch=x86_64' "$root/tests/live/phases/ingest/run.sh" >/dev/null
grep -F 'MCP initialize semantic probe failed' "$root/tests/live/phases/ingest/run.sh" >/dev/null
bash "$root/tests/live/phases/ingest/downtime-selftest.sh"
echo 'ingest phase selftest passed'
