#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"; tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-telemetry.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
for n in 0 1 2 3; do jq -cn --argjson n "$n" '{elapsed:$n,rss_bytes:(100+$n),fds:4,tasks:1,wal_bytes:(10+$n),db_bytes:20,fts_rows:$n,queue_depth:0,ingest_lag_ms:1,notification_backlog:0,reconnects:0,artifact_bytes:$n,cleanup_ms:0}'; done >"$tmp/fixture"
python3 "$root/tests/live/phases/telemetry/collector.py" --output "$tmp/stream" --duration 1 --interval .1 --cap-bytes 4096 --fixture "$tmp/fixture" >"$tmp/collector"
python3 "$root/tests/live/phases/telemetry/analyze.py" "$tmp/stream" --warmup-seconds .2 --hard rss_bytes=1000 --warn-slope rss_bytes=1000 >"$tmp/report"
jq -e '.pass and .samples>=2 and (.hard_abort|all(.==false))' "$tmp/report" >/dev/null
if python3 "$root/tests/live/phases/telemetry/analyze.py" "$tmp/stream" --hard rss_bytes=1 >/dev/null; then exit 1; fi
python3 "$root/tests/live/phases/telemetry/collector.py" --output "$tmp/term" --duration 30 --interval .1 --cap-bytes 4096 >"$tmp/term-result" & pid=$!; sleep .3; kill -TERM "$pid"; wait "$pid"
jq -e '.terminated==true' "$tmp/term-result" >/dev/null
if python3 "$root/tests/live/phases/telemetry/collector.py" --output "$tmp/cap" --duration 2 --interval .1 --cap-bytes 1024 --fixture "$tmp/fixture" >/dev/null 2>&1; then exit 1; fi
echo 'telemetry selftest: PASS'
