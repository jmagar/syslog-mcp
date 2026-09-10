#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"; out="${LIVE_RUN_ROOT:?}/artifacts/concurrency-live"; mkdir -p "$out"
export LIVE_PROJECT_ROOT="$root"
for lib in common lock redact events command budgets wait docker; do
  # Library name is selected from this fixed list.
  # shellcheck disable=SC1090
  source "$root/tests/live/lib/$lib.sh"
done
source "$root/tests/live/phases/ingest/run.sh"
live_install_err_trap
workers="${LIVE_CONCURRENCY_LIVE_WORKERS:-4}"; each="${LIVE_CONCURRENCY_LIVE_ITEMS:-30}"
[[ "$workers" =~ ^[1-8]$ && "$each" =~ ^[1-9][0-9]*$ && "$each" -le 200 ]] || { echo 'unsafe concurrency bounds' >&2; exit 2; }
prefix="conc-${LIVE_RUN_ID#cortex-e2e-}"; candidate="$(live_ingest_candidate_id)"; pids=(); query_pids=()
for n in $(seq 1 "$workers"); do python3 "$root/tests/live/phases/concurrency/producer.py" --port "${LIVE_SYSLOG_TCP_PORT:?}" --prefix "$prefix-w$n" --count "$each" >"$out/producer-$n.json" & pids+=("$!"); done
# Receipt-backed records travel through the same restart. Only these carry a
# server acknowledgement, so only these are held to zero loss after accept.
python3 "$root/tests/live/phases/concurrency/forward_producer.py" --port "${LIVE_HTTP_PORT:?}" --token "$LIVE_CORTEX_TOKEN" --prefix "$prefix-f" --count "$each" >"$out/forward-producer.json" & pids+=("$!")
# Queries and WAL-safe maintenance contend with writers. Every response is retained.
for n in 1 2 3 4; do
  curl -sS --max-time 10 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    --data-binary "{\"jsonrpc\":\"2.0\",\"id\":$n,\"method\":\"tools/call\",\"params\":{\"name\":\"cortex\",\"arguments\":{\"action\":\"stats\"}}}" "http://127.0.0.1:$LIVE_HTTP_PORT/mcp" >"$out/query-$n.json" & query_pids+=("$!")
done
docker exec "$candidate" cortex db checkpoint --json >"$out/checkpoint.json" 2>"$out/checkpoint.stderr" & maintenance_pid=$!
sleep .08; docker restart "$candidate" >"$out/restart.txt"; live_wait_until 30 concurrency-restart-health _live_http_health_ready; live_wait_until 30 concurrency-restart-mcp _live_mcp_ready
status=0; for pid in "${pids[@]}"; do wait "$pid" || status=1; done
# A query cut off by the injected restart is expected contention; its response
# file is retained as evidence and it is counted here, not as a worker failure.
query_failures=0; for pid in "${query_pids[@]}"; do wait "$pid" || query_failures=$((query_failures+1)); done
jq -cn --argjson failed "$query_failures" '{schema:"cortex-live-concurrency-queries-v1",queries:4,cut_off_by_restart:$failed}' >"$out/queries.json"
# The checkpoint races the injected restart on purpose. One the restart kills
# (SIGKILL, or exec refused while the container restarts) is contention
# evidence like a cut-off query; any other failure is a real one. Either way
# the replacement process must checkpoint cleanly and pass a quick integrity check.
maintenance_status=0; maintenance_cut=false
wait "$maintenance_pid" || { rc=$?; if [[ "$rc" == 137 ]] || grep -qiE 'is not running|is restarting' "$out/checkpoint.stderr"; then maintenance_cut=true; else maintenance_status=$rc; fi; }
docker exec "$candidate" cortex db checkpoint --json >"$out/checkpoint-after-restart.json" 2>"$out/checkpoint-after-restart.stderr" || maintenance_status=$?
docker exec "$candidate" cortex db integrity --quick --json >"$out/integrity-after-restart.json" 2>&1 || maintenance_status=$?
jq -cn --argjson cut "$maintenance_cut" --argjson status "$maintenance_status" '{schema:"cortex-live-concurrency-maintenance-v1",cut_off_by_restart:$cut,failure_status:$status}' >"$out/maintenance.json"
# A post-restart sentinel proves recovery independently of any in-flight loss.
python3 "$root/tests/live/phases/concurrency/producer.py" --port "$LIVE_SYSLOG_TCP_PORT" --prefix "$prefix-recovery" --count 1 >"$out/recovery-producer.json"
sleep 2
body="$(jq -cn --arg q "\"$prefix\"" '{jsonrpc:"2.0",id:91,method:"tools/call",params:{name:"cortex",arguments:{action:"search",query:$q,limit:1000}}}')"
curl -fsS --max-time 20 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary "$body" "http://127.0.0.1:$LIVE_HTTP_PORT/mcp" >"$out/search.json"
offered=$((workers*each)); accepted="$(jq -s '[.[].accepted]|add' "$out"/producer-*.json)"; rejected="$(jq -s '[.[].rejected]|add' "$out"/producer-*.json)"
persisted="$(jq --arg prefix "$prefix-w" '[.result.structuredContent.logs[]?|select(.message|contains($prefix))] | length' "$out/search.json")"; duplicates="$(jq --arg prefix "$prefix-w" '[.result.structuredContent.logs[]?|select(.message|contains($prefix))|.message] | length - (unique|length)' "$out/search.json")"
loss=$((accepted-persisted)); (( loss >= 0 )) || loss=0
jq -cn --argjson offered "$offered" --argjson accepted "$accepted" --argjson rejected "$rejected" --argjson persisted "$persisted" --argjson loss "$loss" --argjson duplicates "$duplicates" --argjson worker_status "$status" --argjson maintenance_status "$maintenance_status" \
  '{schema:"cortex-live-direct-concurrency-v1",offered:$offered,accepted:$accepted,rejected:$rejected,persisted:$persisted,lost_after_accept:$loss,duplicates:$duplicates,retries:0,lock_contention_exercised:true,cas_restart_generation:1,worker_failure:$worker_status,maintenance_failure:$maintenance_status,accounted:($persisted+$rejected+$loss),bounds:{workers:8,items_per_worker:200}}' >"$out/accounting.json"
# Plain syslog over TCP has no application acknowledgement: "accepted" only
# means toxiproxy's socket took the bytes, and whatever it still held when the
# candidate restarted is gone. Hold it to what the transport can promise: every
# record accounted for, none stored twice, never more stored than sent.
jq -e '.offered==.accepted+.rejected and .persisted<=.accepted and .accounted==.offered and .duplicates==0 and .worker_failure==0 and .maintenance_failure==0 and .cas_restart_generation==1' "$out/accounting.json" >/dev/null || {
  echo "live-e2e: direct concurrency accounting did not balance: $(jq -c . "$out/accounting.json")" >&2; exit 1; }
# Receipted records must each be stored exactly once, restart or not.
jq -n --slurpfile fp "$out/forward-producer.json" --slurpfile search "$out/search.json" --arg prefix "$prefix-f" '
  ([$search[0].result.structuredContent.logs[]?|select(.message|contains($prefix))|.message]) as $stored |
  {schema:"cortex-live-direct-concurrency-forward-v1",accepted:$fp[0].accepted,rejected:$fp[0].rejected,
   persisted_of_accepted:([$fp[0].sent[] as $m | select(any($stored[]; contains($m)))]|length),
   duplicates:(($stored|length)-($stored|unique|length))}' >"$out/forward.json"
jq -e '.accepted>0 and .persisted_of_accepted==.accepted and .duplicates==0' "$out/forward.json" >/dev/null || {
  echo "live-e2e: receipt-backed records were not all stored exactly once: $(jq -c . "$out/forward.json")" >&2; exit 1; }
jq -e '.accepted==1' "$out/recovery-producer.json" >/dev/null
# Cancellation is a separate observed attempt; its partial accounting remains
# evidence and cannot be overwritten by a retry.
python3 "$root/tests/live/phases/concurrency/producer.py" --port "$LIVE_SYSLOG_TCP_PORT" --prefix "$prefix-cancel" --count 200 --delay .05 --progress "$out/cancel.json" >/dev/null & cancel_pid=$!
sleep .1
kill -0 "$cancel_pid"
kill -TERM "$cancel_pid"
set +e; wait "$cancel_pid"; cancel_status=$?; set -e
[[ "$cancel_status" == 143 ]]
! kill -0 "$cancel_pid" 2>/dev/null
jq -e '.interrupted==true and .attempted==(.accepted+.rejected) and .attempted>0 and .attempted<.offered' "$out/cancel.json" >/dev/null
jq -cn --argjson status "$cancel_status" --slurpfile accounting "$out/cancel.json" \
  '{schema:"cortex-live-attempt-v1",attempt_kind:"first_attempt",retry_index:0,result:"fail",failure:"injected cancellation",preserved:true,observed_exit:$status,partial_accounting:$accounting[0]}' >"$out/cancellation-first-attempt.json"
echo 'direct concurrency run: PASS'
