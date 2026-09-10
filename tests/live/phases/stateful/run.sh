#!/usr/bin/env bash

stateful_mcp_call() {
  local action="$1" arguments="$2" output="$3"
  mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --arg action "$action" --argjson arguments "$arguments" '{jsonrpc:"2.0",id:900,method:"tools/call",params:{name:"cortex",arguments:($arguments+{action:$action})}}')" "$output"
  jq -e '.result.isError==false and .result.structuredContent!=null' "$output" >/dev/null
}

# Count oom_kill firings for this run's host. Reads $dir and $oom_host from the
# calling stateful_phase_run (bash dynamic scope), so live_wait_until can poll it.
_stateful_oom_firings_are() {
  local want="$1"
  stateful_mcp_call notifications_recent '{"rule_id":"oom_kill","limit":100}' "$dir/oom-firings.json" || return 1
  [[ "$(jq --arg h "$oom_host" '[.result.structuredContent[]?|select(.hostname==$h)]|length' "$dir/oom-firings.json")" == "$want" ]]
}

stateful_phase_run() {
  local dir="$LIVE_RUN_ROOT/artifacts/stateful" before after candidate polls=0 started now marker pre_log_id pre_llm_id pre_watermark post_watermark
  mkdir -p "$dir"; chmod 700 "$dir"
  live_event phase_started '{"phase":"stateful"}'

  # The authoritative MCP sweep supplies deterministic transcript, heartbeat,
  # graph, error, notification and disabled-LLM audit fixtures, and applies its
  # action-specific semantic oracles to every stateful read/evidence action.
  mcp_phase_run

  marker="mcp-error-${LIVE_RUN_ID#cortex-e2e-}"
  stateful_mcp_call search "$(jq -cn --arg q "\"$marker\"" '{query:$q,limit:10}')" "$dir/exact-log-before.json"
  pre_log_id="$(jq -er --arg marker "$marker" 'first(.result.structuredContent.logs[]|select(.message==$marker))|.id' "$dir/exact-log-before.json")"
  stateful_mcp_call host_state "$(jq -cn --arg h "$MCP_LIVE_HOST" '{host:$h}')" "$dir/exact-heartbeat-before.json"
  jq -e --arg h "$MCP_LIVE_HOST" '.result.structuredContent.host_id==$h' "$dir/exact-heartbeat-before.json" >/dev/null

  stateful_mcp_call stats '{}' "$dir/stats-before.json"
  before="$(jq -r '.result.structuredContent.total_logs' "$dir/stats-before.json")"
  [[ "$before" =~ ^[1-9][0-9]*$ ]]
  stateful_mcp_call timeline '{}' "$dir/timeline-boundary.json"
  jq -e '.result.structuredContent.points|length>0' "$dir/timeline-boundary.json" >/dev/null
  stateful_mcp_call timeline '{"since":"2099-01-01T00:00:00Z","until":"2099-01-01T01:00:00Z"}' "$dir/timeline-empty.json"
  jq -e '.result.structuredContent.points|length==0' "$dir/timeline-empty.json" >/dev/null
  stateful_mcp_call compare '{"a_from":"2026-08-27T10:00:00Z","a_to":"2026-08-27T11:00:00Z","b_from":"2026-08-27T11:00:00Z","b_to":"2026-08-27T12:00:00Z"}' "$dir/compare-boundary.json"
  jq -e '.result.structuredContent.a.from=="2026-08-27T10:00:00.000Z" and .result.structuredContent.b.to=="2026-08-27T12:00:00.000Z"' "$dir/compare-boundary.json" >/dev/null
  live_result stateful.analytics-boundaries stateful-analytics-boundaries pass 0 artifacts/stateful/compare-boundary.json semantic-positive
  stateful_mcp_call llm_invocations '{}' "$dir/llm-audit-before.json"
  jq -e 'any(.result.structuredContent[]?;.status=="disabled")' "$dir/llm-audit-before.json" >/dev/null
  pre_llm_id="$(jq -er 'first(.result.structuredContent[]|select(.status=="disabled"))|.id' "$dir/llm-audit-before.json")"
  stateful_mcp_call graph "$(jq -cn --arg h "$MCP_LIVE_HOST" '{mode:"entity",entity_type:"host",key:$h}')" "$dir/graph-before.json"
  pre_watermark="$(jq -er '.result.structuredContent.metadata.source_watermark' "$dir/graph-before.json")"

  # A malformed FTS dependency request must fail with a structured error; the
  # immediately following valid query proves recovery rather than a dead path.
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":901,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"search","query":"-","limit":1}}}' "$dir/dependency-failure.json"
  jq -e '.result.isError==true and (.result.content[0].text|length>0)' "$dir/dependency-failure.json" >/dev/null
  live_result stateful.failure-stage-diagnostics stateful-failure-stage-diagnostics pass 0 artifacts/stateful/dependency-failure.json semantic-positive
  stateful_mcp_call search "$(jq -cn --arg q "\"$marker\"" '{query:$q,limit:10}')" "$dir/dependency-recovery.json"
  jq -e --argjson id "$pre_log_id" 'any(.result.structuredContent.logs[]?;.id==$id)' "$dir/dependency-recovery.json" >/dev/null
  live_result stateful.dependency-recovery stateful-dependency-recovery pass 0 artifacts/stateful/dependency-recovery.json semantic-positive

  candidate="$(live_ingest_candidate_id)"
  docker restart "$candidate" >/dev/null
  live_wait_until 30 stateful-restart-health _live_http_health_ready
  live_wait_until 30 stateful-restart-mcp _live_mcp_ready
  # The projection watermark is logs:<max id>;heartbeats:<max id>;signatures:<n>,
  # so it only moves when a new source row lands. Write one after the restart so
  # the watermark check below proves the scheduler re-projected, rather than
  # depending on background traffic arriving within the polling window.
  printf '<134>1 %s stateful-watermark app 1 ID1 - %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "stateful-watermark-${LIVE_RUN_ID#cortex-e2e-}" | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  stateful_mcp_call stats '{}' "$dir/stats-after.json"
  after="$(jq -r '.result.structuredContent.total_logs' "$dir/stats-after.json")"
  [[ "$after" -ge "$before" ]]
  stateful_mcp_call llm_invocations '{}' "$dir/llm-audit-after.json"
  jq -e --arg id "$pre_llm_id" 'any(.result.structuredContent[]?;.id==$id and .status=="disabled")' "$dir/llm-audit-after.json" >/dev/null
  jq -S --arg id "$pre_llm_id" 'first(.result.structuredContent[]|select(.id==$id))' "$dir/llm-audit-before.json" >"$dir/llm-row-before.json"
  jq -S --arg id "$pre_llm_id" 'first(.result.structuredContent[]|select(.id==$id))' "$dir/llm-audit-after.json" >"$dir/llm-row-after.json"
  cmp "$dir/llm-row-before.json" "$dir/llm-row-after.json"
  live_result stateful.llm-audit-exactness stateful-llm-audit-exactness pass 0 artifacts/stateful/llm-audit-after.json semantic-positive
  stateful_mcp_call search "$(jq -cn --arg q "\"$marker\"" '{query:$q,limit:10}')" "$dir/exact-log-after.json"
  jq -e --argjson id "$pre_log_id" --arg marker "$marker" 'any(.result.structuredContent.logs[]?;.id==$id and .message==$marker)' "$dir/exact-log-after.json" >/dev/null
  stateful_mcp_call host_state "$(jq -cn --arg h "$MCP_LIVE_HOST" '{host:$h}')" "$dir/exact-heartbeat-after.json"
  jq -S '.result.structuredContent|{host_id,hostname}' "$dir/exact-heartbeat-before.json" >"$dir/heartbeat-identity-before.json"
  jq -S '.result.structuredContent|{host_id,hostname}' "$dir/exact-heartbeat-after.json" >"$dir/heartbeat-identity-after.json"
  cmp "$dir/heartbeat-identity-before.json" "$dir/heartbeat-identity-after.json"
  live_result stateful.restart-exactness stateful-restart-exactness pass 0 artifacts/stateful/exact-log-after.json semantic-positive

  started="$(date +%s)"
  while (( polls < 20 )); do
    polls=$((polls + 1))
    stateful_mcp_call graph "$(jq -cn --arg h "$MCP_LIVE_HOST" '{mode:"entity",entity_type:"host",key:$h}')" "$dir/graph-watermark.json" || true
    if jq -e --arg h "$MCP_LIVE_HOST" --arg old "$pre_watermark" '.result.structuredContent.resolved_entity.canonical_key==$h and .result.structuredContent.metadata.source_watermark!=$old' "$dir/graph-watermark.json" >/dev/null 2>&1; then break; fi
    sleep 1
  done
  jq -e --arg h "$MCP_LIVE_HOST" '.result.structuredContent.resolved_entity.canonical_key==$h' "$dir/graph-watermark.json" >/dev/null
  jq -e '.projection_status=="never_built" and .source_watermark==""' "$dir/projection-disabled.json" >/dev/null
  jq -e '.result.structuredContent.metadata.projection_status=="ready"' "$dir/graph-watermark.json" >/dev/null
  live_result stateful.projection-lifecycle stateful-projection-lifecycle pass 0 artifacts/stateful/projection-disabled.json semantic-positive
  post_watermark="$(jq -er '.result.structuredContent.metadata.source_watermark' "$dir/graph-watermark.json")"
  [[ "$post_watermark" != "$pre_watermark" ]] || live_die "projection watermark did not advance across restart (before=$pre_watermark after=$post_watermark polls=$polls status=$(jq -r '.result.structuredContent.metadata.projection_status' "$dir/graph-watermark.json"))"
  live_result stateful.projection-watermark stateful-projection-watermark pass 0 artifacts/stateful/graph-watermark.json semantic-positive
  stateful_mcp_call graph "$(jq -cn --arg h "$MCP_LIVE_HOST" '{mode:"entity",entity_type:"host",key:$h}')" "$dir/graph-repeat.json"
  # The projection refreshes every second over a live source, so a repeat
  # query may see a newer watermark (logs;heartbeats;signatures). It must
  # resolve the same entity and never go backwards in any component.
  jq -e --arg h "$MCP_LIVE_HOST" --arg w "$post_watermark" '
    def parts: split(";") | map(split(":") | {(.[0]): (.[1]|tonumber)}) | add;
    .result.structuredContent.resolved_entity.canonical_key==$h and
    (.result.structuredContent.metadata.source_watermark|parts) as $now | ($w|parts) as $was |
    ($was|keys) == ($now|keys) and all($was|keys[]; $now[.] >= $was[.])
  ' "$dir/graph-repeat.json" >/dev/null || live_die "repeat graph query regressed or changed entity: $(jq -c '.result.structuredContent|{entity:.resolved_entity.canonical_key,watermark:.metadata.source_watermark}' "$dir/graph-repeat.json") after $post_watermark"
  live_result stateful.graph-correlation stateful-graph-correlation pass 0 artifacts/stateful/graph-repeat.json semantic-positive
  docker logs --tail 300 "$candidate" >"$dir/container-logs.txt" 2>&1
  jq -n --slurpfile before "$dir/stats-before.json" --slurpfile after "$dir/stats-after.json" --rawfile failure "$dir/dependency-failure.json" --arg pre "$pre_watermark" --arg post "$post_watermark" '{schema:"cortex-live-stateful-observability-v1",container_scoped:true,success_counters:{before:$before[0].result.structuredContent.runtime_observability,after:$after[0].result.structuredContent.runtime_observability},failure:{transport:"mcp-jsonrpc",structured_response:($failure|fromjson),error_kind:"fts-query-validation"},projection:{before:$pre,after:$post,monotonic:true},recovered:true}' >"$dir/observability.json"
  jq -e '.container_scoped and .recovered and (.failure.structured_response.result.isError==true) and (.success_counters.before|type=="object") and (.success_counters.after|type=="object")' "$dir/observability.json" >/dev/null
  live_result stateful.structured-observability stateful-structured-observability pass 0 artifacts/stateful/observability.json semantic-positive
  # Evaluator idempotence: one OOM kill must notify once, however many evaluator
  # cycles re-scan it. The stateful profile runs the evaluator every 2 s (live
  # test mode); the dispatcher delivers every 30 s and suppresses a repeat of
  # the same rule/host/dedup key within its 900 s window.
  local oom_host="stateful-oom-${LIVE_RUN_ID#cortex-e2e-}"
  printf '<2>1 %s %s kernel - - - Out of memory: Killed process 4242 (%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$oom_host" "$oom_host" | nc -w 3 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  live_wait_until 120 stateful-oom-first-firing _stateful_oom_firings_are 1
  # A suppressed repeat leaves nothing observable over MCP, so outlast two more
  # dispatcher cycles before asserting the count did not grow.
  sleep 65
  _stateful_oom_firings_are 1 || live_die "OOM kill notified more than once across evaluator cycles: $(jq -c . "$dir/oom-firings.json")"
  live_result stateful.evaluator-idempotence stateful-evaluator-idempotence pass 0 artifacts/stateful/oom-firings.json semantic-positive
  now="$(date +%s)"
  jq -cn --arg host "$MCP_LIVE_HOST" --arg marker "$marker" --argjson log_id "$pre_log_id" --arg llm_id "$pre_llm_id" --arg pre "$pre_watermark" --arg post "$post_watermark" --argjson polls "$polls" --argjson wait "$((now-started))" --argjson before "$before" --argjson after "$after" \
    '{schema:"cortex-live-stateful-result-v2",marker:$host,exact_log:{message:$marker,id:$log_id},exact_llm_id:$llm_id,stages:{producer:"exact fixture queried",durable_store:"same ids after restart",scheduler:"projection watermark advanced",query:"exact semantic responses"},poll_count:$polls,cumulative_wait_seconds:$wait,projection_watermarks:{before:$pre,after:$post},logs_before_restart:$before,logs_after_restart:$after,secrets_present:false}' >"$dir/result.json"
  live_event stateful_verified "$(jq -c . "$dir/result.json")"
  # Stateful lifecycle capabilities are not SurfaceContract entries, so the
  # profile ledger (live_capability_ledger in lib/contracts.sh) names them
  # itself; each was recorded above as the check proving it passed. The
  # terminal disposition keeps the combined evidence for the profile.
  live_terminal_disposition stateful pass artifacts/stateful/result.json
}
