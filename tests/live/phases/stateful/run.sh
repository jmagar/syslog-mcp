#!/usr/bin/env bash

stateful_mcp_call() {
  local action="$1" arguments="$2" output="$3"
  mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --arg action "$action" --argjson arguments "$arguments" '{jsonrpc:"2.0",id:900,method:"tools/call",params:{name:"cortex",arguments:($arguments+{action:$action})}}')" "$output"
  jq -e '.result.isError==false and .result.structuredContent!=null' "$output" >/dev/null
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
  stateful_mcp_call llm_invocations '{}' "$dir/llm-audit-before.json"
  jq -e 'any(.result.structuredContent[]?;.status=="disabled")' "$dir/llm-audit-before.json" >/dev/null
  pre_llm_id="$(jq -er 'first(.result.structuredContent[]|select(.status=="disabled"))|.id' "$dir/llm-audit-before.json")"
  stateful_mcp_call graph "$(jq -cn --arg h "$MCP_LIVE_HOST" '{mode:"entity",entity_type:"host",key:$h}')" "$dir/graph-before.json"
  pre_watermark="$(jq -er '.result.structuredContent.metadata.source_watermark' "$dir/graph-before.json")"

  # A malformed FTS dependency request must fail with a structured error; the
  # immediately following valid query proves recovery rather than a dead path.
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":901,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"search","query":"-","limit":1}}}' "$dir/dependency-failure.json"
  jq -e '.result.isError==true and (.result.content[0].text|length>0)' "$dir/dependency-failure.json" >/dev/null
  stateful_mcp_call search "$(jq -cn --arg q "\"$marker\"" '{query:$q,limit:10}')" "$dir/dependency-recovery.json"
  jq -e --argjson id "$pre_log_id" 'any(.result.structuredContent.logs[]?;.id==$id)' "$dir/dependency-recovery.json" >/dev/null

  candidate="$(live_ingest_candidate_id)"
  docker restart "$candidate" >/dev/null
  live_wait_until 30 stateful-restart-health _live_http_health_ready
  live_wait_until 30 stateful-restart-mcp _live_mcp_ready
  stateful_mcp_call stats '{}' "$dir/stats-after.json"
  after="$(jq -r '.result.structuredContent.total_logs' "$dir/stats-after.json")"
  [[ "$after" -ge "$before" ]]
  stateful_mcp_call llm_invocations '{}' "$dir/llm-audit-after.json"
  jq -e --arg id "$pre_llm_id" 'any(.result.structuredContent[]?;.id==$id and .status=="disabled")' "$dir/llm-audit-after.json" >/dev/null
  jq -S --arg id "$pre_llm_id" 'first(.result.structuredContent[]|select(.id==$id))' "$dir/llm-audit-before.json" >"$dir/llm-row-before.json"
  jq -S --arg id "$pre_llm_id" 'first(.result.structuredContent[]|select(.id==$id))' "$dir/llm-audit-after.json" >"$dir/llm-row-after.json"
  cmp "$dir/llm-row-before.json" "$dir/llm-row-after.json"
  stateful_mcp_call search "$(jq -cn --arg q "\"$marker\"" '{query:$q,limit:10}')" "$dir/exact-log-after.json"
  jq -e --argjson id "$pre_log_id" --arg marker "$marker" 'any(.result.structuredContent.logs[]?;.id==$id and .message==$marker)' "$dir/exact-log-after.json" >/dev/null
  stateful_mcp_call host_state "$(jq -cn --arg h "$MCP_LIVE_HOST" '{host:$h}')" "$dir/exact-heartbeat-after.json"
  jq -S '.result.structuredContent|{host_id,hostname}' "$dir/exact-heartbeat-before.json" >"$dir/heartbeat-identity-before.json"
  jq -S '.result.structuredContent|{host_id,hostname}' "$dir/exact-heartbeat-after.json" >"$dir/heartbeat-identity-after.json"
  cmp "$dir/heartbeat-identity-before.json" "$dir/heartbeat-identity-after.json"

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
  post_watermark="$(jq -er '.result.structuredContent.metadata.source_watermark' "$dir/graph-watermark.json")"
  [[ "$post_watermark" != "$pre_watermark" ]] || live_die "projection watermark did not advance across restart"
  stateful_mcp_call graph "$(jq -cn --arg h "$MCP_LIVE_HOST" '{mode:"entity",entity_type:"host",key:$h}')" "$dir/graph-repeat.json"
  jq -e --arg h "$MCP_LIVE_HOST" --arg w "$post_watermark" '.result.structuredContent.resolved_entity.canonical_key==$h and .result.structuredContent.metadata.source_watermark==$w' "$dir/graph-repeat.json" >/dev/null
  docker logs --tail 300 "$candidate" >"$dir/container-logs.txt" 2>&1
  jq -n --slurpfile before "$dir/stats-before.json" --slurpfile after "$dir/stats-after.json" --rawfile failure "$dir/dependency-failure.json" --arg pre "$pre_watermark" --arg post "$post_watermark" '{schema:"cortex-live-stateful-observability-v1",container_scoped:true,success_counters:{before:$before[0].result.structuredContent.runtime_observability,after:$after[0].result.structuredContent.runtime_observability},failure:{transport:"mcp-jsonrpc",structured_response:($failure|fromjson),error_kind:"fts-query-validation"},projection:{before:$pre,after:$post,monotonic:true},recovered:true}' >"$dir/observability.json"
  jq -e '.container_scoped and .recovered and (.failure.structured_response.result.isError==true) and (.success_counters.before|type=="object") and (.success_counters.after|type=="object")' "$dir/observability.json" >/dev/null
  now="$(date +%s)"
  jq -cn --arg host "$MCP_LIVE_HOST" --arg marker "$marker" --argjson log_id "$pre_log_id" --arg llm_id "$pre_llm_id" --arg pre "$pre_watermark" --arg post "$post_watermark" --argjson polls "$polls" --argjson wait "$((now-started))" --argjson before "$before" --argjson after "$after" \
    '{schema:"cortex-live-stateful-result-v2",marker:$host,exact_log:{message:$marker,id:$log_id},exact_llm_id:$llm_id,stages:{producer:"exact fixture queried",durable_store:"same ids after restart",scheduler:"projection watermark advanced",query:"exact semantic responses"},poll_count:$polls,cumulative_wait_seconds:$wait,projection_watermarks:{before:$pre,after:$post},logs_before_restart:$before,logs_after_restart:$after,secrets_present:false}' >"$dir/result.json"
  live_event stateful_verified "$(jq -c . "$dir/result.json")"
  # Stateful lifecycle capabilities are not SurfaceContract entries. Preserve
  # their detailed evidence as one terminal profile disposition instead of
  # manufacturing canonical surface results that aggregate qualification can
  # neither own nor reconcile.
  live_terminal_disposition stateful pass artifacts/stateful/result.json
}
