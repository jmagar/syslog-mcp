#!/usr/bin/env bash
set -euo pipefail

mcp_http() {
  local token="$1" body="$2" output="$3" status
  status="$(curl -sS --max-time 20 -o "$output" -w '%{http_code}' -H 'Host: localhost' -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary "$body" "http://127.0.0.1:${LIVE_HTTP_PORT:?}/mcp")"
  [[ "$status" == 200 ]]
}

mcp_result_json() {
  jq -er '.result.content[]?|select(.type=="text")|.text|fromjson' "$1" | head -1
}
mcp_semantic_oracle() {
  local response="$1" key="$2"
  if [[ "$key" == "\$array" ]]; then jq -e '.result.isError==false and (.result.structuredContent|type=="array")' "$response" >/dev/null
  else jq -e --arg key "$key" '.result.isError==false and (.result.structuredContent|has($key))' "$response" >/dev/null; fi
}

mcp_candidate_provenance_write() {
  local dir="$1" candidate binary binary_sha binary_version image_id source_sha manifest
  candidate="$(docker inspect -f '{{.Name}}' "$(live_ingest_candidate_id)")"; candidate="${candidate#/}"
  binary="$(docker exec "$candidate" sh -c 'command -v cortex')"
  binary_sha="$(docker exec "$candidate" sha256sum "$binary" | awk '{print $1}')"
  binary_version="$(docker exec "$candidate" cortex --version)"
  image_id="$(docker inspect -f '{{.Image}}' "$candidate")"
  source_sha="$(find "$LIVE_PROJECT_ROOT/src/mcp" "$LIVE_PROJECT_ROOT/tests/live/phases/mcp" "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp" -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}')"
  manifest="$dir/candidate-provenance.json"
  jq -cn --arg run_id "$LIVE_RUN_ID" --arg candidate "$candidate" --arg image_id "$image_id" --arg binary "$binary" --arg binary_sha "$binary_sha" --arg binary_version "$binary_version" --arg source_sha "$source_sha" --arg contract_sha "$(live_sha256 "$LIVE_SURFACE_CONTRACT")" \
    '{schema:"cortex-live-mcp-candidate-v1",run_id:$run_id,candidate:$candidate,image_id:$image_id,binary:{path:$binary,sha256:$binary_sha,version:$binary_version},source_sha256:$source_sha,surface_contract_sha256:$contract_sha}' >"$manifest"
  live_manifest_seal "$manifest"
  mcp_candidate_provenance_verify "$manifest"
}

mcp_candidate_provenance_verify() {
  local manifest="$1" candidate binary
  live_manifest_verify "$manifest" || return 1
  candidate="$(jq -r .candidate "$manifest")"; binary="$(jq -r .binary.path "$manifest")"
  [[ "$(docker inspect -f '{{.Image}}' "$candidate")" == "$(jq -r .image_id "$manifest")" ]] || return 1
  [[ "$(docker exec "$candidate" sha256sum "$binary" | awk '{print $1}')" == "$(jq -r .binary.sha256 "$manifest")" ]] || return 1
  [[ "$(docker exec "$candidate" cortex --version)" == "$(jq -r .binary.version "$manifest")" ]] || return 1
  [[ "$(find "$LIVE_PROJECT_ROOT/src/mcp" "$LIVE_PROJECT_ROOT/tests/live/phases/mcp" "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp" -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}')" == "$(jq -r .source_sha256 "$manifest")" ]] || return 1
}

mcp_seed_positive_fixtures() {
  local dir="$1" marker body status response i candidate transcript notify_timestamp notify_message notify_title notify_body notify_payload notify_sha assess_status compose_status
  MCP_LIVE_HOST="mcp-host-${LIVE_RUN_ID#cortex-e2e-}"
  MCP_LIVE_SILENT_HOST="mcp-silent-${LIVE_RUN_ID#cortex-e2e-}"
  MCP_LIVE_TOPIC_HOST="mcp-topic-${LIVE_RUN_ID#cortex-e2e-}"
  MCP_LIVE_ERROR_HOST="mcp-error-host-${LIVE_RUN_ID#cortex-e2e-}"
  marker="mcp-error-${LIVE_RUN_ID#cortex-e2e-}"
  MCP_LIVE_NOTIFY_HOST="mcp-notify-host-${LIVE_RUN_ID#cortex-e2e-}"
  body="$(jq -cn --arg h "$MCP_LIVE_HOST" '{host:{host_id:$h,hostname:$h,os:"linux",kernel:"6.8-live",architecture:"x86_64",boot_id:$h,timezone:"UTC"},sample:{sequence:77,sampled_at:(now|todate),uptime_secs:77,monotonic_ms:77,collection_ms:1,partial:false,probe_errors:[],skipped_probes:[]},agent:{version:"3.15.0",mode:"always_on",interval_secs:30,push_latency_ms:1,retry_backlog:0},cpu:{load1:0.1,load5:0.1,load15:0.1,usage_pct:1,iowait_pct:0,steal_pct:0,core_count:1},memory:{mem_total_bytes:1000,mem_available_bytes:900,swap_total_bytes:0,swap_used_bytes:0},disks:[],network:[],processes:{total:1,running:1,sleeping:0,zombies:0,top:[]},containers:{runtime:"docker",reachable:true,running:0,exited:0,restarting:0,unhealthy:0,details:[]}}')"
  status="$(curl -sS --max-time 10 -o "$dir/seed-heartbeat.json" -w '%{http_code}' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "$body" "http://127.0.0.1:$LIVE_HTTP_PORT/v1/heartbeats")"; [[ "$status" == 200 || "$status" == 202 ]]
  # Keep the error fixture on a separate claimed hostname. Reusing the
  # heartbeat hostname would let the later syslog projection downgrade the
  # graph entity from verified to claimed, masking the heartbeat trust path.
  printf '<11>1 %s %s cortex-mcp - - - %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "$MCP_LIVE_ERROR_HOST" "$marker" | nc -w 2 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  notify_timestamp="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
  notify_message="Out of memory: Killed process 4242 (mcp-live-${LIVE_RUN_ID#cortex-e2e-})"
  printf '<11>1 %s %s kernel - - - %s\n' "$notify_timestamp" "$MCP_LIVE_NOTIFY_HOST" "$notify_message" | nc -w 2 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  candidate="$(live_ingest_candidate_id)"
  # A run-owned transcript drives the session, abuse, skill, MCP, and hook
  # projections.  Keep stable IDs in every record so the action oracles can
  # prove relationships rather than merely accepting a response shape.
  transcript="$LIVE_MCP_FILETAIL_ROOT/mcp-live-session.jsonl"
  cat >"$transcript" <<EOF
{"sessionId":"mcp-live-session","attributionSkill":"mcp-live-skill","attributionPlugin":"mcp-live-plugin","content":"mcp-live-project cortex this is fucking broken"}
{"sessionId":"mcp-live-session","message":{"content":[{"type":"tool_use","id":"mcp-live-call","name":"mcp__mcp-live-server__mcp-live-tool","input":{}}]},"attachment":{"type":"hook_failure","hookName":"mcp-live-hook","hookEvent":"PostToolUse","exitCode":1,"content":"mcp live hook failed"},"content":"mcp live call and hook failure"}
EOF
  chmod 0644 "$transcript"
  docker exec "$candidate" cortex sessions add /file-tail-root/mcp-live-session.jsonl --force --json >"$dir/seed-session.json"
  docker exec "$candidate" cortex sessions mcpevents backfill --limit 100 --json >"$dir/seed-mcp-backfill.json"
  docker exec "$candidate" cortex sessions hooksbackfill --limit 100 --json >"$dir/seed-hook-backfill.json"
  set +e
  docker exec "$candidate" cortex assess abuse --json >"$dir/seed-llm-denial.json" 2>"$dir/seed-llm-denial.stderr"
  assess_status=$?
  set -e
  (( assess_status != 0 ))
  [[ -s "$dir/seed-llm-denial.stderr" ]]
  jq -cn --argjson exit "$assess_status" --arg stderr_sha "$(live_sha256 "$dir/seed-llm-denial.stderr")" \
    '{operation:"cortex assess abuse",expected:"llm-provider-denial",exit:$exit,stderr_sha256:$stderr_sha,result:"observed"}' >"$dir/seed-llm-denial-outcome.json"
  # Leave a managed source present for the positive file_tails action. It is
  # removed after the matrix and remains covered by canonical run teardown.
  docker exec "$candidate" sh -c ': > /file-tail-root/mcp-positive.log'
  mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --arg id "mcp-positive-${LIVE_RUN_ID#cortex-e2e-}" '{jsonrpc:"2.0",id:699,method:"tools/call",params:{name:"cortex",arguments:{action:"file_tails",op:"add",id:$id,path:"/file-tail-root/mcp-positive.log",tag:"mcp-positive",start_at_end:true}}}')" "$dir/seed-filetail.json"
  jq -e '.result.isError==false' "$dir/seed-filetail.json" >/dev/null
  # A deliberately stale, distinct heartbeat makes silent_hosts observable.
  body="$(jq -cn --arg h "$MCP_LIVE_SILENT_HOST" '{host:{host_id:$h,hostname:$h,os:"linux",kernel:"6.8-live",architecture:"x86_64",boot_id:$h,timezone:"UTC"},sample:{sequence:1,sampled_at:((now-7200)|todate),uptime_secs:1,monotonic_ms:1,collection_ms:1,partial:false,probe_errors:[],skipped_probes:[]},agent:{version:"3.15.0",mode:"always_on",interval_secs:30,push_latency_ms:1,retry_backlog:0},disks:[],networks:[]}' )"
  curl -fsS --max-time 10 -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "$body" "http://127.0.0.1:$LIVE_HTTP_PORT/v1/heartbeats" >"$dir/seed-silent-heartbeat.json"
  body="$(jq -cn --arg h "$MCP_LIVE_TOPIC_HOST" '{host:{host_id:$h,hostname:$h,os:"linux",kernel:"6.8-live",architecture:"x86_64",boot_id:$h,timezone:"UTC"},sample:{sequence:88,sampled_at:(now|todate),uptime_secs:88,monotonic_ms:88,collection_ms:1,partial:false,probe_errors:[],skipped_probes:[]},agent:{version:"3.15.0",mode:"always_on",interval_secs:30,push_latency_ms:1,retry_backlog:0},disks:[],networks:[]}' )"
  curl -fsS --max-time 10 -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary "$body" "http://127.0.0.1:$LIVE_HTTP_PORT/v1/heartbeats" >"$dir/seed-topic-heartbeat.json"
  # Give the run-owned heartbeat host a current log edge for non-empty state
  # and topic correlation. Its unique full hostname avoids ambiguous graph
  # resolution while the distinct verified host remains available to `graph`.
  printf '<14>1 %s %s cortex-topic - - - topic-%s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "$MCP_LIVE_TOPIC_HOST" "${LIVE_RUN_ID#cortex-e2e-}" | nc -w 2 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  docker exec "$candidate" cortex graph rebuild --json >"$dir/seed-graph-rebuild.json"
  docker exec "$candidate" cortex compose status --json >"$dir/seed-compose-status.json" 2>"$dir/seed-compose-status.stderr"
  jq -e --arg project "$LIVE_COMPOSE_PROJECT" \
    '.status=="running" and .health=="healthy" and .compose_project==$project and .service=="candidate" and (.ports|length)==3 and (.diagnostics|length)==0' \
    "$dir/seed-compose-status.json" >/dev/null
  jq -cn --arg stdout_sha "$(live_sha256 "$dir/seed-compose-status.json")" \
    '{operation:"cortex compose status",expected:"deterministic-read-only-boundary",exit:0,stdout_sha256:$stdout_sha,result:"observed"}' >"$dir/seed-compose-status-outcome.json"
  response="$dir/seed-unaddressed.json"
  for i in $(seq 1 20); do
    mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":700,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"unaddressed_errors","limit":100}}}' "$response"
    MCP_LIVE_SIGNATURE="$(jq -r --arg m "$marker" '.result.structuredContent.signatures[]?|select(.sample_message|contains($m))|.signature_hash // empty' "$response" | head -1)"
    [[ -n "$MCP_LIVE_SIGNATURE" && "$MCP_LIVE_SIGNATURE" != null ]] && break
    sleep 1
  done
  [[ -n "$MCP_LIVE_SIGNATURE" && "$MCP_LIVE_SIGNATURE" != null ]]
  MCP_NOTIFY_BASE="$(curl -fsS -H "Authorization: Bearer $LIVE_ORACLE_TOKEN" "http://127.0.0.1:$LIVE_ORACLE_PORT/capture" | jq '.records|length')"
  # Wait for the real notification evaluator and dispatcher to persist the
  # run-owned OOM firing. Direct DB insertion would not exercise this path.
  for i in $(seq 1 30); do
    mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":701,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"notifications_recent","rule_id":"oom_kill","limit":100}}}' "$dir/seed-notification-recent.json"
    MCP_LIVE_FIRING_ID="$(jq -r --arg h "$MCP_LIVE_NOTIFY_HOST" '.result.structuredContent[]?|select(.rule_id=="oom_kill" and .hostname==$h and .status_code>=200 and .status_code<300)|.id // empty' "$dir/seed-notification-recent.json" | head -1)"
    [[ "$MCP_LIVE_FIRING_ID" =~ ^[0-9]+$ ]] && break
    sleep 1
  done
  if ! [[ "$MCP_LIVE_FIRING_ID" =~ ^[0-9]+$ ]]; then
    echo "live MCP fixture did not produce a persisted run-owned OOM firing" >&2
    return 1
  fi
  notify_title="[CRITICAL] OOM Kill on $MCP_LIVE_NOTIFY_HOST"
  notify_body="$(printf 'Kernel OOM killer fired on **%s** at %s\n\n```\n%s\n```' "$MCP_LIVE_NOTIFY_HOST" "$notify_timestamp" "$notify_message")"
  notify_payload="$(jq -cS -n --arg title "$notify_title" --arg body "$notify_body" '{urls:["json://oracle.invalid"],title:$title,body:$body,type:"failure",format:"markdown"}')"
  notify_sha="$(printf '%s' "$notify_payload" | shasum -a 256 | awk '{print $1}')"
  curl -fsS -H "Authorization: Bearer $LIVE_ORACLE_TOKEN" "http://127.0.0.1:$LIVE_ORACLE_PORT/capture" >"$dir/seed-notification-capture.json"
  jq -e --arg sha "$notify_sha" 'any(.records[]?;.path=="/notify/" and .sha256==$sha)' "$dir/seed-notification-capture.json" >/dev/null
  jq -cn --argjson id "$MCP_LIVE_FIRING_ID" --arg host "$MCP_LIVE_NOTIFY_HOST" --arg timestamp "$notify_timestamp" --arg message "$notify_message" --arg title "$notify_title" --arg body "$notify_body" --arg body_sha "$notify_sha" '{firing_id:$id,rule_id:"oom_kill",hostname:$host,fixture:{timestamp:$timestamp,message:$message},delivery:{status:"2xx",title:$title,body:$body,body_sha256:$body_sha}}' >"$dir/seed-notification-proof.json"
  MCP_LIVE_SESSION=mcp-live-session MCP_LIVE_PROJECT=/ MCP_LIVE_SKILL=mcp-live-skill MCP_LIVE_MCP_SERVER=mcp-live-server MCP_LIVE_HOOK=mcp-live-hook
  export MCP_LIVE_HOST MCP_LIVE_SILENT_HOST MCP_LIVE_TOPIC_HOST MCP_LIVE_ERROR_HOST MCP_LIVE_NOTIFY_HOST MCP_LIVE_FIRING_ID MCP_LIVE_SIGNATURE MCP_NOTIFY_BASE MCP_LIVE_SESSION MCP_LIVE_PROJECT MCP_LIVE_SKILL MCP_LIVE_MCP_SERVER MCP_LIVE_HOOK
}

mcp_read_scope_precheck() {
  local action output
  mkdir -p "$LIVE_RUN_ROOT/artifacts/mcp"
  while IFS= read -r action; do
    output="$LIVE_RUN_ROOT/artifacts/mcp/read-scope-admin-denied-$action.json"
    mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --arg action "$action" '{jsonrpc:"2.0",id:89,method:"tools/call",params:{name:"cortex",arguments:{action:$action}}}')" "$output"
    jq -e '.error.code==-32600 and (.error.message|contains("cortex:admin"))' "$output" >/dev/null
  done < <(jq -r '.admin_actions[]' "$LIVE_PROJECT_ROOT/tests/live/phases/mcp/scenarios.json")
}

mcp_phase_run() {
  local scenarios="$LIVE_PROJECT_ROOT/tests/live/phases/mcp/scenarios.json" contract="$LIVE_SURFACE_CONTRACT"
  local dir="$LIVE_RUN_ROOT/artifacts/mcp" action args auth token request output result ledger surface_id required_key normalized validation auth_output code invalid_args invalid_key
  mkdir -p "$dir"
  live_event phase_started '{"phase":"mcp"}'

  # Seal and verify the exact candidate and source inputs before exercising it.
  mcp_candidate_provenance_write "$dir"

  python3 "$LIVE_PROJECT_ROOT/tests/live/phases/mcp/persistent_client.py" "$LIVE_HTTP_PORT" "$LIVE_CORTEX_TOKEN" "$LIVE_PROJECT_ROOT/tests/live/phases/mcp/discovery.json" "$dir"
  jq -e '.jsonrpc=="2.0" and .id==1 and (.result.protocolVersion|type=="string") and .result.serverInfo.name=="cortex"' "$dir/initialize.json" >/dev/null
  jq -e '.result.tools|length==1 and .[0].name=="cortex" and (.[0].inputSchema.properties.action.enum|length)==58' "$dir/tools-list.json" >/dev/null
  jq -e '.result.resources|type=="array"' "$dir/resources-list.json" >/dev/null
  jq -e '.result.contents[0].uri=="ui://cortex/query-widget" and .result.contents[0].mimeType=="text/html;profile=mcp-app" and (.result.contents[0].text|contains("cortex"))' "$dir/widget-resource.json" >/dev/null
  mcp_seed_positive_fixtures "$dir"

  ledger="$dir/action-ledger.jsonl"; : >"$ledger"
  while IFS=$'\t' read -r action auth; do
    args="$(jq -c --arg a "$action" '.arguments[$a] // {} | .+{action:$a}' "$scenarios")"
    case "$action" in
      ack_error|unack_error) args="$(jq -cn --arg a "$action" --arg s "$MCP_LIVE_SIGNATURE" '{action:$a,signature_hash:$s}')" ;;
      host_state) args="$(jq -cn --arg h "$MCP_LIVE_HOST" '{action:"host_state",host:$h}')" ;;
      graph) args="$(jq -cn --arg h "$MCP_LIVE_HOST" '{action:"graph",mode:"entity",entity_type:"host",key:$h}')" ;;
      notifications_test) args="$(jq -cn --arg b "mcp-notify-$LIVE_RUN_ID" '{action:"notifications_test",body:$b}')" ;;
      sessions) args="$(jq -cn --arg since "$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" '{action:"sessions",since:$since,limit:100}')" ;;
      correlate) args="$(jq -cn --arg q "\"mcp-error-${LIVE_RUN_ID#cortex-e2e-}\"" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{action:"correlate",query:$q,reference_time:$t,window_minutes:10,severity_min:"warning"}')" ;;
      correlate_state) args="$(jq -cn --arg h "$MCP_LIVE_TOPIC_HOST" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{action:"correlate_state",host:$h,reference_time:$t,window_minutes:10}')" ;;
      topic_correlate) args="$(jq -cn --arg topic "$MCP_LIVE_TOPIC_HOST" --arg since "$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" '{action:"topic_correlate",topic:$topic,since:$since,limit:100}')" ;;
    esac
    token="$LIVE_CORTEX_TOKEN"
    request="$(jq -cn --argjson args "$args" --argjson id "$(printf '%s' "$action" | cksum | awk '{print $1}')" '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:"cortex",arguments:$args}}')"
    output="$dir/action-$action.json"; mcp_http "$token" "$request" "$output"
    if [[ "$action" == notifications_test ]]; then
      for i in $(seq 1 10); do
        jq -e '.result.isError==false' "$output" >/dev/null && break
        sleep 1; mcp_http "$token" "$request" "$output"
      done
    fi
    surface_id="$(jq -r --arg action "$action" '.entries[]|select(.kind=="mcp" and .spelling==$action)|.id' "$contract")"
    required_key="$(jq -r --arg action "$action" '.required_key[$action] // ""' "$scenarios")"
    if jq -e --arg action "$action" '.allowed_not_found|index($action)!=null' "$scenarios" >/dev/null; then
      if jq -e '.jsonrpc=="2.0" and .id!=null and .result.content[0].type=="text" and (.result.isError|type=="boolean")' "$output" >/dev/null; then result=pass; else result=fail; fi
    else
      if jq -e '.jsonrpc=="2.0" and .id!=null and .result.content[0].type=="text" and .result.isError==false and .result.structuredContent!=null' "$output" >/dev/null; then result=pass; else result=fail; fi
      if [[ "$result" == pass && -n "$required_key" ]]; then
        mcp_semantic_oracle "$output" "$required_key" || result=fail
      fi
    fi
    if [[ "$result" == pass ]]; then
      case "$action" in
        artifact_evidence_record) jq -e '.result.structuredContent.inserted==true and .result.structuredContent.event.eventId=="mcp-live-event" and .result.structuredContent.event.artifactId=="mcp-live-artifact"' "$output" >/dev/null || result=fail ;;
        artifact_evidence) jq -e 'any(.result.structuredContent.events[]?;.eventId=="mcp-live-event" and .artifactId=="mcp-live-artifact")' "$output" >/dev/null || result=fail ;;
        search_sessions) jq -e --arg s "$MCP_LIVE_SESSION" 'any(.result.structuredContent.sessions[]?;.session_id==$s and .event_count>0)' "$output" >/dev/null || result=fail ;;
        sessions) jq -e --arg s "$MCP_LIVE_SESSION" 'any(.result.structuredContent.sessions[]?;.session_id==$s and .event_count>0)' "$output" >/dev/null || result=fail ;;
        correlate) jq -e --arg h "$MCP_LIVE_ERROR_HOST" '.result.structuredContent.total_events>0 and any(.result.structuredContent.hosts[]?;.hostname==$h and (.events|length)>0)' "$output" >/dev/null || result=fail ;;
        correlate_state) jq -e --arg h "$MCP_LIVE_TOPIC_HOST" 'any(.result.structuredContent.hosts[]?;.hostname==$h and .heartbeat_summary!=null and (.logs|length)>0)' "$output" >/dev/null || result=fail ;;
        topic_correlate) jq -e --arg h "$MCP_LIVE_TOPIC_HOST" 'any(.result.structuredContent.resolved_entities[]?;.key==$h) and (.result.structuredContent.timeline|length)>0 and any(.result.structuredContent.heartbeat_summaries[]?;.hostname==$h)' "$output" >/dev/null || result=fail ;;
        project_context) jq -e --arg p "$MCP_LIVE_PROJECT" '.result.structuredContent.project==$p and .result.structuredContent.event_count>0 and (.result.structuredContent.sessions|length)>0' "$output" >/dev/null || result=fail ;;
        abuse) jq -e '(.result.structuredContent.matches|length)>0' "$output" >/dev/null || result=fail ;;
        abuse_incidents) jq -e '(.result.structuredContent.incidents|length)>0' "$output" >/dev/null || result=fail ;;
        abuse_investigate) jq -e '.result.structuredContent.total_incidents>0 and (.result.structuredContent.evidence|length)>0' "$output" >/dev/null || result=fail ;;
        ai_correlate) jq -e '(.result.structuredContent.anchors|length)>0' "$output" >/dev/null || result=fail ;;
        skill_events) jq -e --arg n "$MCP_LIVE_SKILL" 'any(.result.structuredContent.events[]?;.skill_name==$n)' "$output" >/dev/null || result=fail ;;
        skill_incidents) jq -e '(.result.structuredContent.incidents|length)>0' "$output" >/dev/null || result=fail ;;
        skill_investigate) jq -e '.result.structuredContent.total_incidents>0 and (.result.structuredContent.evidence|length)>0' "$output" >/dev/null || result=fail ;;
        mcp_events) jq -e --arg n "$MCP_LIVE_MCP_SERVER" 'any(.result.structuredContent.events[]?;.mcp_server==$n)' "$output" >/dev/null || result=fail ;;
        mcp_incidents) jq -e '(.result.structuredContent.incidents|length)>0' "$output" >/dev/null || result=fail ;;
        mcp_investigate) jq -e '.result.structuredContent.total_incidents>0 and (.result.structuredContent.evidence|length)>0' "$output" >/dev/null || result=fail ;;
        hook_events) jq -e --arg n "$MCP_LIVE_HOOK" 'any(.result.structuredContent.events[]?;.hook_name==$n)' "$output" >/dev/null || result=fail ;;
        hook_incidents) jq -e '(.result.structuredContent.incidents|length)>0' "$output" >/dev/null || result=fail ;;
        hook_investigate) jq -e '.result.structuredContent.total_incidents>0 and (.result.structuredContent.evidence|length)>0' "$output" >/dev/null || result=fail ;;
        silent_hosts) jq -e --arg h "$MCP_LIVE_ERROR_HOST" 'any(.result.structuredContent.hosts[]?;.hostname==$h and .log_count>0)' "$output" >/dev/null || result=fail ;;
        file_tails) jq -e --arg id "mcp-positive-${LIVE_RUN_ID#cortex-e2e-}" 'any(.result.structuredContent.sources[]?;.id==$id)' "$output" >/dev/null || result=fail ;;
        errors) jq -e '(.result.structuredContent.summary|length)>0' "$output" >/dev/null || result=fail ;;
        llm_invocations) jq -e '(.result.structuredContent|length)>0 and any(.result.structuredContent[]?;.status=="disabled")' "$output" >/dev/null || result=fail ;;
        notifications_recent) jq -e --arg h "$MCP_LIVE_NOTIFY_HOST" --argjson id "$MCP_LIVE_FIRING_ID" 'any(.result.structuredContent[]?;.id==$id and .rule_id=="oom_kill" and .hostname==$h and .status_code>=200 and .status_code<300 and (.fired_at|type=="string"))' "$output" >/dev/null || result=fail ;;
        ack_error)
          jq -e --arg s "$MCP_LIVE_SIGNATURE" '.result.structuredContent.signature_hash==$s and (.result.structuredContent.acknowledged_at|type=="string")' "$output" >/dev/null || result=fail
          mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":710,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"unaddressed_errors","limit":100}}}' "$dir/ack-postcondition.json"
          jq -e --arg s "$MCP_LIVE_SIGNATURE" 'all(.result.structuredContent.signatures[]?;.signature_hash!=$s)' "$dir/ack-postcondition.json" >/dev/null || result=fail ;;
        unack_error)
          jq -e --arg s "$MCP_LIVE_SIGNATURE" '.result.structuredContent.signature_hash==$s and (.result.structuredContent.unacked_at|type=="string")' "$output" >/dev/null || result=fail
          mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":711,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"unaddressed_errors","limit":100}}}' "$dir/unack-postcondition.json"
          jq -e --arg s "$MCP_LIVE_SIGNATURE" 'any(.result.structuredContent.signatures[]?;.signature_hash==$s)' "$dir/unack-postcondition.json" >/dev/null || result=fail ;;
        host_state) jq -e --arg h "$MCP_LIVE_HOST" '.result.structuredContent.host_id==$h and .result.structuredContent.latest.sequence==77' "$output" >/dev/null || result=fail ;;
        graph) jq -e --arg h "$MCP_LIVE_HOST" '.result.structuredContent.resolved_entity.canonical_key==$h and .result.structuredContent.resolved_entity.trust_level=="verified"' "$output" >/dev/null || result=fail ;;
        compose_doctor) jq -e '.result.structuredContent.diagnostics|type=="array"' "$output" >/dev/null || result=fail ;;
        notifications_test)
          for i in $(seq 1 10); do curl -fsS -H "Authorization: Bearer $LIVE_ORACLE_TOKEN" "http://127.0.0.1:$LIVE_ORACLE_PORT/capture" >"$dir/notification-capture.json"; [[ "$(jq '.records|length' "$dir/notification-capture.json")" -gt "$MCP_NOTIFY_BASE" ]] && break; sleep 1; done
          local test_body test_payload test_sha
          test_body="mcp-notify-$LIVE_RUN_ID"
          test_payload="$(jq -cS -n --arg body "$test_body" '{urls:["json://oracle.invalid"],title:"Test Notification",body:$body,type:"info",format:"markdown"}')"
          test_sha="$(printf '%s' "$test_payload" | shasum -a 256 | awk '{print $1}')"
          jq -e --argjson n "$MCP_NOTIFY_BASE" --arg sha "$test_sha" '(.records|length)>$n and any(.records[$n:][]?;.path=="/notify/" and .sha256==$sha)' "$dir/notification-capture.json" >/dev/null || result=fail
          jq -cn --arg body "$test_body" --arg sha "$test_sha" '{title:"Test Notification",body:$body,body_sha256:$sha,status:"2xx"}' >"$dir/notifications-test-proof.json" ;;
      esac
    fi
    normalized="$dir/semantic-$action.json"
    jq -c --arg action "$action" --arg invariant "$required_key" '{action:$action,is_error:(.result.isError//false),invariant:$invariant,semantic:.result.structuredContent,error:(.result.content[0].text//null)}' "$output" >"$normalized"
    [[ "$result" != pass ]] || rm -f "$output"
    jq -cn --arg action "$action" --arg auth "$auth" --arg result "$result" --arg evidence "artifacts/mcp/semantic-$action.json" '{action:$action,auth:$auth,result:$result,evidence:$evidence}' >>"$ledger"
    live_event mcp_action "$(tail -1 "$ledger")"
    live_result "$surface_id" "mcp-$action-semantic" "$result" 0 "artifacts/mcp/semantic-$action.json" semantic-positive

    validation="$dir/validation-$action.json"
    invalid_key="$(jq -r 'keys[]|select(.!="action")' <<<"$args" | head -1)"
    if [[ -n "$invalid_key" ]]; then
      invalid_args="$(jq -c --arg key "$invalid_key" '.[$key]={"invalid_type_for":$key}' <<<"$args")"
    else
      invalid_args="$(jq -cn --arg action "$action" --arg key "invalid_${action}" '{action:$action}+{($key):true}')"
    fi
    mcp_http "$token" "$(jq -cn --argjson args "$invalid_args" '{jsonrpc:"2.0",id:200,method:"tools/call",params:{name:"cortex",arguments:$args}}')" "$validation"
    if jq -e '(.result.isError==true) or (.error.code<0)' "$validation" >/dev/null; then result=pass; else result=fail; fi
    [[ "$result" != pass ]] || jq -c --arg action "$action" --arg parameter "${invalid_key:-invalid_${action}}" '{action:$action,parameter:$parameter,rejected:true,error:(.error//.result.structuredContent//.result.content[0].text)}' "$validation" >"$validation.tmp"
    [[ "$result" != pass ]] || { mv "$validation.tmp" "$validation"; }
    live_result "$surface_id" "mcp-$action-validation" "$result" 0 "artifacts/mcp/validation-$action.json" validation-negative

    if jq -e --arg action "$action" '.entries[]|select(.kind=="mcp" and .spelling==$action)|.required_cases|index("authorization")' "$contract" >/dev/null; then
      auth_output="$dir/auth-$action.json"
      code="$(curl -sS --max-time 10 -o "$auth_output" -w '%{http_code}' -H 'Host: localhost' -H 'Content-Type: application/json' --data-binary "$request" "http://127.0.0.1:$LIVE_HTTP_PORT/mcp")"
      if [[ "$code" == 401 ]] && jq -e '.kind=="auth_failed"' "$auth_output" >/dev/null; then result=pass; else result=fail; fi
      live_result "$surface_id" "mcp-$action-authorization" "$result" 0 "artifacts/mcp/auth-$action.json" authorization
    fi
  done < <(jq -r '.entries[]|select(.kind=="mcp")|[.spelling,.auth]|@tsv' "$contract" | awk -F '\t' '$1=="artifact_evidence_record"{print "000\t"$0;next}$1=="artifact_evidence"{print "001\t"$0;next}$1=="notifications_test"{print "002\t"$0;next}$1=="notifications_recent"{print "003\t"$0;next}{print "100\t"$0}' | sort | cut -f2-)

  jq -se --slurpfile contract "$contract" '
    length==58 and ([.[].action] as $actions | ($actions|length)==($actions|unique|length)) and all(.[];.result=="pass") and
    ([.[].action]|sort)==([$contract[0].entries[]|select(.kind=="mcp")|.spelling]|sort)
  ' "$ledger" >/dev/null
  jq -e -s '[.[]|select(.kind=="result" and (.payload.surface_id|startswith("mcp.")) and .payload.attempt_kind=="first_attempt")]|length==173 and ([.[].payload|(.surface_id+"/"+.case_kind)]|unique|length)==173 and all(.[];.payload.result=="pass")' "$(live_event_file)" >/dev/null

  # Stateful qualification reuses the complete registry-driven semantic,
  # validation, and authorization sweep above, then owns its restart epochs.
  [[ "${LIVE_MCP_SEMANTIC_SWEEP_ONLY:-false}" != true ]] || return 0

  # Recreate without the admin override and prove every read action succeeds
  # under the static read-only scope. Admin denials were asserted before the
  # elevated epoch, so this closes both positive and negative scope edges.
  docker compose -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp/compose.read.yaml" -p "$LIVE_COMPOSE_PROJECT" up -d --no-build --force-recreate candidate
  live_wait_until 30 mcp-read-matrix-health _live_http_health_ready
  live_wait_until 30 mcp-read-matrix-ready _live_mcp_ready
  : >"$dir/read-scope-ledger.jsonl"
  while IFS=$'\t' read -r read_action read_auth; do
    [[ "$read_auth" == read || "$read_auth" == info ]] || continue
    args="$(jq -c --arg a "$read_action" '.arguments[$a] // {} | .+{action:$a}' "$scenarios")"
    case "$read_action" in
      host_state) args="$(jq -cn --arg h "$MCP_LIVE_HOST" '{action:"host_state",host:$h}')" ;;
      graph) args="$(jq -cn --arg h "$MCP_LIVE_HOST" '{action:"graph",mode:"entity",entity_type:"host",key:$h}')" ;;
      sessions) args="$(jq -cn --arg since "$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" '{action:"sessions",since:$since,limit:100}')" ;;
      correlate) args="$(jq -cn --arg q "\"mcp-error-${LIVE_RUN_ID#cortex-e2e-}\"" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{action:"correlate",query:$q,reference_time:$t,window_minutes:10,severity_min:"warning"}')" ;;
      correlate_state) args="$(jq -cn --arg h "$MCP_LIVE_TOPIC_HOST" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{action:"correlate_state",host:$h,reference_time:$t,window_minutes:10}')" ;;
      topic_correlate) args="$(jq -cn --arg topic "$MCP_LIVE_TOPIC_HOST" --arg since "$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)" '{action:"topic_correlate",topic:$topic,since:$since,limit:100}')" ;;
    esac
    output="$dir/read-scope-positive-$read_action.json"
    mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --argjson args "$args" '{jsonrpc:"2.0",id:812,method:"tools/call",params:{name:"cortex",arguments:$args}}')" "$output"
    jq -e '.result.isError==false and .result.structuredContent!=null' "$output" >/dev/null
    jq -cn --arg action "$read_action" --arg scope "$read_auth" --arg evidence "artifacts/mcp/read-scope-positive-$read_action.json" '{action:$action,scope:$scope,result:"pass",evidence:$evidence}' >>"$dir/read-scope-ledger.jsonl"
  done < <(jq -r '.entries[]|select(.kind=="mcp")|[.spelling,.auth]|@tsv' "$contract")
  jq -se 'length==52 and ([.[].action]|unique|length)==52 and all(.[];.result=="pass") and ([.[]|select(.scope=="read")]|length)==51 and ([.[]|select(.scope=="info" and .action=="help")]|length)==1' "$dir/read-scope-ledger.jsonl" >/dev/null
  docker compose -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp/compose.yaml" -p "$LIVE_COMPOSE_PROJECT" up -d --no-build --force-recreate candidate
  live_wait_until 30 mcp-admin-restore-health _live_http_health_ready
  live_wait_until 30 mcp-admin-restore-ready _live_mcp_ready
  # Action-specific edge invariants: FTS syntax, limits/order, empty/not-found,
  # stable IDs, and explicit time windows.
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":301,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"search","query":"\"cortex\"","limit":2}}}' "$dir/search-fts-phrase.json"
  jq -e '.result.isError==false and (.result.structuredContent.count<=2) and ([.result.structuredContent.logs[].received_at] as $t|$t==($t|sort|reverse))' "$dir/search-fts-phrase.json" >/dev/null
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":302,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"search","query":"\"","limit":2}}}' "$dir/search-fts-invalid.json"
  jq -e '.result.isError==true and .result.structuredContent.retryable==false and (.result.structuredContent.kind|type=="string")' "$dir/search-fts-invalid.json" >/dev/null
  local known_id
  known_id="$(jq -r '.semantic.logs[0].id' "$dir/semantic-search.json")"; [[ "$known_id" =~ ^[0-9]+$ ]]
  mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --argjson id "$known_id" '{jsonrpc:"2.0",id:303,method:"tools/call",params:{name:"cortex",arguments:{action:"get",id:$id}}}')" "$dir/get-known-id.json"
  jq -e --argjson id "$known_id" '.result.isError==false and .result.structuredContent.log.id==$id' "$dir/get-known-id.json" >/dev/null
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":304,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"get","id":9223372036854775807}}}' "$dir/get-not-found.json"
  jq -e '.result.isError==true and .result.structuredContent.kind=="invalid_param" and (.result.structuredContent.message|contains("No log found for id"))' "$dir/get-not-found.json" >/dev/null
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":305,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"filter","host":"cryptographically-impossible-live-host","limit":1}}}' "$dir/filter-empty.json"
  jq -e '.result.isError==false and .result.structuredContent.count==0 and (.result.structuredContent.logs|length)==0' "$dir/filter-empty.json" >/dev/null
  jq -e '.semantic.a.from=="2026-08-27T10:00:00.000Z" and .semantic.a.to=="2026-08-27T11:00:00.000Z" and .semantic.b.from=="2026-08-27T11:00:00.000Z" and .semantic.b.to=="2026-08-27T12:00:00.000Z"' "$dir/semantic-compare.json" >/dev/null
  # Cross-transport semantic parity uses the run-unique error fixture. The
  # registry sweep's broad `cortex` query is intentionally exercised much
  # earlier, while later MCP actions ingest additional Cortex-tagged rows; it
  # therefore cannot be compared to a fresh CLI query without a race.
  local candidate
  candidate="$(live_ingest_candidate_id)"
  local parity_query
  parity_query="\"mcp-error-${LIVE_RUN_ID#cortex-e2e-}\""
  mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --arg query "$parity_query" '{jsonrpc:"2.0",id:306,method:"tools/call",params:{name:"cortex",arguments:{action:"search",query:$query,limit:50}}}')" "$dir/mcp-parity-search.json"
  jq -e '.result.isError==false and .result.structuredContent.count>0' "$dir/mcp-parity-search.json" >/dev/null
  docker exec "$candidate" cortex search --http --server http://127.0.0.1:3100 --grep "$parity_query" --limit 50 --json >"$dir/cli-search.json"
  jq -S '{count,logs:[.logs[]|{hostname,app_name,severity,message}]}' "$dir/cli-search.json" >"$dir/normalized-cli-search.json"
  jq -S '.result.structuredContent|{count,logs:[.logs[]|{hostname,app_name,severity,message}]}' "$dir/mcp-parity-search.json" >"$dir/normalized-mcp-search.json"
  jq -e -n --slurpfile cli "$dir/normalized-cli-search.json" --slurpfile mcp "$dir/normalized-mcp-search.json" '$cli[0]==$mcp[0]' >/dev/null
  docker exec "$candidate" cortex stats --http --server http://127.0.0.1:3100 --json >"$dir/cli-stats.json"
  jq -S '{total_logs,total_hosts,write_blocked}' "$dir/cli-stats.json" >"$dir/normalized-cli-stats.json"
  jq -S '.semantic|{total_logs,total_hosts,write_blocked}' "$dir/semantic-stats.json" >"$dir/normalized-mcp-stats.json"
  jq -e -n --slurpfile cli "$dir/normalized-cli-stats.json" --slurpfile mcp "$dir/normalized-mcp-stats.json" '$cli[0].total_logs >= $mcp[0].total_logs and $cli[0].total_hosts >= $mcp[0].total_hosts and $cli[0].write_blocked==$mcp[0].write_blocked' >/dev/null

  # Fail-closed protocol, validation, auth and scope cases.
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"missing","arguments":{}}}' "$dir/unknown-tool.json"
  jq -e '.error.code==-32600 and (.error.message|contains("__deny__"))' "$dir/unknown-tool.json" >/dev/null
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"missing-action"}}}' "$dir/unknown-action.json"
  jq -e '.error.code==-32600 and (.error.message|contains("__deny__"))' "$dir/unknown-action.json" >/dev/null
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"search","query":42}}}' "$dir/missing-required.json"
  jq -e '.result.isError==true' "$dir/missing-required.json" >/dev/null
  local code
  code="$(curl -sS --max-time 10 -o "$dir/unauthorized.json" -w '%{http_code}' -H 'Host: localhost' -H 'Content-Type: application/json' --data-binary '{"jsonrpc":"2.0","id":93,"method":"tools/list","params":{}}' "http://127.0.0.1:$LIVE_HTTP_PORT/mcp")"; [[ "$code" == 401 ]]
  mcp_http "$LIVE_CORTEX_TOKEN" '{"jsonrpc":"2.0","id":94,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"file_tails","op":"list"}}}' "$dir/read-token-admin.json"
  # Static token is deliberately elevated only in this isolated epoch; its
  # admin behavior and reversible mutation are asserted explicitly.
  jq -e '.result.isError==false' "$dir/read-token-admin.json" >/dev/null
  local candidate tail_id
  candidate="$(live_ingest_candidate_id)"; tail_id="mcp-${LIVE_RUN_ID#cortex-e2e-}"
  docker exec "$candidate" sh -c ': > /file-tail-root/action.log'
  mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --arg id "$tail_id" '{jsonrpc:"2.0",id:95,method:"tools/call",params:{name:"cortex",arguments:{action:"file_tails",op:"add",id:$id,path:"/file-tail-root/action.log",tag:"mcp-live",start_at_end:true}}}')" "$dir/admin-filetail-add.json"
  jq -e '.result.isError==false' "$dir/admin-filetail-add.json" >/dev/null
  mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --arg id "$tail_id" '{jsonrpc:"2.0",id:96,method:"tools/call",params:{name:"cortex",arguments:{action:"file_tails",op:"remove",id:$id}}}')" "$dir/admin-filetail-remove.json"
  jq -e '.result.isError==false' "$dir/admin-filetail-remove.json" >/dev/null
  # Concurrent requests retain request identity and valid envelopes.
  local pids=() i
  for i in 1 2 3 4 5 6 7 8; do mcp_http "$LIVE_CORTEX_TOKEN" "$(jq -cn --argjson id "$((100+i))" '{jsonrpc:"2.0",id:$id,method:"tools/call",params:{name:"cortex",arguments:{action:"status"}}}')" "$dir/concurrent-$i.json" & pids+=("$!"); done
  for i in "${pids[@]}"; do wait "$i"; done
  jq -s -e 'length==8 and ([.[].id]|unique|length)==8 and all(.[];.result.isError==false)' "$dir"/concurrent-*.json >/dev/null
  cargo test --quiet --locked --test stdio_mcp -- --nocapture >"$dir/stdio.stdout" 2>"$dir/stdio.stderr"
  grep -F 'test result: ok' "$dir/stdio.stdout" >/dev/null
  live_event mcp_stdio '{"result":"pass","evidence":"artifacts/mcp/stdio.stdout"}'
  mcp_candidate_provenance_verify "$dir/candidate-provenance.json"
  live_event phase_finished '{"phase":"mcp","disposition":"pass","actions":58}'
}
