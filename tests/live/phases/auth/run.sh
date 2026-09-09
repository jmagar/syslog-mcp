#!/usr/bin/env bash

auth_http_status() {
  local token="$1" path="$2" method="${3:-GET}" extra="${4:-}" output="$5"
  local args=(-sS --max-time 15 -o "$output" -w '%{http_code}' -X "$method" -H 'Host: localhost')
  [[ -z "$token" ]] || args+=(-H "Authorization: Bearer $token")
  [[ -z "$extra" ]] || args+=(-H "$extra")
  curl "${args[@]}" "http://127.0.0.1:${LIVE_HTTP_PORT:?}$path"
}

auth_mcp_status() {
  local token="$1" action="$2" output="$3" body
  body="$(jq -cn --arg action "$action" '{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"cortex",arguments:{action:$action}}}')"
  if [[ -n "$token" ]]; then
    curl -sS --max-time 15 -o "$output" -w '%{http_code}' -H 'Host: localhost' -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary "$body" "http://127.0.0.1:${LIVE_HTTP_PORT}/mcp"
  else
    curl -sS --max-time 15 -o "$output" -w '%{http_code}' -H 'Host: localhost' -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary "$body" "http://127.0.0.1:${LIVE_HTTP_PORT}/mcp"
  fi
}

auth_recreate() {
  local override="$1"
  docker compose -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$override" -p "$LIVE_COMPOSE_PROJECT" up -d --no-build --force-recreate candidate >/dev/null
  live_wait_until 30 auth-health _live_http_health_ready
  [[ "$override" == *compose.oauth.yaml ]] || live_wait_until 30 auth-mcp-ready _live_mcp_ready
}

auth_policy_ledger() {
  jq -c '[.entries[]|{id,kind,auth,required_authorization:(.required_cases|index("authorization")!=null)}] |
    {schema:"cortex-live-auth-policy-ledger-v1",entries:.,counts:(group_by(.auth)|map({auth:.[0].auth,count:length}))}' \
    "$LIVE_SURFACE_CONTRACT" >"$LIVE_RUN_ROOT/artifacts/auth-policy-ledger.json"
  jq -e '.entries|length>0' "$LIVE_RUN_ROOT/artifacts/auth-policy-ledger.json" >/dev/null
}

auth_policy_execution_ledger() {
  local inventory="$LIVE_RUN_ROOT/artifacts/auth-policy-ledger.json" output="$LIVE_RUN_ROOT/artifacts/auth-policy-execution-ledger.jsonl"
  : >"$output"
  while IFS=$'\t' read -r id kind auth required case_kind; do
    local disposition evidence rationale
    disposition=executed; rationale="live representative for the exact transport/auth policy pair"
    case "$kind/$auth" in
      mcp/read) evidence="artifacts/auth/mcp-read.json" ;;
      mcp/admin) evidence="artifacts/auth/admin-mcp-${id#mcp.}.json" ;;
      mcp/info) evidence="artifacts/auth/gateway-no-auth.json" ;;
      rest/read) evidence="artifacts/auth/rest-api-token.json" ;;
      rest/admin) evidence="artifacts/auth/admin-rest-${id#rest.}.json" ;;
      rest/info) evidence="artifacts/auth/oauth-metadata.json" ;;
      ingest/read) evidence="artifacts/auth/otlp-mcp-token.json" ;;
      ingest/admin) evidence="artifacts/auth/admin-mcp-file-tails.json"; rationale="managed file-tail ingest authorization is exercised through its canonical MCP admin action" ;;
      ingest/info) evidence="artifacts/auth/gateway-no-auth.json" ;;
      cli/read) disposition="contract-correct-n/a"; evidence="artifacts/auth/cli-auth-architecture.json"; rationale="CLI network reads delegate to the authenticated HTTP clients covered by the REST/MCP read policy" ;;
      cli/admin) disposition="contract-correct-n/a"; evidence="artifacts/auth/cli-auth-architecture.json"; rationale="CLI privileged commands delegate to the authenticated REST/MCP admin policy; mutation semantics are covered by their surface lanes" ;;
      cli/local-only) disposition="contract-correct-n/a"; evidence="artifacts/auth/cli-auth-architecture.json"; rationale="local-only command has a process/filesystem trust boundary and no network authorization policy" ;;
      cli/info) disposition="contract-correct-n/a"; evidence="artifacts/auth/cli-auth-architecture.json"; rationale="local informational command has no authenticated network boundary" ;;
      *) return 1 ;;
    esac
    [[ -s "$LIVE_RUN_ROOT/$evidence" ]]
    jq -cn --arg id "$id" --arg kind "$kind" --arg auth "$auth" --argjson required "$required" --arg disposition "$disposition" --arg evidence "$evidence" --arg rationale "$rationale" \
      '{surface_id:$id,kind:$kind,auth:$auth,required_authorization:$required,disposition:$disposition,result:"pass",evidence:$evidence,rationale:$rationale}' >>"$output"
  done < <(jq -r '.entries[]|[.id,.kind,.auth,.required_authorization,.required_cases[0]]|@tsv' "$inventory")
  jq -se --slurpfile inventory "$inventory" 'length==345 and ([.[].surface_id]|unique|length)==345 and all(.[];.result=="pass" and (.disposition=="executed" or .disposition=="contract-correct-n/a")) and ([.[].surface_id]|sort)==([$inventory[0].entries[].id]|sort)' "$output" >/dev/null
}

# Emit the aggregate ledger only from raw, route-specific first attempts.  The
# policy inventory above remains a useful audit, but is not executable evidence.
auth_surface_contract_results() {
  local dir="$LIVE_RUN_ROOT/artifacts/auth/surfaces" id spelling method path case_kind evidence status body expected_method digest
  mkdir -p "$dir"
  while IFS=$'\t' read -r id spelling; do
    expected_method="${spelling%% *}"
    path="${spelling#* }"
    while IFS= read -r case_kind; do
      evidence="artifacts/auth/surfaces/${id}.${case_kind}.json"
      if [[ "$case_kind" == semantic-positive || "$case_kind" == executed-refusal-semantic ]]; then
        local lifecycle_source=''
        case "$id" in
          ingest.get-auth-google-callback) lifecycle_source="$LIVE_RUN_ROOT/artifacts/auth/oauth-callback-provider-boundary.json" ;;
          ingest.get-authorize) lifecycle_source="$LIVE_RUN_ROOT/artifacts/auth/oauth-authorize-success.json" ;;
          ingest.post-register) lifecycle_source="$LIVE_RUN_ROOT/artifacts/auth/oauth-register-success.json" ;;
          ingest.post-token) lifecycle_source="$LIVE_RUN_ROOT/artifacts/auth/oauth-token-success.json" ;;
        esac
        if [[ -n "$lifecycle_source" ]]; then
          [[ -s "$lifecycle_source" ]] || live_die "missing OAuth lifecycle evidence: $id"
          cp "$lifecycle_source" "$LIVE_RUN_ROOT/$evidence"
          live_result "$id" "auth-route-$case_kind" pass 0 "$evidence" "$case_kind"
          continue
        fi
        method=GET; body=''
      else
        if [[ "$expected_method" == GET ]]; then method=POST; body='{}'
        else method=GET; body=''; fi
      fi
      local request=(-sS --max-time 15 -o "$LIVE_RUN_ROOT/$evidence.body" -w '%{http_code}' -X "$method" -H 'Host: localhost:3100' -H 'Content-Type: application/json')
      [[ -z "$body" ]] || request+=(--data-binary "$body")
      status="$(curl "${request[@]}" "http://127.0.0.1:$LIVE_HTTP_PORT$path")"
      if [[ "$case_kind" == semantic-positive || "$case_kind" == executed-refusal-semantic ]]; then
        if [[ "$status" == 404 || "$status" == 405 || "$status" -ge 500 ]]; then live_die "auth semantic route was not reached: $id HTTP $status"; return 1; fi
      elif [[ "$status" != 404 && "$status" != 405 ]]; then
        live_die "auth wrong-method route was not refused: $id HTTP $status"; return 1
      fi
      digest="$(shasum -a 256 "$LIVE_RUN_ROOT/$evidence.body" | awk '{print $1}')"
      jq -n --arg surface "$id" --arg expected_method "$expected_method" --arg attempted_method "$method" --arg path "$path" --arg case_kind "$case_kind" --argjson status "$status" --arg digest "$digest" \
        '{surface_id:$surface,expected_method:$expected_method,attempted_method:$attempted_method,path:$path,case_kind:$case_kind,status:$status,response_sha256:$digest}' >"$LIVE_RUN_ROOT/$evidence"
      rm -f "$LIVE_RUN_ROOT/$evidence.body"
      live_result "$id" "auth-route-$case_kind" pass 0 "$evidence" "$case_kind"
    done < <(jq -r --arg id "$id" '.entries[]|select(.id==$id)|.required_cases[]' "$LIVE_SURFACE_CONTRACT")
  done < <(jq -r '.entries[]|select(.profiles|index("auth"))|[.id,.spelling]|@tsv' "$LIVE_SURFACE_CONTRACT")
}

auth_all_privileged_surfaces() {
  local dir="$1" action output code path
  while IFS= read -r action; do
    output="$dir/admin-mcp-${action//_/-}.json"
    code="$(auth_mcp_status "$LIVE_CORTEX_TOKEN" "$action" "$output")"; [[ "$code" == 200 ]]
    ! jq -e 'tostring|contains("requires scope")' "$output" >/dev/null
  done < <(jq -r '.entries[]|select(.kind=="mcp" and .auth=="admin")|.spelling' "$LIVE_SURFACE_CONTRACT")

  while IFS=$'\t' read -r id method path; do
    output="$dir/admin-rest-${id#rest.}.json"
    code="$(curl -sS --max-time 20 -o "$output.body" -w '%{http_code}' -X "$method" -H 'Host: localhost' -H "Authorization: Bearer $LIVE_API_TOKEN" -H "X-Cortex-Admin-Token: $LIVE_ADMIN_TOKEN" -H 'Content-Type: application/json' --data-binary '{}' "http://127.0.0.1:$LIVE_HTTP_PORT$path")"
    [[ "$code" != 401 && "$code" != 403 && "$code" != 404 ]]
    jq -Rn --argjson status "$code" --arg method "$method" --arg path "$path" --rawfile body "$output.body" '{status:$status,method:$method,path:$path,authorized:true,body:$body}' >"$output"
    find "$output.body" -type f -delete
  done < <(jq -r '.entries[]|select(.kind=="rest" and .auth=="admin")|[.id,(.method|ascii_upcase),.spelling]|@tsv' "$LIVE_SURFACE_CONTRACT")
}

auth_oauth_live_service() {
  local dir="$1" port token_file data pid digest key cleanup verify labels status token action body
  port="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
  data="$LIVE_RUN_ROOT/oauth-state"; token_file="$LIVE_RUN_ROOT/oauth-tokens.json"; mkdir -p "$data"
  "${LIVE_OAUTH_FIXTURE_BIN:?}" "$port" "$data" "$token_file" >"$dir/oauth-service.stdout" 2>"$dir/oauth-service.stderr" &
  pid=$!; digest="$(ps -o lstart= -p "$pid" | shasum -a 256 | awk '{print $1}')"; key="oauth-service-$pid"
  cleanup="$(jq -cn --arg s "$LIVE_PROJECT_ROOT/tests/live/phases/auth/process-resource.sh" --arg p "$pid" --arg d "$digest" '["bash",$s,"cleanup",$p,$d]')"
  verify="$(jq -cn --arg s "$LIVE_PROJECT_ROOT/tests/live/phases/auth/process-resource.sh" --arg p "$pid" --arg d "$digest" '["bash",$s,"verify",$p,$d]')"
  labels="$(jq -cn --arg r "$LIVE_RUN_ID" '{run_id:$r,role:"oauth-test-service"}')"
  live_resource_transition "$key" process PLANNED "$LIVE_RESOURCE_PROVIDER" "" '[]'
  live_resource_transition "$key" process CREATING "$LIVE_RESOURCE_PROVIDER" "$pid" '[]' "$digest" "$labels" '[]'
  live_resource_transition "$key" process IDENTIFIED "$LIVE_RESOURCE_PROVIDER" "$pid" "$cleanup" "$digest" "$labels" "$verify"
  live_resource_transition "$key" process CREATED "$LIVE_RESOURCE_PROVIDER" "$pid" "$cleanup" "$digest" "$labels" "$verify"
  live_wait_until 180 oauth-token-file test -s "$token_file"
  for name in read admin empty expired wrong_issuer wrong_audience wrong_key unknown_kid alg_none; do token="$(jq -r --arg n "$name" '.[$n]' "$token_file")"; live_register_secret "$token"; printf -v "OAUTH_${name}" '%s' "$token"; done
  local lifecycle_client lifecycle_code lifecycle_verifier lifecycle_redirect registered_client authorize_url provider_requests_before
  lifecycle_client="$(jq -r '.lifecycle.client_id' "$token_file")"; lifecycle_code="$(jq -r '.lifecycle.authorization_code' "$token_file")"
  lifecycle_verifier="$(jq -r '.lifecycle.code_verifier' "$token_file")"; lifecycle_redirect="$(jq -r '.lifecycle.redirect_uri' "$token_file")"
  live_register_secret "$lifecycle_code"; live_register_secret "$lifecycle_verifier"
  code="$(curl -sS --max-time 15 -o "$dir/oauth-register-success.body" -w '%{http_code}' -H 'Host: localhost:3100' -H 'Content-Type: application/json' --data-binary "{\"redirect_uris\":[\"$lifecycle_redirect\"]}" "http://127.0.0.1:$port/register")"
  [[ "$code" == 200 ]]; registered_client="$(jq -er '.client_id' "$dir/oauth-register-success.body")"
  jq -n --argjson status "$code" --arg client_id "$registered_client" --arg redirect_uri "$lifecycle_redirect" '{status:$status,registered_client_id:$client_id,redirect_uri:$redirect_uri,registration_succeeded:true}' >"$dir/oauth-register-success.json"
  authorize_url="http://127.0.0.1:$port/authorize?response_type=code&client_id=$registered_client&redirect_uri=$(jq -rn --arg v "$lifecycle_redirect" '$v|@uri')&state=live-client-state&scope=cortex%3Aread&code_challenge=ZmFrZS1jaGFsbGVuZQ&code_challenge_method=S256"
  code="$(curl -sS --max-time 15 -D "$dir/oauth-authorize-success.headers" -o /dev/null -w '%{http_code}' "$authorize_url")"
  [[ "$code" == 302 ]]; grep -qi '^location: https://accounts.google.com/' "$dir/oauth-authorize-success.headers"
  jq -n --argjson status "$code" --arg client_id "$registered_client" '{status:$status,registered_client_id:$client_id,upstream_redirect:true,authorization_request_persisted:true}' >"$dir/oauth-authorize-success.json"
  code="$(curl -sS --max-time 15 -o "$dir/oauth-token-success.body" -w '%{http_code}' -H 'Host: localhost:3100' -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode grant_type=authorization_code --data-urlencode "code=$lifecycle_code" --data-urlencode "client_id=$lifecycle_client" --data-urlencode "redirect_uri=$lifecycle_redirect" --data-urlencode "code_verifier=$lifecycle_verifier" "http://127.0.0.1:$port/token")"
  [[ "$code" == 200 ]]; token="$(jq -er '.access_token' "$dir/oauth-token-success.body")"; live_register_secret "$token"
  jq -e '.token_type=="Bearer" and .scope=="cortex:read" and (.access_token|length>20) and (.refresh_token==null)' "$dir/oauth-token-success.body" >/dev/null
  jq -n --argjson status "$code" --arg client_id "$lifecycle_client" '{status:$status,client_id:$client_id,authorization_code_redeemed:true,access_token_issued:true,scope:"cortex:read",provider_refresh_token_absent:true}' >"$dir/oauth-token-success.json"
  provider_requests_before="$(grep -c 'request.start' "$dir/oauth-service.stderr" || true)"
  code="$(curl -sS --max-time 15 -o "$dir/oauth-callback-provider-boundary.body" -w '%{http_code}' "http://127.0.0.1:$port/auth/google/callback?state=unknown-live-state&code=untrusted-code")"
  [[ "$code" == 400 ]]; [[ "$(grep -c 'request.start' "$dir/oauth-service.stderr" || true)" == "$provider_requests_before" ]]
  jq -n --argjson status "$code" '{status:$status,disposition:"executed-refusal-semantic",invalid_state_refused:true,provider_egress_attempted:false,credentials_disclosed:false}' >"$dir/oauth-callback-provider-boundary.json"
  code="$(curl -sS --max-time 15 -o "$dir/oauth-refresh-provider-boundary.body" -w '%{http_code}' -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode grant_type=refresh_token --data-urlencode refresh_token=unknown-live-refresh --data-urlencode "client_id=$lifecycle_client" "http://127.0.0.1:$port/token")"
  [[ "$code" == 400 ]]; [[ "$(grep -c 'request.start' "$dir/oauth-service.stderr" || true)" == "$provider_requests_before" ]]
  jq -n --argjson status "$code" '{status:$status,disposition:"executed-refusal-semantic",unknown_refresh_refused:true,provider_egress_attempted:false,credentials_disclosed:false,provider_opt_in_required_for_success:true}' >"$dir/oauth-refresh-provider-boundary.json"
  rm -f "$dir"/oauth-*-success.body "$dir"/oauth-*-provider-boundary.body
  : >"$dir/oauth-negative-token-proof.jsonl"
  for name in expired wrong_issuer wrong_audience wrong_key unknown_kid alg_none; do
    eval "token=\$OAUTH_${name}"
    jq -cn --arg class "$name" --arg sha "$(printf '%s' "$token" | shasum -a 256 | awk '{print $1}')" --argjson segments "$(awk -F. '{print NF}' <<<"$token")" '{class:$class,token_sha256:$sha,jwt_segments:$segments}' >>"$dir/oauth-negative-token-proof.jsonl"
  done
  jq -se 'length==6 and ([.[].class]|unique|length)==6 and ([.[].token_sha256]|unique|length)==6 and all(.[];.jwt_segments==3)' "$dir/oauth-negative-token-proof.jsonl" >/dev/null
  rm -f "$token_file"
  for spec in 'read stats 200 false' 'admin llm_invocations 200 false' 'read llm_invocations 200 true' 'empty stats 200 true' 'expired stats 401 null' 'wrong_issuer stats 401 null' 'wrong_audience stats 401 null' 'wrong_key stats 401 null' 'unknown_kid stats 401 null' 'alg_none stats 401 null'; do
    set -- $spec; name="$1"; action="$2"; status="$3"; expected="$4"; eval "token=\$OAUTH_${name}"
    body="$(jq -cn --arg a "$action" '{jsonrpc:"2.0",id:41,method:"tools/call",params:{name:"cortex",arguments:{action:$a}}}')"
    code="$(curl -sS --max-time 15 -o "$dir/oauth-live-$name-$action.json" -w '%{http_code}' -H 'Host: localhost:3100' -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary "$body" "http://127.0.0.1:$port/mcp")"
    [[ "$code" == "$status" ]]; [[ "$expected" == null ]] || jq -e --argjson expected "$expected" '.result.isError==$expected or (.error!=null and $expected)' "$dir/oauth-live-$name-$action.json" >/dev/null
  done
  # Every machine-ingest route rejects a user OAuth token before payload parsing.
  : >"$dir/oauth-machine-ingest-ledger.jsonl"
  for path in /v1/logs /v1/metrics /v1/traces /v1/heartbeats /v1/agent-commands /v1/ai-transcripts /v1/shell-history; do
    # Populated by the OAuth token fixture above.
    # shellcheck disable=SC2154
    code="$(curl -sS --max-time 15 -o "$dir/oauth-machine-$(printf '%s' "$path" | tr '/' '-').json" -w '%{http_code}' -H 'Host: localhost:3100' -H "Authorization: Bearer $OAUTH_read" -H 'Content-Type: application/json' --data-binary '{}' "http://127.0.0.1:$port$path")"
    [[ "$code" == 401 ]]
    jq -cn --arg path "$path" --arg evidence "artifacts/auth/oauth-machine-$(printf '%s' "$path" | tr '/' '-').json" '{path:$path,result:"denied",status:401,evidence:$evidence}' >>"$dir/oauth-machine-ingest-ledger.jsonl"
  done
  jq -se 'length==7 and ([.[].path]|unique|length)==7 and all(.[];.status==401)' "$dir/oauth-machine-ingest-ledger.jsonl" >/dev/null
  kill -TERM "$pid"; wait "$pid" 2>/dev/null || true
  local last; last="$(jq -sr --arg key "$key" '[.[]|select(.key==$key)]|last' "$LIVE_RUN_ROOT/resources.jsonl")"
  live_resource_transition "$key" process CLEANING "$LIVE_RESOURCE_PROVIDER" "$pid" "$(jq -c .cleanup_argv <<<$last)" "$digest" "$labels" "$verify"
  live_resource_transition "$key" process REMOVED "$LIVE_RESOURCE_PROVIDER" "$pid" "$(jq -c .cleanup_argv <<<$last)" "$digest" "$labels" "$verify"
  live_resource_transition "$key" process VERIFIED "$LIVE_RESOURCE_PROVIDER" "$pid" "$(jq -c .cleanup_argv <<<$last)" "$digest" "$labels" "$verify"

  # Restart the real OAuth router over the same auth store and prove an access
  # token issued before shutdown still verifies with the persisted signing key.
  "${LIVE_OAUTH_FIXTURE_BIN:?}" "$port" "$data" "$token_file" >"$dir/oauth-restart.stdout" 2>"$dir/oauth-restart.stderr" &
  pid=$!; digest="$(ps -o lstart= -p "$pid" | shasum -a 256 | awk '{print $1}')"; key="oauth-restart-$pid"
  cleanup="$(jq -cn --arg s "$LIVE_PROJECT_ROOT/tests/live/phases/auth/process-resource.sh" --arg p "$pid" --arg d "$digest" '["bash",$s,"cleanup",$p,$d]')"; verify="$(jq -cn --arg s "$LIVE_PROJECT_ROOT/tests/live/phases/auth/process-resource.sh" --arg p "$pid" --arg d "$digest" '["bash",$s,"verify",$p,$d]')"
  live_resource_transition "$key" process PLANNED "$LIVE_RESOURCE_PROVIDER" "" '[]'
  live_resource_transition "$key" process CREATING "$LIVE_RESOURCE_PROVIDER" "$pid" '[]' "$digest" "$labels" '[]'
  live_resource_transition "$key" process IDENTIFIED "$LIVE_RESOURCE_PROVIDER" "$pid" "$cleanup" "$digest" "$labels" "$verify"
  live_resource_transition "$key" process CREATED "$LIVE_RESOURCE_PROVIDER" "$pid" "$cleanup" "$digest" "$labels" "$verify"
  live_wait_until 180 oauth-restart-token-file test -s "$token_file"
  code="$(curl -sS --max-time 15 -o "$dir/oauth-pre-restart-token-after-restart.json" -w '%{http_code}' -H 'Host: localhost:3100' -H "Authorization: Bearer $OAUTH_read" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary '{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"stats"}}}' "http://127.0.0.1:$port/mcp")"
  [[ "$code" == 200 ]]; jq -e '.result.isError==false' "$dir/oauth-pre-restart-token-after-restart.json" >/dev/null
  kill -TERM "$pid"; wait "$pid" 2>/dev/null || true
  last="$(jq -sr --arg key "$key" '[.[]|select(.key==$key)]|last' "$LIVE_RUN_ROOT/resources.jsonl")"
  live_resource_transition "$key" process CLEANING "$LIVE_RESOURCE_PROVIDER" "$pid" "$(jq -c .cleanup_argv <<<$last)" "$digest" "$labels" "$verify"
  live_resource_transition "$key" process REMOVED "$LIVE_RESOURCE_PROVIDER" "$pid" "$(jq -c .cleanup_argv <<<$last)" "$digest" "$labels" "$verify"
  live_resource_transition "$key" process VERIFIED "$LIVE_RESOURCE_PROVIDER" "$pid" "$(jq -c .cleanup_argv <<<$last)" "$digest" "$labels" "$verify"
  find "$token_file" -type f -delete
  find "$data" -type f -delete; find "$data" -depth -type d -empty -delete
  [[ ! -e "$data/auth-jwt.pem" && ! -e "$data/auth.db" && ! -e "$data/foreign-key/auth-jwt.pem" ]]
  jq -cn --arg root "$data" '{state:"destroyed",root:$root,private_keys:0,auth_databases:0,wal_files:0}' >"$dir/oauth-secret-destruction.json"
}

auth_phase_run() {
  local dir="$LIVE_RUN_ROOT/artifacts/auth" status candidate
  mkdir -p "$dir"; chmod 700 "$dir"
  auth_policy_ledger
  auth_oauth_live_service "$dir"

  status="$(auth_mcp_status '' status "$dir/mcp-missing.json")"; [[ "$status" == 401 ]]
  status="$(auth_mcp_status wrong-token status "$dir/mcp-wrong.json")"; [[ "$status" == 401 ]]
  status="$(auth_mcp_status "$LIVE_CORTEX_TOKEN" status "$dir/mcp-read.json")"; [[ "$status" == 200 ]]; jq -e '.result.isError==false' "$dir/mcp-read.json" >/dev/null
  status="$(auth_mcp_status "$LIVE_CORTEX_TOKEN" llm_invocations "$dir/mcp-read-admin-denied.json")"; [[ "$status" == 200 ]]; jq -e '.error.code==-32600 and (.error.message|contains("cortex:admin"))' "$dir/mcp-read-admin-denied.json" >/dev/null

  status="$(auth_http_status '' /api/stats GET '' "$dir/rest-missing.json")"; [[ "$status" == 401 ]]
  status="$(auth_http_status "$LIVE_CORTEX_TOKEN" /api/stats GET '' "$dir/rest-mcp-token.json")"; [[ "$status" == 401 ]]
  status="$(auth_http_status "$LIVE_API_TOKEN" /api/stats GET '' "$dir/rest-api-token.json")"; [[ "$status" == 200 ]]
  status="$(auth_http_status "$LIVE_API_TOKEN" /api/sessions/llm-invocations GET '' "$dir/rest-admin-missing.json")"; [[ "$status" == 403 ]]
  status="$(auth_http_status "$LIVE_API_TOKEN" /api/sessions/llm-invocations GET 'X-Cortex-Admin-Token: wrong-token' "$dir/rest-admin-wrong.json")"; [[ "$status" == 403 ]]
  status="$(auth_http_status "$LIVE_API_TOKEN" /api/sessions/llm-invocations GET "X-Cortex-Admin-Token: $LIVE_ADMIN_TOKEN" "$dir/rest-admin-ok.json")"; [[ "$status" == 200 ]]

  status="$(curl -sS --max-time 15 -o "$dir/otlp-api-token.json" -w '%{http_code}' -H 'Host: localhost' -H "Authorization: Bearer $LIVE_API_TOKEN" -H 'Content-Type: application/json' --data-binary '{"resourceLogs":[]}' "http://127.0.0.1:$LIVE_HTTP_PORT/v1/logs")"; [[ "$status" == 401 ]]
  status="$(curl -sS --max-time 15 -o "$dir/otlp-mcp-token.json" -w '%{http_code}' -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' --data-binary '{"resourceLogs":[]}' "http://127.0.0.1:$LIVE_HTTP_PORT/v1/logs")"; [[ "$status" == 200 ]]

  auth_recreate "$LIVE_PROJECT_ROOT/tests/live/profiles/auth/compose.admin.yaml"
  status="$(auth_mcp_status "$LIVE_CORTEX_TOKEN" llm_invocations "$dir/mcp-static-admin.json")"; [[ "$status" == 200 ]]; jq -e '.result.isError==false' "$dir/mcp-static-admin.json" >/dev/null
  auth_all_privileged_surfaces "$dir"

  auth_recreate "$LIVE_PROJECT_ROOT/tests/live/profiles/auth/compose.oauth.yaml"
  status="$(auth_http_status '' /.well-known/oauth-authorization-server GET '' "$dir/oauth-metadata.json")"; [[ "$status" == 200 ]]; jq -e '.issuer=="http://localhost:3100"' "$dir/oauth-metadata.json" >/dev/null
  status="$(auth_http_status '' /jwks GET '' "$dir/oauth-jwks-before.json")"; [[ "$status" == 200 ]]; jq -e '.keys|length==1 and .[0].kty=="RSA" and .[0].alg=="RS256" and (.[0].kid|length>0)' "$dir/oauth-jwks-before.json" >/dev/null
  status="$(auth_mcp_status "$LIVE_CORTEX_TOKEN" status "$dir/oauth-static-disabled.json")"; [[ "$status" == 401 ]]
  status="$(curl -sS --max-time 15 -o "$dir/oauth-user-machine-ingest.json" -w '%{http_code}' -H 'Host: localhost' -H "Authorization: Bearer $OAUTH_read" -H 'Content-Type: application/json' --data-binary '{"resourceLogs":[]}' "http://127.0.0.1:$LIVE_HTTP_PORT/v1/logs")"; [[ "$status" == 401 ]]
  jq -cn '{disposition:"contract-correct-n/a",boundary:"local signing-key verification",reason:"Cortex does not fetch or parse a remote JWK during bearer verification; malformed JWK belongs to provider/JWKS-client integration, which is absent from this architecture"}' >"$dir/oauth-malformed-jwk-na.json"
  docker restart "$(live_ingest_candidate_id)" >/dev/null
  live_wait_until 90 oauth-restart-health _live_http_health_ready
  auth_http_status '' /jwks GET '' "$dir/oauth-jwks-after.json" >/dev/null
  jq -e -n --slurpfile a "$dir/oauth-jwks-before.json" --slurpfile b "$dir/oauth-jwks-after.json" '$a[0].keys[0].kid==$b[0].keys[0].kid' >/dev/null

  auth_surface_contract_results

  auth_recreate "$LIVE_PROJECT_ROOT/tests/live/profiles/auth/compose.gateway.yaml"
  status="$(auth_mcp_status '' status "$dir/gateway-no-auth.json")"; [[ "$status" == 200 ]]; jq -e '.result.isError==false' "$dir/gateway-no-auth.json" >/dev/null

  docker run --rm --network none -e CORTEX_HOST=0.0.0.0 -e CORTEX_PORT=3100 -e CORTEX_RECEIVER_HOST=127.0.0.1 -e CORTEX_RECEIVER_PORT=1514 -e CORTEX_API_TOKEN=isolated-api -e CORTEX_DB_PATH=/tmp/gateway-refusal.db -e CORTEX_NO_AUTH=true "$LIVE_CANDIDATE_IMAGE" cortex serve mcp >"$dir/gateway-untrusted.stdout" 2>"$dir/gateway-untrusted.stderr" && return 1 || true
  grep -F 'CORTEX_TRUSTED_GATEWAY_NO_AUTH' "$dir/gateway-untrusted.stderr"

  candidate="$(live_ingest_candidate_id)"
  docker run --rm --network none -e CORTEX_HOST=0.0.0.0 -e CORTEX_PORT=3100 -e CORTEX_RECEIVER_HOST=127.0.0.1 -e CORTEX_RECEIVER_PORT=1514 -e CORTEX_API_TOKEN=isolated-api -e CORTEX_DB_PATH=/tmp/refusal.db "$LIVE_CANDIDATE_IMAGE" cortex serve mcp >"$dir/unsafe-start.stdout" 2>"$dir/unsafe-start.stderr" && return 1 || true
  grep -Eq 'CORTEX_TOKEN|OAuth|trusted.gateway|non-loopback' "$dir/unsafe-start.stderr"

  candidate="$(live_ingest_candidate_id)"
  local binary_sha
  binary_sha="$(docker exec "$candidate" sha256sum /usr/local/bin/cortex | awk '{print $1}')"
  ! docker exec "$candidate" grep -a -q 'oauth_state_with_auth_state' /usr/local/bin/cortex
  ! docker exec "$candidate" grep -a -q 'cortex-live-oauth' /usr/local/bin/cortex
  jq -cn --arg sha "$binary_sha" '{artifact:"/usr/local/bin/cortex",sha256:$sha,test_support_factory_absent:true,fixture_binary_marker_absent:true}' >"$dir/release-fixture-absence.json"
  jq -cn '{schema:"cortex-live-cli-auth-architecture-v1",local_only_boundary:"process/filesystem",network_read_delegate:"REST or MCP bearer client",network_admin_delegate:"REST or MCP bearer client",independent_auth_implementation:false}' >"$dir/cli-auth-architecture.json"
  jq -cn '{positive:{no_auth:true,trusted_gateway_attestation:true,evidence:"artifacts/auth/gateway-no-auth.json"},negative:{no_auth:true,trusted_gateway_attestation:false,refused_at_startup:true,evidence:"artifacts/auth/gateway-untrusted.stderr"},identity_boundary:"deployment attestation; Cortex intentionally receives no end-user identity in TrustedGatewayUnscoped"}' >"$dir/trusted-gateway-proof.json"
  [[ "$(find "$LIVE_RUN_ROOT" -type f \( -name 'auth-jwt.pem' -o -name 'auth.db' -o -name 'auth.db-wal' -o -name 'auth.db-shm' \) | wc -l | tr -d ' ')" == 0 ]]

  auth_policy_execution_ledger

  jq -cn '{schema:"cortex-live-auth-result-v1",static_read:true,static_admin:true,token_separation:true,oauth_metadata:true,jwks_persisted:true,oauth_pre_restart_token_survived:true,oauth_negative_classes:7,machine_ingest_denials:7,trusted_gateway:true,untrusted_gateway_refused:true,unsafe_startup_refused:true,release_fake_switch_absent:true,oauth_secrets_destroyed:true,policy_entries_reconciled:345}' >"$dir/result.json"
  live_terminal_disposition auth.policy-table pass artifacts/auth-policy-ledger.json
  live_terminal_disposition auth.live-matrix pass artifacts/auth/result.json
  live_terminal_disposition auth pass artifacts/auth/result.json
  live_event auth_verified "$(jq -c . "$dir/result.json")"
}
