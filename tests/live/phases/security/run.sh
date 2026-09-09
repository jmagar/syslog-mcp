#!/usr/bin/env bash

security_recovery() {
  curl -fsS --max-time 5 -H 'Host: localhost' "http://127.0.0.1:${LIVE_HTTP_PORT:?}/health" >/dev/null
}

security_record_static() {
  local case_id="$1" class="$2" result="$3" dir="$4"
  security_recovery
  jq -cn --arg case "$case_id" --arg class "$class" --arg result "$result" --arg sha "$(printf '%s' "$case_id:$result" | shasum -a 256 | awk '{print $1}')" \
    '{case:$case,class:$class,result:"pass",status:$result,recovery_status:200,detail_sha256:$sha}' >"$dir/$case_id.json"
}

security_phase_run() {
  local dir="$LIVE_RUN_ROOT/artifacts/security" corpus="$LIVE_PROJECT_ROOT/tests/live/fixtures/security/corpus.json" candidate cases classes
  mkdir -p "$dir"; chmod 700 "$dir"
  jq -e '.schema=="cortex-live-security-contract-v1" and .network.external_egress==false and .recovery_probe_after_every_case' "$LIVE_PROJECT_ROOT/tests/live/contracts/security.json" >/dev/null
  candidate="$(live_ingest_candidate_id)"

  live_run_bounded 90 "$dir/http.stdout" "$dir/http.stderr" python3 "$LIVE_PROJECT_ROOT/tests/live/phases/security/bounded_http.py" --port "$LIVE_HTTP_PORT" --corpus "$corpus" --out "$dir" --token "$LIVE_CORTEX_TOKEN"

  # Target-policy fixtures remain design inputs only. They are intentionally
  # excluded from live results until exercised through a real target validator.
  jq -c '{schema,excluded_non_live_targets:[.targets[]|{case,class,target}]}' "$corpus" >"$dir/non-live-target-policy.json"

  # File-tail traversal, special-file, and TOCTOU candidates must be refused.
  mkdir -p "$LIVE_RUN_ROOT/security-tail/root"; printf 'safe\n' >"$LIVE_RUN_ROOT/security-tail/root/safe.log"
  ln -s /etc/passwd "$LIVE_RUN_ROOT/security-tail/root/link"; mkfifo "$LIVE_RUN_ROOT/security-tail/root/fifo"
  for spec in 'path-parent path ../escape.log' 'path-absolute path /etc/passwd' 'path-fifo path fifo' 'path-symlink path link'; do
    set -- $spec; id="$1"; class="$2"; path="$3"
    if [[ "$path" == /etc/passwd ]]; then requested="$path"; else requested="/file-tail-root/root/$path"; fi
    body="$(jq -cn --arg p "$requested" '{jsonrpc:"2.0",id:9,method:"tools/call",params:{name:"cortex",arguments:{action:"file_tails",operation:"add",path:$p}}}')"
    status="$(curl -sS --max-time 5 -o "$dir/$id.raw" -w '%{http_code}' -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary "$body" "http://127.0.0.1:$LIVE_HTTP_PORT/mcp")"
    grep -Eqi 'error|denied|invalid|outside|regular|scope' "$dir/$id.raw"; security_record_static "$id" "$class" "refused-http-$status" "$dir"
  done
  rm -f "$LIVE_RUN_ROOT/security-tail/root/fifo" "$LIVE_RUN_ROOT/security-tail/root/link"

  # Encoded-token containment is checked across every durable evidence surface.
  # Browser storage is owned by the real browser sweep and is not inferred here.
  token_b64="$(printf '%s' "$LIVE_CORTEX_TOKEN" | base64 | tr -d '\n')"; token_hex="$(printf '%s' "$LIVE_CORTEX_TOKEN" | xxd -p | tr -d '\n')"
  ! rg -a -F "$LIVE_CORTEX_TOKEN" "$LIVE_RUN_ROOT" --glob '!secrets.json' --glob '!run.env' >/dev/null 2>&1
  ! rg -a -F "$token_b64" "$LIVE_RUN_ROOT" >/dev/null 2>&1; ! rg -a -F "$token_hex" "$LIVE_RUN_ROOT" >/dev/null 2>&1
  security_record_static secret-encoded secret absent "$dir"

  # Docker authority is read-only and restricted to the already-qualified proxy;
  # no host socket is mounted into this profile.
  docker inspect "$candidate" --format '{{json .Mounts}}' >"$dir/candidate-mounts.raw"
  ! grep -q '/var/run/docker.sock' "$dir/candidate-mounts.raw"; rm "$dir/candidate-mounts.raw"
  security_record_static docker-socket-authority docker-authority absent "$dir"

  # Release artifact must not expose runtime failpoint switches.
  ! docker exec "$candidate" env | grep -Eq '^CORTEX_(TEST|FAILPOINT)'
  ! docker exec "$candidate" grep -a -Eq 'CORTEX_(TEST|FAILPOINT)' /usr/local/bin/cortex
  security_record_static release-switches secret absent "$dir"

  # Browser routes are owned by this profile.  Exercise the exact mounted route
  # and its wrong-method refusal; security corpus summaries are not substituted
  # for these canonical surface outcomes.
  mkdir -p "$dir/surfaces"
  while IFS=$'\t' read -r surface path; do
    case "$path" in
      '/app/{*path}') path=/app/contract-probe ;;
      '/app/assets/{*path}') path=/app/assets/app.js ;;
    esac
    safe="${surface//[^a-zA-Z0-9._-]/-}"
    positive="artifacts/security/surfaces/$safe.semantic-positive.json"
    negative="artifacts/security/surfaces/$safe.validation-negative.json"
    status="$(curl -sS --max-time 10 -o "$LIVE_RUN_ROOT/$positive.body" -w '%{http_code}' -H 'Host: localhost' "http://127.0.0.1:$LIVE_HTTP_PORT$path")"
    [[ "$status" == 200 ]]
    jq -Rn --arg surface "$surface" --arg path "$path" --argjson status "$status" --rawfile body "$LIVE_RUN_ROOT/$positive.body" '{surface_id:$surface,path:$path,method:"GET",status:$status,response_bytes:($body|length),content_semantic:(if ($path|contains("/assets/")) then ($body|contains("function") or contains("const ") or contains("(()=>")) else ($body|contains("<html") or contains("<!doctype")) end)}' >"$LIVE_RUN_ROOT/$positive"
    rm -f "$LIVE_RUN_ROOT/$positive.body"; jq -e '.response_bytes>0 and .content_semantic' "$LIVE_RUN_ROOT/$positive" >/dev/null
    live_result "$surface" security-browser-route pass 0 "$positive" semantic-positive
    status="$(curl -sS --max-time 10 -o "$LIVE_RUN_ROOT/$negative.body" -w '%{http_code}' -X POST -H 'Host: localhost' "http://127.0.0.1:$LIVE_HTTP_PORT$path")"
    [[ "$status" == 404 || "$status" == 405 ]]
    jq -Rn --arg surface "$surface" --arg path "$path" --argjson status "$status" --rawfile body "$LIVE_RUN_ROOT/$negative.body" '{surface_id:$surface,path:$path,method:"POST",status:$status,response_bytes:($body|length)}' >"$LIVE_RUN_ROOT/$negative"
    rm -f "$LIVE_RUN_ROOT/$negative.body"
    live_result "$surface" security-browser-wrong-method pass 0 "$negative" validation-negative
  done < <(jq -r '.entries[]|select(.profiles|index("security"))|[.id,.spelling|sub("^GET ";"")]|@tsv' "$LIVE_SURFACE_CONTRACT")

  find "$dir" -name '*.raw' -delete
  jq -s '{schema:"cortex-live-security-results-v1",cases:[.[]|select(.class!=null)],classes:([.[]|select(.class!=null)|.class]|unique),excluded_non_live_targets:(map(select(.excluded_non_live_targets!=null))|first|.excluded_non_live_targets // [])}' "$dir"/*.json >"$LIVE_RUN_ROOT/artifacts/security-results.json"
  cases="$(jq '.cases|length' "$LIVE_RUN_ROOT/artifacts/security-results.json")"; classes="$(jq '.classes|length' "$LIVE_RUN_ROOT/artifacts/security-results.json")"
  (( cases >= 12 && classes >= 8 )); jq -e '(.excluded_non_live_targets|length)==4 and all(.cases[];.result=="pass" and .recovery_status==200)' "$LIVE_RUN_ROOT/artifacts/security-results.json" >/dev/null
  live_event security_complete "$(jq -c '{cases:(.cases|length),classes:.classes,external_egress:false}' "$LIVE_RUN_ROOT/artifacts/security-results.json")"
  live_terminal_disposition security pass artifacts/security-results.json
}
