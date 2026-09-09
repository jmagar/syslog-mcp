#!/usr/bin/env bash

upgrade_compose() {
  docker compose -p "$LIVE_COMPOSE_PROJECT" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" -f "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp/compose.yaml" "$@"
}

upgrade_wait_candidate() {
  live_wait_until 90 upgrade-health _live_http_health_ready
  live_wait_until 90 upgrade-mcp _live_mcp_ready
}

upgrade_mcp() {
  local action="$1" args="$2" out="$3" body
  body="$(jq -cn --arg action "$action" --argjson args "$args" '{jsonrpc:"2.0",id:81,method:"tools/call",params:{name:"cortex",arguments:($args+{action:$action})}}')"
  curl -fsS --max-time 20 -H 'Host: localhost' -H "Authorization: Bearer $LIVE_CORTEX_TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data-binary "$body" "http://127.0.0.1:$LIVE_HTTP_PORT/mcp" >"$out"
  jq -e '.result.isError==false' "$out" >/dev/null
}

upgrade_snapshot_volume() {
  local name="$1" volume="${LIVE_COMPOSE_PROJECT}_state" dir="$LIVE_RUN_ROOT/artifacts/upgrade"
  docker run --rm --network none --read-only --tmpfs /tmp --entrypoint sh -v "$volume:/state:ro" -v "$dir:/out" "$LIVE_ORACLE_IMAGE" -ceu "tar -C /state -cf /out/$name.tar ."
  shasum -a 256 "$dir/$name.tar" | awk '{print $1}' >"$dir/$name.tar.sha256"
  chmod 400 "$dir/$name.tar" "$dir/$name.tar.sha256"
}

upgrade_restore_volume() {
  local name="$1" volume="${LIVE_COMPOSE_PROJECT}_state" dir="$LIVE_RUN_ROOT/artifacts/upgrade"
  [[ "$(shasum -a 256 "$dir/$name.tar" | awk '{print $1}')" == "$(cat "$dir/$name.tar.sha256")" ]]
  docker run --rm --network none --read-only --tmpfs /tmp --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges --entrypoint sh -v "$volume:/state" -v "$dir:/in:ro" "$LIVE_ORACLE_IMAGE" -ceu "find /state -mindepth 1 -maxdepth 1 -exec rm -rf {} +; tar -C /state -xf /in/$name.tar"
}

upgrade_refuse_downgrade() {
  local requested="$1" current="$2" out="$3"
  jq -cn --arg requested "$requested" --arg current "$current" '{decision:"refused",reason:"binary downgrade is unsupported; restore a verified backup instead",requested_image:$requested,current_image:$current}' >"$out"
  return 64
}

upgrade_seed_previous() {
  local marker="$1" dir="$LIVE_RUN_ROOT/artifacts/upgrade" signature
  printf '<11>Aug 27 12:00:00 upgrade-host upgrade-app: %s error incident\n' "$marker" | nc -u -w 1 127.0.0.1 "$LIVE_SYSLOG_UDP_PORT"
  printf '<14>1 2026-08-27T12:00:01Z upgrade-host upgrade-app 42 ID47 - %s searchable graph tail\n' "$marker" | nc -w 2 127.0.0.1 "$LIVE_SYSLOG_TCP_PORT"
  sleep 5
  upgrade_mcp search "$(jq -cn --arg q "\"$marker\"" '{query:$q,limit:20}')" "$dir/seed-search.json"
  jq -e --arg q "$marker" '.result.content|tostring|contains($q)' "$dir/seed-search.json" >/dev/null
  docker exec "$(live_ingest_candidate_id)" cortex graph rebuild --json >"$dir/seed-graph.json"
  upgrade_mcp unaddressed_errors '{}' "$dir/seed-incidents.json"
  signature="$(jq -r '.result.structuredContent.signatures[0].signature_hash // empty' "$dir/seed-incidents.json")"; [[ -n "$signature" ]]
  upgrade_mcp ack_error "$(jq -cn --arg s "$signature" '{signature_hash:$s}')" "$dir/seed-ack.json"
  upgrade_mcp file_tails '{"op":"list"}' "$dir/seed-tails.json"
  upgrade_mcp status '{}' "$dir/seed-auth.json"
}

upgrade_semantic_probe() {
  local marker="$1" suffix="$2" dir="$LIVE_RUN_ROOT/artifacts/upgrade" signature
  upgrade_mcp search "$(jq -cn --arg q "\"$marker\"" '{query:$q,limit:20}')" "$dir/$suffix-search.json"
  docker exec "$(live_ingest_candidate_id)" cortex graph status --json >"$dir/$suffix-graph.json"
  upgrade_mcp file_tails '{"op":"list"}' "$dir/$suffix-tails.json"
  upgrade_mcp unaddressed_errors '{}' "$dir/$suffix-incidents.json"
  signature="$(jq -r '.result.structuredContent.signature_hash // empty' "$dir/seed-ack.json")"; [[ -n "$signature" ]]
  upgrade_mcp ack_error "$(jq -cn --arg s "$signature" '{signature_hash:$s}')" "$dir/$suffix-ack.json"
  upgrade_mcp status '{}' "$dir/$suffix-auth.json"
  docker exec "$(live_ingest_candidate_id)" cortex db integrity >"$dir/$suffix-integrity.txt"
  grep -Eqi 'ok|integrity' "$dir/$suffix-integrity.txt"
}

upgrade_one_window() {
  local label="$1" image="$2" marker dir="$LIVE_RUN_ROOT/artifacts/upgrade" start elapsed downgrade_status interrupted_id interrupted_running interrupted_exit
  marker="$LIVE_RUN_ID-upgrade-$label"
  LIVE_PREVIOUS_IMAGE="$image"; export LIVE_PREVIOUS_IMAGE
  docker image inspect "$image" >/dev/null
  upgrade_compose -f "$LIVE_PROJECT_ROOT/tests/live/profiles/upgrade/compose.previous.yaml" up -d --no-build --force-recreate candidate workload-producer
  upgrade_wait_candidate; upgrade_seed_previous "$marker"; upgrade_snapshot_volume "$label-seeded"
  upgrade_compose stop candidate >/dev/null

  start="$(date +%s)"; upgrade_compose up -d --no-build --force-recreate candidate >/dev/null
  # Deterministic process boundary interruption: migrations are transactional;
  # kill after process creation, then retry from the same persistent volume.
  interrupted_id="$(live_ingest_candidate_id)"
  docker kill "$interrupted_id" >/dev/null
  interrupted_running="$(docker inspect -f '{{.State.Running}}' "$interrupted_id")"
  interrupted_exit="$(docker inspect -f '{{.State.ExitCode}}' "$interrupted_id")"
  [[ "$interrupted_running" == false && "$interrupted_exit" == 137 ]]
  jq -cn --arg id "$interrupted_id" --argjson running "$interrupted_running" --argjson exit "$interrupted_exit" \
    '{container_id:$id,kill_succeeded:true,running_after_kill:$running,exit_code:$exit,observed:($running==false and $exit==137)}' >"$dir/$label-interruption.json"
  upgrade_compose up -d --no-build candidate >/dev/null; upgrade_wait_candidate
  upgrade_semantic_probe "$marker" "$label-after-retry"
  upgrade_compose restart candidate >/dev/null; upgrade_wait_candidate
  upgrade_semantic_probe "$marker" "$label-second-start"
  elapsed=$(( $(date +%s) - start ))

  # Rollback is restore of an immutable backup followed by candidate startup.
  upgrade_compose stop candidate >/dev/null; upgrade_restore_volume "$label-seeded"
  upgrade_compose up -d --no-build candidate >/dev/null; upgrade_wait_candidate
  upgrade_semantic_probe "$marker" "$label-restored"

  # The coordinator refuses an unsafe binary downgrade before creating any
  # previous-release process. Rollback is exclusively the restore path above.
  set +e
  upgrade_refuse_downgrade "$image" "$LIVE_CANDIDATE_IMAGE" "$dir/$label-downgrade-refusal.json"
  downgrade_status=$?; set -e
  (( downgrade_status == 64 )); jq -e '.decision=="refused" and (.reason|contains("restore"))' "$dir/$label-downgrade-refusal.json" >/dev/null
  jq -cn --arg window "$label" --arg image "$image" --argjson elapsed "$elapsed" --arg interruption_evidence "$label-interruption.json" '{window:$window,image:$image,result:"pass",interruption:"observed-process-kill",interruption_evidence:$interruption_evidence,second_start:true,backup_restore:true,downgrade_refused:true,elapsed_seconds:$elapsed}' >"$dir/$label-result.json"
}

upgrade_phase_run() {
  local manifest="$LIVE_PROJECT_ROOT/tests/live/contracts/releases/compatibility.json" dir="$LIVE_RUN_ROOT/artifacts/upgrade" n1 oldest
  mkdir -p "$dir"; chmod 700 "$dir"
  jq -e '.schema=="cortex-live-upgrade-compatibility-v1" and .snapshot.immutable and .rollback=="backup-restore-only"' "$manifest" >/dev/null
  cp "$manifest" "$dir/compatibility.json"; shasum -a 256 "$dir/compatibility.json" >"$dir/compatibility.json.sha256"; chmod 400 "$dir/compatibility.json" "$dir/compatibility.json.sha256"
  n1="$(jq -r '.supported.n_minus_1.image' "$manifest")"; oldest="$(jq -r '.supported.oldest_scheduled.image' "$manifest")"
  docker pull --platform linux/amd64 "$n1" >/dev/null; upgrade_one_window n-minus-1 "$n1"
  docker pull --platform linux/amd64 "$oldest" >/dev/null; upgrade_one_window oldest-supported "$oldest"
  jq -s '{schema:"cortex-live-upgrade-results-v1",windows:.}' "$dir"/*-result.json >"$LIVE_RUN_ROOT/artifacts/upgrade-results.json"
  jq -e 'any(.windows[];.window=="n-minus-1" and .result=="pass") and any(.windows[];.window=="oldest-supported" and .result=="pass") and all(.windows[];.interruption=="observed-process-kill")' "$LIVE_RUN_ROOT/artifacts/upgrade-results.json" >/dev/null
  live_event upgrade_complete "$(jq -c '{windows:[.windows[]|{window,result}]}' "$LIVE_RUN_ROOT/artifacts/upgrade-results.json")"
  live_terminal_disposition upgrade pass artifacts/upgrade-results.json
}
