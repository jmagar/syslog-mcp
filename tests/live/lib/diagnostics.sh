#!/usr/bin/env bash

live_diagnostics_once() {
  local compose_file="$1" project="$2" reason="$3" marker="${LIVE_RUN_ROOT:?}/.diagnostics-captured"
  : "$compose_file"
  # shellcheck disable=SC2329 # invoked indirectly under live_with_lock
  _live_diagnostics_locked() {
    [[ ! -e "$marker" ]] || return 0
    : >"$marker"; chmod 600 "$marker"
    local output tmp ids id
    output="$LIVE_RUN_ROOT/artifacts/diagnostics.txt"; tmp="$output.tmp"
    ids="$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
    {
      printf 'reason=%s\nproject=%s\n' "$reason" "$project"
      docker ps -a --filter "label=com.docker.compose.project=$project" --no-trunc 2>&1 || true
      while IFS= read -r id; do
        [[ -n "$id" ]] || continue
        printf '\ncontainer=%s\n' "$id"
        docker logs --tail 80 "$id" 2>&1 || true
        docker inspect --format '{{json .State}} {{json .NetworkSettings.Ports}}' "$id" 2>&1 || true
      done <<<"$ids"
    } | awk 'BEGIN{left=131072} {if(left>0){line=$0 "\n"; if(length(line)>left) line=substr(line,1,left); printf "%s",line; left-=length(line)}}' | live_redact_stream >"$tmp"
    mv "$tmp" "$output"; chmod 600 "$output"
    live_event diagnostic "$(jq -cn --arg reason "$reason" --arg path artifacts/diagnostics.txt '{reason:$reason,path:$path,bounded:true,redacted:true}')"
  }
  live_with_lock "$marker" _live_diagnostics_locked
}
