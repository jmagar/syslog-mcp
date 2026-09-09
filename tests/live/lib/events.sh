#!/usr/bin/env bash

live_event_file() { printf '%s/events.jsonl\n' "${LIVE_RUN_ROOT:?}"; }

_live_append_line() {
  local file="$1" line="$2"
  [[ ! -L "$file" ]] || { live_die "refusing symlink event stream"; return; }
  umask 077
  printf '%s\n' "$line" >>"$file"
  chmod 600 "$file"
}

live_event() {
  local kind="$1" payload="${2:-}" file line
  [[ -n "$payload" ]] || payload='{}'
  jq -e 'type == "object"' <<<"$payload" >/dev/null || { live_die "event payload must be an object"; return; }
  file="$(live_event_file)"
  line="$(jq -cn --arg run_id "$LIVE_RUN_ID" --arg kind "$kind" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson payload "$payload" \
    '{run_id:$run_id,at:$at,kind:$kind,payload:$payload}')"
  line="$(printf '%s' "$line" | live_redact_stream)"
  live_with_lock "$file" _live_append_line "$file" "$line"
}
