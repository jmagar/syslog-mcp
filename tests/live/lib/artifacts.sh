#!/usr/bin/env bash

live_artifact_allowed() {
  case "$1" in
    *.stdout|*.stderr|*.json|*.jsonl|*.xml|*.txt) return 0;;
    *) return 1;;
  esac
}

live_artifact_write() {
  local relative="$1" max_bytes="$2" target tmp bytes parent
  [[ "$relative" != /* && "/$relative/" != *"/../"* && "/$relative/" != *"/./"* ]] || { live_die "unsafe artifact path"; return; }
  live_artifact_allowed "$relative" || { live_die "artifact type not allowlisted"; return; }
  target="${LIVE_RUN_ROOT:?}/artifacts/$relative"
  parent="$(dirname "$relative")"
  live_secure_subdir "$LIVE_RUN_ROOT/artifacts" "$parent"
  [[ ! -L "$target" ]] || { live_die "refusing symlink artifact"; return; }
  tmp="$(mktemp "${LIVE_RUN_ROOT}/.artifact.XXXXXX")"
  live_redact_stream >"$tmp"
  bytes="$(wc -c <"$tmp" | tr -d ' ')"
  if (( bytes > max_bytes )); then rm -f "$tmp"; live_die "artifact exceeds byte budget"; return; fi
  chmod 600 "$tmp"; mv -f "$tmp" "$target"
}
