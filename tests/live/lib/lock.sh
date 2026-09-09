#!/usr/bin/env bash

live_with_lock() {
  local target="$1"; shift
  local lock="${target}.lock" waited=0
  while ! mkdir "$lock" 2>/dev/null; do
    (( waited++ < 500 )) || { printf 'lock timeout: %s\n' "$target" >&2; return 124; }
    sleep 0.01
  done
  local status=0
  "$@" || status=$?
  rmdir "$lock" || return 125
  return "$status"
}
