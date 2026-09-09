#!/usr/bin/env bash
set -euo pipefail
pid="$1" deadline="$2" max_bytes="$3" path="$4"
[[ "$pid" =~ ^[1-9][0-9]*$ && "$deadline" =~ ^[1-9][0-9]*$ && "$max_bytes" =~ ^[1-9][0-9]*$ ]] || exit 2
while kill -0 "$pid" 2>/dev/null; do
  now="$(date +%s)"
  bytes="$(du -sk "$path" 2>/dev/null | awk '{print $1 * 1024}')"; bytes="${bytes:-0}"
  if (( now >= deadline || bytes > max_bytes )); then
    kill -TERM "$pid" 2>/dev/null || true
    sleep 2
    kill -KILL "$pid" 2>/dev/null || true
    exit 124
  fi
  sleep 1
done
