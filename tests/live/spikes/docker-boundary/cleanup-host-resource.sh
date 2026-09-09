#!/usr/bin/env bash
set -euo pipefail
expected_daemon="${1:?expected daemon ID}"; kind="${2:?kind}"; id="${3:?exact ID}"
current_daemon="$(docker info --format '{{.ID}}')"
[[ -n "$current_daemon" && "$current_daemon" == "$expected_daemon" ]] || { echo "MANUAL_RECONCILIATION_REQUIRED: Docker daemon identity changed" >&2; exit 2; }
case "$kind" in
  container) docker rm -f "$id" >/dev/null;;
  network) docker network rm "$id" >/dev/null;;
  volume) docker volume rm "$id" >/dev/null;;
  *) exit 2;;
esac
