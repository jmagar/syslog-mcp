#!/usr/bin/env bash
set -euo pipefail
expected_daemon="${1:?expected daemon ID}"; kind="${2:?kind}"; id="${3:?exact ID}"
current_daemon="$(docker info --format '{{.ID}}')"
[[ -n "$current_daemon" && "$current_daemon" == "$expected_daemon" ]] || { echo "MANUAL_RECONCILIATION_REQUIRED: Docker daemon identity changed" >&2; exit 2; }
case "$kind" in
  container) ! docker container inspect "$id" >/dev/null 2>&1;;
  network) ! docker network inspect "$id" >/dev/null 2>&1;;
  volume) ! docker volume inspect "$id" >/dev/null 2>&1;;
  *) exit 2;;
esac
