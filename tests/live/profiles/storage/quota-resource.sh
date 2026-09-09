#!/usr/bin/env bash
set -euo pipefail
mode="$1" id="$2" run_id="$3" provider="$4"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
# shellcheck disable=SC1091
source "$root/tests/live/lib/docker.sh"
[[ "$(live_docker_provider)" == "$provider" ]] || exit 2
case "$mode" in
  cleanup-container)
    if [[ "$(docker inspect --format '{{index .Config.Labels "cortex.live.run_id"}}' "$id" 2>/dev/null)" != "$run_id" ]]; then
      docker inspect "$id" >/dev/null 2>&1 && exit 2
      exit 0
    fi
    docker rm -f "$id" >/dev/null
    ;;
  verify-container) ! docker inspect "$id" >/dev/null 2>&1 ;;
  cleanup-volume)
    if [[ "$(docker volume inspect --format '{{index .Labels "cortex.live.run_id"}}' "$id" 2>/dev/null)" != "$run_id" ]]; then
      docker volume inspect "$id" >/dev/null 2>&1 && exit 2
      exit 0
    fi
    docker volume rm "$id" >/dev/null
    ;;
  verify-volume) ! docker volume inspect "$id" >/dev/null 2>&1 ;;
  *) exit 2 ;;
esac
