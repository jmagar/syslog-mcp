#!/usr/bin/env bash
set -euo pipefail
op="${1:?}" kind="${2:?}" id="${3:?}" run_id="${4:?}" outer_id="${5:?}" control="${6:-}"
[[ "$(docker info --format '{{.ID}}')" == "$outer_id" ]]
case "$kind" in
  inner-container)
    dctl() { case "$control" in container-exec://*) docker exec "${control#container-exec://}" docker "$@";; *) docker -H "$control" "$@";; esac; }
    exists() { dctl inspect "$id" >/dev/null 2>&1; }
    owned() { [[ "$(dctl inspect -f '{{index .Config.Labels "cortex.live.run_id"}}' "$id")" == "$run_id" ]]; }
    remove() { dctl rm -f "$id" >/dev/null; }
    ;;
  container)
    exists() { docker inspect "$id" >/dev/null 2>&1; }
    owned() { [[ "$(docker inspect -f '{{index .Config.Labels "cortex.live.run_id"}}' "$id")" == "$run_id" ]]; }
    remove() { docker rm -f "$id" >/dev/null; }
    ;;
  volume)
    exists() { docker volume inspect "$id" >/dev/null 2>&1; }
    owned() { [[ "$(docker volume inspect -f '{{index .Labels "cortex.live.run_id"}}' "$id")" == "$run_id" ]]; }
    remove() { docker volume rm "$id" >/dev/null; }
    ;;
  *) exit 2;;
esac
case "$op" in
  cleanup) exists || exit 0; owned; remove;;
  verify) ! exists;;
  *) exit 2;;
esac
