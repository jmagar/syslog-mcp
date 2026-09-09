#!/usr/bin/env bash
set -euo pipefail
op="${1:?}" pid="${2:?}" start_digest="${3:?}" run_root="${4:?}"
[[ "$pid" =~ ^[1-9][0-9]*$ && "$run_root" == /* && -d "$run_root" ]]
observed() { ps -o lstart= -p "$pid" 2>/dev/null | shasum -a 256 | awk '{print $1}'; }
owned() {
  kill -0 "$pid" 2>/dev/null || return 1
  [[ "$(observed)" == "$start_digest" ]]
  ps -o command= -p "$pid" | grep -F 'heartbeat agent' >/dev/null
}
case "$op" in
  cleanup)
    owned || exit 0
    kill -TERM "$pid"
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || exit 0; sleep 0.2; done
    exit 1
    ;;
  verify) ! owned;;
  *) exit 2;;
esac
