#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
if [[ $# == 0 ]]; then
  bash "$0" normal
  if bash "$0" survived >/dev/null 2>&1; then
    echo 'downtime probe accepted a surviving UDP marker' >&2; exit 1
  fi
  if bash "$0" no-recovery >/dev/null 2>&1; then
    echo 'downtime probe accepted missing UDP recovery evidence' >&2; exit 1
  fi
  echo 'downtime lifecycle and negative assertions passed'
  exit 0
fi
mode="$1"
source "$root/tests/live/phases/ingest/run.sh"
LIVE_RUN_ROOT="$(mktemp -d)"
trap 'rm -rf "$LIVE_RUN_ROOT"' EXIT
mkdir -p "$LIVE_RUN_ROOT/artifacts"
LIVE_RUN_ID=selftest
LIVE_COMPOSE_PROJECT=selftest
LIVE_SYSLOG_UDP_PORT=11514
LIVE_SYSLOG_TCP_PORT=11515
LIVE_HTTP_PORT=3100
LIVE_CORTEX_TOKEN=fixture
live_ingest_candidate_id() { echo candidate; }
docker() {
  local command="$1"; shift
  case "$command" in
    ps) echo relay ;;
    stop)
      [[ "$1" == -t && "$2" == 5 ]]; shift 2
      for id in "$@"; do printf false >"$LIVE_RUN_ROOT/$id"; done ;;
    start) printf true >"$LIVE_RUN_ROOT/$1" ;;
    inspect) cat "$LIVE_RUN_ROOT/${@: -1}" ;;
    exec)
      [[ "$1" == relay && "$(cat "$LIVE_RUN_ROOT/relay")" == true ]]
      touch "$LIVE_RUN_ROOT/relay-ready" ;;
    *) echo "unexpected docker call: $command" >&2; return 1 ;;
  esac
}
nc() {
  local payload
  payload="$(cat)"
  if [[ "$payload" == *downtime-udp-loss* ]]; then
    [[ "$(cat "$LIVE_RUN_ROOT/relay")" == false ]]
    [[ "$(cat "$LIVE_RUN_ROOT/candidate")" == false ]]
    touch "$LIVE_RUN_ROOT/loss-sent"
  elif [[ "$payload" == *downtime-udp-recovered* ]]; then
    [[ "${@: -1}" == 21514 ]] || return 1
    [[ -f "$LIVE_RUN_ROOT/relay-ready" ]]
    [[ "$(cat "$LIVE_RUN_ROOT/candidate")" == true ]]
    [[ "$mode" == no-recovery ]] || touch "$LIVE_RUN_ROOT/recovered"
  fi
}
curl() { printf 000; }
live_topology_port() {
  [[ "$2" == selftest && "$3" == udp-redirector && "$4" == 11514 && "$5" == udp ]]
  [[ -f "$LIVE_RUN_ROOT/relay-ready" ]]
  printf 21514
}
live_wait_until() {
  shift 2
  if [[ "$1" == live_ingest_udp_relay_ready ]]; then "$@"; fi
}
live_ingest_wait_marker() {
  if [[ "$1" == *downtime-udp-recovered* ]]; then
    [[ -f "$LIVE_RUN_ROOT/recovered" ]]
  fi
}
live_ingest_mcp_search() {
  [[ "$mode" == survived && "$1" == *downtime-udp-loss* ]]
}
live_ingest_curl_status() { printf 200; }
live_ingest_case() { :; }
live_die() { echo "$*" >&2; return 1; }
live_ingest_downtime
[[ "$LIVE_SYSLOG_UDP_PORT" == 21514 ]] || exit 1
[[ -f "$LIVE_RUN_ROOT/loss-sent" && -f "$LIVE_RUN_ROOT/recovered" ]]
jq -e '.udp_ingress_while_down == "stopped" and .udp_recovery == "observed"' \
  "$LIVE_RUN_ROOT/artifacts/downtime-transport.json" >/dev/null
