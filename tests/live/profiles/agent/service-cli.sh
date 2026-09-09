#!/usr/bin/env bash
set -euo pipefail
root="${LIVE_PROJECT_ROOT:?}" bin="${LIVE_CORTEX_BIN_REQUIRED:?}" out="${LIVE_AGENT_CLI_OUTPUT:?}"
tmp="$(mktemp -d)"; chmod 700 "$tmp"; transport="$tmp/transport.log"; : >"$transport"
cleanup() { [[ "$tmp" == "${TMPDIR:-/tmp}"/* || "$tmp" == /var/folders/* ]] && rm -rf "$tmp"; }
trap cleanup EXIT
export HOME="$tmp" CORTEX_AI_WATCH_ALLOW_DEBUG_BINARY=true CORTEX_HEARTBEAT_TARGET="http://127.0.0.1:${LIVE_HTTP_PORT}/v1/heartbeats" CORTEX_HEARTBEAT_TOKEN="$LIVE_CORTEX_TOKEN"
export LIVE_AGENT_CLI_TRANSPORT_LOG="$transport" PATH="$root/tests/live/profiles/agent/fake-bin:$PATH"
export LIVE_AGENT_SYSTEMCTL_STATE="$tmp/systemctl.state"

"$bin" setup heartbeatagent install --json >"$tmp/install.json"
"$bin" setup heartbeatagent check --json >"$tmp/check.json"
"$bin" setup heartbeatagent remove --json >"$tmp/remove.json"
"$bin" update config clients --hosts disposable-agent --target "http://127.0.0.1:${LIVE_HTTP_PORT}" --docker --json >"$tmp/update-config.json"
"$bin" update agents --dry-run --binary "$bin" --json >"$tmp/update.json"
"$bin" setup deploy agent --hosts disposable-agent --target "http://127.0.0.1:${LIVE_HTTP_PORT}" --heartbeat-token disposable-live-token --docker --binary "$bin" --json >"$tmp/deploy.json"

grep -F 'setup heartbeatagent install' "$transport" >/dev/null
grep -F 'scp' "$transport" >/dev/null
jq -e '.mode=="heartbeat-agent-install" and .has_errors==false' "$tmp/install.json" >/dev/null
jq -e '.mode=="heartbeat-agent-check" and .has_errors==false and all(.phases[];.status=="ok")' "$tmp/check.json" >/dev/null
jq -e '.mode=="heartbeat-agent-remove" and .has_errors==false' "$tmp/remove.json" >/dev/null
unit="$tmp/.config/systemd/user/cortex-heartbeat-agent.service"
[[ ! -e "$unit" && "$(cat "$LIVE_AGENT_SYSTEMCTL_STATE")" == inactive ]]
jq -s --arg transport "$(wc -l <"$transport" | tr -d ' ')" --arg unit "$unit" '{schema:"cortex-live-agent-cli-live-v1",actual_execution:true,rollback:true,rollback_proof:{unit_absent:true,service_state:"inactive",unit:$unit},transport_calls:($transport|tonumber),results:.}' \
  "$tmp/install.json" "$tmp/check.json" "$tmp/remove.json" "$tmp/update-config.json" "$tmp/update.json" "$tmp/deploy.json" >"$out"
