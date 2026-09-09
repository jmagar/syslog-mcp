#!/usr/bin/env bash

live_timeout() {
  local seconds="$1"; shift
  local marker session_file
  marker="$(mktemp "${TMPDIR:-/tmp}/cortex-live-timeout.XXXXXX")"; rm -f "$marker"
  session_file="${marker}.session"
  export CORTEX_LIVE_SESSION_PID_FILE="$session_file"
  "$@" & local command_pid=$!
  # Poll instead of a single long sleep. On macOS, terminating the watcher
  # shell does not reliably reap its `sleep` child, causing successful short
  # commands to block until the full timeout. This exits within one second of
  # normal completion and also works when the target is a shell function.
  (
    local elapsed=0
    while kill -0 "$command_pid" 2>/dev/null && (( elapsed < seconds )); do
      sleep 1
      ((elapsed+=1))
    done
    kill -0 "$command_pid" 2>/dev/null || exit 0
    touch "$marker"
    local session_pid
    session_pid="$(cat "$session_file" 2>/dev/null || true)"
    if [[ "$session_pid" =~ ^[1-9][0-9]*$ ]]; then
      kill -TERM "-$session_pid" 2>/dev/null || true
    fi
    kill -TERM "$command_pid" 2>/dev/null || true
    sleep 1
    if [[ "$session_pid" =~ ^[1-9][0-9]*$ ]]; then
      kill -KILL "-$session_pid" 2>/dev/null || true
    fi
    kill -KILL "$command_pid" 2>/dev/null || true
  ) & local watcher_pid=$!
  local status=0
  wait "$command_pid" || status=$?
  if [[ -e "$marker" ]]; then
    wait "$watcher_pid" 2>/dev/null || true
    status=124
  else
    kill "$watcher_pid" 2>/dev/null || true
    wait "$watcher_pid" 2>/dev/null || true
  fi
  rm -f "$marker" "$session_file"
  unset CORTEX_LIVE_SESSION_PID_FILE
  return "$status"
}

live_timeout_process_tree() {
  local seconds="$1"; shift
  local home="${LIVE_RUN_ROOT:?}/home" tmp="${LIVE_RUN_ROOT}/tmp"
  live_secure_dir "$home"
  live_secure_dir "$tmp"
  live_timeout "$seconds" python3 "$LIVE_PROJECT_ROOT/tests/live/lib/session_exec.py" "$home" "$tmp" "$@"
}

live_run_bounded() {
  local seconds="$1" stdout="$2" stderr="$3"; shift 3
  [[ "$seconds" =~ ^[1-9][0-9]*$ ]] || { live_die "invalid timeout"; return; }
  live_budget_add processes 1
  live_secure_dir "$(dirname "$stdout")"
  local pipe_dir out_pipe err_pipe status out_filter err_filter
  pipe_dir="$(mktemp -d "${LIVE_RUN_ROOT}/.capture.XXXXXX")"
  out_pipe="$pipe_dir/stdout"; err_pipe="$pipe_dir/stderr"
  mkfifo "$out_pipe" "$err_pipe"; chmod 600 "$out_pipe" "$err_pipe"
  live_redact_stream <"$out_pipe" >"$stdout" & out_filter=$!
  live_redact_stream <"$err_pipe" >"$stderr" & err_filter=$!
  local home="${LIVE_RUN_ROOT:?}/home" tmp="${LIVE_RUN_ROOT}/tmp"
  live_secure_dir "$home"; live_secure_dir "$tmp"
  if live_timeout "$seconds" python3 "$LIVE_PROJECT_ROOT/tests/live/lib/session_exec.py" "$home" "$tmp" "$@" >"$out_pipe" 2>"$err_pipe"; then status=0; else status=$?; fi
  wait "$out_filter"; wait "$err_filter"
  chmod 600 "$stdout" "$stderr"
  rm -f "$out_pipe" "$err_pipe"; rmdir "$pipe_dir"
  live_event command "$(jq -cn --arg status "$status" --arg timeout "$seconds" '{status:($status|tonumber),timeout_seconds:($timeout|tonumber)}')"
  return "$status"
}

live_poll() {
  local timeout="$1" interval="$2" description="$3"; shift 3
  local started now attempts=0
  started="$(date +%s)"
  while true; do
    ((attempts+=1))
    live_budget_add poll_attempts 1
    "$@" && { live_event poll "$(jq -cn --arg d "$description" --argjson a "$attempts" '{description:$d,attempts:$a,result:"ready"}')"; return 0; }
    now="$(date +%s)"
    if (( now - started >= timeout )); then
      live_event poll "$(jq -cn --arg d "$description" --argjson a "$attempts" '{description:$d,attempts:$a,result:"timeout"}')"
      return 124
    fi
    sleep "$interval"
  done
}
