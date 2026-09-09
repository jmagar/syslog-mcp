#!/usr/bin/env bash

live_result() {
  local surface_id="$1" scenario="$2" result="$3" duration_ms="${4:-0}" evidence="${5:-}" case_kind="${6:-semantic-positive}" attempt_kind="${7:-first_attempt}" retry_index="${8:-0}"
  case "$result" in pass|fail|unsupported|not-authorized|platform-qualified|artifact-qualified|not-applicable) ;; *) live_die "invalid result"; return;; esac
  case "$case_kind" in semantic-positive|executed-refusal-semantic|validation-negative|authorization) ;; *) live_die "invalid required case kind"; return;; esac
  case "$attempt_kind" in first_attempt|diagnostic_retry) ;; *) live_die "invalid attempt kind"; return;; esac
  [[ "$duration_ms" =~ ^[0-9]+$ && "$retry_index" =~ ^[0-9]+$ ]] || { live_die "invalid result numeric field"; return; }
  [[ "$attempt_kind" != first_attempt || "$retry_index" == 0 ]] || { live_die "first attempt retry index must be zero"; return; }
  [[ "$attempt_kind" != diagnostic_retry || "$retry_index" != 0 ]] || { live_die "diagnostic retry requires positive retry index"; return; }
  [[ -n "${LIVE_SURFACE_CONTRACT:-}" ]] || { live_die "SurfaceContract not loaded"; return; }
  if [[ "$surface_id" == stateful.* ]]; then
    [[ "$case_kind" == semantic-positive ]] || { live_die "invalid stateful case identity"; return; }
  else
    jq -e --arg id "$surface_id" --arg case "$case_kind" 'any(.entries[]; .id==$id and (.required_cases|index($case)))' "$LIVE_SURFACE_CONTRACT" >/dev/null || { live_die "unknown surface/case identity: $surface_id/$case_kind"; return; }
  fi
  if [[ -n "$evidence" ]]; then
    [[ "$evidence" != /* && "/$evidence/" != *"/../"* && -f "$LIVE_RUN_ROOT/$evidence" && ! -L "$LIVE_RUN_ROOT/$evidence" ]] || { live_die "invalid or missing result evidence"; return; }
  elif [[ "$result" == pass || "$result" == fail ]]; then live_die "executed outcome requires evidence"; return; fi
  local duplicate
  duplicate="$(jq -n --arg surface "$surface_id" --arg case "$case_kind" --arg attempt "$attempt_kind" --argjson retry "$retry_index" 'any(inputs; .kind=="result" and .payload.surface_id==$surface and .payload.case_kind==$case and .payload.attempt_kind==$attempt and .payload.retry_index==$retry)' "$(live_event_file)")"
  [[ "$duplicate" == false ]] || { live_die "duplicate result identity"; return; }
  if [[ "$attempt_kind" == diagnostic_retry ]]; then
    jq -e -n --arg surface "$surface_id" --arg case "$case_kind" 'any(inputs; .kind=="result" and .payload.surface_id==$surface and .payload.case_kind==$case and .payload.attempt_kind=="first_attempt")' "$(live_event_file)" >/dev/null || { live_die "diagnostic retry requires preserved first attempt"; return; }
  fi
  live_event result "$(jq -cn --arg surface_id "$surface_id" --arg scenario "$scenario" --arg result "$result" --arg evidence "$evidence" --arg case_kind "$case_kind" --arg attempt_kind "$attempt_kind" --argjson retry_index "$retry_index" --argjson duration_ms "$duration_ms" '{surface_id:$surface_id,scenario:$scenario,result:$result,duration_ms:$duration_ms,evidence:$evidence,case_kind:$case_kind,attempt_kind:$attempt_kind,retry_index:$retry_index}')"
}

live_terminal_disposition() {
  local capability="$1" disposition="$2" evidence="$3"
  case "$disposition" in pass|fail|unsupported|not-authorized|platform-qualified|artifact-qualified|not-applicable) ;; *) live_die "invalid terminal disposition"; return;; esac
  [[ "$capability" =~ ^[a-z0-9._-]+$ ]] || { live_die "invalid terminal capability"; return; }
  [[ -f "$LIVE_RUN_ROOT/$evidence" && ! -L "$LIVE_RUN_ROOT/$evidence" ]] || { live_die "terminal disposition evidence missing"; return; }
  live_event topology_disposition "$(jq -cn --arg capability "$capability" --arg disposition "$disposition" --arg evidence "$evidence" '{capability:$capability,disposition:$disposition,evidence:$evidence,mandatory:true}')"
}

live_summary_accepts_profile() {
  local profile="$1" profiles="$2" summary="$3" mandatory
  mandatory="$(jq -r --arg p "$profile" '.profiles[$p].mandatory' "$profiles")"
  if [[ "$mandatory" == true ]]; then jq -e '.failed==0 and .platform.accepted==true and .total>0' "$summary" >/dev/null
  else jq -e '.failed==0' "$summary" >/dev/null; fi
}

live_report() {
  local events json="${LIVE_RUN_ROOT}/summary.json" junit="${LIVE_RUN_ROOT}/junit.xml" tmp
  events="$(live_event_file)"
  tmp="$(mktemp "${LIVE_RUN_ROOT}/.summary.XXXXXX")"
  jq -n --arg run_id "$LIVE_RUN_ID" '
    reduce inputs as $event ({run_id:$run_id,total:0,passed:0,failed:0,qualified:0,retries:0};
      if $event.kind == "docker_boundary_result_v1" then
        .total += 1 |
        .passed += (if $event.payload.disposition == "pass" then 1 else 0 end) |
        .failed += (if $event.payload.disposition == "fail" then 1 else 0 end) |
        .qualified += (if (["unsupported","not-authorized","platform-qualified","artifact-qualified","not-applicable"] | index($event.payload.disposition)) then 1 else 0 end)
      elif $event.kind == "topology_disposition" then
        .total += 1 |
        .passed += (if $event.payload.disposition == "pass" then 1 else 0 end) |
        .failed += (if $event.payload.disposition == "fail" then 1 else 0 end) |
        .qualified += (if (["unsupported","not-authorized","platform-qualified","artifact-qualified","not-applicable"] | index($event.payload.disposition)) then 1 else 0 end)
      elif $event.kind != "result" then . else
        if $event.payload.attempt_kind == "diagnostic_retry" then .retries += 1 else
          .total += 1 |
          .passed += (if $event.payload.result == "pass" then 1 else 0 end) |
          .failed += (if $event.payload.result == "fail" then 1 else 0 end) |
          .qualified += (if (["unsupported","not-authorized","platform-qualified","artifact-qualified","not-applicable"] | index($event.payload.result)) then 1 else 0 end)
        end
      end)
  ' "$events" >"$tmp"
  chmod 600 "$tmp"; mv -f "$tmp" "$json"
  if [[ -f "$LIVE_RUN_ROOT/platform-coverage.json" ]]; then
    tmp="$(mktemp "${LIVE_RUN_ROOT}/.summary-platform.XXXXXX")"
    jq --slurpfile platform "$LIVE_RUN_ROOT/platform-coverage.json" '. + {platform:$platform[0]}' "$json" >"$tmp"
    chmod 600 "$tmp"; mv -f "$tmp" "$json"
  fi
  { jq -r '"<?xml version=\"1.0\" encoding=\"UTF-8\"?>","<testsuite name=\"cortex-live\" tests=\"\(.total)\" failures=\"\(.failed)\" skipped=\"\(.qualified)\">"' "$json";
    jq -r 'select(.kind=="result" and .payload.attempt_kind=="first_attempt") | .payload | "  <testcase classname=\"\(.surface_id|@html)\" name=\"\(.case_kind|@html)\" time=\"\(.duration_ms/1000)\">"+(if .result=="fail" then "<failure message=\"scenario failed\"/>" elif .result!="pass" then "<skipped message=\"\(.result|@html)\"/>" else "" end)+"</testcase>"' "$events";
    jq -r 'select(.kind=="docker_boundary_result_v1") | .payload | "  <testcase classname=\"docker-boundary\" name=\"\(.candidate|@html)\" time=\"\(.duration_seconds)\">"+(if .disposition=="fail" then "<failure message=\"scenario failed\"/>" elif .disposition!="pass" then "<skipped message=\"\(.disposition|@html)\"/>" else "" end)+"</testcase>"' "$events";
    jq -r 'select(.kind=="topology_disposition") | .payload | "  <testcase classname=\"topology\" name=\"\(.capability|@html)\" time=\"0\">"+(if .disposition=="fail" then "<failure message=\"scenario failed\"/>" elif .disposition!="pass" then "<skipped message=\"\(.disposition|@html)\"/>" else "" end)+"</testcase>"' "$events";
    printf '%s\n' '</testsuite>'; } >"$junit"
  chmod 600 "$junit"
  cat "$json"
}
