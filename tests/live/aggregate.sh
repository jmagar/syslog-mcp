#!/usr/bin/env bash
set -euo pipefail

[[ $# -ge 2 ]] || { echo "usage: tests/live/aggregate.sh CONTRACT RUN_DIR..." >&2; exit 2; }
contract="$1"; shift
[[ -f "$contract" ]] || { echo "aggregate: contract missing" >&2; exit 2; }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
: >"$tmp/runs.jsonl"
for run in "$@"; do
  [[ -f "$run/events.jsonl" && -f "$run/summary.json" && -f "$run/cleanup-audit.json" && -f "$run/surface-contract.json" ]] || {
    echo "aggregate: incomplete run evidence: $run" >&2; exit 1;
  }
  cmp -s "$contract" "$run/surface-contract.json" || {
    echo "aggregate: stale or mismatched SurfaceContract: $run" >&2; exit 1;
  }
  profile="$(jq -er 'select(.kind=="run_started")|.payload.profile' "$run/events.jsonl" | head -1)"
  jq -e '.failed==0 and .platform.accepted==true' "$run/summary.json" >/dev/null
  jq -e '.state=="CLEAN"' "$run/cleanup-audit.json" >/dev/null
  jq -cn --arg profile "$profile" --arg run "$run" '{profile:$profile,run:$run}' >>"$tmp/runs.jsonl"
done

jq -e -s 'group_by(.profile)|all(.[];length==1)' "$tmp/runs.jsonl" >/dev/null || {
  echo "aggregate: duplicate profile evidence" >&2; exit 1;
}

jq -cn --slurpfile contract "$contract" --slurpfile runs "$tmp/runs.jsonl" '
  $contract[0].entries[] as $entry |
  $entry.profiles[] as $owner |
  $entry.required_cases[] |
  {surface_id:$entry.id,case_kind:.,owner:$owner,
   run:($runs|map(select(.profile==$owner))|first|.run // null)}
' >"$tmp/required.jsonl"

: >"$tmp/ledger.jsonl"
while IFS= read -r row; do
  run="$(jq -r '.run // empty' <<<"$row")"
  if [[ -z "$run" ]]; then
    jq -c '.+{count:0,outcome:null}' <<<"$row" >>"$tmp/ledger.jsonl"
    continue
  fi
  jq -cn --argjson row "$row" --slurpfile events "$run/events.jsonl" '
    [$events[]|select(.kind=="result" and .payload.surface_id==$row.surface_id and
      .payload.case_kind==$row.case_kind and .payload.attempt_kind=="first_attempt")] as $matches |
    $row+{count:($matches|length),outcome:($matches|first|.payload // null)}
  ' >>"$tmp/ledger.jsonl"
done <"$tmp/required.jsonl"

output="${LIVE_AGGREGATE_OUTPUT:-aggregate-qualification.json}"
jq -s --slurpfile contract "$contract" '
  {schema:"cortex-live-aggregate-qualification-v1",
   surface_count:($contract[0].entries|length),required_case_count:length,
   accounted_count:([.[]|select(.count==1 and .outcome.result=="pass")]|length),
   missing:[.[]|select(.count==0)],duplicates:[.[]|select(.count>1)],
   non_green:[.[]|select(.count==1 and .outcome.result!="pass")]} |
  .green=(.surface_count==($contract[0].entries|length) and
    .accounted_count==.required_case_count and
    (.missing|length)==0 and (.duplicates|length)==0 and (.non_green|length)==0)
' "$tmp/ledger.jsonl" >"$output"
jq -e '.green' "$output" >/dev/null || { jq . "$output" >&2; exit 1; }
jq . "$output"
