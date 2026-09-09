#!/usr/bin/env bash

live_platform_name() {
  case "${1:-$(uname -s)}" in Linux) echo linux;; Darwin) echo darwin;; MINGW*|MSYS*|CYGWIN*) echo windows;; *) echo unknown;; esac
}

live_platform_init() {
  LIVE_PLATFORM="$(live_platform_name)"
  LIVE_PLATFORM_POLICY="${LIVE_PLATFORM_POLICY:-}"
  [[ -n "$LIVE_PLATFORM_POLICY" ]] || { if [[ "$LIVE_PLATFORM" == linux ]]; then LIVE_PLATFORM_POLICY=linux-full; else LIVE_PLATFORM_POLICY=portable; fi; }
  LIVE_PLATFORM_CONTRACT="$LIVE_PROJECT_ROOT/tests/live/contracts/platform-coverage.json"
  jq -e --arg policy "$LIVE_PLATFORM_POLICY" --arg platform "$LIVE_PLATFORM" '.policies[$policy] and (.policies[$policy].platforms|index($platform))' "$LIVE_PLATFORM_CONTRACT" >/dev/null || {
    live_die "platform policy $LIVE_PLATFORM_POLICY is not valid for $LIVE_PLATFORM"; return 1;
  }
  export LIVE_PLATFORM LIVE_PLATFORM_POLICY LIVE_PLATFORM_CONTRACT
}

live_platform_coverage_write() {
  local output="$LIVE_RUN_ROOT/platform-coverage.json"
  jq -n --arg platform "$LIVE_PLATFORM" --arg policy "$LIVE_PLATFORM_POLICY" --arg profile "$1" --slurpfile contract "$LIVE_PLATFORM_CONTRACT" --slurpfile events "$(live_event_file)" '
    ($contract[0].policies[$policy]) as $p |
    [$events[]|select(.kind=="topology_disposition" or .kind=="result")|
      {capability:(if .kind=="topology_disposition" then .payload.capability else .payload.surface_id end), disposition:(.payload.disposition // .payload.result),
       kind:.kind} | select(.disposition!="pass" and .disposition!="fail") |
      . as $q | . + {approved:(($q.kind=="topology_disposition") and ((($p.approved_qualifications[$q.capability] // [])|index($q.disposition)) != null)) }
    ] as $qualified |
    [$events[]|select(.kind=="topology_disposition")|{capability:.payload.capability,disposition:.payload.disposition}] as $topology |
    [if (($p.required_profiles // [])|index($profile)) != null then
       (($p.required_passes // []) + ($p.profile_required_passes[$profile] // []))[] |
         select(. as $required | any($topology[]; .capability==$required and .disposition=="pass") | not)
     else empty end] as $missing |
    {schema:"cortex-live-platform-coverage-result-v1",platform:$platform,policy:$policy,profile:$profile,certification:$p.certification,
     qualified:$qualified,approved_count:([$qualified[]|select(.approved)]|length),unapproved_count:([$qualified[]|select(.approved|not)]|length),
     linux_only_coverage:($p.linux_only_coverage // []),required_passes:(($p.required_passes // []) + ($p.profile_required_passes[$profile] // [])),missing_required_passes:$missing,
     accepted:(([$qualified[]|select(.approved|not)]|length)==0 and ($missing|length)==0)}' >"$output"
  chmod 600 "$output"
  return 0
}
