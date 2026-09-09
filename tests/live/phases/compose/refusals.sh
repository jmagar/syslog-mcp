#!/usr/bin/env bash
set -euo pipefail

compose_expect_refusal() {
  local pattern="$1"; shift
  local output status=0
  output="$("$@" 2>&1)" || status=$?
  if (( status == 0 )) || ! grep -Eiq "$pattern" <<<"$output"; then
    echo "expected refusal /$pattern/ (status=$status): $output" >&2
    return 1
  fi
}

compose_refusal_checks() {
  local cortex="$1" fixture="$2" project="$3" service="$4" container="$5"
  local cwd
  cwd="$(mktemp -d "${TMPDIR:-/tmp}/cortex-compose-cwd.XXXXXX")"
  cp "$fixture" "$cwd/docker-compose.yml"
  (cd "$cwd" && compose_expect_refusal 'cwd target|refusing mutation' "$cortex" compose up --container "absent-${container}" --service "absent-${service}" --dry-run)
  rm -rf "$cwd"

  # Explicit selectors must be mutually consistent with the live labels.
  compose_expect_refusal 'does not match|refus' "$cortex" compose restart --project-name "${project}-foreign" --service "$service" --container "$container" --dry-run

  # A partial/stale label fixture must never be accepted for mutation.  The
  # caller creates this exact disposable container and owns its cleanup.
  local partial="${container}-partial"
  docker create --name "$partial" --label com.docker.compose.service="$service" busybox:1.36 true >/dev/null
  local partial_status=0
  compose_expect_refusal 'required compose labels|refus|could not resolve' "$cortex" compose restart --container "$partial" --dry-run || partial_status=$?
  docker rm "$partial" >/dev/null
  (( partial_status == 0 ))

  # Two independently labelled candidates for a unique service must make the
  # resolver ambiguous. Both IDs are exact and removed before returning.
  local ambiguous_service="ambiguous-${LIVE_RUN_ID}" a="${container}-amb-a" b="${container}-amb-b" ambiguous_status=0
  docker create --name "$a" --label com.docker.compose.service="$ambiguous_service" busybox:1.36 true >/dev/null
  docker create --name "$b" --label com.docker.compose.service="$ambiguous_service" busybox:1.36 true >/dev/null
  compose_expect_refusal 'ambiguous|multiple.*candidate|refus' "$cortex" compose restart --container absent-ambiguous --service "$ambiguous_service" --dry-run || ambiguous_status=$?
  docker rm "$a" "$b" >/dev/null
  (( ambiguous_status == 0 ))

  # The macOS `ss` fixture can deterministically report a foreign listener;
  # Up must refuse even though the selected Compose target is otherwise exact.
  LIVE_SS_CONFLICT=1 compose_expect_refusal 'non-target listener|syslog ports|refus' "$cortex" compose up \
    --compose-file "$fixture" --project-dir "$(dirname "$fixture")" --project-name "$project" --service "$service" --container "$container" --dry-run
}
