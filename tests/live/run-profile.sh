#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
profile="${1:-smoke}"
shift || true
runs_root="${LIVE_RUNS_ROOT:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cortex-live-runs}"

case "$profile" in
  artifact) profile=artifacts ;;
  fleet) profile=fleet-read-only ;;
  provider) profile=fleet-mutating ;;
  resilience) profile=stateful ;;
esac

case "$profile" in
  artifacts|fleet-read-only|fleet-mutating|compose-isolated|docker-boundary-reduced|docker-boundary-full|noop)
    exec "$root/tests/live/runner.sh" --profile "$profile" --runs-root "$runs_root" "$@"
    ;;
esac

command -v docker >/dev/null 2>&1 || { echo "live profile '$profile' requires Docker" >&2; exit 69; }
docker info >/dev/null 2>&1 || { echo "live profile '$profile' requires a reachable Docker daemon" >&2; exit 69; }

suffix="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
candidate="${LIVE_CANDIDATE_IMAGE_REF:-cortex-live-candidate:$suffix}"
oracle="${LIVE_ORACLE_IMAGE_REF:-cortex-live-oracle:$suffix}"
toxiproxy="${LIVE_TOXIPROXY_IMAGE_REF:-ghcr.io/shopify/toxiproxy:2.12.0}"

# Create the run and install cleanup before the first daemon mutation.
export LIVE_PROJECT_ROOT="$root"
for lib in common lock redact events command lease resources; do
  # Library name is selected from this fixed list.
  # shellcheck disable=SC1090
  source "$root/tests/live/lib/$lib.sh"
done
live_init_run "$runs_root" "${LIVE_RUN_ID_OVERRIDE:-}" >/dev/null
provider="docker-host:$(docker info --format '{{.ID}}')"
cleanup_images() {
  local status=$? cleanup_status=0 reconcile_status=0 state
  trap - EXIT INT TERM
  reconcile_image() {
    local key="$1" ref="$2" externally_supplied="$3" cleanup verify labels
    [[ -z "$externally_supplied" ]] || return 0
    state="$(jq -rs --arg key "$key" '[.[]|select(.key==$key)]|last.state // ""' "$(live_resource_file)" 2>/dev/null || true)"
    if [[ "$state" == CREATING ]]; then
      if docker image inspect "$ref" >/dev/null 2>&1; then
        identify_owned_image "$key" "$ref"
      else
        # The exact, run-unique tag is the creation intent. Its authoritative
        # absence proves a failed build left no image, so reconcile the intent
        # to a verifiable no-op instead of demanding manual cleanup.
        cleanup="$(jq -cn --arg ref "$ref" '["sh","-c","if docker image inspect \"$1\" >/dev/null 2>&1; then docker image rm -f \"$1\"; fi","sh",$ref]')"
        verify="$(jq -cn --arg ref "$ref" '["sh","-c","! docker image inspect \"$1\" >/dev/null 2>&1","sh",$ref]')"
        labels="$(jq -cn --arg ref "$ref" '{image_ref:$ref,creation_outcome:"absent"}')"
        live_resource_transition "$key" image IDENTIFIED "$provider" "$ref" "$cleanup" "$ref" "$labels" "$verify"
      fi
    fi
  }
  reconcile_image candidate-image "$candidate" "${LIVE_CANDIDATE_IMAGE_REF:-}" || reconcile_status=$?
  reconcile_image oracle-image "$oracle" "${LIVE_ORACLE_IMAGE_REF:-}" || reconcile_status=$?
  live_cleanup_resources "$provider" || cleanup_status=$?
  if (( reconcile_status != 0 || cleanup_status != 0 )); then
    echo "pre-run exact-image cleanup failed; audit: $LIVE_RUN_ROOT/cleanup-audit.json" >&2
    if (( status == 0 )); then
      if (( cleanup_status != 0 )); then status=$cleanup_status; else status=$reconcile_status; fi
    fi
  fi
  exit "$status"
}
trap cleanup_images EXIT INT TERM

plan_owned_image() {
  local key="$1" ref="$2" intent
  intent="$(printf '%s' "$ref" | shasum -a 256 | awk '{print $1}')"
  live_resource_transition "$key" image PLANNED "$provider" '' '[]'
  live_resource_transition "$key" image CREATING "$provider" "$ref" '[]' "$intent" "$(jq -cn --arg ref "$ref" '{image_ref:$ref}')" '[]'
}

identify_owned_image() {
  local key="$1" ref="$2" id cleanup verify labels
  id="$(docker image inspect --format '{{.Id}}' "$ref")"
  cleanup="$(jq -cn --arg id "$id" '["docker","image","rm","-f",$id]')"
  verify="$(jq -cn --arg id "$id" '["sh","-c","! docker image inspect \"$1\" >/dev/null 2>&1","sh",$id]')"
  labels="$(jq -cn --arg ref "$ref" '{image_ref:$ref}')"
  live_resource_transition "$key" image IDENTIFIED "$provider" "$id" "$cleanup" "$id" "$labels" "$verify"
  live_resource_transition "$key" image CREATED "$provider" "$id" "$cleanup" "$id" "$labels" "$verify"
}

if [[ -z "${LIVE_CANDIDATE_IMAGE_REF:-}" ]]; then
  ! docker image inspect "$candidate" >/dev/null 2>&1 || live_die "refusing to overwrite pre-existing candidate image: $candidate"
  plan_owned_image candidate-image "$candidate"
  docker build --pull=false -f "$root/config/Dockerfile" -t "$candidate" "$root"
  identify_owned_image candidate-image "$candidate"
fi
if [[ -z "${LIVE_ORACLE_IMAGE_REF:-}" ]]; then
  ! docker image inspect "$oracle" >/dev/null 2>&1 || live_die "refusing to overwrite pre-existing oracle image: $oracle"
  plan_owned_image oracle-image "$oracle"
  docker build --pull=false -t "$oracle" "$root/tests/live/services/oracle"
  identify_owned_image oracle-image "$oracle"
fi
docker image inspect "$toxiproxy" >/dev/null 2>&1 || docker pull "$toxiproxy"

trap - EXIT INT TERM
exec "$root/tests/live/runner.sh" --profile "$profile" --runs-root "$runs_root" --provider "$provider" \
  --candidate-image "$candidate" --oracle-image "$oracle" --toxiproxy-image "$toxiproxy" "$@"
