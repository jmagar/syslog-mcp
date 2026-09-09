#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
# shellcheck source=tests/live/lib/docker.sh
source "$root/tests/live/lib/docker.sh"
# shellcheck source=refusals.sh
source "$root/tests/live/phases/compose/refusals.sh"

[[ -n "${LIVE_RUN_ID:-}" && -n "${LIVE_RUN_ROOT:-}" ]] || { echo "run through tests/live/runner.sh" >&2; exit 2; }
cortex="${LIVE_CORTEX_BIN:-$root/target/debug/cortex}"
[[ -x "$cortex" ]] || { echo "missing LIVE_CORTEX_BIN executable" >&2; exit 2; }
shim_dir="$root/tests/live/services/cortex-isolated/bin"
chmod +x "$shim_dir/timeout" "$shim_dir/ss"
export PATH="$shim_dir:$PATH"
docker version >/dev/null; docker compose version >/dev/null

provider="$(live_docker_provider)"; project="${LIVE_RUN_ID//_/-}-compose"; service=cortex; container="${project}-cortex-1"
export CORTEX_DATA_VOLUME="${project}_data"
fixture="$root/tests/live/services/cortex-isolated/compose.yaml"; image="${LIVE_COMPOSE_FIXTURE_IMAGE:-busybox:1.36}"
docker pull "$image" >/dev/null
image_id="$(live_docker_image_id "$image")"
image_ref="$(docker image inspect "$image" | jq -er '.[0].RepoDigests[0]')"
export LIVE_COMPOSE_FIXTURE_IMAGE="$image_ref"
digest="${image_id#sha256:}"; live_topology_register "$project" "$provider" "$fixture" "$digest"
common=(--compose-file "$fixture" --project-dir "$root/tests/live/services/cortex-isolated" --project-name "$project" --service "$service" --container "$container")

docker compose -f "$fixture" -p "$project" up -d --wait
live_resource_transition topology compose-project CREATED "$provider" "$project" \
  "$(jq -cn --arg self "$root/tests/live/lib/docker.sh" --arg p "$project" --arg r "$LIVE_RUN_ID" --arg provider "$provider" --arg f "$fixture" '["bash",$self,"cleanup",$p,$r,$provider,$f]')" "$digest" \
  "$(jq -cn --arg project "$project" '{"com.docker.compose.project":$project}')" \
  "$(jq -cn --arg self "$root/tests/live/lib/docker.sh" --arg p "$project" --arg r "$LIVE_RUN_ID" --arg provider "$provider" '["bash",$self,"verify",$p,$r,$provider]')"

"$cortex" compose status "${common[@]}" --json | jq -e '.target.project_name==$p or .target.project_name==null' --arg p "$project" >/dev/null
doctor_output="$("$cortex" compose doctor "${common[@]}" --json 2>&1)" && doctor_status=0 || doctor_status=$?
if (( doctor_status != 0 )); then
  # The disposable fixture deliberately is not a Cortex HTTP server. Doctor
  # must still prove Compose ownership and fail closed on unknown runtime.
  grep -q 'ownership=ComposeOwned runtime_state=Unknown diagnostics=\[\]' <<<"$doctor_output"
fi
"$cortex" compose logs "${common[@]}" --tail 20 | grep -q cortex-live-compose-ready
"$cortex" compose pull "${common[@]}" --yes >/dev/null
"$cortex" compose up "${common[@]}" --yes >/dev/null
"$cortex" compose restart "${common[@]}" --yes >/dev/null
compose_refusal_checks "$cortex" "$fixture" "$project" "$service" "$container"
"$cortex" compose down --project-name "$project" --service "$service" --container "$container" --yes >/dev/null
[[ "$(docker inspect -f '{{.State.Running}}' "$container")" == false ]]
live_event compose_phase "$(jq -cn --arg p "$project" --arg provider "$provider" '{project:$p,provider:$provider,result:"pass",commands:["status","doctor","logs","pull","up","restart","down"],refusals:["cwd-fallback","selector-mismatch","partial-labels"]}')"
