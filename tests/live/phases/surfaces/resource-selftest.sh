#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
export LIVE_PROJECT_ROOT="$root"
for lib in common lock redact events command report lease resources; do source "$root/tests/live/lib/$lib.sh"; done
source "$root/tests/live/phases/surfaces/resources.sh"
grep -q 'background integrity job did not finish before maintenance sweep' "$root/tests/live/phases/surfaces/rest_sweep.py" || {
  echo 'surface selftest: REST sweep does not serialize maintenance after background integrity' >&2
  exit 1
}
grep -Fq '"DOCKER_HOST", "DOCKER_API_VERSION", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"' "$root/tests/live/phases/surfaces/cli_sweep.py" || {
  echo 'surface selftest: CLI sweep does not preserve the selected Docker transport' >&2
  exit 1
}
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
export LIVE_RESOURCE_PROVIDER=docker-host:selftest LIVE_RUN_ID=cortex-e2e-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export LIVE_RUN_ROOT="$tmp/run"; mkdir -p "$LIVE_RUN_ROOT" "$tmp/bin"
printf '{}\n' >"$LIVE_RUN_ROOT/run.json"; : >"$LIVE_RUN_ROOT/events.jsonl"
state="$tmp/project-present"; touch "$state"
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
state="$(cd "$(dirname "$0")/.." && pwd)/project-present"
if [[ "$1" == compose ]]; then rm -f "$state"; exit 0; fi
[[ -e "$state" ]] && printf 'owned-resource\n'
EOF
chmod +x "$tmp/bin/docker"; export PATH="$tmp/bin:$PATH"
compose="$tmp/compose.yaml"; printf 'services: {}\n' >"$compose"

# An interrupted `compose up` leaves the project IDENTIFIED, before CREATED.
surface_cli_resource_register cortex-e2e-surface-selftest "$compose" ""
live_cleanup_resources "$LIVE_RESOURCE_PROVIDER" 5
[[ ! -e "$state" ]]
jq -e '.state=="CLEAN"' "$LIVE_RUN_ROOT/cleanup-audit.json" >/dev/null

# A TERM/EXIT trap must drive the same cleanup path for a created project.
touch "$state"; trapped_run="$tmp/trapped-run"; ready="$tmp/trapped-ready"
bash -ceu '
  root="$1"; run="$2"; compose="$3"; ready="$4"
  export LIVE_PROJECT_ROOT="$root" LIVE_RUN_ROOT="$run"
  mkdir -p "$run"; printf "{}\n" >"$run/run.json"; : >"$run/events.jsonl"
  for lib in common lock redact events command report lease resources; do source "$root/tests/live/lib/$lib.sh"; done
  source "$root/tests/live/phases/surfaces/resources.sh"
  trap '\''live_cleanup_resources "$LIVE_RESOURCE_PROVIDER" 5; exit 143'\'' TERM
  surface_cli_resource_register cortex-e2e-surface-trapped "$compose" ""
  surface_cli_resource_created cortex-e2e-surface-trapped ""
  touch "$ready"
  while :; do sleep 1; done
' _ "$root" "$trapped_run" "$compose" "$ready" & trapped_pid=$!
for _ in $(seq 1 50); do [[ -e "$ready" ]] && break; sleep 0.1; done
[[ -e "$ready" ]]; kill -TERM "$trapped_pid"; wait "$trapped_pid" || [[ "$?" == 143 ]]
[[ ! -e "$state" ]]
jq -e '.state=="CLEAN"' "$trapped_run/cleanup-audit.json" >/dev/null
printf 'surface resource cancellation selftest: PASS\n'
