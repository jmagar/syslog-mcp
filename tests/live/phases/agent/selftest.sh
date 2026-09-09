#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
contract="$root/tests/live/contracts/agent.json"
jq -e '.schema_version==1 and .boundary.daemon_identity_required and (.boundary.forbidden_urls|index("unix://")) and (.surfaces|sort)==["cli","mcp","rest"]' "$contract" >/dev/null
jq -e '(.scenarios|unique|length)==(.scenarios|length) and (.scenarios|index("checkpoint-resume")) and (.scenarios|index("duplicate-prevention")) and (.scenarios|index("bounded-backpressure")) and (.scenarios|index("allowlist")) and (.scenarios|index("log-rotation"))' "$contract" >/dev/null
jq -e '(.agent_cli_commands|length)==6 and (.portable_unsupported|sort)==["container-oom","daemon-restart","socket-permission-loss"]' "$contract" >/dev/null
jq -e '.properties.daemon_id.minLength==1 and .properties.cleanup_evidence.const=="canonical-resource-manifest" and .additionalProperties==false' "$root/tests/live/contracts/agent-driver-evidence.schema.json" >/dev/null
bash -n "$root/tests/live/phases/agent/run.sh"
bash -n "$root/tests/live/profiles/agent/portable-driver.sh" "$root/tests/live/profiles/agent/service-cli.sh"
grep -F 'unrestricted host Docker socket is forbidden' "$root/tests/live/phases/agent/run.sh" >/dev/null
grep -F 'Docker authority identity changed' "$root/tests/live/phases/agent/run.sh" >/dev/null
grep -F 'platform-qualified' "$root/tests/live/phases/agent/run.sh" >/dev/null
grep -F -- '--log-opt max-size=1k' "$root/tests/live/profiles/agent/portable-driver.sh" >/dev/null
grep -F 'setup deploy agent' "$root/tests/live/profiles/agent/service-cli.sh" >/dev/null
grep -F 'agent-live-backpressure-' "$root/tests/live/profiles/agent/portable-driver.sh" >/dev/null
grep -F 'agent-docker-unsupported-event-filter' "$root/tests/live/phases/agent/run.sh" >/dev/null
! grep -F 'agent-docker-auth-denial' "$root/tests/live/phases/agent/run.sh" >/dev/null
validator=(python3)
python3 -c 'import jsonschema' >/dev/null 2>&1 || validator=(uv run --quiet --with jsonschema python)
"${validator[@]}" - "$root/tests/live/contracts/agent-driver-evidence.schema.json" <<'PY'
import json, sys
from jsonschema import Draft202012Validator
schema = json.load(open(sys.argv[1], encoding="utf-8"))
validator = Draft202012Validator(schema)
valid = {
    "schema":"cortex-live-agent-driver-evidence-v1", "scenario":"outage",
    "disposition":"pass", "run_id":"cortex-e2e-selftest", "daemon_id":"owned",
    "checkpoint_before":"before", "checkpoint_after":"after",
    "exact_fixture_ids":["a" * 64], "expected_action":"log",
    "observed_state":"reconnected", "observation_sequence":1,
    "surface_artifacts":["mcp.json", "rest.json", "cli.json"],
    "cleanup_evidence":"canonical-resource-manifest"
}
validator.validate(valid)
for mutate in (
    lambda value: value.update(untrusted=True),
    lambda value: value.update(exact_fixture_ids=["not-an-id"]),
    lambda value: value.update(cleanup_evidence="claimed-clean"),
):
    candidate = dict(valid)
    mutate(candidate)
    if validator.is_valid(candidate):
        raise SystemExit("negative agent evidence mutant unexpectedly passed")
PY
# Execute the DinD publication policy against both its accepted form and an
# insecure TCP-published mutant. The mutant must be rejected, not grep-matched.
(
  live_die() { return 1; }
  LIVE_PROJECT_ROOT="$root"
  # shellcheck disable=SC1090
  source "$root/tests/live/phases/agent/run.sh"
  live_agent_validate_dind_boundary unix-socket-only
  ! live_agent_validate_dind_boundary tcp-published-plaintext
)
! grep -F -- '--host=tcp://0.0.0.0:2375' "$root/tests/live/phases/agent/run.sh" >/dev/null
grep -F 'container-exec://' "$root/tests/live/phases/agent/run.sh" >/dev/null
echo 'agent phase self-test: PASS'
