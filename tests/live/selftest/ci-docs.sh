#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
python3 "$root/tests/live/generate-docs.py" --check
python3 - "$root" <<'PY'
import json, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
profiles = json.loads((root / "tests/live/contracts/profiles.json").read_text())["profiles"]
just = (root / "Justfile").read_text()
workflow = (root / ".github/workflows/live-qualification.yml").read_text()
workflow_lower = workflow.lower()
if 'live profile="smoke"' not in just:
    raise SystemExit("generic stable Just profile command is missing")
for required in ("if: always()", "sanit", "upload-artifact", "runner.sh --janitor"):
    if required not in workflow_lower:
        raise SystemExit(f"live workflow lacks required cleanup/artifact shape: {required}")
aggregate = workflow[workflow.index("  aggregate:"):workflow.index("  requested:")]
for required in ("Sweep expired aggregate leases", "if: always()", "runner.sh --janitor", "Sanitize aggregate evidence"):
    if required not in aggregate:
        raise SystemExit(f"aggregate job lacks cancellation-safe cleanup shape: {required}")
if aggregate.index("Reconcile aggregate leases") > aggregate.index("Sanitize aggregate evidence"):
    raise SystemExit("aggregate evidence is sanitized before cleanup reconciliation")
ci = (root / ".github/workflows/ci.yml").read_text()
block = ci[ci.index("mcp-integration:"):ci.index("ci-gate:")]
if "available=false" in block or "skipped::No reachable Docker" in block:
    raise SystemExit("required PR live job still silently skips missing Docker")
print("ci/docs live-suite contract: PASS")
PY
