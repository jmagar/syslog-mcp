#!/usr/bin/env bash
# Runs only against a real locally isolated Cortex HTTPS proxy/service. It
# deliberately has no synthetic fallback.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
: "${LIVE_TARGET_MANIFEST:?manifest generated from actual isolated Cortex/provider evidence}"
: "${LIVE_FLEET_READ_TOKEN:?actual read token}"
: "${LIVE_FLEET_ADMIN_TOKEN:?actual admin token}"
exec "$root/tests/live/runner.sh" --profile fleet-read-only --target local-isolated-cortex "${@}"
