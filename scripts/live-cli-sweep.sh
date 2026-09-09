#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# -le 1 ]] || { echo "usage: scripts/live-cli-sweep.sh [deprecated-output-directory]" >&2; exit 2; }
echo "scripts/live-cli-sweep.sh is deprecated; CLI coverage is registry-derived in the full profile" >&2
if [[ -n "${LIVE_TARGET_MANIFEST:-}" ]]; then
  exec "$root/tests/live/run-profile.sh" fleet
fi
exec "$root/tests/live/run-profile.sh" full
