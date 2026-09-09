#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
deployed=false
while (($#)); do
  case "$1" in
    --skip-seed) shift ;;
    --url) deployed=true; shift 2 ;;
    *) echo "scripts/smoke-test.sh: unsupported legacy argument: $1" >&2; exit 2 ;;
  esac
done
echo "scripts/smoke-test.sh is deprecated; delegating to tests/live/run-profile.sh" >&2
if $deployed; then
  [[ -n "${LIVE_TARGET_MANIFEST:-}" ]] || { echo "deployed qualification requires LIVE_TARGET_MANIFEST and explicit fleet credentials" >&2; exit 64; }
  exec "$root/tests/live/run-profile.sh" fleet
fi
exec "$root/tests/live/run-profile.sh" smoke
