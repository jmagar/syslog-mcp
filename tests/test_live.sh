#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode=docker
while (($#)); do
  case "$1" in
    --mode) mode="$2"; shift 2 ;;
    --url|--token) shift 2 ;;
    *) echo "tests/test_live.sh: unsupported legacy argument: $1" >&2; exit 2 ;;
  esac
done
echo "tests/test_live.sh is deprecated; delegating to the canonical live runner" >&2
case "$mode" in
  docker|all) exec "$root/tests/live/run-profile.sh" smoke ;;
  http)
    [[ -n "${LIVE_TARGET_MANIFEST:-}" ]] || { echo "HTTP/deployed qualification now requires LIVE_TARGET_MANIFEST and explicit fleet credentials" >&2; exit 64; }
    exec "$root/tests/live/run-profile.sh" fleet
    ;;
  *) echo "unsupported legacy mode: $mode" >&2; exit 2 ;;
esac
