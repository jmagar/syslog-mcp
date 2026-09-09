#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
exec "$root/tests/live/runner.sh" --profile agent "$@"
