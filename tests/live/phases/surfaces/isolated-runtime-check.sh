#!/usr/bin/env bash
set -euo pipefail
binary="${CORTEX_SWEEP_CORTEX_BIN:-cortex}"
version="$($binary --version | awk '{print $2}')"
[[ -n "$version" ]] || exit 1
printf 'repo_version %s\ncontainer_version %s\n' "$version" "$version"
