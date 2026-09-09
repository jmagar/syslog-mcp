#!/usr/bin/env bash
set -euo pipefail
[[ "${MUTANT_ID:?}" && "${MUTANT_FINGERPRINT:?}" && "${MUTANT_KILLER:?}" ]]
exit 42
