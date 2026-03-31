#!/usr/bin/env bash
set -euo pipefail
ENV_FILE="${CLAUDE_PLUGIN_ROOT}/.env"
[ -f "$ENV_FILE" ] && chmod 600 "$ENV_FILE"
