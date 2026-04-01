#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${CLAUDE_PLUGIN_ROOT}/.env"
BACKUP_DIR="${CLAUDE_PLUGIN_ROOT}/backups"
mkdir -p "$BACKUP_DIR"

declare -A MANAGED=(
  [SYSLOG_HOST]="${CLAUDE_PLUGIN_OPTION_SYSLOG_HOST:-}"
  [SYSLOG_PORT]="${CLAUDE_PLUGIN_OPTION_SYSLOG_PORT:-}"
  [SYSLOG_MCP_API_TOKEN]="${CLAUDE_PLUGIN_OPTION_SYSLOG_MCP_API_TOKEN:-}"
)

LOCK_DIR="${CLAUDE_PLUGIN_ROOT:-$(pwd)}"
mkdir -p "${LOCK_DIR}/.cache"

touch "$ENV_FILE"

if [ -s "$ENV_FILE" ]; then
  cp "$ENV_FILE" "${BACKUP_DIR}/.env.bak.$(date +%s)"
fi

(
  flock -x 200

  for key in "${!MANAGED[@]}"; do
    value="${MANAGED[$key]}"
    [ -z "$value" ] && continue
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
      awk -v k="$key" -v v="$value" \
        '$0 ~ "^" k "=" {print k "=" v; next} {print}' \
        "$ENV_FILE" > "${ENV_FILE}.tmp" && mv "${ENV_FILE}.tmp" "$ENV_FILE"
    else
      echo "${key}=${value}" >> "$ENV_FILE"
    fi
  done

  chmod 600 "$ENV_FILE"

) 200>"${LOCK_DIR}/.cache/syslog-sync-env.lock"
