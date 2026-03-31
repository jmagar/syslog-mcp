#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${CLAUDE_PLUGIN_ROOT}/.env"
BACKUP_DIR="${CLAUDE_PLUGIN_ROOT}/backups"
mkdir -p "$BACKUP_DIR"

declare -A MANAGED=(
  [SYSLOG_HOST]="${CLAUDE_PLUGIN_OPTION_SYSLOG_HOST:-}"
  [SYSLOG_PORT]="${CLAUDE_PLUGIN_OPTION_SYSLOG_PORT:-}"
  [SYSLOG_MCP_TOKEN]="${CLAUDE_PLUGIN_OPTION_SYSLOG_MCP_TOKEN:-}"
)

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
        'BEGIN{FS="="; OFS="="} $1==k {$2=v; print; next} {print}' \
        "$ENV_FILE" > "${ENV_FILE}.tmp" && mv "${ENV_FILE}.tmp" "$ENV_FILE"
    else
      echo "${key}=${value}" >> "$ENV_FILE"
    fi
  done

  chmod 600 "$ENV_FILE"

) 200>/tmp/syslog-sync-env.lock
