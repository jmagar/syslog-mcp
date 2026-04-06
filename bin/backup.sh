#!/usr/bin/env bash
# backup.sh — WAL-safe SQLite backup for syslog-mcp
#
# Usage:
#   bash bin/backup.sh [/path/to/backup/dir]
#
# Default backup dir: ./backups/
# Backup file: syslog-YYYY-MM-DD-HHMMSS.db
#
# Schedule via cron:
#   0 */6 * * * cd /path/to/syslog-mcp && bash bin/backup.sh

set -euo pipefail

DB_PATH="${SYSLOG_MCP_DB_PATH:-./data/syslog.db}"
BACKUP_DIR="${1:-./backups}"
TIMESTAMP=$(date -u +%Y-%m-%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/syslog-${TIMESTAMP}.db"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

if [[ ! -f "$DB_PATH" ]]; then
    echo "ERROR: Database not found at $DB_PATH"
    exit 1
fi

# WAL-safe online backup — no service stop required
# Escape single quotes in path to avoid breaking the .backup command syntax
ESCAPED_BACKUP_FILE="${BACKUP_FILE//\'/\'\'}"
sqlite3 "$DB_PATH" ".backup '${ESCAPED_BACKUP_FILE}'"

SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "Backup complete: ${BACKUP_FILE} (${SIZE})"

# Prune backups older than 30 days
find "$BACKUP_DIR" -name "syslog-*.db" -mtime +30 -delete 2>/dev/null || true
REMAINING=$(find "$BACKUP_DIR" -name "syslog-*.db" | wc -l | tr -d ' ')
echo "Retained ${REMAINING} backup(s) in ${BACKUP_DIR}"
