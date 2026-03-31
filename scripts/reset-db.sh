#!/usr/bin/env bash
# reset-db.sh — WAL-safe backup + destructive SQLite reset for syslog-mcp
#
# Usage:
#   bash scripts/reset-db.sh
#   bash scripts/reset-db.sh --force
#   bash scripts/reset-db.sh --backup-dir ./backups
#
# Default backup dir: ./backups/
# Default DB path: ${SYSLOG_MCP_DB_PATH:-./data/syslog.db}

set -euo pipefail

DB_PATH="${SYSLOG_MCP_DB_PATH:-./data/syslog.db}"
BACKUP_DIR="./backups"
FORCE=0

usage() {
    cat <<'EOF'
Usage: bash scripts/reset-db.sh [--force] [--backup-dir DIR] [--help]

Creates a WAL-safe SQLite backup first, then deletes the live DB files:
  - <db>
  - <db>-wal
  - <db>-shm

Options:
  --backup-dir DIR  Directory for the timestamped backup file (default: ./backups)
  --force           Skip the interactive confirmation prompt
  --help            Show this help text

Environment:
  SYSLOG_MCP_DB_PATH   SQLite database path (default: ./data/syslog.db)

Important:
  Stop the syslog-mcp service before running this reset. The backup step is
  WAL-safe online, but deleting the live DB files while the service is still
  writing is unsafe.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --backup-dir)
            if [[ $# -lt 2 ]]; then
                echo "ERROR: --backup-dir requires a directory path" >&2
                exit 1
            fi
            BACKUP_DIR="$2"
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "ERROR: sqlite3 is required for the WAL-safe backup step" >&2
    exit 1
fi

if [[ ! -f "$DB_PATH" ]]; then
    echo "ERROR: Database not found at $DB_PATH" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date -u +%Y-%m-%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/syslog-pre-reset-${TIMESTAMP}.db"
ESCAPED_BACKUP_FILE="${BACKUP_FILE//\'/\'\'}"

if [[ "$FORCE" -ne 1 ]]; then
    echo "About to create a WAL-safe backup and then permanently delete:"
    echo "  $DB_PATH"
    echo "  ${DB_PATH}-wal"
    echo "  ${DB_PATH}-shm"
    echo
    echo "Backup target: $BACKUP_FILE"
    echo "Expected follow-up: restart syslog-mcp so it recreates a fresh schema."
    echo
    read -r -p "Type RESET to continue: " CONFIRM
    if [[ "$CONFIRM" != "RESET" ]]; then
        echo "Aborted."
        exit 1
    fi
fi

sqlite3 "$DB_PATH" ".backup '${ESCAPED_BACKUP_FILE}'"

rm -f "$DB_PATH" "${DB_PATH}-wal" "${DB_PATH}-shm"

BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "Backup complete: ${BACKUP_FILE} (${BACKUP_SIZE})"
echo "Reset complete: removed ${DB_PATH}, ${DB_PATH}-wal, and ${DB_PATH}-shm"
echo "Next step: restart syslog-mcp to recreate the database."
