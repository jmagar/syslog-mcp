#!/usr/bin/env bash
# backup.sh — WAL-safe SQLite backup for cortex
#
# Usage:
#   bash scripts/backup.sh [/path/to/backup/dir]
#
# Default backup dir: ./backups/
# Backup files (per timestamp):
#   syslog-YYYY-MM-DD-HHMMSS.db        — live syslog log database
#   auth-YYYY-MM-DD-HHMMSS.db          — lab-auth OAuth/JWT store (if present)
#   auth-jwt-YYYY-MM-DD-HHMMSS.pem     — RSA signing key (if present)
#
# Schedule via cron:
#   0 */6 * * * cd /path/to/cortex && bash scripts/backup.sh

set -euo pipefail
umask 077

DB_PATH="${CORTEX_DB_PATH:-./data/cortex.db}"
BACKUP_DIR="${1:-./backups}"
# `realpath -m --` is GNU-specific. Create the destination with the restrictive
# process umask, then use POSIX `pwd -P` to resolve `.`/`..` and symlinks on both
# macOS and Linux before changing permissions or writing any artifacts.
mkdir -p "$BACKUP_DIR"
BACKUP_DIR="$(cd "$BACKUP_DIR" && pwd -P)"
if [[ "$BACKUP_DIR" == "/" ]]; then
    echo "ERROR: Refusing unsafe backup directory: filesystem root" >&2
    exit 1
fi
TIMESTAMP=$(date -u +%Y-%m-%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/syslog-${TIMESTAMP}.db"

# Auth artifact paths come from [mcp.auth].sqlite_path and [mcp.auth].key_path
# in config.toml (resolved relative to the syslog DB directory at runtime).
# Defaults below match the out-of-the-box config.toml values. Override here
# if you changed the paths in config.toml.
DB_DIR="$(dirname "$DB_PATH")"
AUTH_DB_PATH="${AUTH_DB_PATH:-${DB_DIR}/auth.db}"
AUTH_KEY_PATH="${AUTH_KEY_PATH:-${DB_DIR}/auth-jwt.pem}"

# Ensure backup directory permissions are private
chmod 700 "$BACKUP_DIR"

if [[ ! -f "$DB_PATH" ]]; then
    echo "ERROR: Database not found at $DB_PATH"
    exit 1
fi

# WAL-safe online backup — no service stop required
# Escape single quotes in path to avoid breaking the .backup command syntax
ESCAPED_BACKUP_FILE="${BACKUP_FILE//\'/\'\'}"
sqlite3 "$DB_PATH" ".backup '${ESCAPED_BACKUP_FILE}'"
chmod 600 "$BACKUP_FILE"

SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "Backup complete: ${BACKUP_FILE} (${SIZE})"

# --- Auth state backup --------------------------------------------------------
# auth.db is a separate SQLite store managed by lab-auth. Use the same
# `.backup` (online, WAL-safe) approach so a running cortex doesn't need
# to be stopped to capture a consistent OAuth state snapshot.
if [[ -f "$AUTH_DB_PATH" ]]; then
    AUTH_BACKUP_FILE="${BACKUP_DIR}/auth-${TIMESTAMP}.db"
    ESCAPED_AUTH_BACKUP="${AUTH_BACKUP_FILE//\'/\'\'}"
    # Best-effort checkpoint before backup. The .backup command is already
    # WAL-safe; this just keeps the WAL trimmed. We tolerate failure (e.g.
    # SQLITE_BUSY while cortex is writing) because .backup will still
    # produce a consistent snapshot.
    sqlite3 "$AUTH_DB_PATH" "PRAGMA wal_checkpoint(FULL);" >/dev/null 2>&1 \
        || echo "Auth DB WAL checkpoint skipped (busy); .backup will still be consistent"
    sqlite3 "$AUTH_DB_PATH" ".backup '${ESCAPED_AUTH_BACKUP}'"
    AUTH_SIZE=$(du -h "$AUTH_BACKUP_FILE" | cut -f1)
    chmod 600 "$AUTH_BACKUP_FILE"
    echo "Auth DB backup complete: ${AUTH_BACKUP_FILE} (${AUTH_SIZE})"
else
    echo "Auth DB not found at ${AUTH_DB_PATH}; skipping (oauth not configured?)"
fi

# JWT signing key — atomic copy with restrictive perms (install -m 600 avoids
# the chmod race window that exists with cp + chmod).
if [[ -f "$AUTH_KEY_PATH" ]]; then
    AUTH_KEY_BACKUP="${BACKUP_DIR}/auth-jwt-${TIMESTAMP}.pem"
    install -m 600 "$AUTH_KEY_PATH" "$AUTH_KEY_BACKUP"
    echo "Auth JWT key backup complete: ${AUTH_KEY_BACKUP}"
else
    echo "Auth JWT key not found at ${AUTH_KEY_PATH}; skipping"
fi

# Prune backups older than 30 days. Backup creation has already succeeded at
# this point, but retention failure is still operationally significant: warn
# for each failed class and return nonzero so schedulers can alert on it.
prune_failed=0
for pattern in "syslog-*.db" "auth-*.db" "auth-jwt-*.pem"; do
    if ! find "$BACKUP_DIR" -name "$pattern" -mtime +30 -delete; then
        echo "WARNING: Failed to prune old ${pattern} backups in ${BACKUP_DIR}" >&2
        prune_failed=1
    fi
done
REMAINING=$(find "$BACKUP_DIR" -name "syslog-*.db" | wc -l | tr -d ' ')
echo "Retained ${REMAINING} syslog backup(s) in ${BACKUP_DIR}"
exit "$prune_failed"
