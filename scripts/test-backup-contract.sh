#!/usr/bin/env bash
set -euo pipefail

image_ref=${1:?usage: test-backup-contract.sh IMAGE_REF}
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
source_dir="$test_root/data"
backup_dir="$test_root/backups"
mkdir -p "$source_dir" "$backup_dir"

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

docker run --rm --user 0:0 -v "$source_dir:/data" "$image_ref" sqlite3 /data/cortex.db \
  "CREATE TABLE proof(value TEXT); INSERT INTO proof VALUES('syslog-survives');"
docker run --rm --user 0:0 -v "$source_dir:/data" "$image_ref" sqlite3 /data/auth.db \
  "CREATE TABLE proof(value TEXT); INSERT INTO proof VALUES('auth-survives');"
printf '%s\n' 'test-signing-key' >"$source_dir/auth-jwt.pem"

docker run --rm --user 0:0 -e CORTEX_DB_PATH=/data/cortex.db \
  -v "$source_dir:/data" -v "$backup_dir:/backups" "$image_ref" \
  bash /usr/local/libexec/cortex-backup.sh /backups

syslog_backup="$(find "$backup_dir" -name 'syslog-*.db' -print -quit)"
auth_backup="$(find "$backup_dir" -name 'auth-*.db' -print -quit)"
key_backup="$(find "$backup_dir" -name 'auth-jwt-*.pem' -print -quit)"
[[ -n "$syslog_backup" && -n "$auth_backup" && -n "$key_backup" ]]
[[ "$(file_mode "$backup_dir")" == "700" ]]
for artifact in "$syslog_backup" "$auth_backup" "$key_backup"; do
  [[ "$(file_mode "$artifact")" == "600" ]]
done

# Model loss of the data volume. Backups remain usable on their independent bind.
rm -rf "$source_dir"
# This fixture deliberately creates a private root-owned backup directory, so
# restore it under the same explicit test identity. The runtime image remains
# non-root by default; this only prevents the contract fixture from testing
# filesystem ownership mismatch instead of backup recoverability.
[[ "$(docker run --rm --user 0:0 -v "$backup_dir:/backups:ro" "$image_ref" sqlite3 "/backups/$(basename "$syslog_backup")" 'SELECT value FROM proof;')" == "syslog-survives" ]]
[[ "$(docker run --rm --user 0:0 -v "$backup_dir:/backups:ro" "$image_ref" sqlite3 "/backups/$(basename "$auth_backup")" 'SELECT value FROM proof;')" == "auth-survives" ]]
[[ "$(docker run --rm --user 0:0 -v "$backup_dir:/backups:ro" "$image_ref" cat "/backups/$(basename "$key_backup")")" == "test-signing-key" ]]

# Retention failures happen after valid artifacts are written. They must warn
# and fail the scheduled run instead of being silently swallowed.
prune_source="$test_root/prune-data"
prune_backups="$test_root/prune-backups"
fake_find="$test_root/find"
mkdir -p "$prune_source" "$prune_backups"
docker run --rm --user 0:0 -v "$prune_source:/data" "$image_ref" sqlite3 /data/cortex.db \
  "CREATE TABLE proof(value TEXT); INSERT INTO proof VALUES('created-before-prune');"
cat >"$fake_find" <<'EOF'
#!/usr/bin/env bash
for arg in "$@"; do
  if [[ "$arg" == "-delete" ]]; then
    echo "forced prune failure" >&2
    exit 73
  fi
done
exec /usr/bin/find "$@"
EOF
chmod +x "$fake_find"
if docker run --rm --user 0:0 -e CORTEX_DB_PATH=/data/cortex.db \
  -v "$prune_source:/data" -v "$prune_backups:/backups" \
  -v "$fake_find:/usr/local/bin/find:ro" "$image_ref" \
  bash /usr/local/libexec/cortex-backup.sh /backups \
  >"$test_root/prune.out" 2>"$test_root/prune.err"; then
  echo "backup unexpectedly succeeded after forced prune failure" >&2
  exit 1
fi
find "$prune_backups" -name 'syslog-*.db' -print -quit | grep -q .
grep -Fq 'WARNING: Failed to prune old syslog-*.db backups' "$test_root/prune.err"

# Reject a normalized root destination before mkdir/chmod or artifact creation.
if docker run --rm --user 0:0 -e CORTEX_DB_PATH=/data/cortex.db \
  -v "$prune_source:/data" "$image_ref" \
  bash /usr/local/libexec/cortex-backup.sh /tmp/.. \
  >"$test_root/root.out" 2>"$test_root/root.err"; then
  echo "backup unexpectedly accepted filesystem root" >&2
  exit 1
fi
grep -Fq 'Refusing unsafe backup directory: filesystem root' "$test_root/root.err"

# The backup script must remain portable to macOS hosts that do not provide
# GNU realpath's -m/-- flags.
if docker run --rm --entrypoint sh "$image_ref" -c \
  "sed '/^[[:space:]]*#/d' /usr/local/libexec/cortex-backup.sh | grep -Eq 'realpath[[:space:]]+-m|realpath.*--'"; then
  echo "backup script uses GNU-only realpath flags" >&2
  exit 1
fi

echo "Backup contents, isolation, recovery, and permission contract passed"
