#!/usr/bin/env bash
set -euo pipefail

# Resolve /backups through Compose so .env interpolation and CLI overrides use
# exactly the same parser as the subsequent `docker compose up`.
compose_json="$(docker compose "$@" config --format json)"
backup_dir="$(python3 -c '
import json
import os
import sys

project = json.load(sys.stdin)
service = project.get("services", {}).get("cortex", {})
for volume in service.get("volumes", []):
    if volume.get("target") == "/backups":
        if volume.get("type") != "bind":
            raise SystemExit("cortex /backups mount must be a bind mount")
        source = volume.get("source", "")
        if not os.path.isabs(source):
            raise SystemExit("cortex /backups bind source must resolve to an absolute path")
        source = os.path.realpath(source)
        if source == os.path.sep:
            raise SystemExit("refusing unsafe cortex /backups bind source: filesystem root")
        print(source)
        break
else:
    raise SystemExit("cortex Compose service has no /backups mount")
  ' <<<"$compose_json"
)"

if ! install -d -m 700 "$backup_dir"; then
  echo "failed to create Cortex backup directory: $backup_dir" >&2
  exit 1
fi
if [[ "$(stat -c '%a' "$backup_dir" 2>/dev/null || stat -f '%Lp' "$backup_dir")" != "700" ]]; then
  echo "Cortex backup directory does not have required mode 0700: $backup_dir" >&2
  exit 1
fi
printf 'Prepared Cortex backup directory: %s (0700)\n' "$backup_dir"
