#!/usr/bin/env bash
set -euo pipefail

GITIGNORE="${CLAUDE_PLUGIN_ROOT}/.gitignore"
REQUIRED=(".env" ".env.*" "!.env.example" ".cache/" "target/" "backups/*" "!backups/.gitkeep" "logs/*" "!logs/.gitkeep")

if [[ "${1:-}" == "--check" ]]; then
  missing=0
  for pattern in "${REQUIRED[@]}"; do
    grep -qxF "$pattern" "$GITIGNORE" 2>/dev/null || { echo "MISSING: $pattern" >&2; missing=1; }
  done
  exit $missing
fi

touch "$GITIGNORE"
for pattern in "${REQUIRED[@]}"; do
  grep -qxF "$pattern" "$GITIGNORE" 2>/dev/null || echo "$pattern" >> "$GITIGNORE"
done
