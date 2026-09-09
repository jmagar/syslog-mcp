#!/usr/bin/env bash
set -euo pipefail

image_ref=${1:?usage: test-agent-env-file.sh IMAGE_REF}
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
env_file="$test_root/agent.env"
cat >"$env_file" <<'EOF'
CORTEX_HEARTBEAT_TOKEN=abcDEF0123_-.:/@%+,=tail
CORTEX_AGENT_FILE_TAILS=/var/log/syslog:syslog,/var/log/auth.log:auth log
EOF

actual="$(docker run --rm --env-file "$env_file" "$image_ref" /usr/bin/env)"
grep -Fx 'CORTEX_HEARTBEAT_TOKEN=abcDEF0123_-.:/@%+,=tail' <<<"$actual"
grep -Fx 'CORTEX_AGENT_FILE_TAILS=/var/log/syslog:syslog,/var/log/auth.log:auth log' <<<"$actual"

echo "Docker env-file parser contract passed for systemd-safe emitted values"
