#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
jq -e '.mandatory_classes|length==8 and ([.[]]|unique|length)==8 and (index("browser")|not) and (index("connection")|not)' "$root/contracts/security.json" >/dev/null
! grep -q 'path-symlink-swap\|browser-storage\|connection-cap' "$root/phases/security/run.sh"
jq -e '(.http|length)==5 and (.targets|length)==4 and (.encoded_secret_variants|length)==4' "$root/fixtures/security/corpus.json" >/dev/null
bash -n "$root/phases/security/run.sh"
python3 -m py_compile "$root/phases/security/bounded_http.py"
echo 'security selftest: PASS'
