#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
python3 - "$root/tests/live/services/apprise/mock_apprise.py" <<'PY'
import pathlib, sys
source=pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
compile(source,sys.argv[1],"exec")
PY
grep -q 'external_canary==0' "$root/tests/live/phases/notifications/run.sh"
grep -q 'MAX_RECORDS' "$root/tests/live/services/apprise/mock_apprise.py"
grep -q 'restart apprise' "$root/tests/live/phases/notifications/run.sh"
echo 'notifications selftest: PASS'
