#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
# shellcheck source=refusals.sh
source "$root/tests/live/phases/compose/refusals.sh"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-compose-refusal.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/fake" <<'SH'
#!/usr/bin/env bash
case " $* " in
  *" --container partial "*) echo 'required compose labels' >&2; exit 1;;
  *" --project-name foreign "*) echo 'does not match' >&2; exit 1;;
  *) echo 'refusing mutation: cwd target' >&2; exit 1;;
esac
SH
chmod +x "$tmp/fake"
compose_expect_refusal 'cwd target' "$tmp/fake" compose up
compose_expect_refusal 'does not match' "$tmp/fake" compose restart --project-name foreign
echo "compose refusal helper selftest: PASS"
