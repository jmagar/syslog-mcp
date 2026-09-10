#!/usr/bin/env bash
# Self-test for the harness's bash-version guard and its ERR-trap abort report.
# Case bodies are literal child scripts, expanded only when the child runs.
# shellcheck disable=SC2016
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091
source "$root/tests/live/lib/common.sh"
live_require_modern_bash || exit 64
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { printf 'harness guard selftest: %s\n' "$*" >&2; exit 1; }

# Version comparison: 4.1 is the floor.
for version in '3 2' '4 0' '2 5' ' ' 'x 1'; do
  # shellcheck disable=SC2086 # split into MAJOR MINOR on purpose
  if live_bash_version_ok $version; then fail "accepted bash version '$version'"; fi
done
for version in '4 1' '4 4' '5 2' '10 0'; do
  # shellcheck disable=SC2086 # split into MAJOR MINOR on purpose
  live_bash_version_ok $version || fail "rejected bash version '$version'"
done

# The guard also rejects an old bash first on PATH, which child phases would
# pick up through their `#!/usr/bin/env bash` shebang.
mkdir "$tmp/old-bash"
printf '#!/bin/sh\necho "3 2"\n' >"$tmp/old-bash/bash"; chmod +x "$tmp/old-bash/bash"
if PATH="$tmp/old-bash:$PATH" live_require_modern_bash 2>"$tmp/guard.err"; then fail 'accepted an old bash on PATH'; fi
grep -qF "bash on PATH is $tmp/old-bash/bash (version 3 2)" "$tmp/guard.err" || fail "unexpected PATH guard message: $(cat "$tmp/guard.err")"
live_require_modern_bash || fail 'rejected the modern bash on PATH'

# Each case runs as its own script under errexit with the trap installed.
# Usage: run_case NAME BODY; sets case_file, case_status, and case_err.
run_case() {
  case_file="$tmp/$1.sh"
  printf 'set -euo pipefail\nsource "%s/tests/live/lib/common.sh"\nlive_install_err_trap\n%s\n' "$root" "$2" >"$case_file"
  case_status=0
  bash "$case_file" >"$tmp/$1.out" 2>"$tmp/$1.err" || case_status=$?
  case_err="$(cat "$tmp/$1.err")"
}
line_of() { grep -n "# $2\$" "$1" | cut -d: -f1; }
aborts() { grep -c '^live-e2e: aborted at ' <<<"$case_err" || true; }

# A bare failing [[ ]] is named by file and line, without the command text.
run_case bare 'token=credential-shaped-value-123456
[[ "$token" == other ]] # fail-here
echo unreachable'
[[ "$case_status" -ne 0 ]] || fail 'bare failing [[ ]] did not abort'
grep -qF "live-e2e: aborted at $case_file:$(line_of "$case_file" fail-here) (status 1) in main" <<<"$case_err" || fail "bare abort not named: $case_err"
[[ "$(aborts)" == 1 ]] || fail "bare abort reported $(aborts) times"
if grep -qF credential-shaped-value <<<"$case_err"; then fail 'abort report leaked a variable value'; fi
if grep -q unreachable "$tmp/bare.out"; then fail 'run continued past a failing [[ ]]'; fi

# A failure inside nested functions reports the whole call chain.
run_case chain 'inner() { [[ a == b ]]; } # inner
outer() { inner; } # outer
wrap() { "$@"; } # wrap
wrap outer # top'
[[ "$case_status" -ne 0 ]] || fail 'nested failure did not abort'
expected="live-e2e: aborted at $case_file:$(line_of "$case_file" inner) (status 1) in inner
  from $case_file:$(line_of "$case_file" outer) in outer
  from $case_file:$(line_of "$case_file" wrap) in wrap
  from $case_file:$(line_of "$case_file" top) in main"
[[ "$case_err" == "$expected" ]] || fail "unexpected call chain:
$case_err"

# Handled failures and set +e regions stay silent.
run_case handled 'if [[ 1 == 2 ]]; then :; fi
[[ 1 == 2 ]] || true
check() { [[ 1 == 2 ]]; }
check || true
set +e
false
[[ 1 == 2 ]]
set -e
echo finished'
[[ "$case_status" -eq 0 && -z "$case_err" ]] || fail "handled failures were reported (status $case_status): $case_err"
grep -qx finished "$tmp/handled.out" || fail 'handled case did not finish'

# A failing subshell or pipeline is reported once, by the installing shell.
run_case subshell '( [[ 1 == 2 ]] ) # fail-here'
[[ "$(aborts)" == 1 ]] || fail "subshell abort reported $(aborts) times: $case_err"
grep -qF "aborted at $case_file:$(line_of "$case_file" fail-here) " <<<"$case_err" || fail "subshell abort not named: $case_err"
run_case pipeline 'false | cat # fail-here'
[[ "$(aborts)" == 1 ]] || fail "pipeline abort reported $(aborts) times: $case_err"
grep -qF "aborted at $case_file:$(line_of "$case_file" fail-here) " <<<"$case_err" || fail "pipeline abort not named: $case_err"

# A failing background job does not claim the run aborted.
run_case background '( false ) & job=$!
wait "$job" || true
echo continued'
[[ "$case_status" -eq 0 && -z "$case_err" ]] || fail "background failure was reported (status $case_status): $case_err"
grep -qx continued "$tmp/background.out" || fail 'background case did not continue'

echo 'harness guard selftest: PASS'
