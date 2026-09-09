#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"; export LIVE_PROJECT_ROOT="$ROOT"
# shellcheck disable=SC1090
for lib in common lock redact events command lease resources report artifacts contracts budgets; do source "$ROOT/tests/live/lib/$lib.sh"; done
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
passes=0
ok() { "$@"; passes=$((passes+1)); }
reject() { if "$@" >/dev/null 2>&1; then echo "expected rejection: $*" >&2; exit 1; else passes=$((passes+1)); fi; }

lock_mutant="$tmp/callback-failure"
reject live_with_lock "$lock_mutant" false
[[ ! -e "$lock_mutant.lock" ]] || { echo 'failing callback stranded lock' >&2; exit 1; }
ok live_with_lock "$lock_mutant" true

live_init_run "$tmp/runs" >/dev/null
contract="$LIVE_RUN_ROOT/surface-contract.json"
printf '%s\n' '{"version":1,"entries":[{"id":"selftest.foundation","kind":"selftest","profiles":["smoke"],"required_cases":["semantic-positive","validation-negative","authorization"]}]}' >"$contract"
live_manifest_seal "$contract"; live_contract_consume "$contract"
live_run_manifest_write smoke daemon:test local "$contract"
live_budget_start
ok live_validate_run_id "$LIVE_RUN_ID"
[[ "$(live_file_mode "$LIVE_RUN_ROOT")" == 700 ]]
tree_pid_file="$tmp/timeout-tree.pid"
tree_status=0
live_timeout_process_tree 1 sh -c 'sleep 300 & echo $! >"$1"; wait' _ "$tree_pid_file" || tree_status=$?
ok test "$tree_status" -eq 124
tree_child="$(cat "$tree_pid_file")"
reject kill -0 "$tree_child"
# Sealed run/target/capability manifests detect any mutation.
cp "$LIVE_RUN_ROOT/target-manifest.json" "$tmp/target.good"
chmod 600 "$LIVE_RUN_ROOT/target-manifest.json"; printf 'tamper\n' >>"$LIVE_RUN_ROOT/target-manifest.json"
reject live_run_manifest_verify
cp "$tmp/target.good" "$LIVE_RUN_ROOT/target-manifest.json"; chmod 400 "$LIVE_RUN_ROOT/target-manifest.json"
ok live_run_manifest_verify
secret='token-value-never-persist'; live_register_secret "$secret"
live_event sample "$(jq -cn --arg token "$secret" '{token:$token}')"
reject grep -F "$secret" "$(live_event_file)"
reject live_require_tools cortex-live-tool-that-does-not-exist
reject live_resource_transition secret-bearing file PLANNED "daemon:$secret" '' '[]'

# Concurrent appenders must retain every complete JSON object.
for n in 1 2 3 4; do (for i in $(seq 1 25); do live_event concurrent "$(jq -cn --argjson n "$n" --argjson i "$i" '{worker:$n,item:$i}')"; done) & done
wait
[[ "$(jq -s '[.[]|select(.kind=="concurrent")]|length' "$(live_event_file)")" == 100 ]]

provider='daemon:test'; marker="$tmp/deleted"; touch "$marker"
argv="$(jq -cn --arg p "$marker" '["rm","-f",$p]')"
verify="$(jq -cn --arg p "$marker" '["sh","-c","test ! -e \"$1\"","_",$p]')"
live_resource_transition one file PLANNED "$provider" '' '[]'
reject live_resource_transition one file CREATED "$provider" "$marker" "$argv"
live_resource_transition one file CREATING "$provider" intent-one '[]' digest '{}' '[]'
live_resource_transition one file IDENTIFIED "$provider" "$marker" "$argv" digest '{}' "$verify"
live_resource_transition one file CREATED "$provider" "$marker" "$argv" digest '{}' "$verify"
ok live_cleanup_resources "$provider" 5
[[ ! -e "$marker" && "$(jq -r .state "$LIVE_RUN_ROOT/cleanup-audit.json")" == CLEAN ]]
ok live_cleanup_resources "$provider" 5

# Concurrent registration remains valid and cleanup follows reverse creation order.
order_file="$tmp/cleanup-order"
for n in 1 2 3 4; do
  concurrent_marker="$tmp/concurrent-$n"; touch "$concurrent_marker"
  concurrent_cleanup="$(jq -cn --arg p "$concurrent_marker" --arg order "$order_file" '["sh","-c","printf \"%s\\n\" \"$1\" >>\"$2\"; rm -f \"$1\"","_",$p,$order]')"
  concurrent_verify="$(jq -cn --arg p "$concurrent_marker" '["sh","-c","test ! -e \"$1\"","_",$p]')"
  (live_resource_transition "concurrent-$n" file PLANNED "$provider" '' '[]'; live_resource_transition "concurrent-$n" file CREATING "$provider" "intent-concurrent-$n" '[]' "digest-$n" '{}' '[]'; live_resource_transition "concurrent-$n" file IDENTIFIED "$provider" "$concurrent_marker" "$concurrent_cleanup" "digest-$n" '{}' "$concurrent_verify"; live_resource_transition "concurrent-$n" file CREATED "$provider" "$concurrent_marker" "$concurrent_cleanup" "digest-$n" '{}' "$concurrent_verify") &
done
wait
jq -e -n 'reduce inputs as $row ({}; .[$row.key]=$row.state) | length >= 5' "$(live_resource_file)" >/dev/null
created_order="$(jq -r 'select(.state=="CREATED" and (.key|startswith("concurrent-")))|.canonical_id' "$(live_resource_file)" | awk '{line[NR]=$0} END {for (n=NR;n>0;n--) print line[n]}')"
live_cleanup_resources "$provider" 5

# Failed cleanup is retryable from CLEANING without losing the original identity.
retry_marker="$tmp/retry"; retry_flag="$tmp/retry-flag"; touch "$retry_marker"
retry_cleanup="$(jq -cn --arg p "$retry_marker" --arg flag "$retry_flag" '["sh","-c","if test ! -e \"$2\"; then touch \"$2\"; exit 1; fi; rm -f \"$1\"","_",$p,$flag]')"
retry_verify="$(jq -cn --arg p "$retry_marker" '["sh","-c","test ! -e \"$1\"","_",$p]')"
live_resource_transition retry file PLANNED "$provider" '' '[]'; live_resource_transition retry file CREATING "$provider" intent-retry '[]' digest-retry '{}' '[]'; live_resource_transition retry file IDENTIFIED "$provider" "$retry_marker" "$retry_cleanup" digest-retry '{}' "$retry_verify"; live_resource_transition retry file CREATED "$provider" "$retry_marker" "$retry_cleanup" digest-retry '{}' "$retry_verify"
reject live_cleanup_resources "$provider" 5; [[ -e "$retry_marker" ]]
live_cleanup_resources "$provider" 5; [[ ! -e "$retry_marker" ]]
[[ "$(cat "$order_file")" == "$created_order" ]]

# Resume/retry every crash boundary, including uncertain CREATING ownership.
crash_marker="$tmp/requested-crash"; touch "$crash_marker"
crash_cleanup="$(jq -cn --arg p "$crash_marker" '["rm","-f",$p]')"; crash_verify="$(jq -cn --arg p "$crash_marker" '["sh","-c","test ! -e \"$1\"","_",$p]')"
live_resource_transition crash-planned file PLANNED "$provider" '' '[]'
live_resource_transition crash-creating file PLANNED "$provider" '' '[]'
live_resource_transition crash-creating file CREATING "$provider" requested-crash '[]' digest-crash '{}' '[]'
reject live_cleanup_resources "$provider" 5
[[ -e "$crash_marker" && "$(jq -r .state "$LIVE_RUN_ROOT/cleanup-audit.json")" == MANUAL_RECONCILIATION_REQUIRED ]]
reject live_resource_transition crash-creating file CLEANING "$provider" "$crash_marker" "$crash_cleanup" digest-crash '{}' "$crash_verify"
[[ -e "$crash_marker" ]]
live_resource_transition crash-creating file IDENTIFIED "$provider" "$crash_marker" "$crash_cleanup" digest-crash '{}' "$crash_verify"
live_cleanup_resources "$provider" 5; [[ ! -e "$crash_marker" ]]
# Provider-assigned identity may replace a feasible creation intent before CREATED.
resolved_marker="$tmp/provider-assigned-id"; touch "$resolved_marker"
resolved_cleanup="$(jq -cn --arg p "$resolved_marker" '["rm","-f",$p]')"; resolved_verify="$(jq -cn --arg p "$resolved_marker" '["sh","-c","test ! -e \"$1\"","_",$p]')"
live_resource_transition provider-id file PLANNED "$provider" '' '[]'
live_resource_transition provider-id file CREATING "$provider" requested-name '[]' intent-digest '{}' '[]'
live_resource_transition provider-id file IDENTIFIED "$provider" "$resolved_marker" "$resolved_cleanup" resolved-digest '{}' "$resolved_verify"
live_resource_transition provider-id file CREATED "$provider" "$resolved_marker" "$resolved_cleanup" resolved-digest '{}' "$resolved_verify"
live_cleanup_resources "$provider" 5; [[ ! -e "$resolved_marker" ]]
touch "$crash_marker"
live_resource_transition crash-cleaning file PLANNED "$provider" '' '[]'; live_resource_transition crash-cleaning file CREATING "$provider" intent-cleaning '[]' digest-cleaning '{}' '[]'; live_resource_transition crash-cleaning file IDENTIFIED "$provider" "$crash_marker" "$crash_cleanup" digest-cleaning '{}' "$crash_verify"; live_resource_transition crash-cleaning file CREATED "$provider" "$crash_marker" "$crash_cleanup" digest-cleaning '{}' "$crash_verify"; live_resource_transition crash-cleaning file CLEANING "$provider" "$crash_marker" "$crash_cleanup" digest-cleaning '{}' "$crash_verify"
live_cleanup_resources "$provider" 5; [[ ! -e "$crash_marker" ]]
touch "$crash_marker"; live_resource_transition crash-removed file PLANNED "$provider" '' '[]'; live_resource_transition crash-removed file CREATING "$provider" intent-removed '[]' digest-removed '{}' '[]'; live_resource_transition crash-removed file IDENTIFIED "$provider" "$crash_marker" "$crash_cleanup" digest-removed '{}' "$crash_verify"; live_resource_transition crash-removed file CREATED "$provider" "$crash_marker" "$crash_cleanup" digest-removed '{}' "$crash_verify"; live_resource_transition crash-removed file CLEANING "$provider" "$crash_marker" "$crash_cleanup" digest-removed '{}' "$crash_verify"; rm -f "$crash_marker"; live_resource_transition crash-removed file REMOVED "$provider" "$crash_marker" "$crash_cleanup" digest-removed '{}' "$crash_verify"
live_cleanup_resources "$provider" 5

# Wrong provider and corrupt/symlink manifests fail closed.
touch "$marker"; live_resource_transition two file PLANNED "$provider" '' '[]' '' '{}' '[]' one; live_resource_transition two file CREATING "$provider" intent-two '[]' digest-two '{}' '[]' one; live_resource_transition two file IDENTIFIED "$provider" "$marker" "$argv" digest-two '{}' "$verify" one; live_resource_transition two file CREATED "$provider" "$marker" "$argv" digest-two '{}' "$verify" one
jq -e --arg run "$LIVE_RUN_ID" 'select(.key=="two" and .parent_key=="one" and .labels["cortex.live.run_id"]==$run and .labels["cortex.live.provider"]=="daemon:test")' "$(live_resource_file)" >/dev/null
reject live_cleanup_resources daemon:other 5
[[ -e "$marker" ]]
cp "$(live_resource_file)" "$tmp/good.jsonl"; printf '{bad' >>"$(live_resource_file)"
reject live_cleanup_resources "$provider" 5
cp "$tmp/good.jsonl" "$(live_resource_file)"
cp "$(live_resource_file)" "$tmp/semantic-good.jsonl"
jq -cn --arg run "$LIVE_RUN_ID" '{run_id:$run,key:"valid-json-corruption",kind:"file",state:"BOGUS",provider:"daemon:test",canonical_id:"x",digest:"x",parent_key:null,labels:{"cortex.live.run_id":$run,"cortex.live.provider":"daemon:test"},at:"2026-08-27T00:00:00Z",cleanup_argv:["true","x"],verify_argv:["true","x"]}' >>"$(live_resource_file)"
reject live_cleanup_resources "$provider" 5
[[ "$(jq -r .state "$LIVE_RUN_ROOT/cleanup-audit.json")" == MANUAL_RECONCILIATION_REQUIRED ]]
cp "$tmp/semantic-good.jsonl" "$(live_resource_file)"; chmod 600 "$(live_resource_file)"
mv "$(live_resource_file)" "$tmp/manifest"; ln -s "$tmp/manifest" "$(live_resource_file)"
reject live_cleanup_resources "$provider" 5
rm "$(live_resource_file)"; cp "$tmp/manifest" "$(live_resource_file)"; chmod 600 "$(live_resource_file)"

# Expired janitor reconciles exact identities; active lease does not.
live_lease_write 1; sleep 2; live_janitor "$tmp/runs" "$provider"; [[ ! -e "$marker" ]]
live_lease_write 60
touch "$marker"
live_resource_transition active file PLANNED "$provider" '' '[]'
live_resource_transition active file CREATING "$provider" intent-active '[]' digest-active '{}' '[]'
live_resource_transition active file IDENTIFIED "$provider" "$marker" "$argv" digest-active '{}' "$verify"
live_resource_transition active file CREATED "$provider" "$marker" "$argv" digest-active '{}' "$verify"
live_janitor "$tmp/runs" "$provider"; [[ -e "$marker" ]]
live_cleanup_resources "$provider" 5; [[ ! -e "$marker" ]]

# A successful remover is not enough: independent absence verification is mandatory.
touch "$marker"
bad_verify="$(jq -cn --arg p "$marker" '["sh","-c","test -e \"$1\"","_",$p]')"
live_resource_transition three file PLANNED "$provider" '' '[]'
live_resource_transition three file CREATING "$provider" intent-three '[]' digest-three '{}' '[]'
live_resource_transition three file IDENTIFIED "$provider" "$marker" "$argv" digest-three '{}' "$bad_verify"
live_resource_transition three file CREATED "$provider" "$marker" "$argv" digest-three '{}' "$bad_verify"
reject live_cleanup_resources "$provider" 5
[[ "$(jq -r .state "$LIVE_RUN_ROOT/cleanup-audit.json")" == RESIDUE ]]

# Bounded command redacts before persistence and classifies timeout.
live_run_bounded 2 "$LIVE_RUN_ROOT/artifacts/out" "$LIVE_RUN_ROOT/artifacts/err" sh -c "printf '%s' '$secret'"
reject grep -F "$secret" "$LIVE_RUN_ROOT/artifacts/out"
set +e
live_run_bounded 1 "$LIVE_RUN_ROOT/artifacts/slow.out" "$LIVE_RUN_ROOT/artifacts/slow.err" sleep 3; timed_status=$?
set -e
[[ "$timed_status" == 124 ]]
grandchild_pid_file="$LIVE_RUN_ROOT/artifacts/grandchild.pid"
set +e
live_run_bounded 1 "$LIVE_RUN_ROOT/artifacts/tree.out" "$LIVE_RUN_ROOT/artifacts/tree.err" \
  bash -c 'bash -c '\''trap "" TERM; echo "$BASHPID" >"$1"; while :; do sleep 1; done'\'' _ "$1" & wait' _ "$grandchild_pid_file"
tree_status=$?
set -e
[[ "$tree_status" == 124 ]]
grandchild_pid="$(cat "$grandchild_pid_file")"
if kill -0 "$grandchild_pid" 2>/dev/null; then
  echo 'bounded command left a TERM-ignoring grandchild alive' >&2
  exit 1
fi
# Expanded by the intentionally isolated child shell.
# shellcheck disable=SC2016
ok live_run_bounded 2 "$LIVE_RUN_ROOT/artifacts/env.out" "$LIVE_RUN_ROOT/artifacts/env.err" sh -c 'test -z "${CORTEX_TOKEN:-}" && test "$HOME" = "$LIVE_RUN_ROOT/home" && test -d "$TMPDIR"'
ok live_secret_scan "$LIVE_RUN_ROOT/artifacts"
printf '%s' "$secret" | live_artifact_write nested/redacted.txt 1024
reject grep -F "$secret" "$LIVE_RUN_ROOT/artifacts/nested/redacted.txt"
reject live_artifact_write forbidden.db 1024 </dev/null
reject live_artifact_write huge.txt 2 <<<long
[[ ! -e "$LIVE_RUN_ROOT/artifacts/forbidden.db" && ! -e "$LIVE_RUN_ROOT/artifacts/huge.txt" ]]
printf original | live_artifact_write atomic.txt 1024
reject live_artifact_write atomic.txt 2 <<<replacement-too-large
[[ "$(cat "$LIVE_RUN_ROOT/artifacts/atomic.txt")" == original ]]

# Mandatory cases cannot green on a qualification/skip disposition.
skip_contract="$tmp/skip-contract.json"
printf '%s\n' '{"version":1,"entries":[{"id":"selftest.skip","kind":"selftest","profiles":["skip"],"required_cases":["semantic-positive"]}]}' >"$skip_contract"
live_manifest_seal "$skip_contract"; live_contract_consume "$skip_contract"
live_result selftest.skip mandatory_skip platform-qualified 0 '' semantic-positive
reject live_ledger_validate "$skip_contract" skip

# Diagnostic retries are recorded but never overwrite the first-attempt result.
live_contract_consume "$contract"
live_result selftest.foundation foundation fail 10 artifacts/err semantic-positive first_attempt 0
live_result selftest.foundation foundation_retry pass 5 artifacts/out semantic-positive diagnostic_retry 1
live_result selftest.foundation validation pass 2 artifacts/out validation-negative first_attempt 0
live_result selftest.foundation authorization pass 2 artifacts/out authorization first_attempt 0
reject live_result selftest.foundation duplicate pass 1 artifacts/out authorization first_attempt 0
reject live_result unknown.surface unknown pass 1 artifacts/out semantic-positive first_attempt 0
reject live_result selftest.foundation missing_evidence pass 1 artifacts/missing semantic-positive diagnostic_retry 2
live_report >/dev/null
jq -e '.total==4 and .passed==2 and .failed==1 and .qualified==1 and .retries==1' "$LIVE_RUN_ROOT/summary.json" >/dev/null
grep -q '<failure message="scenario failed"' "$LIVE_RUN_ROOT/junit.xml"
grep -q '<skipped message="platform-qualified"' "$LIVE_RUN_ROOT/junit.xml"
ok live_ledger_validate "$contract" smoke
live_budget_observe cpu_seconds 1; live_budget_observe rss_bytes 1; live_fixture_account 1 1; live_budget_observe poll_attempts 1; live_connection_opened 1; live_budget_observe processes 1
for metric in wall_seconds cpu_seconds rss_bytes disk_bytes artifact_bytes fixture_records fixture_bytes poll_attempts connections processes; do
  budget_contract="$tmp/budget-$metric.json"
  jq --arg metric "$metric" '.profiles.smoke[$metric]=0' "$ROOT/tests/live/contracts/profiles.json" >"$budget_contract"
  reject live_budget_check smoke "$budget_contract"
done
ok live_budget_check smoke "$ROOT/tests/live/contracts/profiles.json"
first_outcome="$(jq -n 'first(inputs|select(.kind=="result" and .payload.surface_id=="selftest.foundation" and .payload.case_kind=="semantic-positive" and .payload.attempt_kind=="first_attempt")|.payload.result)' "$(live_event_file)")"
[[ "$first_outcome" == '"fail"' ]]

# Concurrent runs never share IDs or roots.
a="$(live_run_id)"; b="$(live_run_id)"; [[ "$a" != "$b" ]]

# Signal path: a child trap records termination without touching this run.
sigroot="$tmp/signal"; mkdir "$sigroot"
bash -c 'trap '\''echo TERM >"$1/seen"; exit 143'\'' TERM; while :; do sleep 1; done' _ "$sigroot" & child=$!
sleep 0.2
kill -TERM "$child"; wait "$child" || true; grep -q TERM "$sigroot/seen"
bash -c 'trap '\''echo INT >"$1/seen-int"; exit 130'\'' INT; kill -INT $$' _ "$sigroot" || true
grep -q INT "$sigroot/seen-int"
grep -q 'trap live_runner_cleanup HUP INT TERM EXIT' "$ROOT/tests/live/runner.sh"
cleanup_trap_line="$(grep -n 'trap live_runner_cleanup HUP INT TERM EXIT' "$ROOT/tests/live/runner.sh" | cut -d: -f1)"
contract_export_line="$(grep -n 'live_contract_export .*surface-contract.json' "$ROOT/tests/live/runner.sh" | cut -d: -f1)"
[[ "$cleanup_trap_line" -lt "$contract_export_line" ]]

# The explicit no-op profile succeeds concurrently without weakening smoke.
noop_runs="$tmp/noop-runs"
env -u LIVE_RUN_ID -u LIVE_RUN_ROOT -u LIVE_SURFACE_CONTRACT \
  bash "$ROOT/tests/live/runner.sh" --profile noop --runs-root "$noop_runs" >"$tmp/noop-1.out" 2>"$tmp/noop-1.err" & noop_one=$!
env -u LIVE_RUN_ID -u LIVE_RUN_ROOT -u LIVE_SURFACE_CONTRACT \
  LIVE_LEGACY_RUNNER="$ROOT/tests/live/selftest/legacy-success.sh" \
  bash "$ROOT/tests/live/runner.sh" --profile noop --runs-root "$noop_runs" --legacy >"$tmp/noop-2.out" 2>"$tmp/noop-2.err" & noop_two=$!
wait "$noop_one"; wait "$noop_two"
[[ "$(find "$noop_runs" -mindepth 1 -maxdepth 1 -type d -name 'cortex-e2e-*' | wc -l | tr -d ' ')" == 2 ]]
legacy_events="$(find "$noop_runs" -name events.jsonl -type f -exec grep -l 'legacy_result' {} \;)"
[[ -n "$legacy_events" ]] && jq -e 'select(.kind=="legacy_result" and .payload.schema=="cortex-live-legacy-result-v1" and .payload.isolated_from_capability_ledger==true and .payload.result=="pass")' "$legacy_events" >/dev/null

bash "$ROOT/tests/live/phases/artifacts/selftest.sh"
bash "$ROOT/tests/live/phases/surfaces/resource-selftest.sh"
bash "$ROOT/tests/live/selftest/artifact-upload.sh"
bash "$ROOT/tests/live/lib/aggregate-selftest.sh"

printf 'live foundation self-tests: %d passed\n' "$passes"
