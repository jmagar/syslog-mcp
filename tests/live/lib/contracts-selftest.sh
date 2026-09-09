#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck disable=SC1091
source "$root/tests/live/lib/common.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/contracts.sh"
# shellcheck disable=SC1091
source "$root/tests/live/lib/events.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
valid="$tmp/valid.json"
jq -cn '{version:1,entries:[{id:"mcp.cortex.help",kind:"mcp",profiles:["smoke","full","storage","soak"],required_cases:["semantic-positive","validation-negative","authorization"]}]}' >"$valid"
live_manifest_seal "$valid"

run_case() { LIVE_RUN_ROOT="$1"; mkdir -p "$LIVE_RUN_ROOT/artifacts"; export LIVE_RUN_ROOT; }

run_case "$tmp/valid-run"
LIVE_SURFACE_CONTRACT_SOURCE="$valid" live_contract_export "$LIVE_RUN_ROOT/surface-contract.json"
live_manifest_verify "$LIVE_RUN_ROOT/surface-contract.json"
live_manifest_verify "$LIVE_RUN_ROOT/artifacts/surface-contract-provenance.json"
jq -e --arg digest "$(live_sha256 "$valid")" '.mode=="reused" and .seal_verified and .validated and .source_digest==$digest and .digest==$digest' \
  "$LIVE_RUN_ROOT/artifacts/surface-contract-provenance.json" >/dev/null

tampered="$tmp/tampered.json"; cp "$valid" "$tampered"; cp "$valid.sha256" "$tampered.sha256"; chmod 600 "$tampered" "$tampered.sha256"
printf '\n' >>"$tampered"
run_case "$tmp/tamper-run"
if LIVE_SURFACE_CONTRACT_SOURCE="$tampered" live_contract_export "$LIVE_RUN_ROOT/surface-contract.json" 2>/dev/null; then echo "tampered reuse passed" >&2; exit 1; fi

ln -s "$valid" "$tmp/link.json"; ln -s "$valid.sha256" "$tmp/link.json.sha256"
run_case "$tmp/symlink-run"
if LIVE_SURFACE_CONTRACT_SOURCE="$tmp/link.json" live_contract_export "$LIVE_RUN_ROOT/surface-contract.json" 2>/dev/null; then echo "symlink reuse passed" >&2; exit 1; fi

stale="$tmp/stale.json"; jq -cn '{version:0,entries:[]}' >"$stale"; live_manifest_seal "$stale"
run_case "$tmp/stale-run"
if LIVE_SURFACE_CONTRACT_SOURCE="$stale" live_contract_export "$LIVE_RUN_ROOT/surface-contract.json" 2>/dev/null; then echo "stale schema reuse passed" >&2; exit 1; fi

# Auth is a policy audit across every authoritative entry, independent of the
# normal execution-profile tags. Require exactly one first-attempt result per
# entry and fail closed on either a missing or duplicate outcome.
auth_contract="$tmp/auth-owned.json"
jq -cn '{version:1,entries:[range(0;22)|{id:("ingest.auth-owned-"+tostring),kind:"ingest",profiles:["auth"],required_cases:["authorization"]}]}' >"$auth_contract"
live_manifest_seal "$auth_contract"
run_case "$tmp/auth-run"; LIVE_RUN_ID=cortex-e2e-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; export LIVE_RUN_ID
: >"$LIVE_RUN_ROOT/events.jsonl"
jq -c --arg run "$LIVE_RUN_ID" '.entries[]|{run_id:$run,at:"2026-01-01T00:00:00Z",kind:"result",payload:{surface_id:.id,scenario:"auth-policy",result:"pass",duration_ms:0,evidence:"evidence.json",case_kind:"authorization",attempt_kind:"first_attempt",retry_index:0}}' "$auth_contract" >"$LIVE_RUN_ROOT/events.jsonl"
live_ledger_validate "$auth_contract" auth
[[ "$(wc -l <"$LIVE_CAPABILITY_LEDGER" | tr -d ' ')" == 22 ]]
sed '$d' "$LIVE_RUN_ROOT/events.jsonl" >"$LIVE_RUN_ROOT/events.missing"; mv "$LIVE_RUN_ROOT/events.missing" "$LIVE_RUN_ROOT/events.jsonl"
if live_ledger_validate "$auth_contract" auth 2>/dev/null; then echo "missing auth result passed" >&2; exit 1; fi
jq -c --arg run "$LIVE_RUN_ID" '.entries[]|{run_id:$run,at:"2026-01-01T00:00:00Z",kind:"result",payload:{surface_id:.id,scenario:"auth-policy",result:"pass",duration_ms:0,evidence:"evidence.json",case_kind:"authorization",attempt_kind:"first_attempt",retry_index:0}}' "$auth_contract" >"$LIVE_RUN_ROOT/events.jsonl"
head -1 "$LIVE_RUN_ROOT/events.jsonl" >>"$LIVE_RUN_ROOT/events.jsonl"
if live_ledger_validate "$auth_contract" auth 2>/dev/null; then echo "duplicate auth result passed" >&2; exit 1; fi

run_case "$tmp/stateful-run"; LIVE_RUN_ID=cortex-e2e-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; export LIVE_RUN_ID
: >"$LIVE_RUN_ROOT/events.jsonl"
for capability in analytics-boundaries restart-exactness projection-lifecycle projection-watermark graph-correlation llm-audit-exactness evaluator-idempotence dependency-recovery structured-observability failure-stage-diagnostics; do
  jq -cn --arg run "$LIVE_RUN_ID" --arg id "stateful.$capability" '{run_id:$run,at:"2026-01-01T00:00:00Z",kind:"result",payload:{surface_id:$id,scenario:"stateful",result:"pass",duration_ms:0,evidence:"evidence.json",case_kind:"semantic-positive",attempt_kind:"first_attempt",retry_index:0}}' >>"$LIVE_RUN_ROOT/events.jsonl"
done
live_ledger_validate "$auth_contract" stateful
[[ "$(wc -l <"$LIVE_CAPABILITY_LEDGER" | tr -d ' ')" == 10 ]]
sed '$d' "$LIVE_RUN_ROOT/events.jsonl" >"$LIVE_RUN_ROOT/missing"; mv "$LIVE_RUN_ROOT/missing" "$LIVE_RUN_ROOT/events.jsonl"
if live_ledger_validate "$auth_contract" stateful 2>/dev/null; then echo "missing stateful result passed" >&2; exit 1; fi

echo "contracts reuse self-test: PASS"
