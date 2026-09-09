#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
contract="$tmp/contract.json"
jq -cn '{version:1,entries:[
  {id:"ingest.logs",profiles:["isolated"],required_cases:["semantic-positive","validation-negative"]},
  {id:"auth.token",profiles:["auth"],required_cases:["semantic-positive"]}
]}' >"$contract"

make_run() {
  local profile="$1" dir
  dir="$tmp/$profile"; mkdir -p "$dir"
  jq -cn --arg p "$profile" '{kind:"run_started",payload:{profile:$p}}' >"$dir/events.jsonl"
  cp "$contract" "$dir/surface-contract.json"
  jq -cn '{failed:0,platform:{accepted:true}}' >"$dir/summary.json"
  jq -cn '{state:"CLEAN"}' >"$dir/cleanup-audit.json"
}
make_run isolated; make_run auth
for spec in 'isolated ingest.logs semantic-positive' 'isolated ingest.logs validation-negative' 'auth auth.token semantic-positive'; do
  read -r profile id kind <<<"$spec"
  jq -cn --arg id "$id" --arg kind "$kind" '{kind:"result",payload:{surface_id:$id,case_kind:$kind,result:"pass",attempt_kind:"first_attempt",duration_ms:0,retry_index:0}}' >>"$tmp/$profile/events.jsonl"
done
LIVE_AGGREGATE_OUTPUT="$tmp/pass.json" "$root/tests/live/aggregate.sh" "$contract" "$tmp/isolated" "$tmp/auth" >/dev/null
jq -e '.green and .surface_count==2 and .required_case_count==3 and .accounted_count==3' "$tmp/pass.json" >/dev/null
cp -R "$tmp/isolated" "$tmp/isolated-good"
cp -R "$tmp/auth" "$tmp/auth-good"

cp -R "$tmp/isolated-good" "$tmp/stale"
jq '.entries[0].id="ingest.stale"' "$contract" >"$tmp/stale/surface-contract.json"
if LIVE_AGGREGATE_OUTPUT="$tmp/stale.json" "$root/tests/live/aggregate.sh" "$contract" "$tmp/stale" "$tmp/auth-good" >/dev/null 2>&1; then
  echo "aggregate stale-contract mutant passed" >&2; exit 1
fi

cp -R "$tmp/isolated-good" "$tmp/residue"
jq '.state="RESIDUE"' "$tmp/residue/cleanup-audit.json" >"$tmp/residue/cleanup.tmp"
mv "$tmp/residue/cleanup.tmp" "$tmp/residue/cleanup-audit.json"
if LIVE_AGGREGATE_OUTPUT="$tmp/residue.json" "$root/tests/live/aggregate.sh" "$contract" "$tmp/residue" "$tmp/auth-good" >/dev/null 2>&1; then
  echo "aggregate cleanup-residue mutant passed" >&2; exit 1
fi

if LIVE_AGGREGATE_OUTPUT="$tmp/profile-duplicate.json" "$root/tests/live/aggregate.sh" "$contract" "$tmp/isolated-good" "$tmp/isolated-good" "$tmp/auth-good" >/dev/null 2>&1; then
  echo "aggregate duplicate-owner-run mutant passed" >&2; exit 1
fi

sed '$d' "$tmp/isolated/events.jsonl" >"$tmp/isolated/missing"; mv "$tmp/isolated/missing" "$tmp/isolated/events.jsonl"
if LIVE_AGGREGATE_OUTPUT="$tmp/missing.json" "$root/tests/live/aggregate.sh" "$contract" "$tmp/isolated" "$tmp/auth" >/dev/null 2>&1; then
  echo "aggregate missing mutant passed" >&2; exit 1
fi
jq -cn '{kind:"result",payload:{surface_id:"ingest.logs",case_kind:"validation-negative",result:"pass",attempt_kind:"first_attempt",duration_ms:0,retry_index:0}}' >>"$tmp/isolated/events.jsonl"
tail -1 "$tmp/isolated/events.jsonl" >>"$tmp/isolated/events.jsonl"
if LIVE_AGGREGATE_OUTPUT="$tmp/duplicate.json" "$root/tests/live/aggregate.sh" "$contract" "$tmp/isolated" "$tmp/auth" >/dev/null 2>&1; then
  echo "aggregate duplicate mutant passed" >&2; exit 1
fi
echo "aggregate qualification self-test: PASS"
