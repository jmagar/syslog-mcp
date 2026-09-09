#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
jq -e '.profiles.auth.mandatory and .profiles.auth.wall_seconds<=1500' "$root/tests/live/contracts/profiles.json" >/dev/null
grep -q 'auth_policy_ledger' "$root/tests/live/phases/auth/run.sh"
grep -q 'CORTEX_AUTH_DISABLE_STATIC_TOKEN_WITH_OAUTH' "$root/tests/live/profiles/auth/compose.oauth.yaml"
! rg -n '(secret|token):[[:space:]]+[A-Za-z0-9]{20,}' "$root/tests/live/profiles/auth" "$root/tests/live/phases/auth"
exported="$(mktemp)"; trap 'rm -f "$exported"' EXIT
cargo run --quiet --manifest-path "$root/tests/live/surface-exporter/Cargo.toml" >"$exported"
jq -e '[.entries[]|select(.profiles|index("auth")) as $e|$e.required_cases[]|[$e.id,.]]|length==22' "$exported" >/dev/null
grep -F 'spelling%% *' "$root/tests/live/phases/auth/run.sh" >/dev/null
grep -F 'auth semantic route was not reached' "$root/tests/live/phases/auth/run.sh" >/dev/null
grep -F 'authorization_code_redeemed:true' "$root/tests/live/phases/auth/run.sh" >/dev/null
grep -F 'executed-refusal-semantic' "$root/tests/live/phases/auth/run.sh" >/dev/null
grep -F 'provider_egress_attempted:false' "$root/tests/live/phases/auth/run.sh" >/dev/null
grep -F 'AuthorizationCodeRow' "$root/tests/live/services/oauth/src/main.rs" >/dev/null
echo 'auth selftest: PASS'
