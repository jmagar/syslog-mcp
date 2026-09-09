#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
# shellcheck source=target.sh
source "$root/tests/live/profiles/fleet/target.sh"
# shellcheck source=grant.sh
source "$root/tests/live/profiles/fleet/grant.sh"
# shellcheck source=mutations.sh
source "$root/tests/live/profiles/fleet/mutations.sh"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/cortex-fleet-test.XXXXXX")"; server_pid=""; trap '[[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
now="$(date +%s)"; observed="$(date -u -r "$now" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$now" +%Y-%m-%dT%H:%M:%SZ)"; expires_epoch=$((now+120)); expires="$(date -u -r "$expires_epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$expires_epoch" +%Y-%m-%dT%H:%M:%SZ)"
port="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=cortex.invalid' -addext 'subjectAltName=DNS:cortex.invalid' -keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
spki="$(openssl x509 -in "$tmp/cert.pem" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)"
mkdir -p "$tmp/api"
printf '{"version":"1.0.0","schema_version":1,"instance_id":"instance-1","deployment_id":"deploy-1","database_fingerprint":"db-sha256","compose_project":"cortex","compose_service":"cortex","compose_container":"0123456789abcdef","fleet_allowlist":["fixture"],"capabilities":["read"]}\n' >"$tmp/api/version"
printf '{"total_logs":0}\n' >"$tmp/api/stats"
printf '{"project":"cortex","service":"cortex","container_id":"0123456789abcdef"}\n' >"$tmp/compose-evidence.json"
printf '{"fingerprint":"db-sha256"}\n' >"$tmp/db-evidence.json"
printf '{"id":"deploy-1"}\n' >"$tmp/deploy-evidence.json"
(cd "$tmp" && openssl s_server -quiet -4 -accept "$port" -cert cert.pem -key key.pem -WWW) >/dev/null 2>&1 & server_pid=$!
sleep .2
export CURL_CA_BUNDLE="$tmp/cert.pem"
export LIVE_RUN_ID=cortex-e2e-fleet-selftest
jq -n --arg o "$observed" --arg e "$expires" --arg url "https://cortex.invalid:$port" --arg spki "$spki" --arg c "$tmp/compose-evidence.json" --arg d "$tmp/db-evidence.json" --arg p "$tmp/deploy-evidence.json" '{schema:"cortex-live-target-v1",target_id:"fixture",profile:"fleet-read-only",base_url:$url,resolved_ip:"127.0.0.1",resolved_addresses:{a:["127.0.0.1"],aaaa:["::1"]},tls_spki_sha256:$spki,server_instance_id:"instance-1",server_version:"1.0.0",deployment_id:"deploy-1",database_fingerprint:"db-sha256",compose:{project:"cortex",service:"cortex",container_id:"0123456789abcdef"},evidence:{compose:$c,database:$d,deployment:$p},roles:{read_token:"verified",admin_token:"verified"},fleet_allowlist:["fixture"],capabilities:["read"],observed_at:$o,expires_at:$e}' >"$tmp/target.json"
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy bash -c 'source "$1"; fleet_target_validate "$2" "$3"' _ "$root/tests/live/profiles/fleet/target.sh" "$tmp/target.json" "$now"
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy bash -c 'source "$1"; fleet_target_snapshot "$2" read-token "$3" pre' _ "$root/tests/live/profiles/fleet/target.sh" "$tmp/target.json" "$tmp/pre.json"
digest="$(fleet_target_digest "$tmp/target.json")"; key="$(openssl rand -hex 32)"
jq -n --arg d "$digest" --argjson e "$expires_epoch" --arg run "$LIVE_RUN_ID" --slurpfile t "$tmp/target.json" '{schema:"cortex-live-mutation-grant-v1",run_id:$run,target_digest:$d,identity:{base_url:$t[0].base_url,resolved_ip:$t[0].resolved_ip,tls_spki_sha256:$t[0].tls_spki_sha256,server_instance_id:$t[0].server_instance_id,server_version:$t[0].server_version,deployment_id:$t[0].deployment_id,database_fingerprint:$t[0].database_fingerprint,compose_project:$t[0].compose.project,compose_service:$t[0].compose.service,compose_container_id:$t[0].compose.container_id},operations:["ingest-low-tagged"],nonce:"fixture-nonce-123456",max_mutations:1,expires_epoch:$e,signature:""}' >"$tmp/grant.json"
fleet_grant_sign "$tmp/grant.json" "$key"
fleet_grant_validate "$tmp/grant.json" "$digest" ingest-low-tagged "$key" "$tmp/ledger" "$now"
reservation="$(fleet_grant_reserve "$tmp/grant.json" "$digest" ingest-low-tagged "$key" "$tmp/ledger" "$now")"
fleet_grant_finalize "$tmp/ledger" "$reservation" FAILED simulated-remote-failure
! fleet_grant_validate "$tmp/grant.json" "$digest" ingest-low-tagged "$key" "$tmp/ledger" "$now"
jq '.deployment_id="changed"' "$tmp/target.json" >"$tmp/changed.json"
! env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy bash -c 'source "$1"; fleet_target_revalidate "$2" "$3"' _ "$root/tests/live/profiles/fleet/target.sh" "$tmp/target.json" "$tmp/changed.json"
for operation in ingest-low-tagged heartbeat-tagged notification-test admin-audit restart file-tail agent-deploy; do fleet_operation_allowed "$operation"; done
for operation in admin pressure; do ! fleet_operation_allowed "$operation"; done
! fleet_operation_allowed target-only
! fleet_grant_validate "$tmp/grant.json" wrong-target ingest-low-tagged "$key" "$tmp/other-ledger" "$now"
! fleet_grant_validate "$tmp/grant.json" "$digest" ingest-low-tagged "$key" "$tmp/other-ledger" "$expires_epoch"
fleet_residual_report "$tmp/residual.json" "$LIVE_RUN_ID" 1 0
jq -e '.append_only_residual==true and .residual_resources==0' "$tmp/residual.json" >/dev/null
fleet_residual_report "$tmp/partial-cleanup.json" "$LIVE_RUN_ID" 1 1
jq -e '.green==false and .residual_resources==1' "$tmp/partial-cleanup.json" >/dev/null
! fleet_cas_rollback suite-written operator-changed '["true"]' "$tmp/cas-audit.json"
jq -e '.status=="MANUAL_RECONCILIATION_REQUIRED"' "$tmp/cas-audit.json" >/dev/null
jq --arg url 'https://cortex.invalid:1' '.base_url=$url' "$tmp/target.json" >"$tmp/unavailable.json"
! env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy bash -c 'source "$1"; fleet_target_snapshot "$2" read "$3" unavailable' _ "$root/tests/live/profiles/fleet/target.sh" "$tmp/unavailable.json" "$tmp/unavailable-snapshot.json"
# Two racers against a max-use=1 grant: the locked validate+consume transaction
# must admit exactly one.
race_ledger="$tmp/race.jsonl"; (fleet_grant_reserve "$tmp/grant.json" "$digest" ingest-low-tagged "$key" "$race_ledger" "$now" >/dev/null && echo pass >"$tmp/r1") & p1=$!; (fleet_grant_reserve "$tmp/grant.json" "$digest" ingest-low-tagged "$key" "$race_ledger" "$now" >/dev/null && echo pass >"$tmp/r2") & p2=$!; wait "$p1" || true; wait "$p2" || true
[[ "$(find "$tmp" -name 'r[12]' | wc -l | tr -d ' ')" == 1 ]]
echo "fleet target/grant selftest: PASS"
