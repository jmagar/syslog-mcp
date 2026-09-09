#!/usr/bin/env bash
set -euo pipefail

fleet_target_digest() { shasum -a 256 "$1" | awk '{print $1}'; }

fleet_target_validate() {
  local manifest="$1" now="${2:-$(date +%s)}" observed expires
  [[ -f "$manifest" && ! -L "$manifest" ]] || { echo "unsafe target manifest" >&2; return 2; }
  jq -e '
    .schema=="cortex-live-target-v1" and
    (.profile|IN("deployed-read-only","fleet-read-only")) and
    (.base_url|test("^https://")) and
    (.resolved_ip|length>1) and (.resolved_addresses.a|type=="array") and (.resolved_addresses.aaaa|type=="array") and (.server_instance_id|length>0) and (.server_version|length>0) and
    (.deployment_id|length>0) and (.database_fingerprint|length>=8) and
    (.compose.project|length>0) and (.compose.service|length>0) and
    (.compose.container_id|test("^[A-Za-z0-9_.-]{12,128}$")) and
    (.roles.read_token=="verified" and .roles.admin_token=="verified") and (.fleet_allowlist|length>0) and (.capabilities|length>0) and
    (.observed_at|type=="string") and (.expires_at|type=="string")
  ' "$manifest" >/dev/null || { echo "invalid target manifest" >&2; return 2; }
  observed="$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$(jq -r .observed_at "$manifest")" +%s 2>/dev/null || date -d "$(jq -r .observed_at "$manifest")" +%s)" || return 2
  expires="$(date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$(jq -r .expires_at "$manifest")" +%s 2>/dev/null || date -d "$(jq -r .expires_at "$manifest")" +%s)" || return 2
  (( observed <= now && now < expires && expires - observed <= 900 )) || { echo "stale or over-broad target observation" >&2; return 2; }
  [[ -z "${http_proxy:-}${https_proxy:-}${HTTP_PROXY:-}${HTTPS_PROXY:-}${ALL_PROXY:-}${all_proxy:-}" ]] || { echo "proxy environment forbidden" >&2; return 2; }
}

fleet_target_snapshot() {
  local manifest="$1" token="$2" output="$3" phase="$4" version stats compose_file db_file deployment_file observed
  version="$(fleet_curl "$manifest" /api/version -H "Authorization: Bearer $token")" || return
  stats="$(fleet_curl "$manifest" /api/stats -H "Authorization: Bearer $token")" || return
  jq -e --argjson m "$(jq -c . "$manifest")" '
    .version==$m.server_version and (.schema_version|type=="number") and
    .instance_id==$m.server_instance_id and .deployment_id==$m.deployment_id and
    .database_fingerprint==$m.database_fingerprint and .compose_project==$m.compose.project and
    .compose_service==$m.compose.service and .compose_container==$m.compose.container_id and
    .fleet_allowlist==$m.fleet_allowlist and .capabilities==$m.capabilities
  ' <<<"$version" >/dev/null || { echo "actual /api/version identity/capability mismatch" >&2; return 3; }
  compose_file="$(jq -r .evidence.compose "$manifest")"; db_file="$(jq -r .evidence.database "$manifest")"; deployment_file="$(jq -r .evidence.deployment "$manifest")"
  for evidence in "$compose_file" "$db_file" "$deployment_file"; do [[ -f "$evidence" && ! -L "$evidence" ]] || { echo "missing independent evidence source" >&2; return 3; }; done
  observed="$(jq -n --argjson version "$version" --argjson stats "$stats" --slurpfile compose "$compose_file" --slurpfile database "$db_file" --slurpfile deployment "$deployment_file" '{version:$version,stats:$stats,compose:$compose[0],database:$database[0],deployment:$deployment[0]}')"
  jq -e --argjson m "$(jq -c . "$manifest")" '.compose==$m.compose and .database.fingerprint==$m.database_fingerprint and .deployment.id==$m.deployment_id' <<<"$observed" >/dev/null || { echo "independent Compose/DB/deployment evidence mismatch" >&2; return 3; }
  jq -n --arg phase "$phase" --arg digest "$(fleet_target_digest "$manifest")" --argjson observed "$observed" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{schema:"cortex-live-target-snapshot-v1",phase:$phase,target_digest:$digest,observed:$observed,at:$at}' >"$output"
}

fleet_snapshot_assert_allowed_diff() {
  local pre="$1" post="$2"
  [[ "$(jq -cS '.observed|{version,compose,database,deployment}' "$pre")" == "$(jq -cS '.observed|{version,compose,database,deployment}' "$post")" ]] || {
    echo "post-run target identity changed" >&2; return 4;
  }
}

fleet_roles_assert() {
  local manifest="$1" read_token="$2" admin_token="$3"
  fleet_curl "$manifest" /api/stats -H "Authorization: Bearer $read_token" >/dev/null || { echo "read role denied read endpoint" >&2; return 3; }
  fleet_curl "$manifest" /api/sessions/llm-invocations -H "Authorization: Bearer $read_token" -H "x-cortex-admin-token: $admin_token" >/dev/null || { echo "admin role denied admin endpoint" >&2; return 3; }
  if fleet_curl "$manifest" /api/sessions/llm-invocations -H "Authorization: Bearer $read_token" >/dev/null 2>&1; then echo "read role unexpectedly reached admin endpoint" >&2; return 3; fi
}

fleet_target_revalidate() {
  local expected="$1" observed="$2"
  fleet_target_validate "$expected" && fleet_target_validate "$observed" || return
  [[ "$(fleet_target_digest "$expected")" == "$(fleet_target_digest "$observed")" ]] || {
    echo "target identity changed; mutation refused" >&2; return 3;
  }
}

fleet_curl() {
  local manifest="$1" path="$2"; shift 2
  fleet_target_validate "$manifest" || return
  local url host port ip spki resolve=()
  url="$(jq -r .base_url "$manifest")$path"; host="$(jq -r '.base_url|sub("^https://";"")|split(":")[0]' "$manifest")"; port="$(jq -r '.base_url|sub("^https://";"")|split(":")[1] // "443"' "$manifest")"; ip="$(jq -r .resolved_ip "$manifest")"
  [[ "$url" != *$'\n'* && "$path" == /* ]] || return 2
  resolve=(--resolve "$host:$port:$ip")
  spki="$(jq -r '.tls_spki_sha256 // empty' "$manifest")"
  [[ -z "$spki" ]] || resolve+=(--pinnedpubkey "sha256//$spki")
  env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u all_proxy \
    curl --fail-with-body --silent --show-error --max-time 10 --proto '=https' --tlsv1.2 --max-redirs 0 "${resolve[@]}" "$@" "$url"
}
