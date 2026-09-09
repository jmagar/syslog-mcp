#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
contract="$here/../../contracts/docker-platforms.json"
url="${CORTEX_LIVE_DOCKER_PROXY_URL:-}"
output="${1:-/dev/stdout}"

emit() {
  jq -cn --arg platform "$(uname -s | tr '[:upper:]' '[:lower:]')" --arg disposition "$1" \
    --arg authority "$2" --arg reason "$3" \
    '{schema_version:1,platform:$platform,disposition:$disposition,authority:$authority,reason:$reason}' >"$output"
}

jq -e '.schema_version == 1 and .probe.timeout_seconds <= 5 and .probe.max_response_bytes <= 65536' "$contract" >/dev/null

if [[ -z "$url" ]]; then
  emit not-authorized none "proxy URL is not explicitly configured"
  exit 3
fi
case "$url" in
  http://127.0.0.1:*|http://localhost:*|https://127.0.0.1:*|https://localhost:*) ;;
  *) emit not-authorized none "proxy URL is not an explicit loopback target"; exit 3;;
esac

curl_args=(--silent --show-error --fail-with-body --max-time 5 --connect-timeout 2 --max-filesize 65536 --noproxy '*' --proto '=http,https')
if ! ping="$(curl "${curl_args[@]}" "$url/_ping" 2>/dev/null)"; then
  emit platform-qualified unreachable "configured read proxy is unreachable"
  exit 4
fi
if [[ "$ping" != OK ]]; then
  emit fail unknown "unexpected Docker ping response"
  exit 1
fi
if ! version="$(curl "${curl_args[@]}" "$url/version" 2>/dev/null)" || ! jq -e '.ApiVersion' <<<"$version" >/dev/null; then
  emit fail unknown "proxy did not provide a bounded daemon identity"
  exit 1
fi
if ! info="$(curl "${curl_args[@]}" "$url/info" 2>/dev/null)" || ! daemon_id="$(jq -er '.ID | select(type=="string" and length>0)' <<<"$info")"; then
  emit fail unknown "proxy did not expose a live daemon identity"
  exit 1
fi

for method in POST PUT PATCH DELETE; do
  for path in /containers/create /containers/forged/start /containers/forged/exec /build /volumes/create /plugins/pull /swarm/init '//containers/create' '/v1.47/containers/create' '/containers%2fcreate' '/containers/%2e%2e/containers/create'; do
    code="$(curl --path-as-is --silent --output /dev/null --write-out '%{http_code}' --max-time 5 --connect-timeout 2 --noproxy '*' --proto '=http,https' -X "$method" "$url$path" || true)"
    case "$code" in 401|403|404|405) ;; *) emit fail "proxy-read-only:$daemon_id" "mutation authority exposed via $method $path (HTTP $code)"; exit 1;; esac
  done
done
# Identity is derived twice from the API to detect proxy/daemon replacement mid-probe.
recheck="$(curl "${curl_args[@]}" "$url/info" 2>/dev/null | jq -er .ID)" || { emit fail unknown "daemon identity recheck failed"; exit 1; }
[[ "$recheck" == "$daemon_id" ]] || { emit fail unknown "daemon identity changed during probe"; exit 1; }
emit platform-qualified "proxy-read-only:$daemon_id" "reduced read-only proxy boundary verified"
