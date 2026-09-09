#!/usr/bin/env bash
set -euo pipefail

image_ref=${1:?usage: container-release-smoke.sh IMAGE_REF}
container="cortex-release-smoke-${GITHUB_RUN_ID:-local}-$$"
marker="releasesmoke${GITHUB_RUN_ID:-local}$$"
cleanup() {
  if docker rm -f "$container" >/dev/null 2>&1; then
    return 0
  fi
  inspect_error="$(mktemp)"
  if docker inspect "$container" >/dev/null 2>"$inspect_error"; then
    rm -f "$inspect_error"
    echo "ERROR: failed to remove release-smoke container ${container}" >&2
    return 1
  fi
  if grep -Eq "No such (object|container): ${container}$" "$inspect_error"; then
    rm -f "$inspect_error"
    return 0
  fi
  cat "$inspect_error" >&2
  rm -f "$inspect_error"
  echo "ERROR: failed to remove release-smoke container ${container}" >&2
  return 1
}
trap cleanup EXIT

emit_startup_diagnostics() {
  echo "ERROR: release-smoke health check failed for ${container}" >&2
  docker inspect --format '{{json .State}}' "$container" 2>/dev/null >&2 || true
  docker logs --tail 200 "$container" 2>&1 \
    | sed -E \
      -e 's/(Bearer )[A-Za-z0-9._~+\/-]+=*/\1[REDACTED]/g' \
      -e 's/((TOKEN|KEY|SECRET|PASSWORD)=)[^[:space:]]+/\1[REDACTED]/g' \
    >&2 || true
}

docker run -d --name "$container" \
  -e CORTEX_API_TOKEN=release-smoke-api \
  -e CORTEX_TOKEN=release-smoke-mcp \
  -e CORTEX_CURSOR_SIGNING_KEY=release-smoke-cursor-signing-key \
  -e CORTEX_SERVER_ID=release-smoke \
  -e CORTEX_HOST=0.0.0.0 \
  -p 127.0.0.1::3100/tcp \
  -p 127.0.0.1::1514/tcp \
  -p 127.0.0.1::1514/udp \
  "$image_ref" >/dev/null

http_port=$(docker port "$container" 3100/tcp | sed 's/.*://')
tcp_port=$(docker port "$container" 1514/tcp | sed 's/.*://')
udp_port=$(docker port "$container" 1514/udp | sed 's/.*://')
# The image serves Cortex on port 3100. Docker's random host publication is
# only a test-harness transport detail; it must not become the HTTP Host
# authority presented to RMCP's DNS-rebinding protection.
http_host='127.0.0.1:3100'

healthy=false
for _ in $(seq 1 60); do
  if curl -fsS -H "Host: ${http_host}" "http://127.0.0.1:${http_port}/health" >/dev/null; then
    healthy=true
    break
  fi
  sleep 1
done
if [[ "$healthy" != true ]]; then
  emit_startup_diagnostics
  exit 1
fi

printf '<13>Aug 29 00:00:00 release-smoke smokeapp: %stcp\n' "$marker" | nc -w 2 127.0.0.1 "$tcp_port"
printf '<13>Aug 29 00:00:00 release-smoke smokeapp: %sudp\n' "$marker" | nc -u -w 2 127.0.0.1 "$udp_port"
response=
for _ in $(seq 1 30); do
  response=$(curl -fsS -X POST "http://127.0.0.1:${http_port}/mcp" \
    -H "Host: ${http_host}" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'Authorization: Bearer release-smoke-mcp' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"cortex\",\"arguments\":{\"action\":\"search\",\"query\":\"${marker}tcp OR ${marker}udp\",\"limit\":10}}}")
  if grep -Fq "${marker}tcp" <<<"$response" && grep -Fq "${marker}udp" <<<"$response"; then
    break
  fi
  sleep 1
done
grep -Fq "${marker}tcp" <<<"$response"
grep -Fq "${marker}udp" <<<"$response"

docker stop --time 30 "$container" >/dev/null
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$container")" == 0 ]]
