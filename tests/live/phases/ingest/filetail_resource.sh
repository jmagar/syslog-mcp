#!/usr/bin/env bash
set -euo pipefail
mode="$1" id="$2" url="$3"
headers=(-H 'Host: localhost' -H "Authorization: Bearer ${LIVE_API_TOKEN:?}" -H "X-Cortex-Admin-Token: ${LIVE_ADMIN_TOKEN:?}" -H 'Content-Type: application/json')
case "$mode" in
  cleanup) curl -fsS --max-time 8 "${headers[@]}" -d "$(jq -cn --arg id "$id" '{op:"remove",id:$id}')" "$url/api/file-tails" >/dev/null;;
  verify) ! curl -fsS --max-time 8 "${headers[@]}" -d '{"op":"list"}' "$url/api/file-tails" | jq -e --arg id "$id" 'any(.sources[]?;.id==$id)' >/dev/null;;
  *) exit 2;;
esac
