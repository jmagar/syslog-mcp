#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: host-audit.sh --binary PATH --state-dir PATH [--candidate-root PATH ...]" >&2
}

binary=''; state_dir=''; candidate_roots=()
while (($#)); do
  case "$1" in
    --binary) binary="$2"; shift 2 ;;
    --state-dir) state_dir="$2"; shift 2 ;;
    --candidate-root) candidate_roots+=("$2"); shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "$binary" && -n "$state_dir" ]] || { usage; exit 2; }
for tool in jq shasum stat find file; do command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 69; }; done

describe() {
  local path="$1"
  if [[ ! -f "$path" ]]; then jq -cn --arg path "$path" '{path:$path,present:false}'; return; fi
  jq -cn --arg path "$path" --arg sha "$(shasum -a 256 "$path" | awk '{print $1}')" \
    --arg type "$(file -b "$path")" --arg size "$(stat -f %z "$path")" --arg mtime "$(stat -f %m "$path")" \
    '{path:$path,present:true,sha256:$sha,type:$type,size:($size|tonumber),mtime_epoch:($mtime|tonumber)}'
}

installed="$(describe "$binary")"
installed_sha="$(jq -r '.sha256 // empty' <<<"$installed")"
matches=()
if [[ -n "$installed_sha" ]]; then
  for root in "${candidate_roots[@]}"; do
    [[ -d "$root" ]] || continue
    candidates_file="$(mktemp "${TMPDIR:-/tmp}/cortex-host-audit.XXXXXX")"
    trap 'rm -f "${candidates_file:-}"' EXIT
    if ! find "$root" -type f -name cortex -perm -111 -print >"$candidates_file"; then
      echo "failed to enumerate candidate recovery sources under $root" >&2
      exit 1
    fi
    while IFS= read -r candidate; do
      [[ "$candidate" != "$binary" ]] || continue
      [[ "$(shasum -a 256 "$candidate" | awk '{print $1}')" == "$installed_sha" ]] && matches+=("$candidate")
    done <"$candidates_file"
    rm -f "$candidates_file"; trap - EXIT
  done
fi

state=()
if [[ -d "$state_dir" ]]; then
  state_file="$(mktemp "${TMPDIR:-/tmp}/cortex-host-state.XXXXXX")"
  trap 'rm -f "${state_file:-}"' EXIT
  if ! find "$state_dir" -maxdepth 3 -type f -print >"$state_file"; then
    echo "failed to enumerate host state under $state_dir" >&2
    exit 1
  fi
  LC_ALL=C sort -o "$state_file" "$state_file"
  while IFS= read -r path; do state+=("$(describe "$path")"); done <"$state_file"
  rm -f "$state_file"; trap - EXIT
fi
state_json='[]'; matches_json='[]'
if ((${#state[@]})); then state_json="$(printf '%s\n' "${state[@]}" | jq -s '.')"; fi
if ((${#matches[@]})); then matches_json="$(printf '%s\n' "${matches[@]}" | jq -Rsc 'split("\n")|map(select(length>0))')"; fi
jq -cn --argjson installed "$installed" --arg state_dir "$state_dir" \
  --argjson state "$state_json" --argjson matches "$matches_json" \
  '{schema:"cortex-live-macos-host-audit-v1",read_only:true,installed_binary:$installed,state_dir:$state_dir,state_files:$state,byte_identical_recovery_sources:$matches,recovery_source_verified:($matches|length>0)}'
