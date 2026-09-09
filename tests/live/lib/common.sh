#!/usr/bin/env bash

live_die() { printf 'live-e2e: %s\n' "$*" >&2; return 1; }

live_require_tools() {
  local tool missing=0
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'missing required tool: %s\n' "$tool" >&2; missing=1; }
  done
  return "$missing"
}

live_file_mode() {
  local path="$1"
  if stat -c '%a' "$path" >/dev/null 2>&1; then
    stat -c '%a' "$path"
  else
    stat -f '%Lp' "$path"
  fi
}

live_run_id() {
  local bytes
  bytes="$(openssl rand -hex 16)" || return 1
  printf 'cortex-e2e-%s\n' "$bytes"
}

live_validate_run_id() { [[ "$1" =~ ^cortex-e2e-[0-9a-f]{32}$ ]]; }

live_secure_dir() {
  local path="$1"
  [[ ! -L "$path" ]] || { live_die "refusing symlink directory: $path"; return; }
  mkdir -p "$path"
  chmod 700 "$path"
  [[ -d "$path" && ! -L "$path" ]] || { live_die "unsafe directory: $path"; return; }
}

live_secure_subdir() {
  local base="$1" relative="$2" component
  local current="$base"
  [[ "$relative" != /* ]] || { live_die "subdirectory must be relative"; return; }
  IFS='/' read -r -a components <<<"$relative"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || continue
    current="$current/$component"
    [[ ! -L "$current" ]] || { live_die "refusing symlink path component: $current"; return; }
    if [[ -e "$current" && ! -d "$current" ]]; then live_die "non-directory path component: $current"; return; fi
    mkdir -p "$current"; chmod 700 "$current"
  done
}

live_init_run() {
  local root="$1" run_id="${2:-}"
  [[ ! -e "$root" || ! -L "$root" ]] || { live_die "refusing symlink run root: $root"; return; }
  [[ -n "$run_id" ]] || run_id="$(live_run_id)"
  live_validate_run_id "$run_id" || { live_die "invalid run id"; return; }
  LIVE_RUN_ID="$run_id"
  LIVE_RUN_ROOT="$root/$run_id"
  [[ ! -e "$LIVE_RUN_ROOT" ]] || { live_die "run directory already exists"; return; }
  live_secure_dir "$root"
  live_secure_dir "$LIVE_RUN_ROOT"
  live_secure_dir "$LIVE_RUN_ROOT/artifacts"
  export LIVE_RUN_ID LIVE_RUN_ROOT
  printf '%s\n' "$run_id"
}

live_sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

live_manifest_seal() {
  local file="$1"
  local digest_file="${file}.sha256"
  [[ -f "$file" && ! -L "$file" ]] || { live_die "manifest missing or unsafe"; return; }
  live_sha256 "$file" >"$digest_file"; chmod 400 "$file" "$digest_file"
}

live_manifest_verify() {
  local file="$1" expected
  local digest_file="${file}.sha256"
  [[ -f "$file" && ! -L "$file" && -f "$digest_file" && ! -L "$digest_file" ]] || { live_die "sealed manifest missing or unsafe"; return; }
  expected="$(cat "$digest_file")"
  [[ "$expected" == "$(live_sha256 "$file")" ]] || { live_die "immutable manifest changed: $file"; return; }
}

live_run_manifest_write() {
  local profile="$1" provider="$2" target="$3" contract="$4" run_manifest="${LIVE_RUN_ROOT:?}/run-manifest.json" target_manifest="${LIVE_RUN_ROOT}/target-manifest.json"
  [[ -n "$provider" && -n "$target" ]] || { live_die "provider and target identity required"; return; }
  live_manifest_verify "$contract" || return
  jq -cn --arg run_id "$LIVE_RUN_ID" --arg profile "$profile" --arg provider "$provider" --arg target "$target" --arg contract_sha "$(live_sha256 "$contract")" '{run_id:$run_id,profile:$profile,provider:$provider,target:$target,surface_contract_sha256:$contract_sha}' >"$run_manifest"
  jq -cn --arg provider "$provider" --arg target "$target" '{provider:$provider,target:$target,capabilities:{contract:"compiled-surface-contract"}}' >"$target_manifest"
  live_manifest_seal "$run_manifest"; live_manifest_seal "$target_manifest"
}

live_run_manifest_verify() {
  live_manifest_verify "${LIVE_RUN_ROOT:?}/run-manifest.json" && live_manifest_verify "$LIVE_RUN_ROOT/target-manifest.json" && live_manifest_verify "${LIVE_SURFACE_CONTRACT:?}"
}

live_sanitized_env() {
  local home="${LIVE_RUN_ROOT:?}/home" tmp="${LIVE_RUN_ROOT}/tmp"
  live_secure_dir "$home"; live_secure_dir "$tmp"
  env -i PATH="${PATH}" LANG="${LANG:-C}" LC_ALL="${LC_ALL:-C}" HOME="$home" \
    TMPDIR="$tmp" LIVE_RUN_ID="${LIVE_RUN_ID:?}" LIVE_RUN_ROOT="$LIVE_RUN_ROOT" "$@"
}
