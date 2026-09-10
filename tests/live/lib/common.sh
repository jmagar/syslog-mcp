#!/usr/bin/env bash

live_die() { printf 'live-e2e: %s\n' "$*" >&2; return 1; }

# The harness needs bash >= 4.1. On older bash (macOS /bin/bash is 3.2) a
# failing `[[ ... ]]` does not trigger errexit, so every bare assertion in a
# phase is silently a no-op and a run can report green over checks that failed.
# Refuse to run rather than produce an untrustworthy result.
#
# Everything from here to the end of live_require_modern_bash must stay
# parseable and runnable by bash 3.2, because it is what refuses 3.2.
live_bash_version_ok() {
  local major="${1:-}" minor="${2:-}"
  [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
  (( major > 4 || (major == 4 && minor >= 1) ))
}

live_require_modern_bash() {
  local path_bash path_version path_major='' path_minor=''
  if ! live_bash_version_ok "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}"; then
    # shellcheck disable=SC2016 # backticks and $PATH are literal advice text
    printf 'live-e2e: bash >= 4.1 required, found %s at %s. On older bash a failing [[ ]] does not stop the run, so assertions are not enforced. Install a newer bash (for example `brew install bash`) and put it first on PATH.\n' "$BASH_VERSION" "${BASH:-bash}" >&2
    return 1
  fi
  # Child phases start through their `#!/usr/bin/env bash` shebang, which
  # resolves bash from PATH again. A modern bash running this script is not
  # enough if an older one is first on PATH.
  path_bash="$(command -v bash 2>/dev/null)" || path_bash=''
  if [[ -z "$path_bash" ]]; then
    # shellcheck disable=SC2016 # backticks and $PATH are literal advice text
    printf 'live-e2e: no bash on PATH. Child phases start through `#!/usr/bin/env bash`, so put a bash >= 4.1 (this one is %s) first on PATH.\n' "${BASH:-bash}" >&2
    return 1
  fi
  [[ "$path_bash" != "${BASH:-}" ]] || return 0
  # shellcheck disable=SC2016 # expanded by the child bash
  path_version="$("$path_bash" -c 'echo "${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"' 2>/dev/null)" || path_version=''
  read -r path_major path_minor <<<"$path_version" || true
  if ! live_bash_version_ok "$path_major" "$path_minor"; then
    # shellcheck disable=SC2016 # backticks and $PATH are literal advice text
    printf 'live-e2e: bash on PATH is %s (version %s), but bash >= 4.1 is required. Child phases start through `#!/usr/bin/env bash` and would run under it, where a failing [[ ]] does not stop the run. Put a newer bash first on PATH (for example `export PATH="%s:$PATH"`).\n' "$path_bash" "${path_version:-unknown}" "${BASH%/*}" >&2
    return 1
  fi
}

# Name the abort. Under errexit a failing command or bare `[[ ... ]]` ends the
# run with no message of its own. Report where it happened, innermost frame
# first and then each caller: file and line only, never the command text or a
# variable, either of which may contain an expanded credential.
# Deliberate `set +e` regions stay quiet because errexit is off there; `if`
# conditions and `||`/`&&` lists stay quiet because bash does not run the ERR
# trap for them.
#
# `set -E` makes subshells, pipeline stages, and background jobs inherit the
# trap. Only the shell that installed it reports: a failing subshell makes its
# parent's command fail, so the parent names the abort once, and a background
# job cannot claim the run aborted while the main shell continues.
live_err_trap() {
  local status=$? i
  [[ $- == *e* ]] || return 0
  [[ "${BASHPID:-}" == "${LIVE_ERR_TRAP_PID:-}" ]] || return 0
  printf 'live-e2e: aborted at %s:%s (status %s) in %s\n' \
    "${BASH_SOURCE[1]:-$0}" "${BASH_LINENO[0]}" "$status" "${FUNCNAME[1]:-main}" >&2
  for (( i = 2; i < ${#FUNCNAME[@]}; i++ )); do
    printf '  from %s:%s in %s\n' "${BASH_SOURCE[i]:-$0}" "${BASH_LINENO[i - 1]}" "${FUNCNAME[i]}" >&2
  done
}

live_install_err_trap() {
  LIVE_ERR_TRAP_PID="$BASHPID"
  set -E
  trap live_err_trap ERR
}

# Assert grep finds nothing. Only "no match" (status 1) passes: a match fails,
# and so does a scan that could not run (status 2), instead of a missing tool or
# unreadable path silently reading as "absent". Never echoes what was searched.
live_grep_absent() {
  local label="$1" status=0; shift
  grep -q "$@" >/dev/null 2>&1 || status=$?
  case "$status" in
    1) return 0 ;;
    0) live_die "$label: forbidden content found"; return 1 ;;
    *) live_die "$label: scan failed (grep status $status)"; return 1 ;;
  esac
}

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
