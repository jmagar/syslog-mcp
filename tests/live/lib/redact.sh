#!/usr/bin/env bash

live_secret_file() { printf '%s/secrets.values\n' "${LIVE_RUN_ROOT:?}"; }

live_register_secret() {
  local value="$1" file
  [[ -n "$value" ]] || return 0
  file="$(live_secret_file)"
  [[ ! -L "$file" ]] || { live_die "refusing symlink secret registry"; return; }
  umask 077
  printf '%s\n' "$value" >>"$file"
  chmod 600 "$file"
}

live_redact_stream() {
  local file secret text
  text="$(cat)"
  file="$(live_secret_file)"
  if [[ -f "$file" ]]; then
    while IFS= read -r secret; do
      [[ -n "$secret" ]] && text="${text//"$secret"/[REDACTED]}"
    done <"$file"
  fi
  printf '%s' "$text" | sed -E \
    -e 's/(Authorization:[[:space:]]*(Bearer|Basic)[[:space:]]+)[^[:space:]"}]+/\1[REDACTED]/Ig' \
    -e 's/((token|secret|password|passwd|api[_-]?key|access[_-]?key|client[_-]?secret|refresh[_-]?token|session|cookie)[=:][[:space:]]*)[^[:space:]&;]+/\1[REDACTED]/Ig' \
    -e 's/("(token|secret|password|passwd|api[_-]?key|access[_-]?key|client[_-]?secret|refresh[_-]?token|session|cookie)"[[:space:]]*:[[:space:]]*")[^"]+"/\1[REDACTED]"/Ig' \
    -e 's#(https?://)[^/@[:space:]]+:[^/@[:space:]]+@#\1[REDACTED]@#Ig' \
    -e 's/(-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----).*/\1 [REDACTED]/Ig'
}

live_secret_scan() {
  local root="$1" file secret hit=0
  file="$(live_secret_file)"
  [[ -f "$file" ]] || return 0
  while IFS= read -r secret; do
    [[ -n "$secret" ]] || continue
    if grep -R -F -l --exclude='secrets.values' -- "$secret" "$root" >/dev/null 2>&1; then
      printf 'secret found in persisted artifacts\n' >&2; hit=1
    fi
  done <"$file"
  return "$hit"
}
