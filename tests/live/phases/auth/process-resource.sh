#!/usr/bin/env bash
set -euo pipefail
op="${1:?}" pid="${2:?}" digest="${3:?}"
observed() { ps -o lstart= -p "$pid" 2>/dev/null | shasum -a 256 | awk '{print $1}'; }
owned() { kill -0 "$pid" 2>/dev/null && [[ "$(observed)" == "$digest" ]] && ps -o command= -p "$pid" | grep -F 'cortex-live-oauth' >/dev/null; }
case "$op" in cleanup) owned || exit 0; kill -TERM "$pid";; verify) ! owned;; *) exit 2;; esac
