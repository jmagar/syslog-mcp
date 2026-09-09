#!/usr/bin/env bash
set -euo pipefail
id="${1:?exact Docker ID required}"
host="${2:?Docker host required}"
[[ "$id" =~ ^[0-9a-f]{64}$ ]]
! DOCKER_HOST="$host" docker inspect "$id" >/dev/null 2>&1
