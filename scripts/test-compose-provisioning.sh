#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_ref="${1:-}"
host_docker_config="${DOCKER_CONFIG:-$HOME/.docker}"
export DOCKER_CONFIG="$host_docker_config"
test_root="$(mktemp -d)"
project="cortex-provision-$PPID-$$"
compose_override="$test_root/compose.override.yml"
cleanup() {
  if [[ -n "$image_ref" ]]; then
    docker compose -p "$project" -f "$repo_dir/docker-compose.yml" -f "$compose_override" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$test_root"
}
trap cleanup EXIT

assert_mode_700() {
  local path="$1"
  [[ -d "$path" ]]
  [[ "$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path")" == "700" ]]
}

default_home="$test_root/default-home"
mkdir -p "$default_home"
HOME="$default_home" CORTEX_ENV_FILE="$repo_dir/.env.example" \
  bash "$repo_dir/scripts/prepare-compose-dirs.sh" -f "$repo_dir/docker-compose.yml"
assert_mode_700 "$default_home/.cortex/backups"

custom_dir="$test_root/custom/backups"
HOME="$default_home" CORTEX_BACKUP_DIR="$custom_dir" \
  CORTEX_ENV_FILE="$repo_dir/.env.example" \
  bash "$repo_dir/scripts/prepare-compose-dirs.sh" -f "$repo_dir/docker-compose.yml"
assert_mode_700 "$custom_dir"

# A hostile/incorrect Compose interpolation must be rejected before install or
# chmod can touch the resolved directory. Use a stub so this test is safe and
# record the root mode to prove the failure did not mutate it.
fake_bin="$test_root/fake-bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/docker" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '{"services":{"cortex":{"volumes":[{"type":"bind","source":"/private/..","target":"/backups"}]}}}'
EOF
chmod +x "$fake_bin/docker"
root_mode_before="$(stat -c '%a' / 2>/dev/null || stat -f '%Lp' /)"
if PATH="$fake_bin:$PATH" bash "$repo_dir/scripts/prepare-compose-dirs.sh"; then
  echo "unsafe root backup source was accepted" >&2
  exit 1
fi
[[ "$(stat -c '%a' / 2>/dev/null || stat -f '%Lp' /)" == "$root_mode_before" ]]

if [[ -n "$image_ref" ]]; then
  live_home="$test_root/live-home"
  live_data="$test_root/live-data"
  live_backups="$live_home/.cortex/backups"
  mkdir -p "$live_home/.cortex/ssh" "$live_home/workspace" "$live_data"
  chmod 700 "$live_home/.cortex" "$live_home/.cortex/ssh" "$live_data"
  cat >"$test_root/runtime.env" <<'EOF'
CORTEX_API_TOKEN=compose-provision-api
CORTEX_TOKEN=compose-provision-mcp
CORTEX_CURSOR_SIGNING_KEY=compose-provision-cursor-key
EOF
  cat >"$compose_override" <<EOF
services:
  cortex:
    image: $image_ref
    build: null
    container_name: ${project}-cortex
    restart: "no"
    volumes:
      - $live_data:/data
      - type: bind
        source: $live_backups
        target: /backups
        bind:
          create_host_path: false
networks:
  cortex:
    external: false
    name: ${project}-network
EOF
  export HOME="$live_home"
  export CORTEX_ENV_FILE="$test_root/runtime.env"
  export CORTEX_BACKUP_DIR="$live_backups"
  export CORTEX_DATA_VOLUME="$live_data"
  export CORTEX_HOME_VOLUME="$live_home/.cortex"
  export CORTEX_SSH_VOLUME="$live_home/.cortex/ssh"
  export CORTEX_WORKSPACE_VOLUME="$live_home/workspace"
  # Bind mounts retain the creator's UID/GID. Hosted runners need not use
  # the image's default UID 1000; preserve private 0700 modes and run the
  # fixture with its actual owner instead of making its data world-writable.
  export CORTEX_UID="$(id -u)"
  export CORTEX_GID="$(id -g)"
  export CORTEX_RECEIVER_HOST_PORT=0
  export CORTEX_PORT=0
  bash "$repo_dir/scripts/prepare-compose-dirs.sh" -p "$project" -f "$repo_dir/docker-compose.yml" -f "$compose_override"
  docker compose -p "$project" -f "$repo_dir/docker-compose.yml" -f "$compose_override" up -d --no-build
  container_id="$(docker compose -p "$project" -f "$repo_dir/docker-compose.yml" -f "$compose_override" ps -q cortex)"
  for _ in $(seq 1 60); do
    [[ "$(docker inspect -f '{{.State.Health.Status}}' "$container_id")" == "healthy" ]] && break
    sleep 1
  done
  if [[ "$(docker inspect -f '{{.State.Health.Status}}' "$container_id")" != "healthy" ]]; then
    docker logs --tail 60 "$container_id" >&2
    docker inspect -f '{{json .State}}' "$container_id" >&2
    exit 1
  fi
  mounted_source="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/backups"}}{{.Source}}{{end}}{{end}}' "$container_id")"
  [[ "$mounted_source" == "$(cd "$live_backups" && pwd -P)" ]]
  docker compose -p "$project" -f "$repo_dir/docker-compose.yml" -f "$compose_override" down -v --remove-orphans
fi

echo "Compose backup-directory provisioning contract passed"
