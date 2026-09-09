#!/usr/bin/env bash
# Check whether the running cortex Docker Compose container is using the
# current local compose image and binary version.
set -euo pipefail

MODE="auto"
PULL="false"
SERVICE="cortex"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_COMPOSE_DIR="${CORTEX_HOME:-${HOME}/.cortex}/compose"
COMPOSE_DIR="${CORTEX_COMPOSE_DIR:-$DEFAULT_COMPOSE_DIR}"
ALLOW_LEGACY="false"
ALLOW_LOCAL_IMAGE="${CORTEX_RUNTIME_CURRENT_ALLOW_LOCAL_IMAGE:-false}"

usage() {
  cat <<'EOF'
Usage: scripts/check-runtime-current.sh [--mode auto|docker] [--pull] [--compose-dir DIR] [--allow-legacy] [--allow-local-image]

Checks:
  docker:  running container image ID == local compose image ID and
           container `cortex --version` == repo Cargo.toml version

Options:
  --pull                  Docker only: pull compose image before comparing.
                          Without this, Docker mode only proves the container
                          matches the image already present in the local cache.
  --compose-dir DIR       Docker compose project dir (default: ~/.cortex/compose)
  --allow-legacy          Permit a running container from a non-canonical
                          Compose working directory.
  --allow-local-image     Permit arbitrary non-ghcr.io/dinglebear-ai/cortex
                          images. The repo-supported cortex:local-debug
                          image is accepted by default.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:?--mode requires a value}"
      case "$MODE" in
        auto|docker) ;;
        *)
          echo "invalid mode: $MODE" >&2
          exit 2
          ;;
      esac
      shift 2
      ;;
    --pull)
      PULL="true"
      shift
      ;;
    --compose-dir)
      COMPOSE_DIR="${2:?--compose-dir requires a value}"
      shift 2
      ;;
    --allow-legacy)
      ALLOW_LEGACY="true"
      shift
      ;;
    --allow-local-image)
      ALLOW_LOCAL_IMAGE="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

status_line() {
  printf '%-10s %s\n' "$1" "$2"
}

detect_mode() {
  if command -v docker >/dev/null 2>&1; then
    if [[ -d "$COMPOSE_DIR" ]] && (cd "$COMPOSE_DIR" && docker compose ps -q "$SERVICE" 2>/dev/null | grep -q .); then
      echo docker
      return
    fi
    if docker ps --filter "name=^/${SERVICE}$" --format '{{.ID}}' 2>/dev/null | grep -q .; then
      echo docker
      return
    fi
  fi
  echo none
}

# Resolve the env file the deployed compose stack actually uses for YAML
# variable substitution (e.g. ${CORTEX_VERSION:-...}). This MUST mirror
# `compose_env_file()` in src/compose/mutation.rs: docker compose only auto-
# loads `.env` from the project dir, but the installed bundle keeps compose
# files under ~/.cortex/compose/ and its env file one level up at
# ~/.cortex/.env. The stack is launched with `--env-file <home>/.env`
# (src/setup/firstrun.rs), so without resolving the same file here the
# version variable falls back to the compose-file default and we compare
# against the wrong image tag.
compose_env_file() {
  if [[ -n "${CORTEX_ENV_FILE:-}" && -f "$CORTEX_ENV_FILE" ]]; then
    printf '%s\n' "$CORTEX_ENV_FILE"
    return
  fi
  local parent_env="${COMPOSE_DIR%/}/../.env"
  if [[ -f "$parent_env" ]]; then
    printf '%s\n' "$parent_env"
    return
  fi
  if [[ -f "${COMPOSE_DIR%/}/.env" ]]; then
    printf '%s\n' "${COMPOSE_DIR%/}/.env"
    return
  fi
  # No env file found — fall back to compose defaults (don't fail).
  printf '%s\n' ""
}

# Populate the global ENV_FILE_ARGS array with `--env-file <path>` (or leave it
# empty when no env file exists, so docker compose uses its YAML defaults).
ENV_FILE_ARGS=()
resolve_env_file_args() {
  ENV_FILE_ARGS=()
  local env_file
  env_file="$(compose_env_file)"
  if [[ -n "$env_file" ]]; then
    ENV_FILE_ARGS=("--env-file" "$env_file")
  fi
}

compose_image() {
  if [[ -d "$COMPOSE_DIR" ]]; then
    (cd "$COMPOSE_DIR" && docker compose ${ENV_FILE_ARGS[@]+"${ENV_FILE_ARGS[@]}"} config --images 2>/dev/null | head -1) || true
  fi
}

realpath_or_echo() {
  if command -v realpath >/dev/null 2>&1; then
    # GNU realpath supports -m; macOS/BSD realpath does not. Existing paths
    # need neither extension, and unresolved paths retain their diagnostic
    # spelling rather than turning a platform difference into a hard failure.
    realpath "$1" 2>/dev/null && return
  fi
  printf '%s\n' "$1"
}

git_common_dir() {
  local path
  path="$(git -C "$1" rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
  if [[ -n "$path" ]]; then
    realpath_or_echo "$path"
  fi
}

check_docker() {
  local cid running_image image local_image repo_digests repo_version container_version label_compose_dir
  local canonical_compose_dir canonical_default_dir canonical_repo_dir
  local compose_git_dir repo_git_dir
  status_line mode docker

  if [[ -d "$COMPOSE_DIR" ]]; then
    cid="$(cd "$COMPOSE_DIR" && docker compose ps -q "$SERVICE" 2>/dev/null || true)"
  else
    cid=""
  fi
  if [[ -z "$cid" ]]; then
    cid="$(docker ps --filter "name=^/${SERVICE}$" --format '{{.ID}}' 2>/dev/null | head -1)"
  fi
  if [[ -z "$cid" ]]; then
    echo "FAIL: cortex container is not running"
    return 1
  fi
  label_compose_dir="$(docker inspect "$cid" --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' 2>/dev/null || true)"
  if [[ -n "$label_compose_dir" && "$label_compose_dir" != "<no value>" ]]; then
    COMPOSE_DIR="$label_compose_dir"
  fi
  status_line compose_dir "$COMPOSE_DIR"
  canonical_compose_dir="$(realpath_or_echo "$COMPOSE_DIR")"
  canonical_default_dir="$(realpath_or_echo "$DEFAULT_COMPOSE_DIR")"
  canonical_repo_dir="$(realpath_or_echo "$REPO_DIR")"
  compose_git_dir="$(git_common_dir "$COMPOSE_DIR")"
  repo_git_dir="$(git_common_dir "$REPO_DIR")"

  # Resolve the deploy env file now that COMPOSE_DIR is final (it may have been
  # rewritten from the container's compose project-dir label above).
  resolve_env_file_args
  if [[ -n "${ENV_FILE_ARGS+x}" && ${#ENV_FILE_ARGS[@]} -gt 0 ]]; then
    status_line env_file "${ENV_FILE_ARGS[1]}"
  fi

  image="$(compose_image)"
  [[ -n "$image" ]] || image="$(docker inspect "$cid" --format '{{.Config.Image}}')"

  # Checkout-built development images use Compose's generated image name. A
  # live Compose owner may be a sibling worktree, so recognize checkouts that
  # share this repository's Git common directory as well as explicit dev tags.
  # Image-ID and binary-version equality are still enforced below.
  local is_local_image="false"
  if [[ "$canonical_compose_dir" == "$canonical_repo_dir" || ( -n "$repo_git_dir" && "$compose_git_dir" == "$repo_git_dir" ) || "$image" == "cortex:dev" || "$image" == "cortex:local-debug" ]]; then
    is_local_image="true"
  fi
  if [[ "$ALLOW_LEGACY" != "true" && "$is_local_image" != "true" && "$canonical_compose_dir" != "$canonical_default_dir" ]]; then
    echo "FAIL: running container belongs to non-canonical Compose dir: $COMPOSE_DIR"
    echo "fix: migrate to $DEFAULT_COMPOSE_DIR or rerun with --allow-legacy for an intentional local/debug deployment"
    return 1
  fi

  if [[ "$ALLOW_LOCAL_IMAGE" != "true" && "$is_local_image" != "true" && "$image" != ghcr.io/dinglebear-ai/cortex:* ]]; then
    echo "FAIL: running container uses unsupported image: $image"
    echo "fix: use ghcr.io/dinglebear-ai/cortex:<version>, cortex:local-debug, or rerun with --allow-local-image for an intentional custom deployment"
    return 1
  fi

  if [[ "$PULL" == "true" && -d "$COMPOSE_DIR" ]]; then
    (cd "$COMPOSE_DIR" && docker compose ${ENV_FILE_ARGS[@]+"${ENV_FILE_ARGS[@]}"} pull --quiet "$SERVICE")
  fi

  running_image="$(docker inspect "$cid" --format '{{.Image}}')"
  local_image="$(docker image inspect "$image" --format '{{.Id}}' 2>/dev/null || true)"
  repo_digests="$(docker image inspect "$image" --format '{{join .RepoDigests ", "}}' 2>/dev/null || true)"
  repo_version="$(awk -F'"' '/^version = / {print $2; exit}' "${REPO_DIR}/Cargo.toml" 2>/dev/null || true)"
  if [[ -z "$repo_version" ]]; then
    echo "FAIL: could not determine repo version from ${REPO_DIR}/Cargo.toml"
    return 1
  fi
  container_version="$(docker exec "$cid" cortex --version 2>/dev/null | awk '{print $2}' || true)"

  status_line container "$cid"
  status_line image "$image"
  status_line running_image_id "$running_image"
  status_line local_image_id "${local_image:-missing}"
  [[ -n "$repo_digests" ]] && status_line repo_digests "$repo_digests"
  [[ -n "$repo_version" ]] && status_line repo_version "$repo_version"
  [[ -n "$container_version" ]] && status_line container_version "$container_version"

  if [[ -z "$local_image" ]]; then
    echo "FAIL: compose image is not present locally"
    echo "fix: cd $COMPOSE_DIR && docker compose pull $SERVICE"
    return 1
  fi
  if [[ "$running_image" != "$local_image" ]]; then
    echo "STALE: running container image differs from local compose image"
    echo "fix: cd $COMPOSE_DIR && docker compose up -d --force-recreate --no-build $SERVICE"
    return 1
  fi
  if [[ -n "$repo_version" && "$container_version" != "$repo_version" ]]; then
    echo "STALE: container cortex version does not match repo version"
    echo "fix: rebuild and restart the Compose service from this repo"
    return 1
  fi

  echo "CURRENT: running container matches local compose image and repo version"
}

if [[ "$MODE" == "auto" ]]; then
  MODE="$(detect_mode)"
fi

case "$MODE" in
  docker) check_docker ;;
  none)
    echo "FAIL: no running cortex Docker container detected"
    exit 1
    ;;
  *)
    echo "invalid mode: $MODE" >&2
    exit 2
    ;;
esac
