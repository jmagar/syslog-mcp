#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="${CORTEX_AUTO_DEPLOY_REPO:-/home/jmagar/workspace/cortex}"
lock_file="${CORTEX_AUTO_DEPLOY_LOCK:-/tmp/cortex-auto-deploy.lock}"
health_url="${CORTEX_AUTO_DEPLOY_HEALTH_URL:-http://localhost:3100/health}"

exec 9>"$lock_file"
if ! flock -n 9; then
  echo "cortex auto-deploy: another deploy is already running"
  exit 0
fi

cd "$repo_dir"

branch="$(git branch --show-current)"
if [[ "$branch" != "main" ]]; then
  echo "cortex auto-deploy: refusing to deploy from branch '$branch' (expected main)"
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "cortex auto-deploy: refusing to deploy from a dirty checkout"
  git status --short
  exit 1
fi

git fetch --no-tags origin main
before="$(git rev-parse HEAD)"
git pull --ff-only
after="$(git rev-parse HEAD)"

expected_version="$(
  awk -F'"' '/^version = / { print $2; exit }' Cargo.toml
)"
if [[ -z "$expected_version" ]]; then
  echo "cortex auto-deploy: could not read Cargo.toml version" >&2
  exit 1
fi

running_version="$(
  docker exec cortex cortex --version 2>/dev/null | awk '{print $2}' || true
)"
if [[ "$before" == "$after" && "$running_version" == "$expected_version" ]]; then
  echo "cortex auto-deploy: current at $expected_version"
  exit 0
fi

echo "cortex auto-deploy: deploying $expected_version (running=${running_version:-unknown})"
bash scripts/prepare-compose-dirs.sh
docker compose build cortex
docker compose up -d --no-deps --force-recreate cortex

for _ in $(seq 1 24); do
  if curl -fsS "$health_url" >/dev/null; then
    deployed="$(docker exec cortex cortex --version 2>/dev/null || true)"
    if [[ "$deployed" == "cortex $expected_version" ]]; then
      echo "cortex auto-deploy: deployed $deployed"
      exit 0
    fi
    echo "cortex auto-deploy: health ok but version is '$deployed', expected cortex $expected_version"
  fi
  sleep 5
done

echo "cortex auto-deploy: deployment did not become healthy at $expected_version" >&2
docker compose ps
docker compose logs --tail 80 cortex
exit 1
