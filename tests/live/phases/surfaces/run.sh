#!/usr/bin/env bash
set -euo pipefail
: "${LIVE_RUN_ROOT:?}" "${LIVE_SURFACE_CONTRACT:?}" "${LIVE_HTTP_PORT:?}" "${LIVE_API_TOKEN:?}" "${LIVE_ADMIN_TOKEN:?}"

surface_dir="$LIVE_PROJECT_ROOT/tests/live/phases/surfaces"
artifact_dir="$LIVE_RUN_ROOT/artifacts/surfaces"
mkdir -p "$artifact_dir"; chmod 700 "$artifact_dir"
# shellcheck disable=SC1091
source "$surface_dir/resources.sh"

# Qualify surfaces against the same fully capable isolated epoch used by the
# MCP matrix: admin scope, notification capture, graph projection, a managed
# file-tail root, and a deterministic read-only Docker diagnostic boundary.
# This recreates only the run-owned candidate container and retains its state
# volume; it never grants access to the host Docker socket.
LIVE_MCP_FILETAIL_ROOT="$LIVE_RUN_ROOT/surfaces-filetail"; export LIVE_MCP_FILETAIL_ROOT
mkdir -p "$LIVE_MCP_FILETAIL_ROOT"; chmod 0777 "$LIVE_MCP_FILETAIL_ROOT"
printf 'cortex-live-cli-tail\n' >"$LIVE_MCP_FILETAIL_ROOT/cli-tail.log"; chmod 0666 "$LIVE_MCP_FILETAIL_ROOT/cli-tail.log"
docker compose -p "$LIVE_COMPOSE_PROJECT" \
  -f "$LIVE_PROJECT_ROOT/tests/live/profiles/isolated/compose.yaml" \
  -f "$LIVE_PROJECT_ROOT/tests/live/profiles/mcp/compose.yaml" \
  up -d --no-build --force-recreate candidate >/dev/null
live_wait_until 30 surfaces-admin-health _live_http_health_ready
live_wait_until 30 surfaces-admin-mcp _live_mcp_ready
# shellcheck disable=SC1091
source "$LIVE_PROJECT_ROOT/tests/live/phases/mcp/run.sh"
mcp_seed_positive_fixtures "$artifact_dir"

binary="${LIVE_CORTEX_BINARY:-}"
if [[ -z "$binary" ]]; then
  target_dir="$(cargo metadata --no-deps --format-version 1 | jq -er .target_directory)"
  binary="$target_dir/debug/cortex"
fi
if [[ ! -x "$binary" ]]; then cargo build --quiet --bin cortex; fi
[[ -x "$binary" ]] || { live_die "compiled Cortex binary missing: $binary"; exit 1; }
live_event phase_progress '{"phase":"surfaces","stage":"binary-ready"}'
export LIVE_RUN_HOME="$LIVE_RUN_ROOT/home" LIVE_RUN_TMP="$LIVE_RUN_ROOT/tmp" LIVE_CORTEX_URL="http://127.0.0.1:$LIVE_HTTP_PORT"
export LIVE_CLI_FIXTURE_BIN="$LIVE_PROJECT_ROOT/tests/live/fixtures/surfaces/bin"
LIVE_CLI_PATH="$LIVE_CLI_FIXTURE_BIN:$(dirname "$binary"):/usr/bin:/bin:/usr/sbin:/sbin"
LIVE_DOCKER_BIN="$(command -v docker)"
LIVE_DOCKER_COMPOSE_BIN="$(command -v docker-compose || true)"
if [[ -z "$LIVE_DOCKER_COMPOSE_BIN" ]]; then
  LIVE_DOCKER_COMPOSE_BIN="$LIVE_CLI_FIXTURE_BIN/docker-compose-plugin"
fi
LIVE_CANDIDATE_ID="$(live_ingest_candidate_id)"
export LIVE_CLI_PATH LIVE_DOCKER_BIN LIVE_DOCKER_COMPOSE_BIN LIVE_CANDIDATE_ID
[[ -n "$LIVE_CANDIDATE_ID" ]] || { live_die "surfaces candidate container was not discoverable"; exit 1; }
live_event phase_progress '{"phase":"surfaces","stage":"candidate-ready"}'
mkdir -p "$LIVE_RUN_HOME" "$LIVE_RUN_TMP"; chmod 700 "$LIVE_RUN_HOME" "$LIVE_RUN_TMP"
mkdir -p "$LIVE_RUN_TMP/bin"
cp "$binary" "$LIVE_RUN_TMP/bin/cortex"
chmod 700 "$LIVE_RUN_TMP/bin/cortex"
binary="$LIVE_RUN_TMP/bin/cortex"
printf '[mcp]\nport = 3100\n' >"$LIVE_RUN_TMP/cli-config.toml"; chmod 600 "$LIVE_RUN_TMP/cli-config.toml"

# A real, run-owned Compose project backs every compose CLI positive. It has
# only run-owned, dynamically allocated loopback ports and no host state. Each mutation resolves the canonical
# labels/file on disk and the project is unconditionally removed immediately
# after the CLI sweep, including when a case fails.
compose_cli_dir="$LIVE_RUN_HOME/.cortex/compose" compose_cli_bin="$LIVE_RUN_TMP/compose-bin" setup_cli_bin="$LIVE_RUN_TMP/setup-bin"
mkdir -p "$compose_cli_dir" "$compose_cli_bin" "$setup_cli_bin"
mkdir -p "$LIVE_RUN_HOME/.cortex/data"
mkdir -p "$LIVE_RUN_HOME/.cortex/backups"
chmod 0777 "$LIVE_RUN_HOME/.cortex/data" "$LIVE_RUN_HOME/.cortex/backups"
ln -s "$LIVE_CLI_FIXTURE_BIN/docker-real-wrapper" "$compose_cli_bin/docker"
ln -s "$LIVE_CLI_FIXTURE_BIN/timeout" "$compose_cli_bin/timeout"
ln -s "$LIVE_CLI_FIXTURE_BIN/systemctl" "$compose_cli_bin/systemctl"
ln -s "$LIVE_CLI_FIXTURE_BIN/ss" "$compose_cli_bin/ss"
ln -s "$LIVE_CLI_FIXTURE_BIN/compose-runner" "$compose_cli_bin/compose-runner"
ln -s "$LIVE_CLI_FIXTURE_BIN/docker-setup" "$setup_cli_bin/docker"
ln -s "$LIVE_CLI_FIXTURE_BIN/systemctl" "$setup_cli_bin/systemctl"
ln -s "$LIVE_CLI_FIXTURE_BIN/ss" "$setup_cli_bin/ss"
ln -s "$LIVE_CLI_FIXTURE_BIN/timeout" "$setup_cli_bin/timeout"
ln -s "$LIVE_CLI_FIXTURE_BIN/ssh" "$setup_cli_bin/ssh"
ln -s "$LIVE_CLI_FIXTURE_BIN/scp" "$setup_cli_bin/scp"
ln -s "$LIVE_CLI_FIXTURE_BIN/curl-setup" "$setup_cli_bin/curl"
export LIVE_COMPOSE_CLI_PATH="$compose_cli_bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export LIVE_SETUP_CLI_PATH="$setup_cli_bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export CORTEX_COMPOSE_PROGRAM="$compose_cli_bin/compose-runner"
compose_cli_image="$(docker inspect "$LIVE_CANDIDATE_ID" --format '{{.Config.Image}}')"
printf '%s\n' \
  'services:' \
  '  cortex:' \
  "    image: $compose_cli_image" \
  '    pull_policy: never' \
  '    container_name: cortex' \
  '    command: ["cortex", "serve", "mcp"]' \
  "    environment: [\"CORTEX_HOST=127.0.0.1\", \"CORTEX_API_TOKEN=$LIVE_API_TOKEN\", \"CORTEX_API_ADMIN_TOKEN=$LIVE_ADMIN_TOKEN\", \"CORTEX_TOKEN=$LIVE_CORTEX_TOKEN\", \"CORTEX_CURSOR_SIGNING_KEY=$LIVE_CURSOR_SIGNING_KEY\", \"CORTEX_SERVER_ID=$LIVE_SERVER_INSTANCE_ID\", \"CORTEX_DB_PATH=/data/cortex.db\", \"CORTEX_VOLUME_NAME=${LIVE_COMPOSE_PROJECT}-surface-cli_cortex-data\"]" \
  "    volumes: [\"$LIVE_RUN_HOME/.cortex/data:/data\", \"$LIVE_RUN_HOME/.cortex/backups:/backups\"]" \
  '    ports: ["127.0.0.1::1514/tcp", "127.0.0.1::1514/udp", "127.0.0.1::3100/tcp"]' \
  "    labels: [\"cortex.live.run_id=$LIVE_RUN_ID\"]" \
  >"$compose_cli_dir/compose.yaml"
chmod 600 "$compose_cli_dir/compose.yaml"
export COMPOSE_PROJECT_NAME="${LIVE_COMPOSE_PROJECT}-surface-cli" COMPOSE_FILE="$compose_cli_dir/compose.yaml"
live_event phase_progress '{"phase":"surfaces","stage":"cli-fixture-ready"}'

# Register this secondary project before creation so EXIT cleanup owns it.
surface_cli_resource_register "$COMPOSE_PROJECT_NAME" "$COMPOSE_FILE"
live_event phase_progress '{"phase":"surfaces","stage":"cli-resource-registered"}'

python3 "$surface_dir/rest_sweep.py" "$LIVE_SURFACE_CONTRACT" "$artifact_dir/rest.json"
python3 "$surface_dir/domain_normalizers.py" --self-test >"$artifact_dir/domain-normalizer-self-test.json"
set +e
docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" up -d --wait
cli_sweep_status=$?
if ((cli_sweep_status == 0)); then
  surface_cli_resource_created "$COMPOSE_PROJECT_NAME"
  python3 "$surface_dir/cli_sweep.py" "$LIVE_SURFACE_CONTRACT" "$binary" "$artifact_dir/cli.json"
  cli_sweep_status=$?
else
  docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" logs --no-color >"$artifact_dir/cli-compose-failure.log" 2>&1 || true
fi
set -e
docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" down -v --remove-orphans >/dev/null 2>&1 || cli_sweep_status=1
if ((cli_sweep_status == 0)); then
  surface_cli_resource_verified_removed "$COMPOSE_PROJECT_NAME"
fi
((cli_sweep_status == 0)) || exit "$cli_sweep_status"
python3 "$surface_dir/browser_sweep.py"

# Generate the standalone HTTP CLI from the live server. Credentials live in
# a mode-0600 ephemeral config (never argv); the generated source is inspected
# and deleted before artifact scanning because it may embed connection auth.
mcporter_bin="$(command -v mcporter || true)"
if [[ "$mcporter_bin" == */mise/shims/* ]]; then
  mcporter_bin="$(mise which mcporter)"
fi
[[ -x "$mcporter_bin" ]] || { live_die "mcporter is required for generated CLI qualification"; exit 1; }
node_bin="$(command -v node || true)"
if [[ "$node_bin" == */mise/shims/* ]]; then
  node_bin="$(mise which node)"
fi
[[ -x "$node_bin" ]] || { live_die "Node.js is required to execute generated CLI"; exit 1; }
mcporter_config="$LIVE_RUN_TMP/mcporter.json" generated_source="$LIVE_RUN_TMP/cortex-generated-cli.ts"
generated_cli="$LIVE_RUN_TMP/cortex-generated-cli.js"
jq -cn --arg url "$LIVE_CORTEX_URL/mcp" --arg auth "Bearer $LIVE_CORTEX_TOKEN" \
  '{mcpServers:{cortex:{url:$url,transport:"http",protocolVersion:"legacy",headers:{Authorization:$auth}}}}' >"$mcporter_config"
chmod 600 "$mcporter_config"
# rmcp 3.1 serves the stable MCP list-result shape. Explicitly qualify that
# protocol boundary: mcporter auto mode advertises the experimental 2026 era,
# where ttlMs/cacheScope are mandatory, while its documented legacy mode
# validates the stable Cortex response.
live_run_bounded 30 "$artifact_dir/mcporter-tools-list.log" "$artifact_dir/mcporter-tools-list.stderr" \
  env PATH="$(dirname "$node_bin"):$(dirname "$mcporter_bin"):/usr/bin:/bin" \
  "$mcporter_bin" list cortex --config "$mcporter_config"
grep -q '1 tool' "$artifact_dir/mcporter-tools-list.log" || { live_die "mcporter did not validate Cortex stable tools/list"; exit 1; }
live_run_bounded 60 "$artifact_dir/generated-cli.log" "$artifact_dir/generated-cli.stderr" \
  env PATH="$(dirname "$node_bin"):$(dirname "$mcporter_bin"):/usr/bin:/bin" \
  "$mcporter_bin" generate-cli cortex --config "$mcporter_config" --runtime node \
  --output "$generated_source" --bundle "$generated_cli"
[[ -s "$generated_source" && -s "$generated_cli" ]] || { live_die "mcporter generated CLI artifacts are empty"; exit 1; }
generated_bytes="$(wc -c <"$generated_cli" | tr -d ' ')"; generated_sha="$(live_sha256 "$generated_cli")"
source_sha="$(live_sha256 "$generated_source")"
live_run_bounded 30 "$artifact_dir/generated-cli-help.log" "$artifact_dir/generated-cli-help.stderr" \
  "$node_bin" "$generated_cli" --help
live_run_bounded 30 "$artifact_dir/generated-cli-live.log" "$artifact_dir/generated-cli-live.stderr" \
  "$node_bin" "$generated_cli" cortex --action status
grep -q 'status' "$artifact_dir/generated-cli-live.log" || { live_die "generated CLI did not return live status output"; exit 1; }
rm -f "$generated_source" "$generated_cli" "$mcporter_config"
live_event generated_cli "$(jq -cn --argjson bytes "$generated_bytes" --arg sha256 "$generated_sha" \
  --arg source_sha256 "$source_sha" '{schema:"cortex-live-generated-cli-v1",result:"pass",transport:"http",bytes:$bytes,sha256:$sha256,source_sha256:$source_sha256,executed_live:true,ephemeral_source_removed:true,bundle_removed:true}')"

# The registry-derived CLI sweep above is now the sole semantic CLI adapter.
# Historical `scripts/live-cli-sweep.sh` remains only as a compatibility entry
# point and must not be invoked recursively from the canonical runner.

while IFS= read -r result; do
  live_event result "$(jq -c '. + {duration_ms:(.duration_ms // 0),retry_index:(.retry_index // 0),attempt_kind:"first_attempt",evidence:"artifacts/surfaces/rest.json"}' <<<"$result")"
done < <(jq -c '.results[]' "$artifact_dir/rest.json")
while IFS= read -r result; do
  live_event result "$(jq -c '. + {duration_ms:(.duration_ms // 0),retry_index:(.retry_index // 0),attempt_kind:"first_attempt",evidence:"artifacts/surfaces/cli.json"}' <<<"$result")"
done < <(jq -c '.results[] | select(.case_kind != "alias-positive")' "$artifact_dir/cli.json")

live_event surface_phase "$(jq -cn --argjson rest "$(jq '.entry_count' "$artifact_dir/rest.json")" --argjson cli "$(jq '.entry_count' "$artifact_dir/cli.json")" \
  '{schema:"cortex-live-surface-phase-v1",rest_entries:$rest,cli_entries:$cli,browser_evidence:"artifacts/browser-sweep.json",stdio_evidence:"artifacts/surfaces/stdio-mcp.log"}')"

stdio_binary="$(cargo test --test stdio_mcp --no-run --message-format=json 2>"$artifact_dir/stdio-build.stderr" | \
  jq -r 'select(.reason=="compiler-artifact" and .target.name=="stdio_mcp" and .executable!=null)|.executable' | tail -1)"
[[ -x "$stdio_binary" ]] || { live_die "stdio MCP test binary was not produced"; exit 1; }
live_run_bounded 180 "$artifact_dir/stdio-mcp.log" "$artifact_dir/stdio-mcp.stderr" \
  "$stdio_binary" --nocapture

# Setup/doctor qualification intentionally writes deploy assets containing the
# run's disposable tokens. They are execution state, not evidence, and must not
# survive into the global persisted-artifact secret audit.
rm -f "$LIVE_RUN_HOME/.cortex/compose/compose.yaml"

jq -e --argjson rest "$(jq '[.entries[]|select(.kind=="rest")]|length' "$LIVE_SURFACE_CONTRACT")" \
  --argjson cli "$(jq '[.entries[]|select(.kind=="cli")]|length' "$LIVE_SURFACE_CONTRACT")" \
  '.entry_count==$rest and ([.results[].surface_id]|unique|length)==$rest and (.failures|length)==0' "$artifact_dir/rest.json" >/dev/null
jq -e --argjson cli "$(jq '[.entries[]|select(.kind=="cli")]|length' "$LIVE_SURFACE_CONTRACT")" \
  '.entry_count==$cli and ([.results[].surface_id]|unique|length)==$cli and (.failures|length)==0' "$artifact_dir/cli.json" >/dev/null

jq -n \
  --arg run_id "$LIVE_RUN_ID" \
  --argjson rest "$(jq '.entry_count' "$artifact_dir/rest.json")" \
  --argjson cli "$(jq '.entry_count' "$artifact_dir/cli.json")" \
  --argjson rest_cases "$(jq '.results|length' "$artifact_dir/rest.json")" \
  --argjson cli_cases "$(jq '.results|length' "$artifact_dir/cli.json")" \
  '{schema:"cortex-live-surfaces-summary-v1",run_id:$run_id,result:"pass",rest_entries:$rest,cli_entries:$cli,rest_cases:$rest_cases,cli_cases:$cli_cases,browser_real:true,generated_cli:true,stdio:true,unexpected_imperative_failures:0}' \
  >"$LIVE_RUN_ROOT/summary.json"
chmod 600 "$LIVE_RUN_ROOT/summary.json"
live_event phase_completed "$(jq -c '. + {phase:"surfaces"}' "$LIVE_RUN_ROOT/summary.json")"
live_event suite_completed "$(jq -c '.' "$LIVE_RUN_ROOT/summary.json")"
