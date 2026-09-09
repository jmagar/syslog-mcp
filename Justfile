# `set dotenv-load` is GLOBAL (bead i5lx): every recipe below runs with the
# variables from `.env` injected into its environment — including
# CORTEX_API_TOKEN, NO_AUTH, and any OAuth secrets. Two consequences to keep in
# mind:
#   1. A local `.env` override silently changes what a recipe tests vs. CI.
#   2. Test recipes that must exercise the no-auth path explicitly strip the
#      auth vars (`env -u CORTEX_API_TOKEN -u NO_AUTH ...`); any new test or
#      release recipe that runs the suite MUST do the same, or it will test a
#      different environment than `just test`.
set dotenv-load

dev:
    cargo run -- serve mcp

build:
    cargo build

release:
    cargo build --release
    just link-bin

check:
    cargo check
    bash scripts/check-rust-module-size.sh --limit 500

# AO-001: parse/compile/validate the Agent Observatory planning contracts
# (JSON, SQL, Rust, TypeScript) and fail on unresolved placeholders.
check-agent-observatory-contracts:
    bash scripts/check-agent-observatory-contracts.sh

# ENV-004: confirm the deprecated CORTEX_AGENT_AI_TRANSCRIPTS env var only
# appears in the approved allowlist locations.
validate-transcript-forward-env-rename:
    bash scripts/validate-transcript-forward-env-rename.sh
    bash scripts/test-validate-transcript-forward-env-rename.sh

lint:
    cargo clippy -- -D warnings

fmt:
    cargo fmt

test:
    env -u CORTEX_API_TOKEN -u NO_AUTH cargo nextest run

coverage:
    env -u CORTEX_API_TOKEN -u NO_AUTH -u CORTEX_DB_PATH cargo llvm-cov nextest --summary-only

coverage-html:
    env -u CORTEX_API_TOKEN -u NO_AUTH -u CORTEX_DB_PATH cargo llvm-cov nextest --html

# Doc tests (nextest does not run these; no executable doc tests currently exist)
test-doc:
    cargo test --doc

docker-build:
    docker build -f config/Dockerfile -t cortex .

up:
    bash scripts/prepare-compose-dirs.sh
    docker compose up -d

down:
    docker compose down

restart:
    bash scripts/prepare-compose-dirs.sh
    docker compose restart

logs:
    docker compose logs -f

health:
    curl -sf http://localhost:3100/health | jq .

test-live:
    bash tests/live/run-profile.sh smoke

# Canonical live qualification entry points. These never read the operator's
# deployed ~/.cortex state; fleet/provider runs require explicit target grants.
live profile="smoke":
    bash tests/live/run-profile.sh "{{ profile }}"

live-smoke: (live "smoke")
live-full: (live "full")
live-auth: (live "auth")
live-stateful: (live "stateful")
live-resilience: (live "resilience")
live-storage: (live "storage")
live-artifact: (live "artifact")
live-upgrade: (live "upgrade")
live-security: (live "security")
live-mutation: (live "mutation")
live-soak: (live "soak")
live-agent: (live "agent")
live-mcp: (live "mcp")
live-notifications: (live "notifications")
live-compose: (live "compose-isolated")
live-fleet: (live "fleet")
live-provider: (live "provider")
live-boundary-reduced: (live "docker-boundary-reduced")
live-boundary-full: (live "docker-boundary-full")

live-selftest:
    bash tests/live/selftest/run.sh
    bash tests/live/selftest/ci-docs.sh

live-docs:
    python3 tests/live/generate-docs.py

live-docs-check:
    python3 tests/live/generate-docs.py --check

setup:
    cp -n .env.example .env || true
    bash scripts/prepare-compose-dirs.sh

gen-token:
    openssl rand -hex 32

# Validate plugin manifests, MCP config, and skill frontmatter
validate-plugin:
    #!/usr/bin/env bash
    set -euo pipefail
    python3 - <<'PY'
    import json
    from pathlib import Path

    plugin = json.loads(Path(".claude-plugin/plugin.json").read_text())
    if "version" in plugin:
        raise SystemExit("FORBIDDEN: .claude-plugin/plugin.json version")
    for key in ["mcpServers", "skills"]:
        value = plugin.get(key)
        if not value:
            raise SystemExit(f"MISSING: .claude-plugin/plugin.json {key}")
        path = Path(value)
        if not path.exists():
            raise SystemExit(f"MISSING: {path}")

    mcp_path = Path(plugin["mcpServers"])
    mcp = json.loads(mcp_path.read_text())
    if "cortex" not in mcp.get("mcpServers", {}):
        raise SystemExit(f"MISSING: cortex server in {mcp_path}")

    if "hooks" in plugin:
        raise SystemExit("FORBIDDEN: .claude-plugin/plugin.json hooks")
    PY
    found=0
    for dir in plugins/cortex/skills/*; do
      [[ -d "$dir" ]] || continue
      found=1
      test -f "$dir/SKILL.md" || { echo "MISSING: $dir/SKILL.md"; exit 1; }
      grep -q '^name:' "$dir/SKILL.md" || { echo "MISSING name: $dir/SKILL.md"; exit 1; }
      grep -q '^description:' "$dir/SKILL.md" || { echo "MISSING description: $dir/SKILL.md"; exit 1; }
    done
    [[ "$found" -eq 1 ]] || { echo "MISSING: plugins/cortex/skills/*"; exit 1; }
    echo "OK"

validate-skills: validate-plugin

# Generate a standalone CLI for this server (requires running server; HTTP-only transport)
generate-cli:
    #!/usr/bin/env bash
    set -euo pipefail
    TOKEN="${CORTEX_TOKEN:-}"
    if [[ -z "${TOKEN}" ]]; then
      echo "Set CORTEX_TOKEN before running generate-cli"
      exit 1
    fi
    echo "⚠  Server must be running on port 3100 (run 'just dev' first)"
    echo "⚠  Generated CLI embeds your OAuth token — do not commit or share"
    mkdir -p dist dist/.cache
    current_hash=$(timeout 10 curl -sf \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Accept: application/json, text/event-stream" \
      http://localhost:3100/mcp/tools/list 2>/dev/null | sha256sum | cut -d' ' -f1 || echo "nohash")
    cache_file="dist/.cache/cortex-cli.schema_hash"
    if [[ -f "$cache_file" ]] && [[ "$(cat "$cache_file")" == "$current_hash" ]] && [[ -f "dist/cortex-cli" ]]; then
      echo "SKIP: cortex tool schema unchanged — use existing dist/cortex-cli"
      exit 0
    fi
    timeout 30 mcporter generate-cli \
      --command http://localhost:3100/mcp \
      --header "Authorization: Bearer ${TOKEN}" \
      --name cortex-cli \
      --output dist/cortex-cli
    printf '%s' "$current_hash" > "$cache_file"
    echo "✓ Generated dist/cortex-cli (requires bun at runtime)"

clean:
    cargo clean
    rm -rf .cache/

# Linux only — Windows would need .exe binaries; requires git lfs install
build-plugin: release
    #!/bin/sh
    set -eu
    target_dir="${CARGO_TARGET_DIR:-target}"
    if [ ! -x "$target_dir/release/cortex" ] && [ -x ".cache/cargo/release/cortex" ]; then
      target_dir=".cache/cargo"
    fi
    mkdir -p bin plugins/cortex/bin
    install -m 755 "$target_dir/release/cortex" bin/cortex
    install -m 755 "$target_dir/release/cortex" plugins/cortex/bin/cortex

# Symlink the compiled release binary into PATH and all known plugin cache slots.
# Called automatically by `just release` and `just install`. Safe to call manually
# after `cargo build --release` so that `cortex` on $PATH matches the repo build.
link-bin:
    #!/usr/bin/env bash
    set -euo pipefail
    CORTEX_TARGET_DIR="${CARGO_TARGET_DIR:-.cache/cargo}"
    case "$CORTEX_TARGET_DIR" in
      /*) CORTEX_BIN="$CORTEX_TARGET_DIR/release/cortex" ;;
      *)  CORTEX_BIN="$(pwd)/$CORTEX_TARGET_DIR/release/cortex" ;;
    esac
    if [ ! -x "$CORTEX_BIN" ]; then
      echo "release binary not found at $CORTEX_BIN — run 'just release' first" >&2
      exit 1
    fi
    mkdir -p ~/.local/bin
    ln -sf "$CORTEX_BIN" ~/.local/bin/cortex
    while IFS= read -r -d '' plugin_bin; do
      ln -sf "$CORTEX_BIN" "$plugin_bin"
    done < <(find "${HOME}/.claude/plugins/cache/jmagar-lab/cortex" -maxdepth 3 -name "cortex" \( -type f -o -type l \) -print0 2>/dev/null)
    echo "cortex → $CORTEX_BIN"

install: release
    just link-bin

build-mcpb:
    bash scripts/build-mcpb.sh

build-mcpb-windows:
    bash scripts/build-mcpb.sh --target windows

runtime-current:
    bash scripts/check-runtime-current.sh

# Build the local release-fast binary when stale, point PATH + plugin symlinks at
# it, rebuild the Docker image only when its inputs changed, then (re)start the
# cortex compose service. Synchronous, cortex-adapted port of axon's sync-container.
sync-container:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v mold >/dev/null 2>&1; then
      export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-fuse-ld=mold"
    fi

    profile="release-fast"
    CORTEX_TARGET_DIR="${CARGO_TARGET_DIR:-.cache/cargo}"
    case "$CORTEX_TARGET_DIR" in
      /*) CORTEX_BIN="$CORTEX_TARGET_DIR/$profile/cortex" ;;
      *)  CORTEX_BIN="$(pwd)/$CORTEX_TARGET_DIR/$profile/cortex" ;;
    esac

    # 1. Rebuild the local binary only if a tracked source is newer than it.
    release_stale=0
    if [ ! -x "$CORTEX_BIN" ]; then
      release_stale=1
    else
      while IFS= read -r -d '' input; do
        if [ "$input" -nt "$CORTEX_BIN" ]; then
          release_stale=1
          break
        fi
      done < <(git ls-files -z -- Cargo.toml Cargo.lock .cargo src config.toml)
    fi
    if [ "$release_stale" -eq 1 ]; then
      cargo build --profile "$profile" --locked --bin cortex
    else
      echo "release binary is current: $CORTEX_BIN"
    fi

    # 2. Point PATH + plugin cache slots at the fresh binary (mirrors `just link-bin`,
    #    but for the release-fast binary rather than the release one).
    mkdir -p ~/.local/bin
    ln -sf "$CORTEX_BIN" ~/.local/bin/cortex
    while IFS= read -r -d '' plugin_bin; do
      ln -sf "$CORTEX_BIN" "$plugin_bin"
    done < <(find "${HOME}/.claude/plugins/cache/jmagar-lab/cortex" -maxdepth 3 -name "cortex" \( -type f -o -type l \) -print0 2>/dev/null)
    echo "cortex → $CORTEX_BIN"

    # 3. Rebuild the Docker image only when its build inputs changed (tracked via a
    #    sentinel), then (re)start the cortex compose service.
    container_sentinel="$CORTEX_TARGET_DIR/.container-built"
    image_stale=0
    if [ ! -f "$container_sentinel" ]; then
      image_stale=1
    else
      while IFS= read -r -d '' input; do
        if [ "$input" -nt "$container_sentinel" ]; then
          image_stale=1
          break
        fi
      done < <(git ls-files -z -- config/Dockerfile docker-compose.yml)
    fi
    if [ "$image_stale" -eq 1 ]; then
      docker compose build cortex
      mkdir -p "$(dirname "$container_sentinel")"
      touch "$container_sentinel"
      docker compose up -d cortex --no-deps
    else
      echo "docker image is current"
      docker compose up -d cortex --no-deps --no-build
    fi
    docker compose restart cortex
    docker compose ps cortex
    echo "container synced"

# Publish: bump version, tag, push (triggers crates.io + Docker publish)
publish bump="patch":
    #!/usr/bin/env bash
    set -euo pipefail
    [ "$(git branch --show-current)" = "main" ] || { echo "Switch to main first"; exit 1; }
    [ -z "$(git status --porcelain)" ] || { echo "Commit or stash changes first"; exit 1; }
    git pull origin main
    case "{{ bump }}" in
      major|minor|patch) ;;
      *) echo "Usage: just publish [major|minor|patch]"; exit 1 ;;
    esac
    cargo xtask bump-version "{{ bump }}"
    NEW=$(grep -m1 "^version" Cargo.toml | sed "s/.*\"\(.*\)\".*/\1/")
    cargo xtask check-release-versions
    # Reuse the canonical gates (bead ok8c) so the release gate can't drift from
    # them: `test` strips the auth vars `set dotenv-load` injects and runs
    # nextest, `test-doc` covers doc tests (nextest skips those), `lint` is
    # clippy -D warnings.
    just test
    just test-doc
    just lint
    git add -A
    git commit -m "release: v${NEW}"
    git tag "v${NEW}"
    git push origin main --tags
    echo "Tagged v${NEW} — publish workflow will run automatically"
