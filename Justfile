dev:
    cargo run

build:
    cargo build

release:
    cargo build --release

check:
    cargo check

lint:
    cargo clippy -- -D warnings

fmt:
    cargo fmt

test:
    cargo test

docker-build:
    docker build -t syslog-mcp .

up:
    docker compose up -d

down:
    docker compose down

restart:
    docker compose restart

logs:
    docker compose logs -f

health:
    curl -sf http://localhost:3100/health | jq .

test-live:
    bash tests/test_live.sh

setup:
    cp -n .env.example .env || true

gen-token:
    openssl rand -hex 32


validate-skills:
    @test -f skills/syslog/SKILL.md && echo "OK" || { echo "MISSING: skills/syslog/SKILL.md"; exit 1; }

# Generate a standalone CLI for this server (requires running server; HTTP-only transport)
generate-cli:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "⚠  Server must be running on port 3100 (run 'just dev' first)"
    echo "⚠  Generated CLI embeds your OAuth token — do not commit or share"
    mkdir -p dist dist/.cache
    current_hash=$(timeout 10 curl -sf \
      -H "Authorization: Bearer $MCP_TOKEN" \
      -H "Accept: application/json, text/event-stream" \
      http://localhost:3100/mcp/tools/list 2>/dev/null | sha256sum | cut -d' ' -f1 || echo "nohash")
    cache_file="dist/.cache/syslog-mcp-cli.schema_hash"
    if [[ -f "$cache_file" ]] && [[ "$(cat "$cache_file")" == "$current_hash" ]] && [[ -f "dist/syslog-mcp-cli" ]]; then
      echo "SKIP: syslog-mcp tool schema unchanged — use existing dist/syslog-mcp-cli"
      exit 0
    fi
    timeout 30 mcporter generate-cli \
      --command http://localhost:3100/mcp \
      --header "Authorization: Bearer $MCP_TOKEN" \
      --name syslog-mcp-cli \
      --output dist/syslog-mcp-cli
    printf '%s' "$current_hash" > "$cache_file"
    echo "✓ Generated dist/syslog-mcp-cli (requires bun at runtime)"

clean:
    cargo clean
    rm -rf .cache/

# Linux only — Windows would need syslog-mcp.exe; requires git lfs install
build-plugin: release
    install -m 755 target/release/syslog-mcp bin/syslog-mcp

# Publish: bump version, tag, push (triggers crates.io + Docker publish)
publish bump="patch":
    #!/usr/bin/env bash
    set -euo pipefail
    [ "$(git branch --show-current)" = "main" ] || { echo "Switch to main first"; exit 1; }
    [ -z "$(git status --porcelain)" ] || { echo "Commit or stash changes first"; exit 1; }
    git pull origin main
    CURRENT=$(grep -m1 "^version" Cargo.toml | sed "s/.*\"\(.*\)\".*/\1/")
    IFS="." read -r major minor patch <<< "$CURRENT"
    case "{{bump}}" in
      major) major=$((major+1)); minor=0; patch=0 ;;
      minor) minor=$((minor+1)); patch=0 ;;
      patch) patch=$((patch+1)) ;;
      *) echo "Usage: just publish [major|minor|patch]"; exit 1 ;;
    esac
    NEW="${major}.${minor}.${patch}"
    echo "Version: ${CURRENT} → ${NEW}"
    sed -i "s/^version = \"${CURRENT}\"/version = \"${NEW}\"/" Cargo.toml
    cargo check 2>/dev/null || true
    for f in .claude-plugin/plugin.json .codex-plugin/plugin.json gemini-extension.json; do
      [ -f "$f" ] && python3 -c 'import json,sys; p=sys.argv[1]; v=sys.argv[2]; d=json.load(open(p)); d["version"]=v; json.dump(d,open(p,"w"),indent=2); open(p,"a").write("\n")' "$f" "${NEW}"
    done
    git add -A && git commit -m "release: v${NEW}" && git tag "v${NEW}" && git push origin main --tags
    echo "Tagged v${NEW} — publish workflow will run automatically"

