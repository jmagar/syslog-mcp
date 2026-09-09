---
title: "Deployment Guide -- cortex"
created: "2026-07-30"
updated: "2026-07-30"
---

# Deployment Guide -- cortex

Deployment patterns for cortex. Choose the method that fits your environment.

## Local development

```bash
cargo run -- serve mcp
```

Or via Justfile:

```bash
just dev
```

The server reads `config.toml` in the working directory. Syslog listens on `0.0.0.0:1514` and MCP on `0.0.0.0:3100`.

## Cargo install

```bash
cargo install cortex
cortex serve mcp
```

The binary reads `config.toml` from the current directory and accepts env var overrides.

The installed binary is `cortex`. Use `cortex mcp` for local MCP clients that require stdio. That mode is query-only: it reads `CORTEX_DB_PATH`, exposes the MCP tools over stdin/stdout, and does not start syslog listeners, HTTP routes, retention purge, or storage-budget cleanup. Keep `cortex serve mcp` running somewhere for ingestion.

## One-line installer

```bash
curl -fsSL https://raw.githubusercontent.com/dinglebear-ai/cortex/main/install.sh | sh
```

The installer installs the `cortex` binary to `~/.local/bin/cortex`, then runs
`cortex setup`. Setup owns the shared Docker-only runtime layout:

| Path | Purpose |
| --- | --- |
| `~/.cortex/.env` | Runtime environment and generated token |
| `~/.cortex/compose/docker-compose.yml` | Installed Compose bundle using the published image |
| `~/.cortex/data/` | Default SQLite data bind mount |

Useful setup commands:

```bash
cortex setup          # first run or normal repair
cortex setup check    # inspect prerequisites and files only
cortex setup repair   # rewrite managed assets and restart Compose
cortex setup deploy preflight       # operator-facing preflight
cortex setup deploy local           # operator-facing local deploy/reconcile
cortex setup deploy local --dry-run # preflight without Docker mutation
cortex setup deploy remote host-a --dry-run # SSH preflight for a remote Compose host
cortex setup deploy remote host-a           # SSH deploy/reconcile on a remote host
set -a && source deploy/hosts.env && set +a
scripts/check-deploy-hosts.sh
cortex setup deploy remote --home /mnt/cache/appdata/cortex "$NAS_HOST"
```

`cortex setup` also disables and removes stale user-level
`cortex.service` units/drop-ins from older releases. The supported
automated deployment path is Docker Compose only.

### Remote CLI Deploy

`cortex setup deploy remote <host>` writes/replaces `.env`, the managed Compose
YAML, and `config/Dockerfile` under the selected remote home, then runs Docker
Compose there. The default remote home is `~/.cortex`; pass `--home PATH` for
hosts whose runtime lives elsewhere. After the server profile exists, the normal
update workflow is:

```bash
cortex update --dry-run
cortex update
```

`cortex setup deploy remote --home /mnt/cache/appdata/cortex "$NAS_HOST"` remains the
low-level primitive and a useful escape hatch. A successful low-level remote
deploy records the server profile so later updates do not repeat host/home
details; otherwise configure it with
`cortex update config server --host HOST --home PATH`.

Client-agent updates preserve the existing remote heartbeat-agent env and fail
if the saved token cannot be read or preserved. Use
`cortex setup deploy agent --heartbeat-token-file PATH` for first-time client
bootstrap or token repair, then return to `cortex update clients`.

Use `--dry-run` first to verify SSH and Docker prerequisites. Non-dry-run remote
deploy preserves existing remote env values from `<home>/.env` or the legacy
`<home>/compose/.env` path, but it intentionally drops `CORTEX_VERSION` so the
release-managed Compose template owns the image tag. After migration, the legacy
compose-local env file is archived as `<home>/compose/.env.legacy`; `<home>/.env`
is the canonical runtime env.

Deploy mutations remain CLI-only. MCP exposes only redacted read-only Compose
diagnostics.

## Docker

The Docker image is daemon-focused: it runs `cortex serve mcp` for syslog ingest and HTTP MCP. Direct stdio is intended for host-installed binaries where the MCP client can launch `cortex mcp` and read the SQLite DB path directly.

### Build

Multi-stage Dockerfile: Rust 1.86 builder compiles the release binary, Debian bookworm-slim runtime copies only the binary.

```bash
just docker-build
# or: docker build -t cortex .
```

### Compose

```yaml
services:
  cortex:
    build: .
    container_name: cortex
    restart: unless-stopped
    user: "${CORTEX_UID:-1000}:${CORTEX_GID:-1000}"
    env_file:
      - path: ~/.claude-homelab/.env
        required: false
    ports:
      - "${CORTEX_RECEIVER_PORT:-1514}:1514/udp"
      - "${CORTEX_RECEIVER_PORT:-1514}:1514/tcp"
      - "${CORTEX_PORT:-3100}:3100/tcp"
    volumes:
      - ${CORTEX_DATA_VOLUME:-cortex-data}:/data
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:3100/health || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    deploy:
      resources:
        limits:
          memory: ${CORTEX_MEMORY_LIMIT:-2G}
          cpus: '${CORTEX_CPU_LIMIT:-1.0}'
```

```bash
just up         # docker compose up -d
just down       # docker compose down
just restart    # docker compose restart
just logs       # docker compose logs -f
```

The installed `cortex` binary also provides guarded lifecycle diagnostics and mutations:

```bash
cortex compose doctor
cortex compose status --json
cortex compose pull
cortex compose up
cortex compose restart
cortex compose logs --tail 50
```

MCP exposes only redacted read-only Compose diagnostics (`compose_status`, `compose_doctor`). Lifecycle mutations remain CLI-only: ask the assistant to run `cortex compose ...` locally rather than invoking MCP actions.

### Container conventions

| Concern | Pattern |
| --- | --- |
| Base image | `rust:1.86-slim-bookworm` (builder) + `debian:bookworm-slim` (runtime) |
| User | Non-root, UID 1000 (`cortex`) |
| Health check | `curl -sf http://localhost:3100/health` every 30s |
| Data | Named volume mounted at `/data` |
| Network | External Docker network (`${DOCKER_NETWORK:-cortex}`) |
| Signals | Graceful shutdown on SIGTERM/SIGINT (tokio signal handler) |
| Config | No `config.toml` in image -- defaults + env vars only |

### Entrypoint

The entrypoint is minimal -- it delegates directly to the binary:

```bash
#!/bin/bash
set -euo pipefail
exec "$@"
```

All configuration is handled by the Rust binary's config loading (defaults + env vars).

## Port assignment

| Service | Default Port | Env Var | Protocol |
| --- | --- | --- | --- |
| Syslog receiver | 1514 | `CORTEX_RECEIVER_PORT` | UDP + TCP |
| MCP HTTP server | 3100 | `CORTEX_PORT` | TCP |

Port 1514 is used instead of the standard syslog port 514 to avoid needing root or `CAP_NET_BIND_SERVICE`. Use iptables PREROUTING to redirect 514 to 1514 for devices that cannot be reconfigured.

## SWAG reverse proxy

Use `/config/nginx/proxy-confs/cortex.subdomain.conf` on the SWAG host, or an
equivalent nginx vhost, to expose MCP over HTTPS at `https://cortex.example.invalid/mcp`.

The MCP endpoint uses RMCP Streamable HTTP in stateless JSON-response mode.
Clients use `POST /mcp`; `GET` and `DELETE` on `/mcp` are not supported after
auth succeeds.

## See also

- [ENV.md](ENV.md) -- environment variables
- [LOGS.md](LOGS.md) -- logging configuration
- [CONNECT.md](CONNECT.md) -- client connection methods
