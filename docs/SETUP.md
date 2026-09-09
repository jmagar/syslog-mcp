---
title: "Setup Guide -- cortex"
created: 2026-04-04
updated: 2026-07-30
---

# Setup Guide -- cortex

Step-by-step instructions to get cortex running locally, in Docker, or as a Claude Code plugin.

## Prerequisites

| Dependency | Version | Purpose |
| --- | --- | --- |
| Rust | 1.86+ | Compiler toolchain |
| cargo | (bundled) | Build system and package manager |
| Docker | 24+ | Container deployment |
| Docker Compose | v2+ | Orchestration |
| just | latest | Task runner |
| openssl | any | Token generation |
| curl | any | Health checks |
| jq | any | JSON parsing (optional, for readable output) |

## 1. Clone the repository

```bash
git clone https://github.com/dinglebear-ai/cortex.git
cd cortex
```

## 2. Install Rust toolchain

If Rust is not installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
```

## 3. Build

```bash
just build          # Debug build
just release        # Release build (optimized)
```

Or directly:

```bash
cargo build --release
```

## 4. Configure environment

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` and set values as needed:

```bash
# Syslog listener
CORTEX_RECEIVER_HOST=0.0.0.0
CORTEX_RECEIVER_PORT=1514

# MCP server (default bind is loopback; 0.0.0.0 requires CORTEX_TOKEN)
CORTEX_HOST=127.0.0.1
CORTEX_PORT=3100

# Required for non-loopback binds: bearer auth on /mcp and OTLP endpoints
#   openssl rand -hex 32
CORTEX_TOKEN=

# Storage
CORTEX_DB_PATH=/data/cortex.db
CORTEX_POOL_SIZE=8
CORTEX_SQLITE_PAGE_CACHE_MB=128
CORTEX_SQLITE_MMAP_MB=256
CORTEX_HEAVY_READ_CONCURRENCY=1
CORTEX_WAL_CHECKPOINT_MB=256
CORTEX_RETENTION_DAYS=90

# Log verbosity
RUST_LOG=info
```

See [CONFIG](CONFIG.md) for all environment variables.

### AI transcript roots

Local indexing and host-agent forwarding discover supported provider data only
under these bounded roots:

- Claude Code projects: `~/.claude/projects`
- Codex sessions and worktrees: `~/.codex/sessions` and `~/.codex/worktrees`
- Gemini CLI chats: `~/.gemini/tmp`
- Antigravity desktop projections: `~/.gemini/antigravity/brain`
- Antigravity CLI projections: `~/.gemini/antigravity-cli/brain`

Within either Antigravity root, Cortex accepts only the provider's redacted
`<session>/.system_generated/logs/transcript.jsonl` projection. It does not
read Antigravity conversation databases or unrelated generated/user-authored
brain artifacts. Skill, MCP, and hook lanes are reported according to what the
provider projection actually contains; Cortex does not infer unsupported
events.

On Linux, `cortex setup sessions-watch-service install` grants the hardened
user service read-only access to all five provider root families above. The
setup permission check covers both Antigravity roots as well as Claude, Codex,
and Gemini CLI.

## 5. Start locally

```bash
just dev
```

Or directly:

```bash
cargo run
```

The server reads `config.toml` in the working directory. Syslog listens on `0.0.0.0:1514` (UDP+TCP) and MCP on `127.0.0.1:3100` (HTTP) by default.

## 6. Start via Docker

```bash
just up
```

Or manually:

```bash
bash scripts/prepare-compose-dirs.sh
docker compose up -d
```

`prepare-compose-dirs.sh` resolves the configured `/backups` bind through
Compose and creates it at mode `0700`; this is required because Compose is not
allowed to silently create the host backup directory.

Docker uses defaults and env vars exclusively -- `config.toml` is not copied into the image.

## 7. Verify

```bash
just health
```

Or:

```bash
curl http://localhost:3100/health
```

Expected response:

```json
{"status": "ok"}
```

Send a test syslog message and confirm it arrives:

```bash
logger -n localhost -P 1514 --tcp "test from $(hostname)"

curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"tail","n":5}}}' | jq .
```

Optionally confirm the MCP Apps query widget resource is served (host-agnostic —
no UI client required):

```bash
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"ui://cortex/query-widget"}}' | jq -r '.result.contents[0].mimeType'
# Expected: text/html;profile=mcp-app
```

See the [MCP Apps query widget](../README.md#mcp-apps-query-widget) section for
what the widget does and how non-UI hosts are unaffected.

## 8. Install as Claude Code plugin

```bash
/plugin marketplace add jmagar/claude-homelab
/plugin install cortex @jmagar-claude-homelab
```

Configure the plugin with your MCP URL and optional API token when prompted.

## 9. Configure syslog sources

Per-host forwarder configuration (rsyslog, syslog-ng, WSL2, UniFi, routers/appliances, port-514 redirect, firewall rules) lives in the [README "Syslog Forwarder Setup" section](../README.md#syslog-forwarder-setup):

- **Linux hosts**: rsyslog `/etc/rsyslog.d/99-remote.conf`
- **WSL hosts**: rsyslog with Tailscale IP
- **UniFi**: Settings > System > Advanced > Remote Syslog
- **Routers/appliances**: device syslog settings (Diagnostics > Syslog on ATT BGW-320)
- **Docker hosts**: host-local cortex agent streams container logs from each host's local Docker socket; the legacy pull mode below is optional compatibility coverage

### Optional Docker host log ingest

The recommended deployment uses the host-local cortex agent, which reads Docker logs from `unix:///var/run/docker.sock` on each host and forwards them to cortex without changing Docker's daemon-level logging driver.

The `CORTEX_DOCKER_*` settings are a legacy central pull compatibility mode for explicit remote Docker Engine HTTP endpoints. If your hosts still expose a Docker-compatible endpoint, cortex can pull container logs from those hosts directly.

If the compatibility endpoint is docker-socket-proxy, expose only the read endpoints cortex needs:

```env
CONTAINERS=1
EVENTS=1
PING=1
VERSION=1
POST=0
```

Set `CORTEX_DOCKER_HOSTS` to a comma-separated list of hostnames in `.env`:

```env
CORTEX_DOCKER_INGEST_ENABLED=true
CORTEX_DOCKER_HOSTS=edgehost,nashost,devhost
```

Each hostname resolves to `http://<host>:2375`. Use only on trusted private networks (e.g. tailscale).

The ingest loop follows existing containers, listens for container start events, records checkpoints in SQLite, and reconnects with backoff if a host is unavailable. Remote containers still start normally if cortex is down because this path does not use Docker's daemon-level syslog logging driver.

Plain `http://` remote Docker endpoints require `allow_insecure_http = true`. Use that only on trusted private networks, firewall the endpoint so only cortex can connect, or put it behind authenticated TLS. `CONTAINERS=1` exposes Docker's broader read-only container API to anything that can reach a docker-socket-proxy, not just the log endpoints cortex calls.

For Docker ingest integration testing, keep the default smoke test focused on UDP/TCP syslog, REST/CLI parity, and file-tail ingest. Host-local agent Docker streaming is covered by agent deployment tests. For the legacy central pull path, start cortex with `CORTEX_DOCKER_INGEST_ENABLED=true` against a disposable Docker-compatible HTTP fixture, emit a unique marker from a short-lived container, then verify it with `search` or `tail`. Container stdout/stderr rows should report `source_ip` as `docker://<host>/<container>/<stream>`. Container lifecycle events such as `create`, `start`, `restart`, `die`, `stop`, `destroy`, `rename`, and `oom` should report `source_ip` as `docker-event://<host>/<container>/<action>`.

## Troubleshooting

### "Connection refused" on health check

- Confirm the server is running: `docker compose ps` or `ps aux | grep cortex`
- Verify `CORTEX_PORT` matches the port you are curling
- If running in Docker, remember port 3100 is published on `127.0.0.1` only by default — set `CORTEX_MCP_BIND=0.0.0.0` (plus `CORTEX_TOKEN`) to reach it from other hosts

### "401 Unauthorized" on tool calls

- Verify `CORTEX_TOKEN` in `.env` matches the token configured in your MCP client
- If behind a reverse proxy (SWAG), fix the token mismatch — keep `CORTEX_TOKEN` set and pass it through the proxy.

> **WARNING — do not "fix" a 401 by disabling auth.** Setting `CORTEX_NO_AUTH=true` + `CORTEX_TRUSTED_GATEWAY_NO_AUTH=true` (TrustedGatewayUnscoped) disables **both** authentication **and** the read/admin scope gates — including the write actions `ack_error`, `unack_error`, and `notifications_test`. Use it only when an upstream gateway enforces auth before traffic reaches cortex **and** port 3100 is not published beyond loopback (`CORTEX_MCP_BIND=127.0.0.1`, the default). Never combine it with host-published ports. See [docs/SECURITY.md](SECURITY.md).

### No syslog messages arriving

- Confirm the syslog port is reachable: `nc -zvu <host> 1514`
- Check iptables rules if redirecting 514 to 1514
- Verify rsyslog config on the sending host: `systemctl status rsyslog`
- Check Docker port mapping: `docker port cortex`

### Database errors at startup

- Ensure the data directory exists and is writable by UID 1000
- Check volume mounts: `docker inspect cortex | jq '.[0].Mounts'`
- Verify `CORTEX_DB_PATH` points to a writable location

### Plugin not discovered by Claude Code

- Run `/plugin list` and confirm cortex appears
- Check `~/.claude/plugins/cache/` for the plugin directory
- Re-run `/plugin marketplace add jmagar/claude-homelab` to refresh

---

## OAuth Authentication

cortex supports Google OAuth 2.0 in addition to the static bearer token. See **[docs/OAUTH.md](OAUTH.md)** for the full setup guide, including:

- Google Console configuration (redirect URI, credentials)
- Required env vars (`CORTEX_AUTH_MODE`, `CORTEX_PUBLIC_URL`, Google client ID/secret)
- `config.toml` fields for `admin_email`, TTLs, and signing key path
- Operator FAQ (revoking users, rotating the JWT key)
