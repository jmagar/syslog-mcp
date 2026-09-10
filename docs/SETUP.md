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
watcher resolves its watch targets once at startup and refuses to start when no
root exists, so install creates any missing root (`~/.claude/projects`,
`~/.codex/sessions`, `~/.gemini/tmp`, and both Antigravity `brain` roots) as a
private `0700` directory before the permission check. A provider installed
later then writes into a directory the running watcher already observes.
Existing roots are never modified; the setup permission check still reports
any root that is missing, not a directory, unreadable, unwritable, or owned by
another user.

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

## 10. macOS heartbeat agent

This is the authoritative operator contract for the macOS heartbeat agent.
Shorter examples elsewhere link here instead of duplicating lifecycle rules.

### Lifecycle commands and service identity

Run as the macOS user whose sessions are collected; do not use `sudo`:

```bash
cortex setup heartbeatagent install
cortex setup heartbeatagent check
cortex setup heartbeatagent remove
```

The installer manages one per-user LaunchAgent:

| Item | Contract |
| --- | --- |
| launchd label | `ai.dinglebear.cortex-heartbeat-agent` |
| launchd domain | `gui/$UID` |
| plist | `~/Library/LaunchAgents/ai.dinglebear.cortex-heartbeat-agent.plist` |
| private environment | `~/.cortex/heartbeat-agent.env` |
| stable service binary | `~/.local/lib/cortex/heartbeat-agent/cortex` |
| identity/checkpoints | retained under `~/.cortex/` |
| stdout/stderr | `~/.cortex/logs/heartbeat-agent.log` and `heartbeat-agent.error.log`; normal log rotates at 10 MiB |
| lifecycle lock | `~/.cortex/heartbeat-agent.lifecycle.lock` |
| migration journal | `~/.cortex/heartbeat-agent-migration.json` |

`install` validates configuration, stages the executable at the stable
Cortex-managed binary path reported by `check`, writes private state
atomically, bootstraps launchd, and verifies that the job is running. Re-running
it is an idempotent repair/upgrade. The plist never targets a Cargo build,
Homebrew Cellar version, temporary directory, or the invoking binary's path.

`check` is read-only. It checks ownership/modes, exact generated content,
managed-binary integrity, launchd registration and process state, recovery
state, and delivery freshness. Installation health and delivery health are
separate: a loaded process can still fail authentication or delivery.

```bash
cortex setup heartbeatagent check --json
```

`remove` boots out only the exact label in `gui/$UID`, then removes the plist
and managed service binary. It retains the environment, stable host ID,
checkpoints, lifecycle recovery records, and logs under `~/.cortex/` for replay
prevention and diagnosis. Delete retained state manually only for an intentional
identity/checkpoint reset; reinstalling after that can resend old records.

### GUI login and SSH semantics

A LaunchAgent belongs to an active Aqua login, not merely a Unix account. An
SSH session for the same user can manage `gui/$UID` only while that GUI session
exists. If it is absent, lifecycle commands fail with an instruction to log in
at the Mac; they never report false success. The service starts at GUI login
and is not promised before first login, at the FileVault screen, or after
logout.

### Environment, precedence, paths, and security

The managed environment is a strict data file, not a shell script. It permits
only documented `KEY=VALUE` assignments: no `export`, expansion, substitution,
duplicate recognized keys, NUL/newline values, or shell fragments. Unknown
non-sensitive keys are warned about and ignored; unknown token, secret, password,
loader, proxy, TLS, and certificate variables are rejected. Setup copies only
the heartbeat-agent allowlist. Explicit process values override values in
`~/.cortex/.env`; the generated `~/.cortex/heartbeat-agent.env` is launchd's
sole environment source.

Private configuration, tokens, checkpoints, journal, and plist are mode `0600`
inside directories mode `0700`; the executable is mode `0755` and atomically
staged in its user-owned directory. Managed files are not group/world writable.
`check` rejects wrong ownership, symlinks in managed
paths, and unsafe modes. Tokens never belong in the plist or command arguments.

- `CORTEX_HEARTBEAT_TOKEN` is the agent ingest credential. Setup may derive it
  from managed `CORTEX_TOKEN`; it must match the server ingest token.
- `CORTEX_TOKEN` protects static MCP, OTLP, heartbeat, and forwarding ingest.
- `CORTEX_API_TOKEN` is only for REST queries that prove delivered data is
  visible. It is not an ingest credential.

Prefer HTTPS. Plain HTTP is acceptable only on a trusted, access-controlled
overlay such as private Tailscale; the bearer is otherwise observable on the
path. A trusted overlay does not make shared Wi-Fi or a public listener safe.

### Capability matrix

Capabilities are explicit and default off unless stated otherwise:

| Capability | macOS support | Configuration and notes |
| --- | --- | --- |
| Heartbeat/system telemetry | yes, always | `CORTEX_HEARTBEAT_TARGET` plus ingest token |
| Claude/Codex/Gemini transcripts | yes | `CORTEX_AGENT_AI_TRANSCRIPT_FORWARD=true`; reads the current user's configured roots |
| Docker logs | conditional | `CORTEX_AGENT_DOCKER=true`; configure a supported Docker Desktop/OrbStack Unix socket with `CORTEX_AGENT_DOCKER_URL` |
| Shell history | opt-in | `CORTEX_AGENT_SHELL_HISTORY_FORWARD=true`; history may contain secrets |
| Agent command spool | opt-in | `CORTEX_AGENT_COMMAND_FORWARD=true`; path via `CORTEX_AGENT_COMMAND_SPOOL` |
| File tails/syslog files | opt-in | `CORTEX_AGENT_FILE_TAILS` / `CORTEX_AGENT_SYSLOG_FILE`; macOS file access must permit reads |
| journald | unavailable | macOS has no systemd journal; enabling `CORTEX_AGENT_JOURNALD` is rejected, not ignored |
| Auto-update | limited | `CORTEX_AGENT_AUTO_UPDATE`; subject to the publication boundary below |

Full Disk Access may be required for privacy-protected transcript, history, or
tail paths. Grant it to the stable managed binary, not a transient terminal.
Docker setup never weakens socket permissions or exposes unauthenticated TCP.

### Exact legacy migration and rollback

The legacy exact assignment `CORTEX_AGENT_AI_TRANSCRIPTS` migrates to
`CORTEX_AGENT_AI_TRANSCRIPT_FORWARD`. Only assignment lines are rewritten;
comments and longer keys are preserved. Equal old/new values collapse to the
canonical key. Conflicts stop for operator resolution. Boot out and remove the
old Python job `ai.dinglebear.cortex-transcript-forwarder` and
`~/Library/LaunchAgents/ai.dinglebear.cortex-transcript-forwarder.plist` only
after the canonical agent passes installation and delivery checks. During
install Cortex inventories that exact legacy job, stops it before canonical
bootstrap, and records whether it was loaded in the migration journal. It
restores the exact legacy job if canonical startup fails and retains the legacy
plist until live delivery is proven. It does not glob or stop similarly named
jobs. Never run both: duplicates and competing checkpoints make evidence
ambiguous.

To roll back, run `remove`, restore the previous private environment if needed,
install the prior known-good Cortex binary, then run `install` and `check`.
Retained identity/checkpoints make this a service rollback, not a data reset.

### Lock, journal, and interrupted-operation recovery

Lifecycle operations use `~/.cortex/heartbeat-agent.lifecycle.lock`; concurrent same-user
operations fail instead of interleaving binary, plist, environment, and launchd
changes. Migration state is journaled in
`~/.cortex/heartbeat-agent-migration.json`, and files use atomic replacement. The
next command detects an interrupted transaction and either safely recovers or
stops with manual instructions. Never delete a live lock. Treat one as stale
only after confirming its recorded process is gone, and retain the journal
until `check` reports consistency.

### Delivery proof, publication, and auto-update boundary

Passing installation phases is not end-to-end proof. Emit a unique marker for
each enabled source, observe a successful forwarding batch, then query the
server using `CORTEX_API_TOKEN` and verify marker, host ID, source kind, and
timestamp. Backlog movement does not prove the newest event arrived.

Setup installs the binary already present or an artifact supplied by the
release workflow; it does not publish releases. Auto-update is unavailable or
must fail closed without a macOS artifact and integrity-verifiable digest or
signature. HTTPS alone does not prove artifact provenance. Do not claim
auto-update until publication and the integrity chain are independently proven.

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
