# CLAUDE.md — syslog-mcp

Rust binary: syslog receiver (UDP/TCP) + MCP server for homelab log intelligence. Receives RFC 3164/5424 syslog from all homelab hosts, stores in SQLite with FTS5, exposes 6 MCP tools for AI agents.

## Commands

```bash
cargo build                      # debug build
cargo build --release            # release build
cargo run                        # run locally (reads config.toml)
cargo test                       # test suite
cargo clippy                     # lint (must pass before committing)
cargo fmt                        # format (enforced by CI)
docker compose up -d             # production deployment
docker compose down              # stop
docker compose logs -f           # follow logs
docker compose build             # rebuild image
```

## Architecture

Five modules in `src/`:

| Module | Purpose |
|--------|---------|
| `config.rs` | Config: `config.toml` + env vars (`SYSLOG_*` and `SYSLOG_MCP_*` prefixes) |
| `db.rs` | SQLite pool (r2d2 + rusqlite), FTS5 full-text index, schema init, retention purge |
| `syslog.rs` | UDP + TCP listeners, RFC 3164/5424 parsing via `syslog_loose`, mpsc batch writer |
| `mcp.rs` | Axum HTTP server, JSON-RPC 2.0 handler, all 6 MCP tool implementations |
| `main.rs` | Wires everything, starts hourly retention purge task, graceful shutdown |

Tests: 51 unit tests across `syslog.rs` (29), `db.rs` (18), `config.rs` (4). Run with `cargo test`.

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 1514 | UDP + TCP | Syslog receiver (not 514 — avoids `CAP_NET_BIND_SERVICE`) |
| 3100 | TCP | MCP HTTP endpoint (`POST /mcp`, `GET /health`, `GET /sse`) |

## MCP Tools

| Tool | Description |
|------|-------------|
| `search_logs` | Full-text search (FTS5 syntax) with host/severity/app/time filters |
| `tail_logs` | Recent N entries, optionally filtered by host/app |
| `get_errors` | Error/warning summary grouped by host and severity |
| `list_hosts` | All known hosts with first/last seen + log counts |
| `correlate_events` | Cross-host event correlation in a time window |
| `get_stats` | DB stats (total logs, size, time range) |

## Config

`config.toml` at repo root for local dev. **Not copied into Docker** — the Dockerfile was cleaned up (no COPY for config.toml). In Docker, defaults + env vars apply exclusively.

Two env var prefixes — `SYSLOG_*` for the listener, `SYSLOG_MCP_*` for the MCP server and storage:
```bash
# Syslog listener
SYSLOG_HOST=0.0.0.0              # host only, no port
SYSLOG_PORT=1514                 # shared by UDP + TCP
SYSLOG_MAX_MESSAGE_SIZE=8192
SYSLOG_BATCH_SIZE=100
SYSLOG_FLUSH_INTERVAL=500        # ms

# MCP server
SYSLOG_MCP_HOST=0.0.0.0
SYSLOG_MCP_PORT=3100
SYSLOG_MCP_API_TOKEN=your-secret-token  # optional; enables Bearer auth on /mcp

# Storage
SYSLOG_MCP_DB_PATH=/data/syslog.db
SYSLOG_MCP_POOL_SIZE=4
SYSLOG_MCP_RETENTION_DAYS=90     # 0 = keep forever

# Log verbosity (set to debug or trace for development)
RUST_LOG=info
```

## Key Files

| File | Purpose |
|------|---------|
| `config.toml` | Runtime config (syslog bind, DB path, retention) |
| `docker-compose.yml` | Production deployment (ports 1514, 3100) |
| `SETUP.md` | Per-host syslog forwarding (rsyslog, UniFi, ATT router, WSL) |
| `src/db.rs` | Schema definition, FTS5 table, all SQL queries |
| `src/mcp.rs` | All 6 MCP tool implementations |
| `config/mcporter.json` | mcporter config (HTTP transport to localhost:3100) |
| `scripts/smoke-test.sh` | Live smoke test — all 6 MCP tools via mcporter, strict 25-assertion PASS/FAIL |
| `scripts/backup.sh` | WAL-safe SQLite backup script (checkpoint + `.backup` method) |
| `CHANGELOG.md` | Version history; updated by `quick-push` on each release |
| `.lavra/memory/recall.sh` | Query the local knowledge DB: `bash .lavra/memory/recall.sh <keyword>` |

## Gotchas

- **Port 1514 not 514** — avoids needing root; use iptables PREROUTING to redirect 514→1514 for devices that can't be reconfigured (see SETUP.md)
- **Cargo.lock is tracked** — binary crates should commit Cargo.lock for reproducible builds (Cargo docs guidance)
- **FTS5 query syntax** — `search_logs` uses SQLite FTS5: `error AND nginx`, `"disk full"`, `kern OR syslog`; invalid FTS5 syntax returns a db error. **Hyphen is the FTS5 NOT operator** — to search for hyphenated terms, use phrase syntax: `"smoke-test"` not `smoke-test`
- **WAL mode** — SQLite runs in WAL mode; copying `.db`, `.db-wal`, and `.db-shm` together without a checkpoint captures potentially inconsistent state. Safe backup options: (1) run `PRAGMA wal_checkpoint(FULL);` first, then copy all three files, or (2) use `sqlite3 source.db '.backup dest.db'` which is WAL-safe and requires no manual checkpoint
- **SSE proxy** — nginx/SWAG must set `proxy_buffering off`, `chunked_transfer_encoding off`, and `proxy_http_version 1.1` for SSE (`GET /sse`) to stream correctly
- **Data volume** — DB lives in `./data/` (bind mount); `*.db` is gitignored so the database files won't be committed
- **Retention purge** — `retention_days` defaults to 90; logs older than 90 days are **permanently deleted hourly** with no recovery path. Set `SYSLOG_MCP_RETENTION_DAYS=0` to disable purging entirely.
- **CEF hostname vs source_ip** — For UniFi CEF messages, the stored `hostname` comes from the CEF `UNIFIdeviceName` extension field (message body), **not** the syslog header. Any LAN device can spoof this value. `source_ip` is the only network-verified identity. See `src/syslog.rs` parse_syslog for the trust boundary.
- **Batch writer failure** — If `insert_logs_batch` fails, the batch is retained for the next flush (up to 1000 entries, then discarded). A 250ms pause prevents hammering a failing DB. Persistent write failures will eventually cause data loss via the 10K-entry channel cap. The mpsc channel is in-memory only — no durable write-ahead log.
- **correlate_events limit cap** — The `limit` parameter is silently capped at 999 (not 1000) because the implementation fetches `limit+1` rows to detect truncation, and `search_logs` hard-caps at 1000.
- **Auth / trust model** — MCP endpoint is unauthenticated by default; any client reaching port 3100 has full log read access. Set `SYSLOG_MCP_API_TOKEN` to require Bearer auth. CORS is restricted to `localhost:3100` (browser-only; curl/mcporter unaffected). If exposing via SWAG/reverse proxy, add auth at the proxy layer or set the token. See README Security section for details.

## Testing MCP Tools

```bash
# Full smoke test (requires server running)
bash scripts/smoke-test.sh

# Using mcporter (project config at config/mcporter.json)
mcporter list syslog-mcp --config config/mcporter.json
mcporter call --config config/mcporter.json syslog-mcp.get_stats
mcporter call --config config/mcporter.json syslog-mcp.tail_logs n=10
mcporter call --config config/mcporter.json syslog-mcp.search_logs query=error limit=5

# Health check
curl http://localhost:3100/health

# Tail recent logs (raw JSON-RPC)
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tail_logs","arguments":{"n":10}}}'

# Search
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_logs","arguments":{"query":"error","limit":5}}}'

# Stats
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}'
```


<!-- BEGIN BEADS INTEGRATION v:1 profile:compact hash:f65d5d33 -->
## Issue Tracking with bd (beads)

This project uses **bd (beads)** for ALL issue tracking. Full beads context is injected by the session hook — see `bd --help` for complete command reference.

**Essential workflow:** `bd ready` → `bd update <id> --claim` → work → `bd close <id>`

Do NOT use markdown TODOs, TaskCreate, or external trackers. Always use `--json` for programmatic output. Link discovered work with `discovered-from` dependencies.

## Session Completion

Work is NOT complete until `git push` succeeds. The session-close hook enforces this checklist:
`git status` → `git add` → `git commit` → `bd dolt push` → `git push`

<!-- END BEADS INTEGRATION -->
