# syslog-mcp

Homelab syslog receiver + MCP server. One Rust binary that:

1. **Receives syslog** (UDP + TCP, RFC 3164/5424) from all your hosts
2. **Stores** in SQLite with FTS5 full-text search
3. **Exposes MCP tools** for your AI agents to search, tail, and correlate logs

## MCP Tools

| Tool | Description |
|------|-------------|
| `search_logs` | Full-text search with host/severity/time filters (FTS5 syntax) |
| `tail_logs` | Recent N entries per host/app (like `tail -f` across all hosts) |
| `get_errors` | Error/warning summary grouped by host and severity |
| `list_hosts` | All known hosts with first/last seen + log counts |
| `correlate_events` | Cross-host event correlation in a time window |
| `get_stats` | Database stats (total logs, logical/physical size, free disk, write-block state, time range) |

## Quick Start

```bash
docker compose up -d
```

The compose file uses a `proxy` network (configurable via `DOCKER_NETWORK` env var, defaults to `syslog_mcp`). If attaching to an existing reverse-proxy network, set `DOCKER_NETWORK=your-network-name` in `.env`.
It also runs the container as a configurable UID/GID, defaulting to `1000:1000` via `SYSLOG_UID` and `SYSLOG_GID`.

Then configure each host to forward syslog to port 1514. See [SETUP.md](SETUP.md).

## MCP Endpoint

```
POST https://syslog-mcp.tootie.tv/mcp    (via SWAG)
POST http://<host>:3100/mcp               (direct)
```

## Config

Environment variables use two prefixes — `SYSLOG_*` for the syslog listener, `SYSLOG_MCP_*` for the MCP server and storage:

```bash
SYSLOG_HOST=0.0.0.0        # Syslog listener host
SYSLOG_PORT=1514            # Syslog listener port (UDP + TCP)
SYSLOG_MCP_HOST=0.0.0.0    # MCP HTTP server host
SYSLOG_MCP_PORT=3100        # MCP HTTP server port
SYSLOG_MCP_DB_PATH=/data/syslog.db
SYSLOG_MCP_RETENTION_DAYS=90   # logs older than this are permanently deleted hourly; set to 0 to keep forever
SYSLOG_MCP_MAX_DB_SIZE_MB=1024        # 0 = disable logical DB size guard
SYSLOG_MCP_RECOVERY_DB_SIZE_MB=900    # cleanup target after DB-size breach
SYSLOG_MCP_MIN_FREE_DISK_MB=512       # 0 = disable free-disk guard
SYSLOG_MCP_RECOVERY_FREE_DISK_MB=768  # cleanup target after free-disk breach
SYSLOG_MCP_CLEANUP_INTERVAL_SECS=60   # storage-budget enforcement interval
SYSLOG_UID=1000                       # Docker runtime user for bind-mounted data
SYSLOG_GID=1000                       # Docker runtime group for bind-mounted data
```

See `.env.example` for the complete list.

> **Warning:** `retention_days` defaults to 90. Logs older than 90 days are **permanently and irreversibly deleted hourly**. Set `SYSLOG_MCP_RETENTION_DAYS=0` to disable.

> **Warning:** The storage guardrail also performs **permanent oldest-first emergency deletion by `received_at`** when the DB exceeds `SYSLOG_MCP_MAX_DB_SIZE_MB` or the DB filesystem drops below `SYSLOG_MCP_MIN_FREE_DISK_MB`. If cleanup still cannot recover enough space, new syslog writes are blocked until storage becomes healthy again.

> **Note (Docker):** When running in Docker, `config.toml` is NOT read — the binary reads from CWD (`/`) and the TOML is at a different path. Use environment variables via `.env` instead.

> **Note (Bind mounts):** If you set `SYSLOG_MCP_DATA_VOLUME=./data`, ensure the host directory is writable by the configured `SYSLOG_UID`/`SYSLOG_GID`. With the default settings, that means `1000:1000`.

## SSE Endpoint

`GET /sse` is a legacy MCP transport stub. It returns a single SSE event with the `/mcp` endpoint URL and then closes — it is **not** a persistent event stream. MCP clients should use `POST /mcp` (Streamable HTTP) for all tool calls.

## Architecture

```
┌─────────────────────────────────────────────────┐
│              syslog-mcp (single binary)         │
│                                                 │
│  ┌──────────┐   ┌─────────┐   ┌─────────────┐  │
│  │ Syslog   │──▶│ Batch   │──▶│   SQLite    │  │
│  │ UDP/TCP  │   │ Writer  │   │   + FTS5    │  │
│  │ Listener │   │ (mpsc)  │   │             │  │
│  └──────────┘   └─────────┘   └──────┬──────┘  │
│                                      │         │
│                               ┌──────▼──────┐  │
│                               │  MCP Server │  │
│                               │  (Axum HTTP)│  │
│                               └─────────────┘  │
└─────────────────────────────────────────────────┘
         ▲                              │
    syslog from                    MCP tools to
    all hosts                      your agents
```

## Security / Trust Model

The MCP endpoint is designed for **homelab-internal use**. It exposes your log data and should be treated accordingly.

### Authentication

Optional Bearer token auth is supported. Set the `SYSLOG_MCP_API_TOKEN` env var to require a token on all requests:

```bash
SYSLOG_MCP_API_TOKEN=your-secret-token
```

When set, every request must include:

```
Authorization: Bearer your-secret-token
```

Without this env var set, the endpoint is **unauthenticated** — any client that can reach port 3100 has full read access to all logs.

### CORS

CORS is restricted to `localhost:3100`. This is a browser-side restriction only — it does not protect against `curl`, `mcporter`, or any non-browser client.

### Reverse Proxy Exposure

The SWAG config in [SETUP.md](SETUP.md) exposes the endpoint at `https://syslog-mcp.tootie.tv/mcp` with no auth layer at the proxy. If you use this config, you should either:

- Set `SYSLOG_MCP_API_TOKEN` so the service enforces auth itself, **or**
- Add authentication at the SWAG layer (e.g. `auth_basic`, Authelia, or IP allowlist)

**Do not expose this service to the public internet without one of the above in place.**

### Summary

| Scenario | Recommendation |
|----------|---------------|
| LAN-only, no SWAG | No action required; trust your LAN |
| Exposed via SWAG/reverse proxy | Set `SYSLOG_MCP_API_TOKEN` or add proxy-layer auth |
| Public internet exposure | Set token **and** add proxy-layer auth |

## Backup

The database runs in WAL mode. Copying `.db`, `.db-wal`, and `.db-shm` together without a checkpoint can capture inconsistent state if writes are in progress. Use one of these safe approaches:

```bash
# Option 1: checkpoint first, then copy all three files
sqlite3 /data/syslog.db 'PRAGMA wal_checkpoint(FULL);'
cp /data/syslog.db /data/syslog.db-wal /data/syslog.db-shm /backup/

# Option 2: WAL-safe online backup (no manual checkpoint needed)
sqlite3 /data/syslog.db ".backup /backup/syslog.db"
```

## Deployment

See `SETUP.md` for per-host syslog forwarding setup and `scripts/backup.sh` for WAL-safe backup procedures.

## License

MIT
