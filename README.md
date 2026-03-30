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
| `get_stats` | Database stats (total logs, size, time range) |

## Quick Start

```bash
docker compose up -d
```

The compose file uses a `proxy` network (configurable via `DOCKER_NETWORK` env var, defaults to `syslog_mcp`). If attaching to an existing reverse-proxy network, set `DOCKER_NETWORK=your-network-name` in `.env`.

Then configure each host to forward syslog to port 1514. See [SETUP.md](SETUP.md).

## MCP Endpoint

```
POST https://syslog-mcp.tootie.tv/mcp    (via SWAG)
POST http://<host>:3100/mcp               (direct)
```

## Config

Environment variables (prefix `SYSLOG_MCP_`, double underscore for nesting within sections):

```bash
SYSLOG_MCP_SYSLOG__UDP_BIND=0.0.0.0:1514
SYSLOG_MCP_STORAGE__DB_PATH=/data/syslog.db
SYSLOG_MCP_STORAGE__RETENTION_DAYS=90   # logs older than this are permanently deleted hourly; set to 0 to keep forever
SYSLOG_MCP_MCP__BIND=0.0.0.0:3100
```

> **Warning:** `retention_days` defaults to 90. Logs older than 90 days are **permanently and irreversibly deleted hourly**. Set `SYSLOG_MCP_STORAGE__RETENTION_DAYS=0` to disable.

> **Note (Docker):** When running in Docker, `config.toml` is NOT read — the binary reads from CWD (`/`) and the TOML is copied to `/etc/syslog-mcp/` which is not CWD. Use environment variables (`SYSLOG_MCP_` prefix) or the `docker-compose.yml` environment block instead. Editing `config.toml` has no effect in Docker.

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

As of v0.1.6, optional Bearer token auth is supported. Set the `SYSLOG_MCP_MCP__API_TOKEN` env var to require a token on all requests:

```bash
SYSLOG_MCP_MCP__API_TOKEN=your-secret-token
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

- Set `SYSLOG_MCP_MCP__API_TOKEN` so the service enforces auth itself, **or**
- Add authentication at the SWAG layer (e.g. `auth_basic`, Authelia, or IP allowlist)

**Do not expose this service to the public internet without one of the above in place.**

### Summary

| Scenario | Recommendation |
|----------|---------------|
| LAN-only, no SWAG | No action required; trust your LAN |
| Exposed via SWAG/reverse proxy | Set `SYSLOG_MCP_MCP__API_TOKEN` or add proxy-layer auth |
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

See [docs/runbooks/deploy.md](docs/runbooks/deploy.md) for rolling update and rollback procedures.

## License

MIT
