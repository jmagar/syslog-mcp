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
SYSLOG_MCP_STORAGE__RETENTION_DAYS=90
SYSLOG_MCP_MCP__BIND=0.0.0.0:3100
```

Or edit `config.toml`.

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

## License

MIT
