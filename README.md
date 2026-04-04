# Syslog MCP

Rust syslog receiver and MCP server for homelab log intelligence. This repo ingests syslog over UDP/TCP, stores it in SQLite with FTS5 indexing, and exposes search, tail, error summary, correlation, and stats tools to MCP clients.

## What this repository ships

- `src/`: Rust server, ingestion, storage, HTTP, and MCP implementation
- `config/`: runtime configuration
- `SETUP.md`: deployment/setup notes
- `.claude-plugin/`, `.codex-plugin/`, `gemini-extension.json`: client manifests
- `Dockerfile`, `docker-compose*`: container deployment
- `tests/`: live and unit validation

## MCP surface

### Main tools

| Tool | Purpose |
| --- | --- |
| `search_logs` | Full-text search across syslog messages |
| `tail_logs` | Return the N most recent entries |
| `get_errors` | Summarize warnings/errors by host and severity |
| `list_hosts` | List known hosts with first/last seen timestamps |
| `correlate_events` | Search across hosts around a reference timestamp |
| `get_stats` | Database/storage stats and write-block state |
| `syslog_help` | Return markdown help for the MCP toolset |

## Installation

### Marketplace

```bash
/plugin marketplace add jmagar/claude-homelab
/plugin install syslog-mcp @jmagar-claude-homelab
```

### Local development

```bash
cargo build
cargo run
```

## Configuration

Create `.env` from `.env.example` and set:

```bash
SYSLOG_MCP_TOKEN=your_bearer_token
SYSLOG_MCP_PORT=8080
SYSLOG_MCP_TRANSPORT=http
NO_AUTH=false
ALLOW_DESTRUCTIVE=false
ALLOW_YOLO=false
SYSLOG_HOST=your-syslog-host
SYSLOG_PORT=514
SYSLOG_MCP_HOST=0.0.0.0
SYSLOG_MCP_DB_PATH=/data/syslog.db
SYSLOG_MCP_POOL_SIZE=4
SYSLOG_MCP_RETENTION_DAYS=90
RUST_LOG=info
```

Notes:

- the README previously hardcoded ports that did not match `.env.example`; use the explicit values in your deployment
- SQLite FTS5 is enabled through the bundled `rusqlite` feature set
- Bearer auth is optional but strongly recommended for HTTP exposure

## Development commands

```bash
just dev
just check
just lint
just fmt
just test
just build
just up
just logs
```

## Verification

Recommended:

```bash
just check
just lint
just test
```

Optional runtime verification:

```bash
just health
```

## Related files

- `Cargo.toml`: crate metadata and dependency surface
- `SETUP.md`: deployment setup
- `.env.example`: canonical runtime configuration
- `CHANGELOG.md`: release history

## License

MIT
