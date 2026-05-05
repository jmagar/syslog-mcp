# Configuration Reference -- syslog-mcp

Complete configuration reference. syslog-mcp uses a three-layer config system: compiled defaults, `config.toml` overlay, environment variable overrides.

## Configuration precedence

Precedence (highest to lowest):
1. Environment variables (always win)
2. `config.toml` in the working directory (partial configs supported -- missing fields keep defaults)
3. Compiled defaults in `src/config.rs`

## config.toml

The TOML config file at the repo root is used for local development. It is **not** copied into the Docker image -- container deployments use defaults + env vars exclusively.

```toml
[syslog]
host = "0.0.0.0"
port = 1514
max_message_size = 8192

[storage]
db_path = "/data/syslog.db"
pool_size = 4
retention_days = 90
wal_mode = true
max_db_size_mb = 1024
recovery_db_size_mb = 900
min_free_disk_mb = 512
recovery_free_disk_mb = 768
cleanup_interval_secs = 60

[mcp]
host = "0.0.0.0"
port = 3100
server_name = "syslog-mcp"
allowed_hosts = ["syslog.example.com", "syslog.example.com:443"]
allowed_origins = ["https://syslog.example.com"]

[api]
enabled = false

[docker_ingest]
enabled = false
reconnect_initial_ms = 1000
reconnect_max_ms = 30000

[[docker_ingest.hosts]]
name = "edge-host-a"
base_url = "http://edge-host-a:2375"
allow_insecure_http = true
```

Bind host fields (`SYSLOG_HOST` and `SYSLOG_MCP_HOST`) must be hostnames or IP
addresses without `:` because their ports are configured separately.
`allowed_hosts` / `SYSLOG_MCP_ALLOWED_HOSTS` are RMCP Host-header allow-list
entries and may include `host:port` values such as `syslog.example.com:443`.
`allowed_origins` / `SYSLOG_MCP_ALLOWED_ORIGINS` remain full browser origin URLs
such as `https://syslog.example.com`.

## Environment variables

### Syslog listener (`SYSLOG_*`)

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `SYSLOG_HOST` | no | `0.0.0.0` | no | Listen host for UDP+TCP syslog (no port -- use separate setting) |
| `SYSLOG_PORT` | no | `1514` | no | Listen port shared by UDP and TCP syslog listeners |
| `SYSLOG_MAX_MESSAGE_SIZE` | no | `8192` | no | Max message size in bytes per syslog frame |
| `SYSLOG_BATCH_SIZE` | no | `100` | no | Entries per batch flush to SQLite |
| `SYSLOG_FLUSH_INTERVAL` | no | `500` | no | Batch flush interval in milliseconds |

### Docker socket-proxy ingest (`SYSLOG_DOCKER_*`)

This optional mode pulls stdout/stderr logs from remote Docker hosts through `docker-socket-proxy` instead of changing Docker's daemon-level logging driver. Containers keep their existing local logging behavior, and remote host/container startup does not depend on syslog-mcp being online.

The hosts file is a TOML file with `[[hosts]]` entries:

```toml
[[hosts]]
name = "edge-host-a"
base_url = "http://edge-host-a:2375"
allow_insecure_http = true

[[hosts]]
name = "app-host-b"
base_url = "http://app-host-b:2375"
allow_insecure_http = true
```

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `SYSLOG_DOCKER_INGEST_ENABLED` | no | `false` | no | Enable pull-based Docker log ingestion |
| `SYSLOG_DOCKER_HOSTS_FILE` | yes, if hosts are not configured elsewhere | (none) | no | Path to TOML hosts file |
| `SYSLOG_DOCKER_RECONNECT_INITIAL_MS` | no | `1000` | no | Initial reconnect delay after host stream failure |
| `SYSLOG_DOCKER_RECONNECT_MAX_MS` | no | `30000` | no | Maximum reconnect delay after repeated failures |

Minimum recommended docker-socket-proxy permissions on each remote host:

```env
CONTAINERS=1
EVENTS=1
PING=1
VERSION=1
POST=0
```

`CONTAINERS=1` exposes the broader read-only Docker container API to every client that can reach docker-socket-proxy. Bind the proxy on a trusted private network, firewall it so only syslog-mcp can connect, or put it behind authenticated TLS. Hosts using plain `http://` must set `allow_insecure_http = true` in the hosts file; otherwise config validation rejects them.

### MCP server (`SYSLOG_MCP_*`)

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `SYSLOG_MCP_HOST` | no | `0.0.0.0` | no | HTTP listen host for MCP endpoint |
| `SYSLOG_MCP_PORT` | no | `3100` | no | HTTP listen port for MCP endpoint |
| `SYSLOG_MCP_TOKEN` | no | (none) | **yes** | Bearer token for `/mcp` auth. Generate: `openssl rand -hex 32`. When unset, auth is disabled. |
| `SYSLOG_MCP_ALLOWED_HOSTS` | no | (none) | no | Extra comma-separated Host header values for RMCP Host validation |
| `SYSLOG_MCP_ALLOWED_ORIGINS` | no | (none) | no | Extra comma-separated browser origins for RMCP Origin validation |

### Non-MCP API (`SYSLOG_API_*`)

The plain JSON API is disabled by default. When enabled, it is mounted under `/api/*` on the same HTTP listener and requires its own bearer token.

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `SYSLOG_API_ENABLED` | no | `false` | no | Enable the non-MCP JSON API |
| `SYSLOG_API_TOKEN` | yes, when enabled | (none) | **yes** | Bearer token for `/api/*` routes |

### Storage (`SYSLOG_MCP_*`)

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `SYSLOG_MCP_DB_PATH` | no | `/data/syslog.db` | no | Path to SQLite database file |
| `SYSLOG_MCP_POOL_SIZE` | no | `4` | no | SQLite connection pool size (must be > 0) |
| `SYSLOG_MCP_RETENTION_DAYS` | no | `90` | no | Days to retain logs before automatic hourly purge (0 = keep forever) |

### Storage budget (`SYSLOG_MCP_*`)

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `SYSLOG_MCP_MAX_DB_SIZE_MB` | no | `1024` | no | Soft limit for logical DB size in MB (0 = disable) |
| `SYSLOG_MCP_RECOVERY_DB_SIZE_MB` | no | `900` | no | Cleanup target after DB-size breach (must be < max) |
| `SYSLOG_MCP_MIN_FREE_DISK_MB` | no | `512` | no | Minimum free disk space in MB (0 = disable) |
| `SYSLOG_MCP_RECOVERY_FREE_DISK_MB` | no | `768` | no | Cleanup target after free-disk breach (must be > min) |
| `SYSLOG_MCP_CLEANUP_INTERVAL_SECS` | no | `60` | no | Storage budget enforcement interval in seconds (minimum 5) |
| `SYSLOG_MCP_CLEANUP_CHUNK_SIZE` | no | `2000` | no | Rows deleted per chunk during enforcement (1 to 1,000,000) |

### Logging

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `RUST_LOG` | no | `info` | no | Rust tracing filter directive. Examples: `debug`, `syslog_mcp=debug,tower_http=info`, `trace` |

### Docker / container

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `SYSLOG_UID` | no | `1000` | no | Container user ID |
| `SYSLOG_GID` | no | `1000` | no | Container group ID |
| `SYSLOG_PORT` | no | `1514` | no | Host-side syslog port mapping |
| `SYSLOG_MCP_PORT` | no | `3100` | no | Host-side MCP port mapping |
| `SYSLOG_MCP_DATA_VOLUME` | no | `syslog-mcp-data` | no | Named Docker volume for `/data` |
| `SYSLOG_MCP_CONFIG_VOLUME` | no | `./config` | no | Read-only config mount for optional files such as `docker-hosts.toml` |
| `DOCKER_NETWORK` | no | `syslog-mcp` | no | External Docker network name |

## Storage budget behavior

The storage budget is a two-threshold system with hysteresis to prevent oscillation:

1. **Trigger threshold**: When logical DB size exceeds `max_db_size_mb` or free disk drops below `min_free_disk_mb`, enforcement begins.
2. **Recovery target**: Oldest logs are deleted in chunks until logical DB size drops below `recovery_db_size_mb` and free disk rises above `recovery_free_disk_mb`.
3. **Write blocking**: If cleanup cannot recover enough space (e.g., no more logs to delete), the batch writer blocks new writes until storage becomes healthy.
4. **Enforcement interval**: Checked every `cleanup_interval_secs` seconds (default 60).

Set both `max_db_size_mb` and `min_free_disk_mb` to 0 to disable all storage enforcement.

## Validation rules

- `SYSLOG_MCP_POOL_SIZE` must be > 0
- `recovery_db_size_mb` must be > 0 and < `max_db_size_mb` when DB size guard is enabled
- `recovery_free_disk_mb` must be > 0 and > `min_free_disk_mb` when free-disk guard is enabled
- `cleanup_interval_secs` must be >= 5
- `cleanup_chunk_size` must be between 1 and 1,000,000
- `SYSLOG_API_TOKEN` is required when `SYSLOG_API_ENABLED=true`
- Bind host fields (`SYSLOG_HOST`, `SYSLOG_MCP_HOST`) must not contain a colon (port is a separate setting)
- `SYSLOG_MCP_ALLOWED_HOSTS` values may include `host:port` to match reverse-proxy Host headers
- `docker_ingest.hosts` or `SYSLOG_DOCKER_HOSTS_FILE` must contain at least one host when Docker ingest is enabled
- Docker ingest host names must be unique
- Docker ingest host `base_url` values must start with `http://` or `https://`
- Docker ingest `http://` hosts must set `allow_insecure_http = true`

## Plugin deployment

syslog-mcp runs as a daemon (syslog listener + HTTP MCP server), so the plugin connects via HTTP -- not stdio.

When installed as a Claude Code plugin, users are prompted for:

| Field | Sensitive | Description |
| --- | --- | --- |
| `syslog_mcp_url` | no | Full MCP endpoint URL (e.g. `https://syslog.example.com/mcp`) |
| `syslog_mcp_token` | yes | Bearer token for authentication |

These values are interpolated into `.mcp.json` via `${userConfig.*}` syntax. See [plugin/CONFIG.md](plugin/CONFIG.md) for details.

## .env.example conventions

- Group variables by section with comment headers
- Required variables first within each group
- No actual secrets -- use descriptive placeholders
- See `.env.example` at the repo root for the full template
