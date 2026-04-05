# Environment Variable Reference -- syslog-mcp

Concise reference. See [CONFIG.md](../CONFIG.md) for full documentation including config.toml overlay and validation rules.

## Syslog listener

| Variable | Required | Default | Description | Sensitive |
| --- | --- | --- | --- | --- |
| `SYSLOG_HOST` | no | `0.0.0.0` | Listen host for UDP+TCP syslog | no |
| `SYSLOG_PORT` | no | `1514` | Listen port (shared UDP and TCP) | no |
| `SYSLOG_MAX_MESSAGE_SIZE` | no | `8192` | Max message size in bytes | no |
| `SYSLOG_BATCH_SIZE` | no | `100` | Entries per batch flush | no |
| `SYSLOG_FLUSH_INTERVAL` | no | `500` | Batch flush interval in ms | no |

## MCP server

| Variable | Required | Default | Description | Sensitive |
| --- | --- | --- | --- | --- |
| `SYSLOG_MCP_HOST` | no | `0.0.0.0` | HTTP bind address | no |
| `SYSLOG_MCP_PORT` | no | `3100` | HTTP listen port | no |
| `SYSLOG_MCP_API_TOKEN` | no | (none) | Bearer token for `/mcp` and `/sse`. Generate: `openssl rand -hex 32` | **yes** |

## Storage

| Variable | Required | Default | Description | Sensitive |
| --- | --- | --- | --- | --- |
| `SYSLOG_MCP_DB_PATH` | no | `/data/syslog.db` | SQLite database file path | no |
| `SYSLOG_MCP_POOL_SIZE` | no | `4` | Connection pool size | no |
| `SYSLOG_MCP_RETENTION_DAYS` | no | `90` | Days before automatic purge (0 = forever) | no |

## Storage budget

| Variable | Required | Default | Description | Sensitive |
| --- | --- | --- | --- | --- |
| `SYSLOG_MCP_MAX_DB_SIZE_MB` | no | `1024` | Soft DB size limit in MB (0 = disable) | no |
| `SYSLOG_MCP_RECOVERY_DB_SIZE_MB` | no | `900` | Cleanup target after DB-size breach | no |
| `SYSLOG_MCP_MIN_FREE_DISK_MB` | no | `512` | Min free disk in MB (0 = disable) | no |
| `SYSLOG_MCP_RECOVERY_FREE_DISK_MB` | no | `768` | Cleanup target after free-disk breach | no |
| `SYSLOG_MCP_CLEANUP_INTERVAL_SECS` | no | `60` | Enforcement check interval in seconds | no |
| `SYSLOG_MCP_CLEANUP_CHUNK_SIZE` | no | `2000` | Rows deleted per chunk (1 to 1,000,000) | no |

## Logging

| Variable | Required | Default | Description | Sensitive |
| --- | --- | --- | --- | --- |
| `RUST_LOG` | no | `info` | Tracing filter directive (e.g. `debug`, `syslog_mcp=trace`) | no |

## Docker / container

| Variable | Required | Default | Description | Sensitive |
| --- | --- | --- | --- | --- |
| `SYSLOG_UID` | no | `1000` | Container user ID | no |
| `SYSLOG_GID` | no | `1000` | Container group ID | no |
| `DOCKER_NETWORK` | no | `syslog-mcp` | External Docker network name | no |

## Token generation

```bash
openssl rand -hex 32
```

Store the result in `SYSLOG_MCP_API_TOKEN` in your `.env` file.

## See also

- [AUTH.md](AUTH.md) -- how tokens are used for authentication
- [TRANSPORT.md](TRANSPORT.md) -- transport-specific variable usage
- [../CONFIG.md](../CONFIG.md) -- full configuration reference with validation rules
