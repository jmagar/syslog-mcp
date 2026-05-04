# MCP Tools Reference -- syslog-mcp

## Design philosophy

syslog-mcp exposes 6 independent MCP tools using a flat dispatch pattern. Each tool has its own name, input schema, and handler -- there is no action/subaction router. All tools are read-only.

| Tool | Purpose |
| --- | --- |
| `search_logs` | Full-text search with filters |
| `tail_logs` | Recent log entries |
| `get_errors` | Error/warning summary by host and severity |
| `list_hosts` | Host registry with first/last seen |
| `correlate_events` | Cross-host event correlation in a time window |
| `get_stats` | Database statistics and storage health |

## search_logs

Full-text search across all syslog messages. Uses SQLite FTS5 with porter stemming.

**Parameters:**

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `query` | string | no | -- | FTS5 search query. Examples: `kernel panic`, `OOM AND killer`, `"connection refused"`, `error*` |
| `hostname` | string | no | -- | Exact hostname match. Use `list_hosts` to enumerate. |
| `severity` | enum | no | -- | One of: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug` |
| `app_name` | string | no | -- | Application name (e.g. `sshd`, `dockerd`, `kernel`) |
| `from` | string | no | -- | Start of time range (ISO 8601, e.g. `2025-01-15T00:00:00Z`) |
| `to` | string | no | -- | End of time range (ISO 8601) |
| `limit` | integer | no | 100 | Max results (hard cap: 1000) |

**Response:**

```json
{
  "count": 3,
  "logs": [
    {
      "id": 42,
      "timestamp": "2025-01-15T14:30:00Z",
      "hostname": "tootie",
      "facility": "kern",
      "severity": "err",
      "app_name": "kernel",
      "process_id": null,
      "message": "Out of memory: Killed process 1234",
      "received_at": "2025-01-15T14:30:01.123Z",
      "source_ip": "10.0.0.5:54321"
    }
  ]
}
```

**FTS5 query syntax:**

| Pattern | Example | Meaning |
| --- | --- | --- |
| Simple words | `kernel panic` | Both terms in the message |
| AND | `OOM AND killer` | Explicit AND |
| OR | `kern OR syslog` | Either term |
| NOT | `error NOT nginx` | Exclude term |
| Phrase | `"connection refused"` | Exact phrase match |
| Prefix | `error*` | Prefix match |
| Hyphenated terms | `"smoke-test"` | Use phrase syntax (hyphen is FTS5 NOT operator) |

## tail_logs

Get the N most recent log entries. Equivalent to `tail -f` across all hosts.

**Parameters:**

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `hostname` | string | no | -- | Filter to a specific host |
| `app_name` | string | no | -- | Filter to a specific application |
| `n` | integer | no | 50 | Number of recent entries (max 500) |

**Response:**

```json
{
  "count": 50,
  "logs": [ /* same LogEntry shape as search_logs */ ]
}
```

## get_errors

Get a summary of errors and warnings across all hosts in a time window. Groups by hostname and severity level, showing counts.

**Parameters:**

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `from` | string | no | (all time) | Start of time range (ISO 8601) |
| `to` | string | no | (now) | End of time range (ISO 8601) |

**Response:**

```json
{
  "summary": [
    {"hostname": "tootie", "severity": "err", "count": 42},
    {"hostname": "dookie", "severity": "warning", "count": 17}
  ]
}
```

## list_hosts

List all hosts that have sent syslog messages.

**Parameters:** none

**Response:**

```json
{
  "hosts": [
    {
      "hostname": "tootie",
      "first_seen": "2025-01-01T00:00:00Z",
      "last_seen": "2025-01-15T14:30:00Z",
      "log_count": 150000
    }
  ]
}
```

## correlate_events

Search for related events across multiple hosts within a time window. Useful for debugging cascading failures.

**Parameters:**

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `reference_time` | string | **yes** | -- | Center timestamp (ISO 8601 / RFC 3339) |
| `window_minutes` | integer | no | 5 | Minutes before and after reference_time (max 60) |
| `severity_min` | enum | no | `warning` | Minimum severity to include. `warning` returns warning/err/crit/alert/emerg. `debug` returns everything. |
| `hostname` | string | no | -- | Limit correlation to a specific host |
| `query` | string | no | -- | FTS5 query to narrow results |
| `limit` | integer | no | 500 | Max total events (cap: 999) |

**Response:**

```json
{
  "reference_time": "2025-01-15T14:30:00Z",
  "window_minutes": 5,
  "window_from": "2025-01-15T14:25:00Z",
  "window_to": "2025-01-15T14:35:00Z",
  "severity_min": "warning",
  "total_events": 12,
  "truncated": false,
  "hosts_count": 3,
  "hosts": [
    {
      "hostname": "tootie",
      "event_count": 5,
      "events": [ /* LogEntry objects */ ]
    }
  ]
}
```

The limit parameter is capped at 999 (not 1000) because the implementation fetches `limit+1` rows to detect truncation, and the underlying `search_logs` hard-caps at 1000.

## get_stats

Get database statistics including storage health.

**Parameters:** none

**Response:**

```json
{
  "total_logs": 500000,
  "total_hosts": 6,
  "oldest_log": "2025-01-01T00:00:00Z",
  "newest_log": "2025-01-15T14:30:00Z",
  "logical_db_size_mb": "245.67",
  "physical_db_size_mb": "260.12",
  "free_disk_mb": "15360.00",
  "max_db_size_mb": 1024,
  "min_free_disk_mb": 512,
  "write_blocked": false,
  "phantom_fts_rows": 0
}
```

Fields:
- `logical_db_size_mb`: Active data size (page_count - freelist) in MB
- `physical_db_size_mb`: On-disk file size including WAL and freelist
- `free_disk_mb`: Available disk space on the database filesystem
- `write_blocked`: Whether the batch writer is currently blocked due to storage budget exhaustion
- `phantom_fts_rows`: FTS5 entries for deleted logs (cleaned up by periodic merge)

## Error responses

Errors follow the MCP content format with `isError: true`:

```json
{
  "content": [
    {"type": "text", "text": "Tool execution failed"}
  ],
  "isError": true
}
```

JSON-RPC level errors use standard codes:
- `-32602`: Missing required parameter (e.g., `correlate_events` without `reference_time`)
- `-32601`: Unknown method
- `-32001`: Unauthorized (missing or invalid bearer token)

## See also

- [SCHEMA.md](SCHEMA.md) -- JSON Schema definitions for tool inputs
- [AUTH.md](AUTH.md) -- authentication required before tool calls
- [ENV.md](ENV.md) -- environment variables affecting tool behavior
