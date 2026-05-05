# MCP Tools Reference -- syslog-mcp

## Design Philosophy

syslog-mcp exposes one read-only MCP tool named `syslog`. The required
`action` argument selects the operation:

| Action | Purpose |
| --- | --- |
| `search` | Full-text search with filters |
| `tail` | Recent log entries |
| `errors` | Error/warning summary by host and severity |
| `hosts` | Host registry with first/last seen |
| `correlate` | Cross-host event correlation in a time window |
| `stats` | Database statistics and storage health |
| `help` | Markdown reference for all actions |

## syslog search

Full-text search across all syslog messages. Uses SQLite FTS5 with porter stemming.

Required argument: `action = "search"`

Optional arguments: `query`, `hostname`, `source_ip`, `severity`, `app_name`, `from`, `to`, `limit`.

## syslog tail

Get the N most recent log entries. Equivalent to `tail -f` across all hosts.

Required argument: `action = "tail"`

Optional arguments: `hostname`, `source_ip`, `app_name`, `n`.

## syslog errors

Get a summary of errors and warnings across all hosts in a time window, grouped by hostname and severity.

Required argument: `action = "errors"`

Optional arguments: `from`, `to`.

## syslog hosts

List all hosts that have sent syslog messages.

Required argument: `action = "hosts"`

## syslog correlate

Search for related events across multiple hosts within a time window.

Required arguments: `action = "correlate"`, `reference_time`.

Optional arguments: `window_minutes`, `severity_min`, `hostname`, `source_ip`, `query`, `limit`.

## syslog stats

Get database statistics including storage health.

Required argument: `action = "stats"`

## syslog help

Return markdown documentation for all actions.

Required argument: `action = "help"`

## Error Responses

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

- `-32602`: Missing or invalid parameter, such as an unknown action or missing `reference_time`
- `-32601`: Unknown method
- `-32001`: Unauthorized, missing, or invalid bearer token

## See Also

- [SCHEMA.md](SCHEMA.md) -- JSON Schema definitions for tool inputs
- [AUTH.md](AUTH.md) -- authentication required before tool calls
- [ENV.md](ENV.md) -- environment variables affecting tool behavior
