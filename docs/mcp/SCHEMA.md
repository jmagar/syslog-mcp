# Tool Schema Documentation -- syslog-mcp

## Overview

Tool schemas define the input validation contract for MCP tools. In syslog-mcp, schemas are defined as `serde_json::json!()` objects in `src/mcp.rs` within the `tool_definitions()` function. These follow JSON Schema conventions.

## Schema definition pattern

Each tool definition is a JSON object with `name`, `description`, and `inputSchema`:

```rust
json!({
    "name": "search_logs",
    "description": "Full-text search across all syslog messages...",
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "FTS5 search query..."
            },
            "hostname": {
                "type": "string",
                "description": "Filter by hostname..."
            },
            "severity": {
                "type": "string",
                "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"],
                "description": "Filter by syslog severity level"
            },
            "limit": {
                "type": "integer",
                "description": "Max results (default 100, max 1000)"
            }
        }
    }
})
```

## Parameter types

| JSON Schema type | Rust type | Extraction |
| --- | --- | --- |
| `"string"` | `Option<String>` | `args.get("key").and_then(\|v\| v.as_str()).map(String::from)` |
| `"integer"` | `u32` or `u64` | `args.get("key").and_then(\|v\| v.as_u64()).unwrap_or(default)` |
| `"string"` with `"enum"` | validated string | Checked against known values in handler |

## Response format

All tool responses use MCP text content blocks:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"count\": 3, \"logs\": [...]}"
    }
  ]
}
```

The `text` field contains pretty-printed JSON. Error responses add `"isError": true`.

## Database types

Request parameters are deserialized into `db::SearchParams`:

```rust
pub struct SearchParams {
    pub query: Option<String>,        // FTS5 query
    pub hostname: Option<String>,     // Exact match filter
    pub severity: Option<String>,     // Single severity
    pub severity_in: Option<Vec<String>>, // Multi-severity (correlate_events)
    pub app_name: Option<String>,     // App name filter
    pub from: Option<String>,         // ISO 8601 start
    pub to: Option<String>,           // ISO 8601 end
    pub limit: Option<u32>,           // Max results
}
```

Response types are serde-serializable structs:

| Struct | Used by |
| --- | --- |
| `LogEntry` | search_logs, tail_logs, correlate_events |
| `ErrorSummaryEntry` | get_errors |
| `HostEntry` | list_hosts |
| `DbStats` | get_stats |

## Validation

Input validation happens in the tool handler functions, not at the schema level:
- `limit` values are capped at their maximum (1000 for search, 500 for tail, 999 for correlate)
- `severity` is validated against the known severity level list
- `reference_time` is parsed as RFC 3339 and normalized to UTC
- `from` and `to` timestamps are parsed and validated for correctness
- Unknown parameters are silently ignored (JSON object properties are open by default)

## See also

- [TOOLS.md](TOOLS.md) -- tool reference with parameters and response shapes
- [PATTERNS.md](PATTERNS.md) -- code patterns for tool dispatch
