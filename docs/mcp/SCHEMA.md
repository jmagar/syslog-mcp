# Tool Schema Documentation -- syslog-mcp

## Overview

syslog-mcp exposes one MCP tool named `syslog`. The required `action` argument selects the operation:

- `search`
- `tail`
- `errors`
- `hosts`
- `correlate`
- `stats`
- `help`

The schema is defined in `src/mcp/schemas.rs` as a `serde_json::json!()` object returned by `tool_definitions()`.

## Schema Pattern

```rust
json!({
    "name": "syslog",
    "description": "Query syslog-mcp logs with action-based subcommands...",
    "inputSchema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["search", "tail", "errors", "hosts", "correlate", "stats", "help"]
            },
            "query": { "type": "string" },
            "hostname": { "type": "string" },
            "severity": {
                "type": "string",
                "enum": ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
            },
            "limit": { "type": "integer" }
        },
        "required": ["action"]
    }
})
```

## Response Format

All tool responses use MCP text content blocks. The `text` field contains pretty-printed JSON:

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

Error responses add `"isError": true` or return an MCP invalid-params error for validation failures.

## Validation

Input validation happens in the action handlers, not only at the schema level:

- `action` is required and must be one of the supported actions
- `limit` values are capped at their action-specific maximum
- `severity` and `severity_min` are validated against known syslog levels
- `reference_time`, `from`, and `to` timestamps are parsed as RFC 3339 and normalized to UTC
- Unknown parameters are ignored

## See Also

- [TOOLS.md](TOOLS.md) -- tool reference with parameters and response shapes
- [PATTERNS.md](PATTERNS.md) -- code patterns for tool dispatch
