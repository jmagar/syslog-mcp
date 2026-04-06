# Plugin Settings -- syslog-mcp

Plugin configuration and user-facing settings for Claude Code plugin deployment.

## How it works

syslog-mcp is a Rust binary that runs as a long-lived daemon (syslog listener + MCP HTTP server). The plugin connects via HTTP transport, not stdio.

Credentials flow through two files:

1. **`plugin.json`** -- declares `userConfig` fields that Claude Code prompts for at install time
2. **`.mcp.json`** -- references those fields as `${userConfig.<key>}` in the URL and headers

```
plugin.json userConfig (user enters values)
  --> .mcp.json (${userConfig.*} interpolated by Claude Code)
    --> HTTP connection to running syslog-mcp server
```

The syslog-mcp server must be running separately (Docker Compose or systemd). The plugin only connects to it.

## userConfig fields

| Field | Type | Sensitive | Description |
| --- | --- | --- | --- |
| `syslog_mcp_url` | string | no | Full MCP endpoint URL (e.g. `https://syslog.example.com/mcp`) |
| `syslog_mcp_token` | string | yes | Bearer token for MCP authentication (leave empty if auth disabled) |

Sensitive fields are stored encrypted by Claude Code and masked in the UI.

## Why HTTP (not stdio)

syslog-mcp is fundamentally a daemon: it listens on UDP/TCP for syslog messages and stores them in SQLite. It cannot run as a short-lived stdio process. The plugin connects to a running instance over HTTP.

## See also

- [PLUGINS.md](PLUGINS.md) -- plugin manifest reference
- [../CONFIG.md](../CONFIG.md) -- full configuration reference
