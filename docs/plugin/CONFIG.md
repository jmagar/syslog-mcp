# Plugin Settings -- syslog-mcp

Plugin configuration and user-facing settings for Claude Code plugin deployment.

## How it works

syslog-mcp ships one `syslog` binary with two MCP modes:

- `syslog serve mcp` -- long-lived daemon with syslog listener + MCP HTTP server.
- `syslog mcp` -- local query-only stdio MCP server.

The published Claude Code plugin remains HTTP-first because plugin installs commonly target a running Docker, systemd, or reverse-proxy deployment.

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

## Why the plugin defaults to HTTP

Syslog ingestion is daemon-oriented: something must listen on UDP/TCP and keep writing SQLite. Direct stdio is useful only when the MCP host can read the database path locally. For remote/Docker/plugin deployments, HTTP keeps the ingestion and query surfaces attached to the same running service.

## See also

- [PLUGINS.md](PLUGINS.md) -- plugin manifest reference
- [../CONFIG.md](../CONFIG.md) -- full configuration reference
