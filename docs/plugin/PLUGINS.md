<!--
plugin: syslog-mcp
surface: plugin-manifests
version: 0.6.0
-->

# Plugin Manifest Reference -- syslog-mcp

Structure and conventions for plugin manifest files.

## File locations

| File | Platform | Key fields |
| --- | --- | --- |
| `.claude-plugin/plugin.json` | Claude Code | name, version, tools, userConfig |
| `.codex-plugin/plugin.json` | Codex | name, version, description |
| `gemini-extension.json` | Gemini | mcpServers configuration |
| `server.json` | MCP Registry | name, packages, transport |

All manifests must have the same `version` value.

## .claude-plugin/plugin.json

```json
{
  "name": "syslog-mcp",
  "version": "0.6.0",
  "description": "Syslog management via MCP",
  "author": "jmagar",
  "repository": "https://github.com/jmagar/syslog-mcp",
  "license": "MIT",
  "keywords": ["syslog", "mcp", "logging", "homelab"],
  "tools": [
    "search_logs",
    "tail_logs",
    "get_errors",
    "list_hosts",
    "correlate_events",
    "get_stats",
    "syslog_help"
  ],
  "transport": "http",
  "port": 3100,
  "userConfig": {
    "SYSLOG_MCP_URL": {
      "type": "string",
      "title": "Syslog MCP URL",
      "description": "Base URL of the syslog-mcp server",
      "sensitive": false,
      "default": "https://syslog.tootie.tv/mcp"
    },
    "syslog_mcp_token": {
      "type": "string",
      "title": "API Token",
      "description": "Bearer token for authenticating MCP requests",
      "sensitive": true
    }
  }
}
```

## .codex-plugin/plugin.json

Contains name, version, description, and Codex-specific metadata.

## gemini-extension.json

Contains `mcpServers` configuration for Gemini CLI discovery.

## server.json

MCP Registry entry with OCI package reference:

```json
{
  "name": "tv.tootie/syslog-mcp",
  "title": "Syslog MCP",
  "version": "0.6.0",
  "packages": [
    {
      "registryType": "oci",
      "identifier": "ghcr.io/jmagar/syslog-mcp:0.6.0"
    }
  ]
}
```

## Version synchronization

All manifests must be updated together when bumping versions. Use `just publish [major|minor|patch]` to automate this.

## See also

- [MARKETPLACES.md](MARKETPLACES.md) -- marketplace publishing
- [CONFIG.md](CONFIG.md) -- plugin settings and userConfig
- [../mcp/PUBLISH.md](../mcp/PUBLISH.md) -- versioning strategy
