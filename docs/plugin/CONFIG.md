# Plugin Settings -- syslog-mcp

Plugin configuration, user-facing settings, and environment sync.

## Configuration layers

| Layer | File | Scope |
| --- | --- | --- |
| Plugin userConfig | `.claude-plugin/plugin.json` | Per-plugin settings prompted at install |
| Hook-synced .env | `.env` | Runtime environment variables |
| config.toml | `config.toml` | Local development overrides |
| Compiled defaults | `src/config.rs` | Fallback values |

## userConfig fields

When installed as a Claude Code plugin, users are prompted for:

| Field | Type | Sensitive | Description |
| --- | --- | --- | --- |
| `SYSLOG_MCP_URL` | string | no | Base URL of the syslog-mcp server |
| `SYSLOG_MCP_API_TOKEN` | string | yes | Bearer token for MCP authentication |

Sensitive fields are stored encrypted by Claude Code. The `sync-env.sh` hook writes these values to `.env` at session start.

## settings.json

syslog-mcp does not currently ship a `settings.json` for additional plugin settings beyond userConfig.

## See also

- [PLUGINS.md](PLUGINS.md) -- plugin manifest reference
- [HOOKS.md](HOOKS.md) -- sync-env hook that bridges userConfig to .env
- [../CONFIG.md](../CONFIG.md) -- full configuration reference
