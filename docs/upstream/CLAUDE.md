# Upstream Service Integration -- syslog-mcp

## Self-contained architecture

syslog-mcp has no upstream API dependency. Unlike other MCP servers that wrap an external service (Plex, Overseerr, Gotify), syslog-mcp **is** the service. It receives syslog messages directly via UDP/TCP, stores them in SQLite, and exposes them through MCP tools.

```
                No upstream API
                      ↓
  Syslog sources ──▶ syslog-mcp ──▶ MCP clients
  (rsyslog, UniFi,    (receiver +     (Claude Code,
   ATT router, etc.)   query server)   Codex, Gemini)
```

## Inbound data sources

Instead of an upstream API, syslog-mcp receives data from syslog sources:

| Source | Protocol | Configuration |
| --- | --- | --- |
| Linux hosts (rsyslog) | TCP or UDP | `/etc/rsyslog.d/99-remote.conf` |
| WSL hosts | TCP or UDP | rsyslog with Tailscale IP |
| UniFi Cloud Gateway | UDP | Settings > System > Remote Syslog |
| ATT BGW-320 Router | UDP | Diagnostics > Syslog > Remote Syslog |

See [SETUP.md](../../SETUP.md) for per-host configuration.

## Syslog protocol support

| Standard | Support |
| --- | --- |
| RFC 3164 (BSD syslog) | Full -- parsed by `syslog_loose` |
| RFC 5424 (IETF syslog) | Full -- parsed by `syslog_loose` |
| UniFi CEF (Common Event Format) | Partial -- hostname extracted from UNIFIdeviceName extension |

The `syslog_loose` crate performs lenient parsing that tolerates non-compliant messages common in homelab environments.

## Trust boundary

Syslog content is untrusted user-controlled data:
- `hostname`: claimed by the sender, spoofable via UDP
- `message`, `app_name`: arbitrary text from the sending device
- `source_ip`: actual network sender address (the only trustworthy identity)

All query parameters are SQL-parameterized. FTS5 queries use their own DSL (not SQL), preventing injection.

## No outbound credentials

syslog-mcp reads no `_URL`, `_API_KEY`, or similar environment variables for upstream connectivity. The only credential is the optional `SYSLOG_MCP_API_TOKEN` for inbound MCP authentication.

## Cross-references

- [../mcp/ENV.md](../mcp/ENV.md) -- environment variables (no upstream credentials)
- [../stack/ARCH.md](../stack/ARCH.md) -- architecture overview
- [../mcp/TOOLS.md](../mcp/TOOLS.md) -- MCP tools that query the stored data
- [../GUARDRAILS.md](../GUARDRAILS.md) -- input handling and trust boundaries
