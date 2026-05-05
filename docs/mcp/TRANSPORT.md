# Transport Methods Reference -- syslog-mcp

## Overview

syslog-mcp supports RMCP Streamable HTTP for MCP communication. It does not support direct stdio transport -- the binary is a long-running syslog receiver that must bind UDP/TCP ports, which is incompatible with stdio's parent-process model.

| Transport | Auth | Use Case | Default |
| --- | --- | --- | --- |
| RMCP Streamable HTTP, stateless JSON response | Bearer token (optional) | Docker, remote servers, reverse proxy | yes |
| Stateful Streamable HTTP sessions/SSE | n/a | Deferred; not enabled in this release | no |
| Direct stdio | n/a | Use an HTTP-to-stdio bridge such as `mcp-remote` | no |

## HTTP transport

The MCP server listens on port 3100 (configurable via `SYSLOG_MCP_PORT`).

```bash
SYSLOG_MCP_HOST=0.0.0.0
SYSLOG_MCP_PORT=3100
SYSLOG_MCP_TOKEN=your-token-here   # optional
```

### Endpoints

| Endpoint | Method | Auth | Description |
| --- | --- | --- | --- |
| `/mcp` | POST | yes (when token set) | RMCP Streamable HTTP JSON-response endpoint |
| `/mcp` | GET, DELETE | yes (when token set) | `405 Method Not Allowed` in stateless mode |
| `/health` | GET | no | Health check (unauthenticated) |

### Claude Code configuration

`.claude/settings.local.json`:

```json
{
  "mcpServers": {
    "syslog-mcp": {
      "type": "http",
      "url": "http://localhost:3100/mcp",
      "headers": {
        "Authorization": "Bearer your-token-here"
      }
    }
  }
}
```

### Codex CLI configuration

`.codex/mcp.json`:

```json
{
  "mcpServers": {
    "syslog-mcp": {
      "type": "http",
      "url": "http://localhost:3100/mcp",
      "headers": {
        "Authorization": "Bearer your-token-here"
      }
    }
  }
}
```

### Gemini CLI configuration

`gemini-extension.json`:

```json
{
  "mcpServers": {
    "syslog-mcp": {
      "type": "http",
      "url": "http://localhost:3100/mcp",
      "headers": {
        "Authorization": "Bearer your-token-here"
      }
    }
  }
}
```

## Stateless mode

The production server uses `StreamableHttpServerConfig::with_stateful_mode(false)` and `with_json_response(true)`. Request/response calls return `Content-Type: application/json` instead of SSE framing. Full stateful sessions with `Mcp-Session-Id`, `GET /mcp` SSE streams, and `DELETE /mcp` session cleanup are not enabled.

Raw HTTP clients must send:

```bash
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## Reverse proxy Host/Origin validation

RMCP validates the `Host` header to reduce DNS rebinding risk. Loopback hosts and the configured bind host are allowed by default. Add public names or proxy authorities with:

```bash
SYSLOG_MCP_ALLOWED_HOSTS=syslog.example.com,syslog.example.com:443
SYSLOG_MCP_ALLOWED_ORIGINS=https://syslog.example.com
```

## Why no stdio transport

syslog-mcp is a dual-port server:
- Port 1514: UDP + TCP syslog receiver (must bind to receive logs)
- Port 3100: HTTP MCP server

stdio transport requires the MCP server to communicate exclusively over stdin/stdout with a parent process. A syslog receiver must bind network ports independently, making stdio unsuitable. Use HTTP transport directly, or bridge stdio-only clients with `mcp-remote`:

```json
{
  "mcpServers": {
    "syslog-mcp": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:3100/mcp", "--transport", "http-only"]
    }
  }
}
```

## Port assignment

| Service | Default Port | Env Var |
| --- | --- | --- |
| Syslog receiver (UDP + TCP) | 1514 | `SYSLOG_PORT` |
| MCP HTTP server | 3100 | `SYSLOG_MCP_PORT` |

## See also

- [AUTH.md](AUTH.md) -- bearer token setup for HTTP transport
- [ENV.md](ENV.md) -- transport-related environment variables
- [CONNECT.md](CONNECT.md) -- client connection methods
