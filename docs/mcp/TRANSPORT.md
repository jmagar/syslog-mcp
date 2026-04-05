# Transport Methods Reference -- syslog-mcp

## Overview

syslog-mcp supports HTTP transport for MCP communication. It does not support stdio transport -- the binary is a long-running syslog receiver that must bind UDP/TCP ports, which is incompatible with stdio's parent-process model.

| Transport | Auth | Use Case | Default |
| --- | --- | --- | --- |
| HTTP (Streamable-HTTP) | Bearer token (optional) | Docker, remote servers, reverse proxy | yes |
| SSE (legacy) | Bearer token (optional) | Older MCP clients | available |

## HTTP transport

The MCP server listens on port 3100 (configurable via `SYSLOG_MCP_PORT`).

```bash
SYSLOG_MCP_HOST=0.0.0.0
SYSLOG_MCP_PORT=3100
SYSLOG_MCP_API_TOKEN=your-token-here   # optional
```

### Endpoints

| Endpoint | Method | Auth | Description |
| --- | --- | --- | --- |
| `/mcp` | POST | yes (when token set) | MCP JSON-RPC 2.0 endpoint |
| `/sse` | GET | yes (when token set) | Server-Sent Events stream (returns endpoint URL) |
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

## SSE transport (legacy)

The `/sse` endpoint returns a single SSE event with the MCP endpoint URL:

```
event: endpoint
data: /mcp
```

Older MCP clients use this to discover the JSON-RPC endpoint. Newer clients connect directly to `/mcp`.

### SSE proxy requirements

When running behind nginx/SWAG, configure SSE-compatible proxy settings:

```nginx
proxy_set_header Connection '';
proxy_http_version 1.1;
chunked_transfer_encoding off;
proxy_buffering off;
proxy_cache off;
```

Without these settings, nginx buffers SSE events and the connection appears to hang.

## Why no stdio transport

syslog-mcp is a dual-port server:
- Port 1514: UDP + TCP syslog receiver (must bind to receive logs)
- Port 3100: HTTP MCP server

stdio transport requires the MCP server to communicate exclusively over stdin/stdout with a parent process. A syslog receiver must bind network ports independently, making stdio unsuitable. Use HTTP transport with Docker or a direct binary for all deployments.

## Port assignment

| Service | Default Port | Env Var |
| --- | --- | --- |
| Syslog receiver (UDP + TCP) | 1514 | `SYSLOG_PORT` |
| MCP HTTP server | 3100 | `SYSLOG_MCP_PORT` |

## See also

- [AUTH.md](AUTH.md) -- bearer token setup for HTTP transport
- [ENV.md](ENV.md) -- transport-related environment variables
- [CONNECT.md](CONNECT.md) -- client connection methods
