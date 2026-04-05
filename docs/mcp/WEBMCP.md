# Web MCP Integration -- syslog-mcp

Browser-accessible MCP endpoints and CORS configuration.

## CORS policy

syslog-mcp restricts CORS to localhost origins only:

```rust
CorsLayer::new()
    .allow_origin([
        "http://localhost:3100",
        "http://127.0.0.1:3100",
    ])
    .allow_methods([Method::POST, Method::GET])
    .allow_headers(Any)
```

## Why restricted CORS

MCP CLI clients (mcporter, curl, Claude Code) are not browser-based and ignore CORS entirely. The restriction only prevents malicious webpages visited by a LAN user from silently exfiltrating the log database via a cross-origin browser `fetch()`.

## Browser access patterns

### Allowed

- Local web dashboards served from `localhost:3100` or `127.0.0.1:3100`
- Direct navigation to `http://localhost:3100/health`

### Blocked

- Cross-origin requests from other origins (e.g., `http://evil.example.com`)
- Requests from other local ports (e.g., `http://localhost:8080`)

### Unaffected

- All non-browser clients (curl, mcporter, Claude Code, Codex, httpie)
- Reverse proxy requests (SWAG/nginx acts as the origin)

## Customizing CORS

CORS origins are currently hardcoded in `src/mcp.rs`. To allow additional origins:

1. Edit the `allow_origin` list in `src/mcp.rs`
2. Rebuild: `just build`

A future enhancement could make CORS origins configurable via environment variables.

## See also

- [AUTH.md](AUTH.md) -- bearer token authentication (required even with CORS access)
- [TRANSPORT.md](TRANSPORT.md) -- HTTP transport details
- [../GUARDRAILS.md](../GUARDRAILS.md) -- network security patterns
