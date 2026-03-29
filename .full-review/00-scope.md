# Review Scope

## Target

Full codebase review of `syslog-mcp` — a Rust binary that receives RFC 3164/5424 syslog over UDP/TCP and exposes an MCP (Model Context Protocol) HTTP server with 6 tools for homelab log intelligence. SQLite backend with FTS5.

## Files

### Rust Source (primary review target)
- `src/main.rs` — entry point, wires all modules, hourly retention purge, graceful shutdown
- `src/config.rs` — figment-based config loading with env override and startup validation
- `src/db.rs` — SQLite pool (r2d2 + rusqlite), FTS5 full-text index, schema init, all SQL queries
- `src/mcp.rs` — Axum HTTP server, JSON-RPC 2.0 handler, 6 MCP tool implementations
- `src/syslog.rs` — UDP + TCP listeners, RFC 3164/5424 parsing, mpsc batch writer

### Configuration & Build
- `Cargo.toml` — package manifest and dependencies
- `config.toml` — runtime config (syslog bind, DB path, retention)
- `Dockerfile` — multi-stage Rust build, `rust:1.86-slim-bookworm`
- `docker-compose.yml` — production deployment

### Scripts & Tooling
- `scripts/smoke-test.sh` — end-to-end smoke test, 25 assertions
- `config/mcporter.json` — mcporter HTTP transport config

## Flags

- Security Focus: no
- Performance Critical: no
- Strict Mode: no
- Framework: rust (auto-detected)

## Tech Stack Context

- **Runtime**: Tokio async, Axum 0.8 HTTP
- **Database**: SQLite via rusqlite (bundled), r2d2 connection pool, FTS5
- **Syslog parsing**: syslog_loose 0.21
- **Config**: figment (TOML + env)
- **Logging**: tracing + tracing-subscriber

## Review Phases

1. Code Quality & Architecture
2. Security & Performance
3. Testing & Documentation
4. Best Practices & Standards
5. Consolidated Report
