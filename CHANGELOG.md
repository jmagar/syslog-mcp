# Changelog

All notable changes to syslog-mcp are documented here.

## [Unreleased]

---

## [0.1.3] — 2026-03-28

### Fixed
- Clippy `type_complexity` errors: introduced `LogBatchEntry` type alias for the 8-field batch tuple (`src/db.rs`, `src/syslog.rs`)
- `ORDER BY timestamp` → `ORDER BY l.timestamp` for consistency with table alias in non-FTS search path
- `#[allow(dead_code)]` → `#[expect(dead_code, reason = "...")]` on `jsonrpc` field for self-cleaning lint suppression

### Changed
- Removed single-insert `insert_log` in favour of batch-only path via `insert_logs_batch`
- `search_logs` non-FTS path now uses `FROM logs l` alias, consistent with the FTS join path
- `syslog_loose::parse_message` updated to explicit `Variant::Either` API; timestamp handling simplified from 5-arm `IncompleteDate` match to direct `dt.to_rfc3339()`
- Removed unused imports (`NaiveDateTime`, `StreamExt`, `error`/`info` from tracing, `uuid`, `thiserror`, `axum-extra`, `tower`)
- Removed dead `idx += 1` at end of `tail_logs`

---

## [0.1.2] — 2026-03-27

### Added
- Project documentation (`SETUP.md`, `docs/`)
- Lavra project config and codebase profile (`.lavra/`)
- Beads issue tracking init (`.beads/`)
- Session doc for 2026-03-27 repo init and restructure

### Changed
- Updated Rust base image in `Dockerfile`

### Fixed
- Removed root-level source files after `src/` migration (duplicate artifact cleanup)

---

## [0.1.1] — 2026-03-27

### Changed
- Restructured project to standard Rust layout (`src/` modules)
- Migrated flat source files into `src/config.rs`, `src/db.rs`, `src/mcp.rs`, `src/syslog.rs`, `src/main.rs`

---

## [0.1.0] — 2026-03-27

### Added
- Initial release: syslog receiver + MCP server in Rust
- UDP + TCP syslog listeners on port 1514 (RFC 3164 / RFC 5424 / loose via `syslog_loose`)
- SQLite storage with FTS5 full-text index, WAL mode, and hourly retention purge
- Six MCP tools over JSON-RPC 2.0 (`POST /mcp`):
  - `search_logs` — FTS5 search with host/severity/app/time filters
  - `tail_logs` — most recent N entries
  - `get_errors` — error/warning summary grouped by host and severity
  - `list_hosts` — all known hosts with first/last seen and log counts
  - `correlate_events` — cross-host event correlation in a time window
  - `get_stats` — DB stats (total logs, size, time range)
- SSE endpoint (`GET /sse`) for legacy MCP transport
- Health check endpoint (`GET /health`)
- figment-based config (`config.toml` + `SYSLOG_MCP_` env vars)
- Docker Compose deployment with bind-mounted `./data/` volume
- Batch writer with mpsc channel, 100-entry batches, 500ms flush interval

---

[Unreleased]: https://github.com/jmagar/syslog-mcp/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/jmagar/syslog-mcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/jmagar/syslog-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jmagar/syslog-mcp/releases/tag/v0.1.0
