# Changelog

All notable changes to syslog-mcp are documented here.

## [Unreleased]

---

## [0.1.5] — 2026-03-28

### Fixed
- `syslog.rs`: Normalize stored timestamps to UTC (`dt.with_timezone(&Utc)`) — mixed-offset sources no longer misorder SQLite rows or break retention purges
- `smoke-test.sh`: `--url` flag now creates a temp mcporter config so health checks and tool calls always target the same server; guard `$2` dereference under `set -u`; fix `limit=0` boundary test that was silently passing `limit=1`
- `recall.sh`: Fix `--all --recent` ordering (archive first → newest entries last in `tail`); use `grep -F` for literal bead matching; fix auto-build to `source + kb_sync` (subprocess call was a no-op)
- `knowledge.jsonl`: Strip embedded shell command fragments from `content` and `bead` fields

### Changed
- `knowledge-db.sh`: Quoted temp file path in `sqlite3 .import`; consolidated 7→1 jq invocations per JSONL line and 2→1 per beads-import row
- `.gitignore`: Narrow `*.db` to `data/*.db` to avoid hiding fixture files
- `README.md` / `CLAUDE.md`: Correct env var prefix `SYSLOG_MCP__` → `SYSLOG_MCP_`
- `docker-compose.yml`: Switch network from internal `syslog-mcp` to external `jakenet`
- Session docs: blank lines after subsection headings; complete rollback command

---

## [0.1.4] — 2026-03-28

### Added
- Session docs for syslog host onboarding (tootie, dookie, squirts, steamy-wsl, vivobook-wsl) and systemd service cleanup

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

[Unreleased]: https://github.com/jmagar/syslog-mcp/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/jmagar/syslog-mcp/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/jmagar/syslog-mcp/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/jmagar/syslog-mcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/jmagar/syslog-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jmagar/syslog-mcp/releases/tag/v0.1.0
