# Changelog

All notable changes to syslog-mcp are documented here.

## [0.1.9] — 2026-03-30

### Changed
- **Breaking: env var rename** — dropped figment's nested `SYSLOG_MCP_SECTION__KEY` format for flat `SYSLOG_*` and `SYSLOG_MCP_*` prefixes. See `.env.example` for the new names.
- `src/config.rs`: Replaced `figment` with `toml` crate + manual env var overlay — simpler, supports two prefixes
- `src/config.rs`: Merged `udp_bind`/`tcp_bind` into `host` + `port` (UDP and TCP always share the same address)
- `src/config.rs`: Renamed `flush_interval_ms` to `flush_interval`
- `docker-compose.yml`: Host-side ports use `${SYSLOG_PORT}` and `${SYSLOG_MCP_PORT}` env vars
- `docker-compose.yml`: Data volume uses `${SYSLOG_MCP_DATA_VOLUME}` (defaults to named volume `syslog-mcp-data`)
- `docker-compose.yml`: Replaced `environment:` block with `env_file: .env`
- `docker-compose.yml`: Removed SWAG labels; network uses `external: true`
- `Dockerfile`: `SYSLOG_MCP_STORAGE__DB_PATH` → `SYSLOG_MCP_DB_PATH`
- `Cargo.toml`: `figment` dependency replaced with `toml`

### Added
- `src/config.rs`: `SyslogConfig::bind_addr()` and `McpConfig::bind_addr()` helper methods
- `src/config.rs`: `validate_host()` rejects host strings containing ports
- `src/config.rs`: 2 new tests — `env_var_overrides_syslog_port`, `host_with_port_is_rejected`

---

## [0.1.7] — 2026-03-30

### Fixed
- `src/db.rs`: Retention purge now uses `received_at` (server clock) instead of `timestamp` (device clock) — prevents misconfigured device clocks from causing immediate purge or infinite retention (syslog-mcp-x6l)
- `src/db.rs`: Added composite `(severity, timestamp)` index for `get_error_summary` query performance (syslog-mcp-ctj)
- `src/db.rs`: `std::collections::HashMap` imported at module level instead of inline paths (syslog-mcp-rva)
- `src/mcp.rs`: `/health` endpoint now runs `SELECT 1` instead of `COUNT(*)` over entire logs table (syslog-mcp-068)
- `src/mcp.rs`: `severity_to_num` moved to `db.rs` as single source of truth (syslog-mcp-nu6)
- `src/mcp.rs`: 401 response uses JSON-RPC 2.0 envelope; replaced `futures` crate with `futures-core` (syslog-mcp-zr4)
- `src/syslog.rs`: TCP accept error now uses exponential backoff (100ms → 5s cap) instead of flat 100ms sleep (syslog-mcp-ve1)
- `src/syslog.rs`: `looks_like_timestamp` now validates digit positions, not just separator offsets (syslog-mcp-qus)
- `src/syslog.rs`: Removed false "octet-counting" claim from TCP listener doc comment (syslog-mcp-jsv)
- `src/syslog.rs`: Flush retry adds 250ms pause to avoid hammering a failing DB (syslog-mcp-rjt)
- `src/config.rs`: Renamed `parse_addr` to `validate_addr` for clarity (syslog-mcp-e5m)
- `scripts/smoke-test.sh`: `assert_no_error` now fails on non-JSON output instead of silently passing (syslog-mcp-tef)
- `Cargo.toml`: Removed unused `ws` feature from axum; removed unused `json` feature from tracing-subscriber (syslog-mcp-3ou, syslog-mcp-avg)
- `docker-compose.yml`: SWAG labels updated to `swag=enable` + url/port/proto format (syslog-mcp-j4m)

### Added
- `src/db.rs`: `PRAGMA wal_checkpoint(PASSIVE)` after hourly purge to prevent unbounded WAL growth (syslog-mcp-dah)
- `src/db.rs`: `pub fn severity_to_num()` for reuse across modules (syslog-mcp-nu6)
- `src/config.rs`: `batch_size` and `flush_interval_ms` fields in `SyslogConfig` with serde defaults (syslog-mcp-7uv)
- `src/db.rs`: 4 new unit tests — timestamp range filtering, severity_to_num edge cases, error summary severity filter, severity_in filter (syslog-mcp-063, syslog-mcp-v9r, syslog-mcp-3su, syslog-mcp-94p)
- `scripts/backup.sh`: WAL-safe SQLite backup script with cron scheduling and 30-day pruning (syslog-mcp-8zi)
- `docs/runbooks/deploy.md`: Rolling update, rollback, health check, and pre-deploy checklist (syslog-mcp-8np)
- `.env.example`: Added `max_message_size`, `batch_size`, `flush_interval_ms` documentation (syslog-mcp-vri)
- `README.md`: SSE endpoint stub behavior documented; Docker network prereq documented (syslog-mcp-3t7, syslog-mcp-7r4)
- `CLAUDE.md`: CEF hostname trust boundary, batch writer failure path, correlate_events 999 limit cap documented (syslog-mcp-dum, syslog-mcp-2oj, syslog-mcp-y1n)

---

## [0.1.6] — 2026-03-30

### Security
- `src/main.rs`: Redact `api_token` from startup log — log individual fields with `auth_enabled=bool` instead of printing full config struct (syslog-mcp-4yw)
- `src/mcp.rs`: Add optional Bearer token auth middleware; restrict CORS to localhost origins only (syslog-mcp-gm3)

### Fixed
- `Dockerfile`: Fix `ENV SYSLOG_MCP__STORAGE__DB_PATH` → `SYSLOG_MCP_STORAGE__DB_PATH` — double-underscore prefix was silently ignored by figment (syslog-mcp-s9b)
- `src/syslog.rs`: Drop TCP lines exceeding `max_message_size` to prevent OOM from unbounded lines (syslog-mcp-zu9)
- `src/syslog.rs`: Warn when CEF heuristic fires but all fields extract as None — malformed CEF body now emits a log line instead of silently falling back (syslog-mcp-w5e)
- `src/syslog.rs`: Cap TCP connections at 512 with semaphore + 300s wall-clock timeout per connection (syslog-mcp-ct2)
- `src/db.rs`: Chunked DELETE + incremental FTS merge to release WAL write-lock during retention purge (syslog-mcp-75i)
- `src/config.rs`: Replace blocking `to_socket_addrs()` DNS call with non-blocking `SocketAddr::parse()` at config load time
- `Dockerfile`: Run container as non-root user uid/gid 10001 (syslog-mcp-ab8)
- `.lavra/memory/recall.sh`: Remove stray `local` keyword outside function scope (syslog-mcp-1mg)

### Added
- `.github/workflows/ci.yml`: GitHub Actions CI — fmt check, clippy `-D warnings`, test, cargo audit (syslog-mcp-7ee)
- `src/db.rs`: 7 unit tests covering insert, FTS search, severity filter, purge, stats, host aggregation (syslog-mcp-sd0)
- `.env.example`: Document `SYSLOG_MCP_MCP__API_TOKEN` bearer token option

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

[Unreleased]: https://github.com/jmagar/syslog-mcp/compare/v0.1.7...HEAD
[0.1.7]: https://github.com/jmagar/syslog-mcp/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/jmagar/syslog-mcp/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/jmagar/syslog-mcp/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/jmagar/syslog-mcp/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/jmagar/syslog-mcp/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/jmagar/syslog-mcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/jmagar/syslog-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jmagar/syslog-mcp/releases/tag/v0.1.0
