# Comprehensive Code Review Report — syslog-mcp

**Review date:** 2026-03-28
**Branch:** `chore/add-lavra-project-config`
**Version:** v0.1.5
**Phases completed:** Code Quality, Architecture, Security, Performance, Testing, Documentation, Rust Best Practices, CI/CD

---

## Executive Summary

syslog-mcp is a well-scoped, architecturally honest Rust binary for homelab log intelligence. The concurrency model (Tokio + r2d2 sync pool + `spawn_blocking`), FTS5 integration, batch write pipeline, and graceful shutdown are all production-quality. The dependency graph is clean and acyclic.

Three structural gaps require immediate attention before this can be considered production-hardened: the MCP endpoint has no authentication with CORS fully open (enabling browser-pivot exfiltration), the FTS5 triggers run inside write transactions degrading write throughput and creating a data loss path during retention purges, and the codebase has zero automated tests making every change a leap of faith. Additionally, several one-line fixes have been documented in CLAUDE.md for months but never applied to the actual code (Dockerfile env prefix, container non-root user).

---

## Findings by Priority

### P0 — Critical: Must Fix Before Production Use

**[SEC-CRIT-01] Unauthenticated MCP endpoint + CORS `Allow-Origin: *`**
- **CVSS**: 9.1 | **CWE**: CWE-306
- Any webpage a LAN user visits can silently exfiltrate the entire log database via browser `fetch()`. Wildcard CORS makes this cross-site. Port 3100 serves all 6 tools with no token, IP filter, or rate limit.
- **Files**: `src/main.rs:66-70`, `src/mcp.rs:81-93`
- **Fix**: Replace `Allow-Origin: Any` with an explicit origin allowlist. Add 20-line bearer token middleware. Or: bind port to `127.0.0.1:3100` and let SWAG handle external auth.

**[PERF-CRIT-01] FTS5 triggers inside write transaction — data loss path during retention purge**
- FTS5 `logs_ai`/`logs_ad` triggers fire synchronously inside the batch insert transaction. Effective write ceiling: ~600-800 msg/s. During hourly retention purge (3.6M row delete at 90-day/1k msg/s), the write lock is held for 30-120 seconds. The batch writer times out after 5s, exceeds the 1,000-entry retention cap, and **discards data**.
- **Files**: `src/db.rs:111-122` (triggers), `src/db.rs:296-317` (purge)
- **Fix**: (1) Chunked DELETE (`LIMIT 10000` loop). (2) Replace threshold-rebuild with incremental FTS merge: `INSERT INTO logs_fts(logs_fts) VALUES('merge=-500,8')`. (3) Decouple FTS sync from write transaction: insert batch → commit → sync FTS in separate `spawn_blocking`.

**[TEST-CRIT-01] Zero automated tests**
- No `#[cfg(test)]` modules, no dev-dependencies. `parse_syslog`, `purge_old_logs`, `append_filters`, all 6 MCP tool handlers — untested. The smoke test requires a live server and only covers the happy path.
- **Fix**: Add `tempfile = "3"` to dev-deps. Write unit tests for `parse_syslog` (RFC 3164/5424 edge cases), `purge_old_logs` (retention correctness), `search_logs` (FTS error handling), `insert_logs_batch` (host aggregation). See Phase 3 for complete test code examples.

**[OPS-CRIT-01] Container runs as root**
- No `USER` directive in Dockerfile. Container compromise gives root in Docker namespace; bind-mounted `./data` is writable as root on host.
- **Files**: `Dockerfile`
- **Fix**: Add `RUN useradd --uid 10001 syslog && chown syslog /data` + `USER 10001:10001`. One Dockerfile addition.

**[OPS-CRIT-02] Dockerfile `SYSLOG_MCP__` double-underscore prefix — silently ignored**
- `ENV SYSLOG_MCP__STORAGE__DB_PATH` has no effect. figment strips `SYSLOG_MCP_` (single underscore) and uses `__` as the section/key separator. Any Dockerfile env override is silently discarded. Documented in CLAUDE.md since v0.1.5 but unfixed in the file.
- **Files**: `Dockerfile:24`
- **Fix**: `ENV SYSLOG_MCP_STORAGE__DB_PATH=/data/syslog.db` — one character.

**[CODE-CRIT-01] Unbounded TCP connections — OOM via connection flood**
- Every TCP connection spawns an unconstrained Tokio task. No idle timeout. A device making rapid reconnects or a malicious host can exhaust file descriptors and memory.
- **Files**: `src/syslog.rs:108-157`
- **Fix**: `Arc<Semaphore>` capped at 512 connections + `tokio::time::timeout(Duration::from_secs(300), ...)` per connection.

**[CODE-CRIT-02] No TCP message size limit — single connection causes OOM**
- `BufReader::lines()` reads until `\n` with no upper bound. `max_message_size` is applied to UDP but silently ignored for TCP. A 2GB line fills heap before returning.
- **Files**: `src/syslog.rs:118-139`
- **Fix**: Wrap TCP stream with `.take(max_message_size as u64)` before `BufReader`. Apply symmetrically to both transport paths.

**[SEC-CRIT-02] No CI/CD pipeline**
- No automated lint, test, security scan, or image build. Changes ship from developer machine with no gate. `cargo audit` never runs.
- **Fix**: GitHub Actions CI: `cargo fmt`, `cargo clippy -D warnings`, `cargo test`, `cargo audit`, Docker build. See Phase 4 for complete workflow YAML.

---

### P1 — High: Fix Before Next Release

**[SEC-HIGH-01] FTS5 query injection — complexity DoS + schema disclosure**
- `query` param passed verbatim to `MATCH ?1`. 28-term wildcard query pins SQLite for seconds. Invalid syntax leaks raw rusqlite error messages exposing schema details.
- **Fix**: Validate query length (≤512 chars) and term count (≤16). Return generic error to caller; log full detail server-side.

**[SEC-HIGH-02] Log injection poisons AI agent queries**
- Any LAN host can UDP-spoof syslog messages with arbitrary hostnames and inject prompt injection payloads into the log corpus. Log content is returned raw to AI agents consuming MCP output.
- **Fix**: Record actual sender IP as `source_ip` column. Document that log content is untrusted. Add optional hostname allowlist.

**[SEC-HIGH-03] Tool errors expose raw SQLite error strings**
- File paths, lock states, FTS5 internals forwarded verbatim to callers via `format!("Error: {e}")`.
- **Fix**: Log internally (`tracing::error!`); return generic `"Tool execution failed"` to callers.

**[CODE-HIGH-01] `LogBatchEntry` 8-tuple → named struct**
- Positional indexing (`entry.1`) is fragile. Field reordering silently corrupts data; all fields are `String`/`Option<String>` so the compiler can't detect swaps.
- **Fix**: `pub struct LogBatchEntry { pub timestamp: String, pub hostname: String, ... }`. Unify with `ParsedLog` from `syslog.rs`.

**[CODE-HIGH-02] Deprecated `chrono::Duration::days()` / `::minutes()`**
- Deprecated since 0.4.38. Clippy will escalate to errors with `-D warnings`.
- **Fix**: `chrono::TimeDelta::try_days(n).ok_or_else(|| anyhow!("overflow"))?`

**[CODE-HIGH-03] `execute_tool` 160-line match → extract per-tool functions**
- `correlate_events` arm is 80 lines of domain logic inside the transport handler. Untestable without HTTP infrastructure.
- **Fix**: `async fn tool_correlate_events(state, args) -> Result<Value>` per tool. Dispatch becomes a 10-line match.

**[CODE-HIGH-04] `serde_json::Value` from DB layer → typed structs**
- `get_error_summary`, `list_hosts`, `get_stats` return opaque `Value` objects. No compile-time field safety. Double-serialization in MCP layer.
- **Fix**: `ErrorSummaryEntry`, `HostEntry`, `DbStats` structs with `#[derive(Serialize)]`.

**[CODE-HIGH-05] `Box<dyn ToSql + '_>` → `rusqlite::types::Value` owned enum**
- Boxing + lifetime annotations in `append_filters` for no benefit. `rusqlite::types::Value` eliminates the lifetime parameter entirely.

**[OPS-HIGH-01] No health check in `docker-compose.yml`**
- Zombie process holding port is invisible to Docker. `/health` endpoint exists but is not wired.
- **Fix**: 5-line `healthcheck:` block using `curl -f http://localhost:3100/health`.

**[OPS-HIGH-02] No `.dockerignore` file**
- Build context includes `target/` (gigabytes), `data/` (live DB), `.env` files.
- **Fix**: Create `.dockerignore` excluding `target/`, `data/`, `.git/`, `.env*`, `*.db`.

**[OPS-HIGH-03] External `jakenet` network requires manual pre-creation**
- `docker compose up` fails on fresh clone with confusing error. No automation.
- **Fix**: Convert to internal bridge network, or add `scripts/setup.sh`.

**[OPS-HIGH-04] No resource limits on container**
- Unbounded memory and CPU. FTS5 runaway query or syslog flood can starve other homelab services.
- **Fix**: `deploy.resources.limits: memory: 512M, cpus: "1.0"`.

**[DOC-HIGH-01] No authentication or trust model documented**
- README/CLAUDE.md/SETUP.md don't mention the endpoint is unauthenticated. SETUP.md shows SWAG proxying it with no auth warning.
- **Fix**: "Security / Trust Model" section in README. Note in CLAUDE.md Gotchas.

**[DOC-HIGH-02] Retention purge data loss is undocumented**
- 90-day default silently deletes logs hourly. No user-facing warning.
- **Fix**: Add to README and CLAUDE.md: "90-day default, set to 0 to keep forever."

**[TEST-HIGH-01] `parse_syslog()` entirely untested — highest combinatorial risk**
- RFC 3164/5424 differences, severity/facility arithmetic, timestamp normalization, hostname fallback — all unverified.
- **Fix**: 8-10 unit tests covering the scenarios in Phase 3 test code examples.

**[TEST-HIGH-02] `purge_old_logs()` entirely untested — the only data-deletion function**
- Cutoff calculation bug could purge all logs. FTS rebuild branch never exercised outside production.
- **Fix**: 3 tests: purge deletes only old rows; `retention_days=0` is a no-op; `deleted > 1000` doesn't panic.

**[TEST-HIGH-03] `Config::load()` env var override untested**
- No regression test for the `SYSLOG_MCP_` prefix. Any figment refactor silently breaks all env overrides.
- **Fix**: Test that `SYSLOG_MCP_MCP__BIND=127.0.0.1:3200` changes `cfg.mcp.bind`.

---

### P2 — Medium: Plan for Next Sprint

**Performance**
- [PERF-MED-01] `get_stats` COUNT(*) on every `/health` probe — cache in `hosts` table sum
- [PERF-MED-02] Missing `(severity, timestamp)` composite index for `get_error_summary`
- [PERF-MED-03] WAL checkpoint never triggered explicitly — add `PRAGMA wal_autocheckpoint=500` at init; `wal_checkpoint(TRUNCATE)` in hourly maintenance
- [PERF-MED-04] `raw` column doubles storage cost with zero query value — consider dropping or isolating to `logs_raw` opt-in table
- [PERF-MED-05] `correlate_events` post-query grouping on async thread — move into `spawn_blocking` closure

**Security**
- [SEC-MED-01] Timestamp params (`from`/`to`) not validated — parse with `DateTime::parse_from_rfc3339` at boundary
- [SEC-MED-02] No request body size limit — `DefaultBodyLimit::max(65536)` on the router
- [SEC-MED-03] No MCP endpoint rate limiting / concurrency cap — `ConcurrencyLimitLayer::new(8)`
- [SEC-MED-04] Retention purge by device `timestamp` not `received_at` — devices with bad clocks cause unexpected early/late purge

**Code Quality**
- [CODE-MED-01] Backpressure state-machine duplicated in UDP and TCP handlers → `BackpressureGuard` struct
- [CODE-MED-02] `batch_size`/`flush_interval` hardcoded → add to `StorageConfig`
- [CODE-MED-03] `severity_to_num` in `mcp.rs` operates on `db::SEVERITY_LEVELS` → move to `db.rs`
- [CODE-MED-04] `let-else` for required argument extraction (Rust 1.65+)
- [CODE-MED-05] `expect()` in `shutdown_signal` → propagate error instead of panic

**Documentation**
- [DOC-MED-01] TCP framing comment falsely claims octet-counting support — correct to newline-only
- [DOC-MED-02] `config.toml` not read in Docker — only in CLAUDE.md, missing from README
- [DOC-MED-03] `correlate_events` 999 cap unexplained — document `limit+1` truncation sentinel
- [DOC-MED-04] Batch write failure data loss path undocumented — add to CLAUDE.md Gotchas
- [DOC-MED-05] WAL backup procedure incomplete — add checkpoint requirement and `sqlite3 .backup` example

**Testing**
- [TEST-MED-01] Timestamp range filtering untested — `from`/`to` boundary verification
- [TEST-MED-02] `correlate_events` error paths untested — missing `reference_time`, invalid RFC 3339, unknown `severity_min`
- [TEST-MED-03] `insert_logs_batch` host aggregation untested — multiple entries per host, empty batch

**Ops**
- [OPS-MED-01] No SQLite backup automation — `scripts/backup.sh` using `sqlite3 .backup`
- [OPS-MED-02] No rolling update / rollback runbook — `docs/runbooks/deploy.md`
- [OPS-MED-03] `config.toml` volume mount path mismatch — binary reads from CWD `/`, mount is at `/etc/syslog-mcp/`
- [OPS-MED-04] Smoke test not wired to CI — add compose-up + smoke test job

---

### P3 — Low: Track in Backlog

**Code**: `pub(crate)` visibility; `str::to_owned` idiom consistency; `tracing-subscriber` `json` feature unused; `futures` dep redundant with `tokio-stream`; inline `std::collections::` paths; TCP accept flat sleep → exponential backoff; `tokio = ["full"]` → enumerate features

**Security**: UDP source unauthenticated (hostname spoofable); `received_at` not used for retention; magic sentinel `"9999-12-31T23:59:59Z"` in `get_error_summary`; request body size limit

**Documentation**: `max_message_size` / `mcp.server_name` absent from `.env.example`; `jakenet` prereq missing from README Quick Start; SSE endpoint behavior undocumented; `raw` column storage impact undocumented; CLAUDE.md says `Cargo.lock` is gitignored but it's tracked; `[Unreleased]` CHANGELOG empty

**Ops**: Incomplete SWAG label; no Prometheus `/metrics` endpoint; no per-source UDP rate limiting; `Cargo.lock` CLAUDE.md inconsistency

---

## Findings by Category

| Category | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| Security | 2 | 3 | 4 | 3 | **12** |
| Performance | 1 | 2 | 5 | 4 | **12** |
| Code Quality | 2 | 5 | 5 | 6 | **18** |
| Architecture | 0 | 2 | 4 | 3 | **9** |
| Testing | 1 | 3 | 3 | 2 | **9** |
| Documentation | 0 | 2 | 5 | 5 | **12** |
| Rust Best Practices | 1 | 7 | 8 | 7 | **23** |
| CI/CD & DevOps | 2 | 4 | 4 | 4 | **14** |
| **Total** | **9** | **28** | **38** | **34** | **109** |

---

## Recommended Action Plan

### Immediate (this PR / next commit)

1. **Fix Dockerfile env prefix** [OPS-CRIT-02] — one character. `SYSLOG_MCP__` → `SYSLOG_MCP_`. 2 minutes.
2. **Add non-root user to Dockerfile** [OPS-CRIT-01] — 3 lines. Already documented, just not done.
3. **Add TCP connection semaphore** [CODE-CRIT-01] — ~15 lines. `Arc<Semaphore::new(512)>` + idle timeout.
4. **Apply TCP message size limit** [CODE-CRIT-02] — ~5 lines. `.take(max_message_size)` on stream before BufReader.
5. **Add `.dockerignore`** [OPS-HIGH-02] — new file, 10 lines.
6. **Add health check to docker-compose.yml** [OPS-HIGH-01] — 5 lines.

### Sprint 1 (1-2 weeks)

7. **Write first tests** [TEST-CRIT-01] — Add `tempfile` dev-dep. `parse_syslog` unit tests (8 cases). `purge_old_logs` tests (3 cases). `insert_logs_batch` host aggregation tests.
8. **CI pipeline** [OPS-CRIT-02] — `.github/workflows/ci.yml` with fmt/clippy/test/audit. ~50 lines YAML.
9. **Restrict MCP access** [SEC-CRIT-01] — Bearer token middleware OR bind to `127.0.0.1`. Either takes < 1 hour.
10. **`LogBatchEntry` named struct** [CODE-HIGH-01] — Unify with `ParsedLog`. Safe with tests in place from step 7.
11. **Chunked retention purge** [PERF-CRIT-01] — Replace bulk DELETE with `LIMIT 10000` loop + incremental FTS merge.
12. **FTS5 query validation** [SEC-HIGH-01] — Length cap + term count limit in `execute_tool`.
13. **Opaque error responses** [SEC-HIGH-03] — `tracing::error!` + generic caller message.
14. **WAL checkpoint in maintenance task** [PERF-MED-03] — `wal_checkpoint(TRUNCATE)` after purge; `wal_autocheckpoint=500` at init.
15. **Document trust model in README** [DOC-HIGH-01] — "Security" section.

### Sprint 2 (2-4 weeks)

16. **Extract per-tool functions from `execute_tool`** [CODE-HIGH-03] — Required for testability.
17. **Typed DB return structs** [CODE-HIGH-04] — `ErrorSummaryEntry`, `HostEntry`, `DbStats`.
18. **Timestamp validation at MCP boundary** [SEC-MED-01] — `parse_from_rfc3339` + UTC normalization.
19. **Backup automation** [OPS-MED-01] — `scripts/backup.sh` + cron.
20. **Resource limits in compose** [OPS-HIGH-04] — `deploy.resources.limits`.
21. **`correlate_events` test coverage** [TEST-MED-02] — Invalid args, missing required fields.
22. **Drop `raw` column** [PERF-MED-04] — Schema migration; cuts storage in half.

### Backlog

23. Deprecated `chrono::Duration` → `TimeDelta::try_*` [CODE-HIGH-02]
24. Trim Cargo.toml features (tokio full, axum ws, futures) [RS-H3/H4/L3]
25. `pub(crate)` visibility pass [RS-L1]
26. `BackpressureGuard` struct extraction [CODE-MED-01]
27. Composite `(severity, timestamp)` index [PERF-MED-02]
28. Source IP column for log injection provenance [SEC-HIGH-02]
29. Prometheus `/metrics` endpoint [OPS-L2]

---

## What the Codebase Gets Right

Before closing, worth naming what's solid:

- **Batch write pipeline** — the mpsc channel → `batch_writer` → `flush_batch` with time+size flushing, backpressure detection, retry-with-cap, and `std::mem::take` is production-quality work
- **FTS5 content-sync triggers** — correctly implemented; the `content=` and `content_rowid=` declarations are right
- **`hosts` materialized view** — avoids `GROUP BY hostname` scans via upsert during batch insert
- **`run_db` helper** — `spawn_blocking` abstraction is clean and used consistently across all 6 tools
- **Deferred read transaction in `get_stats`** — correctly isolates PRAGMA reads outside the transaction
- **Graceful shutdown** — both SIGTERM and SIGINT handled; retention purge task is properly managed
- **figment config layering** — `defaults → TOML → env` is the right order; env override semantics are correct (modulo the Dockerfile prefix bug)
- **Dependency graph** — clean, acyclic, no circular imports; all modules flow correctly toward `main.rs`
- **`anyhow::Result` consistency** — no mixed error types; error context chains are used where appropriate
- **Structured logging** — `tracing` with field-keyed values throughout; `RUST_LOG` is the right knob

The architecture is honest and appropriately scoped. The gaps are well-understood and fixable.
