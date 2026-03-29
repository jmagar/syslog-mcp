# Phase 1: Code Quality & Architecture Review

---

## Code Quality Findings

### Critical

**C1. Unbounded TCP connections — denial-of-service vector**
- **File**: `src/syslog.rs` ~line 112
- Every incoming TCP connection spawns a new Tokio task with no concurrency limit. A malicious or misconfigured host opening thousands of connections exhausts memory and file descriptors.
- **Fix**: Semaphore with `max_connections = 256` held for connection lifetime.

**C2. Silent listener death — syslog ingestion stops without alerting**
- **File**: `src/syslog.rs` ~lines 47-60
- UDP and TCP listener `JoinHandle`s are dropped. If a listener exits due to panic or bind failure, syslog ingestion silently dies while `/health` still returns OK (it only checks SQLite stats). The health endpoint cannot detect dead listeners.
- **Fix**: Return `JoinHandle`s from `start()`, `select!` on them in `main`, and trigger shutdown on any listener exit. Expose liveness in health response.

**C3. CORS `Allow-Origin: *` on MCP endpoint**
- **File**: `src/main.rs` ~lines 66-70
- Combined with no authentication, any browser tab on the network can query log data. Cross-site requests are fully permitted.
- **Fix**: Restrict CORS to known origins or remove it entirely (machine-to-machine API doesn't need browser CORS).

### High

**H1. No authentication or authorization on MCP endpoint**
- **File**: `src/mcp.rs` ~line 81
- All 6 MCP tools exposed unauthenticated. Log data contains hostnames, IPs, usernames from auth failures, app error details.
- **Fix**: Bearer token check via Axum middleware; `SYSLOG_MCP_MCP__AUTH_TOKEN` env var.

**H2. `LogBatchEntry` is an 8-element positional tuple**
- **File**: `src/db.rs` ~lines 13-22
- Primary interface between syslog parser and DB writer uses `entry.1` index access. Any reordering silently corrupts data; all fields are `String`/`Option<String>` so compiler can't catch swaps.
- **Fix**: Replace with `NewLogEntry` named struct. `ParsedLog` in `syslog.rs` already has the same shape — make it public and reuse, or introduce `db::NewLogEntry`.

**H3. String interpolation of `limit`/`n` values into SQL**
- **File**: `src/db.rs` ~lines 196, 211, 242
- `format!(" ORDER BY ... LIMIT {limit}")` — values are `u32` so no immediate injection risk, but establishes a dangerous pattern. If type ever changes to a user-controlled string, this becomes critical.
- **Fix**: Use parameterized binding for all SQL values.

**H4. Duplicated query-building and row-mapping logic**
- **File**: `src/db.rs` ~lines 179-247
- `search_logs` (two branches: FTS and non-FTS) and `tail_logs` all independently construct SQL with `WHERE 1=1`, append filter clauses, manage bind indexes, and map rows identically.
- **Fix**: Extract a `QueryBuilder` helper. FTS/non-FTS split only affects the `FROM` clause.

**H5. `execute_tool` is 160 lines with high cyclomatic complexity**
- **File**: `src/mcp.rs` ~lines 350-507
- `correlate_events` arm alone is ~100 lines: argument parsing, validation, date arithmetic, query, grouping, JSON. Untestable without HTTP infrastructure.
- **Fix**: Extract each tool into `handle_<tool>(state, args) -> Result<Value>`. Dispatch match becomes a 10-line router.

**H6. User-supplied timestamps not validated or normalized**
- **File**: `src/db.rs`, `src/mcp.rs`
- `search_logs` `from`/`to` passed through without normalization. `parse_syslog` can produce `+00:00` suffix instead of `Z`. String `BETWEEN` comparison breaks if formats differ. `correlate_events` normalizes but `search_logs` does not.
- **Fix**: Validate and normalize all user-supplied timestamps to UTC `Z` format at the `execute_tool` boundary.

### Medium

**M1. DB functions return `serde_json::Value` instead of typed structs**
- **Files**: `src/db.rs` — `get_error_summary`, `list_hosts`, `get_stats`
- DB layer produces presentation-layer JSON; schema changes have no compile-time safety.
- **Fix**: Define typed structs (`ErrorSummary`, `HostInfo`, `DbStats`) with `#[derive(Serialize)]`.

**M2. Backpressure logging duplicated between UDP and TCP listeners**
- **File**: `src/syslog.rs` ~lines 84-92 and 129-136
- Identical state-transition logic copy-pasted.
- **Fix**: Extract `log_backpressure(capacity, was_full, context)` helper.

**M3. Tool definitions disconnected from handler argument parsing**
- **File**: `src/mcp.rs` ~lines 202-335
- JSON schemas are raw `json!()` blobs. No compile-time check that schema fields match what `execute_tool` reads. Renaming in one place silently breaks the other.
- **Fix**: Use `serde_json::from_value::<ToolInput>(args)` with typed structs + `schemars::JsonSchema` to generate schemas from types.

**M4. `batch_size` and `flush_interval` are hardcoded**
- **File**: `src/syslog.rs` ~lines 161-162
- High-volume: 100 entries too small; low-volume: 500ms too slow. No way to tune without recompilation.
- **Fix**: Add `batch_size` and `flush_interval_ms` to `SyslogConfig`.

**M5. `chrono::Duration::days()` and `::minutes()` are deprecated**
- **Files**: `src/db.rs` line 303, `src/mcp.rs` lines 440-441
- Deprecated since chrono 0.4.35; replacement is `TimeDelta::try_days()` / `try_minutes()`.
- **Fix**: Use `chrono::TimeDelta::try_days(n).ok_or_else(|| anyhow!("overflow"))?`.

**M6. Connection pool size 4 may cause pool exhaustion under load**
- **File**: `src/config.rs` ~line 56
- Batch writer + purge task + MCP queries concurrently = potential pool starvation during heavy batch + query overlap.
- **Fix**: Increase default to 8; consider separate read/write pools.

**M7. No size limit on TCP syslog messages**
- **File**: `src/syslog.rs` ~lines 118-119
- `BufReader::lines()` reads until `\n` with no length cap. A single very long line consumes unbounded memory.
- **Fix**: Length-check before processing; use fixed-size buffer.

**M8. Unused `axum` `ws` feature**
- **File**: `Cargo.toml` line 13
- No WebSocket code exists. Adds compile time and binary size.
- **Fix**: `axum = { version = "0.8" }` (remove `ws` feature).

### Low

- **L1**: Dead `idx += 1` at end of `tail_logs` — manual index tracking is fragile
- **L2**: `tokio = { features = ["full"] }` — pulls in unused features (`process`, `fs`, `test-util`)
- **L3**: `String::from_utf8_lossy` silently replaces invalid bytes with no metric/log
- **L4**: Config file path hardcoded as `"config.toml"` — not overridable via env var
- **L5**: `Arc::clone` in purge loop every hour — negligible but avoidable
- **L6**: `jsonrpc` field accepted but version not validated (`"2.0"` requirement per spec)
- **L7**: Zero unit or integration tests

---

## Architecture Findings

### Critical

**A-C1. Dockerfile env var prefix is wrong**
- **File**: `Dockerfile` ~line 24
- `SYSLOG_MCP__STORAGE__DB_PATH` (double underscore prefix) is silently ignored by figment, which expects `SYSLOG_MCP_` (single underscore). The Docker env override has no effect. Coincidentally harmless because the default path matches, but breaks any future Dockerfile env customization.
- **Fix**: `SYSLOG_MCP_STORAGE__DB_PATH=/data/syslog.db` in Dockerfile.

**A-C2. Zero test coverage**
- All modules, all tools, all parsing edge cases are tested only by an external shell script requiring a running server. No `#[cfg(test)]` modules exist anywhere.
- **Fix**: Unit tests for `parse_syslog` (RFC 3164/5424 edge cases), `append_filters` (SQL generation), `severity_to_num` (boundary values), `Config::load` (env var overrides).

### High

**A-H1. No input validation on tool arguments**
- **File**: `src/mcp.rs` — all tool handlers
- Arguments extracted with `.as_str()` returning `None` on type mismatch. Invalid types silently become defaults. `severity="CRITICAL"` silently produces unfiltered results. AI agents receive incorrect output with no error signal.
- **Fix**: Deserialize into typed structs with `serde_json::from_value`; return JSON-RPC errors on type/validation failures.

**A-H2. Listener JoinHandles dropped — no supervision**
- **File**: `src/syslog.rs`, `src/main.rs`
- UDP/TCP listener failures are undetected by `main`. Service appears running while syslog ingestion is dead. Health endpoint gives false green.
- **Fix**: Return `JoinHandle`s, `select!` them alongside the MCP server, trigger shutdown on exit.

### Medium

**A-M1. `mcp.rs` conflates HTTP transport with tool business logic**
- The module handles JSON-RPC framing AND contains domain logic (severity threshold math, time window computation, result grouping). `correlate_events` is 70+ lines of domain logic inside the transport layer.
- **Fix**: Extract tool handlers to a `tools.rs` module (or `mod tools` submodule in `mcp.rs`). Transport layer becomes a thin dispatcher.

**A-M2. `LogBatchEntry` tuple — fragile cross-module interface**
- The 8-element positional tuple is the primary `syslog.rs` → `db.rs` data contract. Positional coupling means no compile-time safety on field reordering.
- **Fix**: Named struct (same as Code Quality H2 — converging recommendation).

**A-M3. Timestamps stored as strings without enforced format**
- SQLite `TEXT` columns with no CHECK constraint. Correctness of all time-range queries depends on the invariant that all values are ISO 8601 UTC with `Z` suffix. Nothing enforces this.
- **Fix**: Document the invariant; add validation in `insert_logs_batch`; normalize in `execute_tool`.

**A-M4. Listener death causes silent service degradation**
- A listener crash reduces ingestion capacity with no restart or alerting.
- **Fix**: Supervision loop or tokio `JoinSet` with restart-on-failure semantics.

### Low

**A-L1. No structured error types for MCP callers**
- All errors are `anyhow` strings. AI agents can't distinguish FTS5 syntax errors from pool timeouts or invalid arguments.
- **Fix**: MCP-layer error enum with variants mapping to distinct JSON-RPC error codes.

**A-L2. Direct `db::` coupling in all tool handlers**
- Acceptable at current scale. If a second backend (DuckDB, Postgres) is ever added, there's no storage abstraction to swap.
- **Fix**: No action needed now. Introduce `Storage` trait if a second backend materializes.

**A-L3. CORS wide open (homelab context)**
- Acceptable for private homelab. Would be a critical finding in any other context.

---

## Critical Issues for Phase 2 Context

The following findings should inform security and performance review:

1. **No authentication on MCP endpoint** (A-H1, Code H1) — network-accessible unauthenticated API serving log data
2. **CORS `Allow-Origin: *`** (Code C3) — browser-accessible via cross-site requests
3. **Unbounded TCP connections** (Code C1) — resource exhaustion path
4. **No TCP message size limit** (Code M7) — memory exhaustion path
5. **Connection pool exhaustion** (Code M6) — contention between batch writes, purge, and MCP queries
6. **Listener death is undetected** (Code C2, A-H2) — health endpoint gives false green
7. **Unvalidated user-supplied timestamps in `search_logs`** (Code H6) — potential for incorrect results silently returned to AI agents
8. **Dockerfile env var bug** (A-C1) — any future env-based Dockerfile customization will silently fail
