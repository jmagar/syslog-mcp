# Phase 4: Best Practices & Standards

---

## Rust Language & Framework Findings

### Critical

**RS-C1: Zero tests — highest leverage gap in the entire codebase**
- Zero `#[cfg(test)]` modules. No dev-dependencies. Cannot verify correctness of any refactor.
- **Fix**: Add `tempfile = "3"` to `[dev-dependencies]`. Write db.rs tests using `TempDir` + `init_pool`. All subsequent changes should be tested first.

### High

**RS-H1: `LogBatchEntry` 8-tuple → named struct**
- `pub type LogBatchEntry = (String, String, Option<String>, ...)` — positional indexing (`entry.1`), no compiler safety on field reordering.
- **Fix**: `pub struct LogBatchEntry { pub timestamp: String, pub hostname: String, ... }` — `ParsedLog` in syslog.rs is identical; unify them.

**RS-H2: Deprecated `chrono::Duration::days()` / `::minutes()`**
- Deprecated since chrono 0.4.38. Clippy will warn. Replacement: `chrono::TimeDelta::try_days(n).ok_or_else(|| anyhow!("overflow"))?`.
- **Files**: `src/db.rs:303`, `src/mcp.rs:440-441`

**RS-H3: `tokio = { features = ["full"] }` → enumerate needed features**
- Pulls in unused `process`, `fs`, `test-util` subsystems. Explicit: `["rt-multi-thread", "net", "io-util", "time", "signal", "sync", "macros"]`.

**RS-H4: `axum` `ws` feature unused**
- Remove `features = ["ws"]` from Cargo.toml. No WebSocket code exists.

**RS-H5: `execute_tool` 160-line match → extract per-tool functions**
- Each arm should be `async fn tool_correlate_events(state, args) -> Result<Value>`. Dispatch becomes a 10-line router. Required for testability.

**RS-H6: `serde_json::Value` returned from DB layer → typed structs**
- `get_error_summary`, `list_hosts`, `get_stats` return `Vec<Value>`. No compile-time field safety.
- **Fix**: `ErrorSummaryEntry`, `HostEntry`, `DbStats` structs with `#[derive(Serialize)]`. MCP layer serializes via `serde_json::to_value`.

**RS-H7: `Box<dyn ToSql + '_>` dynamic dispatch → `rusqlite::types::Value` owned enum**
- `append_filters` requires boxing and explicit lifetime annotations. `rusqlite::types::Value` (`Text`, `Integer`, `Null`) is owned, implements `ToSql`, eliminates the lifetime parameter entirely.

### Medium

- **RS-M1**: `.map(|h| h.to_string())` → `.map(str::to_string)` — idiomatic `str` conversion
- **RS-M2**: `let-else` for required argument extraction in `execute_tool` (Rust 1.65+, within 1.86 target)
- **RS-M3**: `String::from` / `.to_string()` / `.into()` mixed inconsistently — standardize to `.to_owned()` for `&str`→`String`
- **RS-M4**: `expect()` in `shutdown_signal` (`main.rs:91-99`) — signal handler failure should propagate, not panic
- **RS-M5**: Backpressure state-machine duplicated in UDP and TCP handlers → extract `BackpressureGuard` struct
- **RS-M6**: `batch_size = 100` and `flush_interval = 500ms` are hardcoded magic constants → add to `StorageConfig`
- **RS-M7**: `severity_to_num` in `mcp.rs` operates on `db::SEVERITY_LEVELS` → move to `db.rs`
- **RS-M9**: Missing `Vec::with_capacity` for `severity_levels` slice in `correlate_events`

### Low

- **RS-L1**: All types `pub` — use `pub(crate)` for crate-internal types; enables dead_code linting
- **RS-L2**: `tracing-subscriber` `json` feature included but `fmt().json()` never called — wire it or remove feature
- **RS-L3**: `futures` crate redundant with `tokio-stream` for SSE use case — remove `futures` dep
- **RS-L4**: Inline `std::collections::HashMap/BTreeMap` paths → top-level `use` imports
- **RS-L5**: TCP accept error uses flat 100ms sleep → exponential backoff with ceiling (e.g., 100ms→5s)

---

## CI/CD & DevOps Findings

### Critical

**OPS-C1: Container runs as root — no `USER` directive**
- **File**: `Dockerfile` (missing instruction)
- Container exploit gives root in Docker namespace; `./data` bind mount writable as root on host.
- **Fix**:
  ```dockerfile
  RUN groupadd --gid 10001 syslog && \
      useradd --uid 10001 --gid syslog --no-create-home --shell /sbin/nologin syslog && \
      mkdir -p /data && chown syslog:syslog /data
  USER syslog:syslog
  ```

**OPS-C2: Dockerfile `SYSLOG_MCP__` prefix still broken**
- `Dockerfile:24` — `ENV SYSLOG_MCP__STORAGE__DB_PATH` silently ignored. One character fix.
- **Fix**: `ENV SYSLOG_MCP_STORAGE__DB_PATH=/data/syslog.db`

**OPS-C3: No CI/CD pipeline**
- No `.github/workflows/`. No automated lint, test, security scan, or image build. Changes ship directly from developer machine.
- **Fix**: GitHub Actions CI with `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo audit`, Docker build.
  ```yaml
  # .github/workflows/ci.yml
  on: [push, pull_request]
  jobs:
    check:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: dtolnay/rust-toolchain@stable
          with: { components: clippy, rustfmt }
        - uses: Swatinem/rust-cache@v2
        - run: cargo fmt --all -- --check
        - run: cargo clippy --all-targets -- -D warnings
        - run: cargo test --all-features
        - run: cargo install cargo-audit --quiet && cargo audit
  ```

### High

**OPS-H1: No `cargo audit` for dependency CVEs**
- Cargo.lock exists and is tracked. `cargo audit` against it takes 5 seconds and catches known CVEs.
- **Fix**: Add to CI (shown above) + to pre-release checklist.

**OPS-H2: No health check in `docker-compose.yml`**
- Service has `restart: unless-stopped` but no `healthcheck`. A zombie process holding the port is invisible to Docker.
- **Fix**:
  ```yaml
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:3100/health"]
    interval: 30s
    timeout: 5s
    retries: 3
    start_period: 10s
  ```

**OPS-H3: External `jakenet` network requires manual pre-creation**
- `docker compose up` fails on a fresh clone with a confusing error. No automation exists.
- **Fix (Option A)**: Convert to internal bridge network. **Option B**: Add `scripts/setup.sh` that runs `docker network inspect jakenet || docker network create jakenet` before compose up.

**OPS-H4: No resource limits on container**
- Unbounded memory, CPU, and PID usage. A syslog flood or FTS5 runaway query can starve other homelab services.
- **Fix**:
  ```yaml
  deploy:
    resources:
      limits:
        memory: 512M
        cpus: "1.0"
  ```

**OPS-H5: No `.dockerignore` file**
- Build context includes `target/` (gigabytes of Rust build cache), `data/` (live SQLite DB), `.env` files.
- **Fix**: Create `.dockerignore`:
  ```
  target/
  data/
  .git/
  docs/
  .env
  .env.*
  *.db
  *.db-wal
  *.db-shm
  ```

### Medium

**OPS-M1: No SQLite backup runbook or automation**
- Data volume is a bind mount with no backup script, no cron, no recovery procedure.
- **Fix**: `scripts/backup.sh` using `sqlite3 .backup` (WAL-safe, no service stop required). Schedule via cron or systemd timer.

**OPS-M2: No WAL truncation or VACUUM after retention purge**
- SQLite file doesn't shrink after deletes without `VACUUM`. WAL can grow without `wal_checkpoint(TRUNCATE)`.
- **Fix**: Add `PRAGMA wal_checkpoint(TRUNCATE)` after purge in `db.rs`. Add `PRAGMA wal_autocheckpoint=500` at pool init.

**OPS-M3: No rolling update or rollback runbook**
- Deploy is `docker compose up -d`. If new image fails health check, service is down until manual intervention.
- **Fix**: `docs/runbooks/deploy.md` with: build → smoke-test image → `up -d` → health gate → smoke test → rollback procedure.

**OPS-M4: `config.toml` copy path mismatch — never read in Docker**
- Dockerfile copies to `/etc/syslog-mcp/config.toml`. Binary reads from CWD (`/`). Volume mount in compose also wrong path. TOML is dead weight in the image.
- **Fix**: Either mount at `/config.toml` (matching binary's CWD load), or support `SYSLOG_MCP_CONFIG` env var to override config path.

**OPS-M5: Smoke test not wired to CI**
- `scripts/smoke-test.sh` has 25 assertions and covers all 6 tools, but is never run automatically.
- **Fix**: Add a `smoke` CI job that starts `docker compose up -d`, waits for health, runs the script, and tears down.

### Low

- **OPS-L1**: `Cargo.lock` status documented incorrectly in CLAUDE.md — says gitignored, is actually tracked
- **OPS-L2**: No Prometheus `/metrics` endpoint — add atomic counters for `messages_received`, `messages_dropped`, `batch_flushes`
- **OPS-L3**: SWAG label is incomplete — partial label may generate broken nginx upstream config
- **OPS-L4**: UDP has no per-source rate limiting — a single misconfigured host can flood the channel
