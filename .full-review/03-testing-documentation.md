# Phase 3: Testing & Documentation Review

---

## Test Coverage Findings

### Current State

**Test pyramid: 0% unit / 0% integration / 100% E2E (external shell script)**

The smoke test (`scripts/smoke-test.sh`) is a competent happy-path harness but requires a live server. Zero `#[cfg(test)]` modules exist in the codebase.

**Coverage map by function:**

| Function | Module | Tested? |
|---|---|---|
| `Config::load()`, `parse_addr()` | config.rs | No |
| `init_pool()` | db.rs | No |
| `insert_logs_batch()` host aggregation | db.rs | No (insertion only via seeding) |
| `search_logs()` — FTS path | db.rs | Happy path only |
| `search_logs()` — non-FTS path | db.rs | No |
| `search_logs()` — invalid FTS5 syntax | db.rs | No |
| `tail_logs()` — edge cases | db.rs | No |
| `get_error_summary()` — time filters | db.rs | No |
| `purge_old_logs()` | db.rs | No |
| `append_filters()` — SQL generation | db.rs | No |
| `get_stats()` — empty DB | db.rs | No |
| `parse_syslog()` — RFC 3164/5424 | syslog.rs | No |
| `parse_syslog()` — malformed inputs | syslog.rs | No |
| `batch_writer()` retry/discard logic | syslog.rs | No |
| `severity_to_num()` | mcp.rs | No |
| `correlate_events` — invalid args | mcp.rs | No |
| `execute_tool` — JSON-RPC error paths | mcp.rs | No |
| `GET /health` — empty DB | mcp.rs | No |
| `tools/call` — missing `name` | mcp.rs | No |

---

### Critical

**TC-C1: FTS5 invalid query returns no error — propagates raw rusqlite error to callers**
- `search_logs` passes `query` verbatim to `MATCH ?1`. Bare `AND`, `"unclosed`, and lone `-` are all valid concerns. No test verifies the error is handled gracefully vs panicking or leaking schema detail.
- **Test priority**: Verify `is_err()` for `"AND"`, `"\"unclosed"`, `"-"` inputs; verify error message doesn't contain file paths.

**TC-C2: `purge_old_logs()` entirely untested — the only data-deletion function**
- A `cutoff` calculation bug (wrong timezone, retention_days overflow, off-by-one) could silently purge all logs. The FTS rebuild branch (`deleted > 1000`) is never exercised outside production.
- **Required tests**: Purge deletes exactly old rows; retention_days=0 is a no-op; purge+FTS rebuild path doesn't panic; `list_hosts` and FTS search both work correctly after large purge.

**TC-C3: `parse_syslog()` has zero tests — highest combinatorial risk in the codebase**
- RFC 3164 vs 5424 handling, severity/facility index arithmetic, timestamp normalization, hostname fallback, malformed priority — all untested.
- **Required tests**: RFC 3164 standard message field mapping; RFC 5424 with structured data; missing PRI defaults to `info`; missing hostname falls back to `"unknown"`; empty input doesn't panic; timestamp is always valid RFC 3339.

### High

**TC-H1: `Config::load()` env var prefix is untested — the double-underscore bug was a real production regression**
- No regression test for `SYSLOG_MCP_MCP__BIND` override. Any refactor of the figment chain could silently break all env var overrides.
- **Required**: Test that `SYSLOG_MCP_MCP__BIND=127.0.0.1:3200` actually changes `cfg.mcp.bind`.

**TC-H2: Timestamp range filtering is untested**
- `search_logs` `from`/`to` filters, `get_error_summary` time range, `correlate_events` window — all use SQL string comparison. Tests must verify both "inside window is returned" and "outside window is excluded."

**TC-H3: `batch_writer` retry/discard logic is untested**
- On DB write failure: retain if `<1000 entries`, discard if `>=1000`. The 1000-entry boundary and the `spawn_blocking` panic path are untested.
- **Recommendation**: Extract retry decision into pure `should_retain_batch(len, err) -> bool` — trivially unit-testable without async.

**TC-H4: `correlate_events` error paths are untested**
- Missing `reference_time` (required field), invalid RFC 3339, unknown `severity_min`, `window_minutes > 60` (clamped silently), `limit > 999` (clamped silently) — none verified.

### Medium

**TC-M1: `tail_logs` n=0 and n>500 boundary — untested**
- `n=0` returns empty via `LIMIT 0`; `n=600` should be clamped. Neither verified.

**TC-M2: `insert_logs_batch` host aggregation — untested**
- Multiple entries for same host in one batch, empty batch, mixing new+existing hosts — all untested.

**TC-M3: `get_stats()` on empty DB — untested**
- `MIN(timestamp)` returns NULL on empty table. The `Option<String>` handling is untested. Health check breaks at startup if this regresses.

### Low

- **TC-L1**: `severity_to_num()` — case-sensitivity, boundary at index 7, None for typos
- **TC-L2**: SSE endpoint response format — content-type, first event body
- **TC-L3**: `tools/list` schema — validate all 6 tool schemas have required fields

### Required Cargo.toml Changes

```toml
[dev-dependencies]
tempfile = "3"
tower = "0.5"
tokio = { version = "1", features = ["full", "test-util"] }
```

`tempfile` is the critical addition — provides `TempDir` for disposable SQLite databases, foundational for all db-layer unit tests.

### Sample Test Code (highest priority)

```rust
// db.rs — add at bottom, inside #[cfg(test)] mod tests
fn test_pool(dir: &TempDir) -> DbPool {
    let config = StorageConfig {
        db_path: dir.path().join("test.db"),
        pool_size: 1, retention_days: 0, wal_mode: false,
    };
    init_pool(&config).expect("init_pool failed")
}

#[test]
fn fts5_invalid_query_returns_err_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let pool = test_pool(&dir);
    let params = SearchParams { query: Some("AND".to_string()), ..Default::default() };
    assert!(search_logs(&pool, &params).is_err(), "bare AND must return Err");
}

#[test]
fn purge_old_logs_deletes_only_old_entries() {
    let dir = tempfile::tempdir().unwrap();
    let pool = test_pool(&dir);
    let old_ts = (Utc::now() - Duration::days(100)).to_rfc3339();
    let new_ts = Utc::now().to_rfc3339();
    let entries = vec![
        (old_ts, "host-a".into(), None, "info".into(), None, None, "old".into(), "r".into()),
        (new_ts, "host-b".into(), None, "info".into(), None, None, "new".into(), "r".into()),
    ];
    insert_logs_batch(&pool, &entries).unwrap();
    assert_eq!(purge_old_logs(&pool, 90).unwrap(), 1);
    assert_eq!(tail_logs(&pool, None, None, 10).unwrap()[0].hostname, "host-b");
}

// syslog.rs — parse_syslog unit tests
#[test]
fn parse_rfc3164_maps_fields_correctly() {
    let raw = "<14>Mar 28 12:00:00 myhost sshd[42]: login ok";
    let p = parse_syslog(raw);
    assert_eq!(p.hostname, "myhost");
    assert_eq!(p.severity, "info");   // pri 14: facility 1 (user), severity 6 (info)
    assert_eq!(p.app_name.as_deref(), Some("sshd"));
    assert_eq!(p.process_id.as_deref(), Some("42"));
}

#[test]
fn parse_empty_input_does_not_panic() {
    let p = parse_syslog("");
    assert!(!p.hostname.is_empty());
    assert_eq!(p.severity, "info");
    chrono::DateTime::parse_from_rfc3339(&p.timestamp).expect("must be valid RFC 3339");
}
```

### What the Smoke Test Does Well (preserve these behaviors)

- Seeds known data via UDP and waits for batch flush
- Validates response structure for all 6 tools
- Checks timestamp ordering on `tail_logs`
- Verifies FTS phrase query syntax
- Validates `severity` values in `get_errors` against known enum
- Checks `limit=0` boundary

---

## Documentation Findings

### Critical

**DOC-C1: Dockerfile still has broken `SYSLOG_MCP__` double-underscore prefix**
- **File**: `Dockerfile:24` — `ENV SYSLOG_MCP__STORAGE__DB_PATH=/data/syslog.db`
- CHANGELOG v0.1.5 says this was fixed everywhere. The Dockerfile was missed. Any operator who tries to override the DB path in a Dockerfile-derived image will have the change silently ignored.
- **Fix**: `ENV SYSLOG_MCP_STORAGE__DB_PATH=/data/syslog.db` (one character change)

**DOC-C2: CLAUDE.md says "Cargo.lock is gitignored" but it is tracked**
- **File**: `CLAUDE.md` Gotchas section
- The note says `Cargo.lock is gitignored — intentional for this project`. The file is actually present and tracked. The note is the opposite of reality. For a binary crate, tracking Cargo.lock is correct per Cargo docs.
- **Fix**: Update to: `**Cargo.lock is tracked** — correct for a binary crate; ensures reproducible builds.`

### High

**DOC-H1: No authentication or trust model documented**
- **Files**: README.md, CLAUDE.md, SETUP.md
- The MCP endpoint is unauthenticated with `CORS: *`. SETUP.md shows SWAG proxying it to a public HTTPS subdomain with no auth layer mentioned. No document states the trust boundary.
- **Fix**: Add "Security / Trust Model" section to README: endpoint is unauthenticated by design; homelab-internal only; if exposing through SWAG/reverse proxy, add auth at proxy layer; CORS is fully open.

**DOC-H2: README config section prose misleads on env var prefix**
- **File**: `README.md:37`
- "prefix `SYSLOG_MCP_`, double underscore for nesting" — reads as if the double underscore is part of the prefix. Creates exactly the SYSLOG_MCP__ bug.
- **Fix**: "prefix is `SYSLOG_MCP_` (single underscore). Use `__` (double underscore) to separate section from key after the prefix."

**DOC-H3: Retention purge data loss is undocumented**
- Retention defaults to 90 days. Logs are **permanently and irreversibly deleted** hourly. No user-facing document warns that this is enabled by default or that `retention_days=0` disables it.
- **Fix**: Add to README and CLAUDE.md: `retention_days defaults to 90 — logs older than 90 days are permanently deleted hourly. Set to 0 to keep forever.`

**DOC-H4: WAL backup procedure is incomplete**
- **File**: `CLAUDE.md` Gotchas — "also copy `.db-wal` and `.db-shm`"
- Copying all three files without a checkpoint captures potentially inconsistent state if writes are in progress. The safe approach is `PRAGMA wal_checkpoint(FULL)` before copy, or `sqlite3 source.db ".backup dest.db"`.
- **Fix**: Expand to explain checkpoint requirement. Add a brief backup section to README.

**DOC-H5: `raw` column stores full unparsed text but is never exposed or documented**
- 8-tuple `LogBatchEntry` includes `raw` field, inserted for every log, never selected by any query. Roughly doubles on-disk storage. Invisible to operators.
- **Fix**: Add CLAUDE.md gotcha: `**\`raw\` column** — stores full unparsed syslog text for every row, never exposed through MCP tools. Doubles storage cost vs message-only. Reserved for future re-parsing use.`

### Medium

**DOC-M1: `correlate_events` 999 limit cap unexplained**
- Tool schema says `max 999` without explaining why not 1000. Implementation uses `limit+1` as a truncation sentinel; if limit=1000, the fetch would be 1001 which would trigger a different code path.
- **Fix**: Add CLAUDE.md note: `correlate_events caps at 999 (not 1000) — fetches limit+1 rows to detect truncation without a COUNT query.`

**DOC-M2: Batch write failure data loss path undocumented**
- On sustained DB failure, batches exceeding 1000 entries are silently discarded. No operator warning in any document.
- **Fix**: Add CLAUDE.md gotcha: `**Batch write failure drops data** — if DB is unavailable and retry batch exceeds 1000 entries, logs are discarded. Monitor with RUST_LOG=error.`

**DOC-M3: TCP framing comment claims octet-counting support — false**
- **File**: `src/syslog.rs:107` comment says "(newline-delimited, octet-counting)"
- Implementation uses `BufReader::lines()` only. Octet-counting is not implemented.
- **Fix**: Correct comment to "newline-delimited only; RFC 5425 octet-counting NOT supported". Add to CLAUDE.md gotchas.

**DOC-M4: `config.toml` is not read in Docker — only in CLAUDE.md, not README**
- Users reading only README will edit `config.toml` and see their changes silently ignored in Docker.
- **Fix**: Add callout to README config section: "When running in Docker, `config.toml` is not read. Use env vars or the `docker-compose.yml` environment block."

**DOC-M5: MCP protocol version undocumented**
- Server advertises `"protocolVersion": "2025-03-26"` but this version string appears nowhere in docs.
- **Fix**: Add to README: "MCP protocol version 2025-03-26. Implements: initialize, tools/list, tools/call over JSON-RPC 2.0 HTTP POST."

**DOC-M6: `severity_in` is an internal-only field not documented as such**
- **File**: `src/db.rs:48-50`
- `SearchParams.severity_in` is used internally by `correlate_events`; `search_logs` hardcodes `None`. A developer reading the struct expects it to be callable through the API.
- **Fix**: Add comment: `// internal use only — not exposed in search_logs; used by correlate_events for threshold filtering via SEVERITY_LEVELS slice`

**DOC-M7: UDP flood backpressure behavior undocumented**
- When the 10,000-entry channel fills, the UDP listener stalls and OS drops datagrams silently.
- **Fix**: Add to CLAUDE.md gotchas: `**UDP flood drops messages** — channel capacity is 10,000. Under extreme load the UDP listener stalls and the OS drops datagrams. Watch for "backpressure applied" in RUST_LOG=warn.`

### Low

- **DOC-L1**: `max_message_size` absent from `.env.example` and README config table
- **DOC-L2**: `mcp.server_name` absent from `.env.example` and README
- **DOC-L3**: `jakenet` external network prereq (`docker network create jakenet`) missing from README Quick Start; only in a comment
- **DOC-L4**: SSE endpoint behavior undocumented at user level — one-shot stub, modern clients use HTTP POST directly
- **DOC-L5**: Retention purges by device `timestamp`, not `received_at` — misconfigured device clocks cause unexpected early/late purging (undocumented)
- **DOC-L6**: `[Unreleased]` CHANGELOG section is empty but staged changes exist

---

## Prioritized Fix Order

1. **DOC-C1** (Dockerfile env prefix) — one character, fixes silent config override failure
2. **TC-C3** (`parse_syslog` tests) + **TC-C2** (`purge_old_logs` tests) — highest risk untested paths
3. **DOC-H1** (security/trust model in README) — closes the "SWAG exposes this to internet" gap
4. **TC-C1** (FTS5 invalid query tests) — validates error handling before hardening
5. **DOC-C2** (CLAUDE.md Cargo.lock note) — factual inaccuracy
6. **TC-H1** (Config env var regression test) — prevents the double-underscore class of bug from recurring
7. **DOC-H3** (retention data loss warning) — operators need to know this is on by default
8. **DOC-M3** (TCP framing false claim) — fix comment + CLAUDE.md
