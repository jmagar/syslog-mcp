# Phase 2: Security & Performance Review

---

## Security Findings

### Critical

**CRIT-01: Unauthenticated MCP endpoint + CORS `Allow-Origin: *` = browser-pivot data exfiltration**
- **File**: `src/main.rs:66-70`, `src/mcp.rs:81-93`
- **CVSS 3.1**: 9.1 | **CWE**: CWE-306
- Any webpage a homelab user visits can silently call all 6 MCP tools via browser `fetch()`. CORS wildcard makes this cross-site. Logs contain SSH args, API tokens at debug level, hostnames, private IP topology, usernames from auth failures.
- **Fix**: Replace `Allow-Origin: *` with explicit LAN origin allowlist. Add static bearer token middleware (20-line Axum extractor).

### High

**HIGH-01: Unbounded TCP connections — connection flood exhausts memory**
- **File**: `src/syslog.rs:108-157`
- **CVSS 3.1**: 7.5 | **CWE**: CWE-400
- Every accepted TCP connection spawns an unconstrained Tokio task. No connection limit, no idle timeout. 50,000 connections consume ~100MB just for task stacks before socket/buffer overhead.
- **Fix**: `Arc<Semaphore>` capped at 512, acquired before `tokio::spawn`. Per-connection `tokio::time::timeout(Duration::from_secs(300), ...)`.

**HIGH-02: No TCP message size limit — single connection causes OOM**
- **File**: `src/syslog.rs:118-139`
- **CVSS 3.1**: 7.5 | **CWE**: CWE-789
- `BufReader::lines()` reads until `\n` with no upper bound. `max_message_size` is applied to UDP but ignored for TCP. A 2GB line with no newline consumes 2GB of heap before processing.
- **Fix**: Apply `max_message_size` symmetrically to TCP path; use `take(max_size as u64)` on stream before `BufReader`.

**HIGH-03: FTS5 query injection — complexity DoS + schema information disclosure**
- **File**: `src/db.rs:184-200`
- **CVSS 3.1**: 7.3 | **CWE**: CWE-943
- User-supplied `query` passed verbatim to `MATCH ?1`. No length/complexity cap. A 28-term wildcard query pins SQLite for seconds. Invalid syntax returns raw SQLite error messages exposing schema details.
- **Fix**: Validate query length (≤512 chars) and term count (≤16). Return generic error on DB failure; log full detail server-side.

**HIGH-04: Log injection poisons AI agent queries**
- **File**: `src/syslog.rs:247-286`
- **CVSS 3.1**: 7.1 | **CWE**: CWE-117
- Any LAN host can UDP-spoof syslog messages with any hostname and inject prompt injection payloads, fake security events, or SSRF triggers. Log content is returned raw to AI agents consuming MCP output.
- **Fix**: Record actual sender IP as `source_ip` column separate from claimed `hostname`. Document in tool descriptions that log content is untrusted. Add hostname allowlist option.

### Medium

**MED-01: Dockerfile env var double-underscore bug**
- **File**: `Dockerfile:24` — `SYSLOG_MCP__STORAGE__DB_PATH` silently ignored by figment
- **Fix**: `SYSLOG_MCP_STORAGE__DB_PATH=/data/syslog.db` (single underscore prefix)

**MED-02: Container runs as root**
- **File**: `Dockerfile` — no `USER` directive
- **CVSS 3.1**: 5.9 | **CWE**: CWE-250
- **Fix**: `RUN useradd -r -u 1001 syslogmcp && chown 1001 /data` + `USER syslogmcp`

**MED-03: Timestamp params not validated — silent wrong results**
- **File**: `src/db.rs:253-254`, `src/mcp.rs:385-386`
- `from`/`to` in `search_logs` and `get_errors` accepted without parsing. `"yesterday"` produces no error, just wrong data.
- **Fix**: `DateTime::parse_from_rfc3339()` + UTC normalization at boundary.

**MED-04: No rate limiting or concurrency cap on MCP HTTP endpoint**
- **File**: `src/main.rs` — no `ConcurrencyLimitLayer`
- 4 concurrent full-table-scan queries starve the entire pool including the batch writer.
- **Fix**: `ConcurrencyLimitLayer::new(8)` on the router.

**MED-05: Tool errors expose raw SQLite error strings**
- **File**: `src/mcp.rs:183-193`
- DB paths, lock states, FTS5 internals forwarded verbatim to callers.
- **Fix**: Log internally; return generic `"Tool execution failed"` to caller.

### Low

- **LOW-01**: UDP source unauthenticated — any host can claim any hostname; no source IP recorded
- **LOW-02**: No request body size limit on MCP endpoint (`DefaultBodyLimit::max(65536)`)
- **LOW-03**: Magic sentinel `"9999-12-31T23:59:59Z"` in `get_error_summary`
- **LOW-04**: Retention purge uses caller-supplied `timestamp`, not authoritative `received_at`

### Dependency Audit

All declared deps are actively maintained, no known CVEs. **Critical gap**: `Cargo.lock` is gitignored. Without it, transitive dependency versions are unverifiable and builds are non-reproducible.
- **Action**: Commit `Cargo.lock`. Add `cargo audit` to CI.

---

## Performance Findings

### Critical

**P-C1: FTS5 triggers fire synchronously inside write transaction — halves write throughput**
- **File**: `src/db.rs:111-122` (triggers), `db.rs:140` (batch insert)
- Every `INSERT INTO logs` fires `logs_ai` inline, running the porter stemmer for every row within the write lock. FTS5 overhead is 40-80% of raw insert cost. At 1,000 msg/s the write lock is held continuously, starving all MCP read queries.
- **Estimated ceiling**: ~600-800 msg/s effective throughput before visible degradation
- **Fix**: Decouple FTS indexing from write transaction. Sync FTS in a separate `spawn_blocking` task after batch commit: `INSERT INTO logs_fts(rowid, message) SELECT id, message FROM logs WHERE id > ?last_id`.

**P-C2: `correlate_events` post-query grouping runs on Tokio async thread**
- **File**: `src/mcp.rs:463-486`
- After `run_db` returns, the BTreeMap grouping, json!() allocations, and serde_json serialization run synchronously on a Tokio worker thread. Blocks other futures on the same thread for the duration.
- **Fix**: Move grouping inside the `run_db` closure (executes in `spawn_blocking`). Or push to SQL: `GROUP BY hostname ORDER BY hostname, timestamp`.

**P-C3: Retention purge deletes via trigger + FTS rebuild holds write lock for 30-120 seconds**
- **File**: `src/db.rs:296-317`
- At 90-day retention with 1,000 msg/s, hourly purge deletes ~3.6M rows. Each fires `logs_ad` inside a single implicit transaction. The subsequent `rebuild` (for deletions >1000) holds the write lock for the entire FTS re-index. Batch writer blocks on `pool.get()` and will discard batches after 5s timeout. **This is a data loss path.**
- **Fix**: Chunked DELETE (`LIMIT 10000` in a loop); replace threshold-rebuild with incremental FTS merge (`INSERT INTO logs_fts(logs_fts) VALUES('merge=-500,8')`); remove `logs_ad` trigger, handle FTS deletes lazily.

### High

**P-H1: Connection pool of 4 starves under concurrent load**
- **File**: `src/config.rs:56`
- Batch writer + purge + N MCP queries contend for 4 connections. At pool exhaustion, r2d2 blocks `spawn_blocking` threads. Easily triggered with 3 concurrent MCP calls during a batch flush.
- **Fix**: Default `pool_size = 8-16`; document minimum as `concurrent_mcp_requests + 2`. Consider dedicated single-connection write path.

**P-H2: FTS5 + host filter: no predicate pushdown, post-FTS scan for all matches**
- **File**: `src/db.rs:184-200`
- `WHERE logs_fts MATCH ?1 AND l.hostname = ?2`: FTS materializes all matches for the query, then filters by hostname. `idx_logs_host_time` index is unused in the FTS join path. At 5M+ rows, broad queries with host filter take 1-5 seconds.
- **Fix**: Run `ANALYZE` at pool init (`PRAGMA optimize`). Consider adding hostname as a column to the FTS virtual table.

**P-H3: `raw` column doubles storage cost with zero query value**
- **File**: `src/db.rs:83` (schema), `src/syslog.rs:285` (parser)
- Every log stores full original bytes in `raw TEXT NOT NULL`. At 1,000 msg/s over 90 days: ~23GB just from `raw`. Column is never read by any query function (`map_row` reads 9 columns; `raw` is position 9 in INSERT but position 10 — outside `map_row`'s 0-8 range).
- **Fix**: Drop `raw` column from schema (add migration). If debug replay is needed, add `logs_raw(id, raw)` as a separate opt-in table.

**P-H4: `get_stats` COUNT(*) runs on every `/health` probe**
- **File**: `src/db.rs:330`, `src/mcp.rs:97-104`
- `SELECT COUNT(*) FROM logs` is a full B-tree scan. No cached rowcount. Health endpoints polled at 10Hz by mcporter/load balancers = 10 full table scans/second.
- **Fix**: Cache total in `hosts` table (sum of `log_count`). Health check reads the cached value.

**P-H5: TCP message size — memory exhaustion (see Security HIGH-02)**

**P-H6: Unbounded TCP connections — memory exhaustion (see Security HIGH-01)**

### Medium

**P-M1: `ORDER BY timestamp DESC` without `ANALYZE` may pick wrong index**
- SQLite query planner statistics are never initialized. As data grows, the planner may choose suboptimal indexes for `tail_logs` with hostname filter. `ANALYZE` at startup and periodic `PRAGMA optimize` prevents regression.

**P-M2: Missing composite `(severity, timestamp)` index for `get_error_summary`**
- `WHERE severity IN (...) AND timestamp BETWEEN` — SQLite uses only one index. A composite `idx_logs_sev_time(severity, timestamp)` would serve this query with a tight range scan.
- **Fix**: Add `CREATE INDEX IF NOT EXISTS idx_logs_sev_time ON logs(severity, timestamp);`

**P-M3: WAL checkpoint never triggered explicitly — WAL grows unboundedly**
- **File**: `src/db.rs:74-79`
- Default WAL autocheckpoint at 1,000 pages. Under concurrent read load, passive checkpoints skip locked pages, WAL can grow without bound. At 1,000 msg/s: ~5-10 MB/min WAL growth.
- **Fix**: `PRAGMA wal_autocheckpoint=500;` at init. Add `PRAGMA wal_checkpoint(TRUNCATE);` to hourly maintenance task.

**P-M4: Batch writer `sleep` future re-allocated every inner loop iteration**
- **File**: `src/syslog.rs:167`
- `let deadline = tokio::time::sleep(flush_interval)` inside inner loop allocates a new sleep future on every receive. Move deadline reset to post-flush only.

**P-M5: `serde_json::Value` from DB layer causes double-serialization**
- `get_error_summary`, `list_hosts`, `get_stats` return `Value` from DB layer, then `execute_tool` wraps them in another `json!()`. Allocates serde_json nodes twice.

### Low

- **P-L1**: Channel capacity 10,000 not configurable; 5,000 msg/s burst fills channel in 2s
- **P-L2**: `parse_syslog` allocates 8 String values per message — `raw.to_string()` is avoidable if `raw` column is dropped
- **P-L3**: `get_stats` queries on health endpoint (see P-H4 — redundant mention)
- **P-L4**: `received_at` column has no index and no query uses it — wasted 25 bytes/row (~600MB at scale)
- **P-L5**: `prepare` vs `prepare_cached` inconsistency — common `tail_logs` with no filters always generates same SQL and could benefit from `prepare_cached`

---

## Scalability Ceiling

| Bottleneck | Limit | Failure Mode |
|---|---|---|
| FTS5 trigger overhead (P-C1) | ~600-800 msg/s effective | Write starvation, read queries blocked |
| Pool starvation (P-H1) | ~3-4 concurrent MCP calls | P99 latency spikes, timeouts |
| Retention purge write lock (P-C3) | 1×/hour, 30-120s | **Data loss** via batch discard |
| WAL growth (P-M3) | ~24h at 1k/s | Disk exhaustion, read degradation |
| Channel fill (P-L1) | ~2s burst at 5k/s | Silent UDP drop, TCP backpressure |

**At homelab scale (17-167 msg/s)**: Issues P-C1 and P-H1 will not manifest. Issues **P-C3** (purge locking), **P-H3** (storage doubling), **P-H4** (health probe scans), and **P-M3** (WAL growth) **will manifest** regardless of message rate.

---

## Critical Issues for Phase 3 Context

1. **Zero unit tests** — parsing edge cases, SQL generation, severity validation all untested
2. **FTS5 injection** — `search_logs` `query` parameter needs input validation tests
3. **Timestamp normalization** — missing in `search_logs`/`get_errors` paths needs test coverage
4. **Retention purge data loss path** (P-C3) — needs an integration test verifying batch writer survives a purge cycle
5. **No auth** — any documentation/README must clearly call out the network trust boundary
6. **Dockerfile env bug** — needs a deployment smoke test that verifies env vars actually take effect
