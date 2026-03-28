# Session: correlate_events Debug, Fix, and Code Simplification

**Date:** 2026-03-28
**Branch:** `chore/add-lavra-project-config`
**Working directory:** `/home/jmagar/workspace/syslog-mcp`

---

## Session Overview

Systematically debugged the `correlate_events` MCP tool, found a critical data-loss bug (severity filtering done post-SQL while capped at 500 rows), fixed it along with three other issues, then ran a simplify pass that consolidated a constant, eliminated a `.unwrap()` panic risk, and fixed a truncation off-by-one. Also fixed docker-compose network config to use `jakenet`.

---

## Timeline

1. **Tool invocation** — Called `correlate_events` with `window_seconds` (wrong param) → confirmed server running, `reference_time` required
2. **Code + live testing in parallel** — Read `src/mcp.rs` and `src/db.rs`, ran `get_stats` to find real timestamp range (314,882 logs, 8 hosts)
3. **Root cause investigation** — Tested with valid `reference_time`, compared `correlate_events` vs `search_logs` for same window → confirmed 2 vs 8 warning events returned
4. **Additional probes** — Tested `severity_min=debug` (returns 500, hard cap), invalid severity (silently passed through), `window_minutes=0`, future timestamp
5. **Fixes implemented** — `src/db.rs` + `src/mcp.rs` changes; build verified clean
6. **Docker networking** — Container couldn't start: `jakenet` not configured; also killed stale non-Docker `syslog-mcp` process (PID 777298) holding port 1514
7. **Redeployment** — `docker-compose.yml` updated to `jakenet` external network; service restarted successfully
8. **Simplify pass** — Three review agents (reuse, quality, efficiency) ran in parallel; four additional fixes applied

---

## Key Findings

### Critical Bug: Post-SQL severity filtering with capped result set

**File:** `src/mcp.rs:403` (before fix)

`correlate_events` fetched 500 rows ordered by `timestamp DESC`, then called `results.retain(|log| severity_to_num(&log.severity) <= sev_threshold)` in Rust. In an active 5-minute window with 1000+ events (mostly debug/info), the 500 most-recent rows were fetched. Warning-level events in the older half of the window were never in the result set and were silently dropped.

**Evidence:**
- `search_logs` with `severity=warning` in the same window: **8 events**
- `correlate_events` (default `severity_min=warning`): **2 events**
- `search_logs` with no severity filter, `limit=1000`: **1000 events** (still capped — actual count higher)
- Severity breakdown: 729 debug, 238 info, 30 notice, 3 warning in that 1000-row sample

### Bug: Invalid `severity_min` silently accepted

**File:** `src/mcp.rs:447-458` (before fix)

`severity_to_num` returned `7` (debug, all-pass) for unknown values. The invalid string was echoed back in the response with no error. After fix: returns `None`, handler returns JSON-RPC error with message listing valid values.

### Bug: Truncation detection off-by-one

**File:** `src/mcp.rs:432` (before fix)

`results.len() == limit` triggers `truncated: true` when DB has exactly `limit` matching rows — a false positive. Fix: query `limit + 1`, check `> limit`, trim vec.

### Bug: Severity string duplicated in three places

The ordered severity sequence appeared in `severity_to_num` match arms, inline as a literal array in the filter, and implicitly in `get_error_summary`'s hardcoded SQL `IN ('emerg', 'alert', 'crit', 'err', 'warning')`. Fix: extracted `SEVERITY_LEVELS: &[&str]` constant; `severity_to_num` now uses `position()` against it.

---

## Technical Decisions

- **Push filter to SQL via `severity_in: Option<Vec<String>>`** rather than adding a `severity_threshold: u8` — keeps `SearchParams` in terms of domain strings, lets the DB do the filtering without requiring a custom function or `CASE` expression in SQL.
- **Slice `SEVERITY_LEVELS[..=sev_threshold]` instead of `.filter(severity_to_num(...).unwrap())`** — eliminates the `.unwrap()` panic risk entirely; the threshold index directly bounds the slice, no fallible call needed.
- **Keep `BTreeMap` for host grouping** — gives alphabetically sorted host output (deterministic, useful for diffing); agent review flagged it as potentially unintentional overhead but the sort guarantee is worth the minor cost at homelab scale (8 hosts).
- **Skip `tail_logs` / `get_error_summary` divergence** — pre-existing issue, outside scope of this session's diff.
- **Skip `severity_in: Option<Vec<String>>` type strengthening** — making it `Option<Vec<Severity>>` with an enum would be the right long-term move but requires a larger refactor across db/mcp boundary; left as a known item.

---

## Files Modified

| File | Purpose |
|------|---------|
| `src/db.rs` | Added `severity_in: Option<Vec<String>>` to `SearchParams`; updated `append_filters` to emit `AND l.severity IN (...)` SQL clause |
| `src/mcp.rs` | Fixed `correlate_events` handler (SQL-side filtering, truncation, validation, `hostname` param, `limit` param); added `SEVERITY_LEVELS` const; refactored `severity_to_num` to use `position()`; added `window_from`/`window_to`/`truncated`/`hosts_count` to response; updated tool schema description |
| `docker-compose.yml` | Changed network from custom `syslog-mcp` bridge to external `jakenet`; removed internal network definition |

---

## Commands Executed

```bash
# Root cause investigation
curl -s -X POST http://localhost:3100/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}'
# → 314,882 logs, 8 hosts, newest: 2026-03-28T08:43:09-04:00

# Confirmed bug: correlate_events returned 2 warnings
curl -s -X POST http://localhost:3100/mcp \
  -d '...correlate_events reference_time=2026-03-28T08:43:09-04:00 window_minutes=5'
# → total_events: 2

# Ground truth: search_logs found 8 warnings in same window
curl -s -X POST http://localhost:3100/mcp \
  -d '...search_logs from=08:38:09 to=08:48:09 severity=warning limit=100'
# → count: 8

# Build verification
cargo build   # → Finished `dev` profile in 1.43s (initial), 3.77s (post-simplify)

# Docker fix
sudo kill 777298                          # killed stale syslog-mcp process holding :1514
docker compose down && docker compose up -d  # → Container syslog-mcp Started

# Post-deploy verification
curl -s http://localhost:3100/health
# → status: ok, total_logs: 363,482

# Post-fix verification
# correlate_events now returns 19 events (all severities ≥ warning in window)
# truncated: false (correct — 19 << 500 limit)
```

---

## Behavior Changes (Before/After)

| Behavior | Before | After |
|----------|--------|-------|
| Warning events in busy window | Silently dropped if outside top-500 by recency | Always returned (filtered in SQL before cap) |
| Invalid `severity_min` | Silently treated as `debug` (all-pass) | Returns JSON-RPC error with valid values list |
| `truncated` flag | False positive when DB has exactly `limit` rows | Correct: queries `limit+1`, checks `> limit` |
| Response fields | `reference_time`, `window_minutes`, `severity_min`, `total_events`, `hosts` | + `window_from`, `window_to`, `truncated`, `hosts_count` |
| `hostname` filter | Not supported | Added as optional parameter |
| `limit` parameter | Hardcoded 500 | Caller-configurable, default 500, max 2000 |
| `window_minutes` cap | Uncapped | Max 60 |
| Docker network | Custom `syslog-mcp` bridge (broken) | External `jakenet` |

---

## Verification Evidence

| Command | Expected | Actual | Status |
|---------|----------|--------|--------|
| `correlate_events` same 5-min window | ≥8 warning events | 19 events (window grew due to new logs) | PASS |
| `correlate_events severity_min=badvalue` | isError: true | isError: true, descriptive message | PASS |
| `cargo build` | 0 errors | Finished dev profile | PASS |
| `curl http://localhost:3100/health` | `status: ok` | `status: ok`, 367,443 logs | PASS |
| `docker compose ps` | Container Up on jakenet | Container Up, port 3100 mapped | PASS |

---

## Source IDs + Collections Touched

Axon embedding attempted post-session (see below).

---

## Risks and Rollback

- **Low risk** — Changes are additive (`severity_in` field) or correctness fixes (filter location, truncation). No schema changes, no data migration.
- **Rollback:** `git revert` the two source file commits + `docker compose build && docker compose up -d`. The `jakenet` network change is infrastructure — verify `jakenet` exists before rollback (`docker network ls`).
- **`severity_in` field** — Used only by `correlate_events`; `search_logs` MCP tool sets it to `None`. No existing callers affected.

---

## Decisions Not Taken

| Option | Why Rejected |
|--------|-------------|
| Add `Severity` enum to `SearchParams` | Larger refactor crossing db/mcp boundary; `Vec<String>` is safe with current validation |
| Fix `tail_logs` to use `append_filters` | Pre-existing divergence, outside this session's scope |
| Fix `get_error_summary` SQL hardcode | Same — pre-existing, would need its own session |
| Use `HashMap` instead of `BTreeMap` for host grouping | Sorted host output is useful; cost is negligible at homelab scale |
| Use `raw_entry` to avoid `hostname.clone()` in grouping loop | API is unstable in Rust std; not worth it for 8 hosts |

---

## Open Questions

- `get_error_summary` in `db.rs:255` hardcodes `IN ('emerg', 'alert', 'crit', 'err', 'warning')` — this diverges from `correlate_events`'s dynamic severity filtering. Should it be unified?
- `tail_logs` builds its own filter loop instead of routing through `append_filters` — if `severity_in` support is ever needed for `tail_logs`, this will need to be addressed.
- Should `severity_in: Option<Vec<String>>` be typed as `Option<Vec<Severity>>` with a `Severity` enum to get compile-time guarantees?

---

## Next Steps

- Consider adding `severity_min` parameter to `get_errors` tool (currently fixed to warning+)
- Unify `get_error_summary` SQL hardcode with `SEVERITY_LEVELS` constant
- Add integration tests for `correlate_events` covering the severity-filter-in-busy-window case
- Consider `tail_logs` refactor to use `append_filters`
