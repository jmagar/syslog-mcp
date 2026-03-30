# Session: lavra-work 10-bead wave + review + P1 fixes

**Date:** 2026-03-30
**Branch:** `chore/add-lavra-project-config`
**Version:** 0.1.5 → 0.1.6

---

## Session Overview

Executed 10 ready beads via `/lavra-work` (3-wave parallel dispatch), then ran `/lavra-review` to find issues before pushing. Review surfaced 2 P1 and 6 P2 findings; both P1s were fixed before push. Final state: 26 tests pass, branch pushed, v0.1.6 released.

---

## Timeline

| Time | Activity |
|------|----------|
| Start | `/lavra-work` — 10 beads, 3 waves, parallel agent dispatch |
| Wave 1 | `e1dbdeb` non-root Docker user, `6b13555` CI pipeline, `aa052dc` chunked purge |
| Wave 2 | `2dd8411` non-blocking config parse, `adad56e` CORS + auth, `69c6b9d` TCP semaphore |
| Wave 3 | `e1276df` TCP line-length cap, `8004ffa` CEF warn, `5026c32` recall.sh fix, `a1e0707` db tests |
| Review | `/lavra-review` — 4 agents (security-sentinel, performance-oracle, architecture-strategist, code-simplicity-reviewer) |
| P1 fixes | `166794a` redact api_token, `0237496` fix Dockerfile ENV prefix |
| Ship | `c9026de` v0.1.6 bump + changelog, `git push` |

---

## Key Findings

- **api_token plaintext in logs** (`src/main.rs:26`): `info!(config = ?config)` printed entire Config struct including bearer token via derive(Debug). Fixed by logging individual non-sensitive fields.
- **Dockerfile ENV prefix bug** (`Dockerfile:24`): `SYSLOG_MCP__STORAGE__DB_PATH` used double-underscore prefix; figment strips `SYSLOG_MCP_` then splits on `__`, leaving `_STORAGE__DB_PATH` which matched nothing. Silent because default equals `/data/syslog.db`.
- **FTS5 merge on small index returns error**: `INSERT INTO logs_fts VALUES('merge=500,250')` fails on tiny/empty indexes. Made best-effort: catch error, log as `warn!`, continue.
- **FTS5 tests require file-based SQLite**: `:memory:` databases do not fire content-table triggers. Used `tempfile::TempDir` for all db unit tests.
- **PathBuf not Display**: `%config.storage.db_path` in tracing macro fails; requires `.display()`.

---

## Technical Decisions

- **Log individual fields instead of custom Debug impl**: Simpler than implementing `fmt::Debug` for `McpConfig`; `auth_enabled=bool` conveys whether auth is active without exposing the value.
- **Wall-clock TCP timeout (P2, not fixed this session)**: 300s total timeout is known to be suboptimal vs idle timeout. Deferred to `syslog-mcp-c5p`.
- **Semaphore cap hardcoded at 512 (P2)**: Wired through config deferred to `syslog-mcp-7cw`.
- **Bearer token comparison not constant-time (P2)**: `subtle` crate deferred to `syslog-mcp-rme`.
- **`/health` behind auth (P2)**: Breaks Docker healthchecks. Deferred to `syslog-mcp-kp0`.
- **Auth 401 returns plain JSON not JSON-RPC envelope (P2)**: Deferred to `syslog-mcp-472`.

---

## Files Modified

| File | Change |
|------|--------|
| `src/main.rs` | Replace `info!(config = ?config)` with per-field log; localhost-only CORS |
| `src/mcp.rs` | Bearer auth middleware (`require_auth`); apply to all routes |
| `src/config.rs` | Add `api_token: Option<String>` to McpConfig; replace `to_socket_addrs` with `SocketAddr::parse` |
| `src/db.rs` | Chunked DELETE purge + incremental FTS merge; 7 unit tests |
| `src/syslog.rs` | TCP semaphore (512) + 300s timeout; line-length cap; CEF warn on all-None extraction |
| `Dockerfile` | Non-root user uid 10001; fix `SYSLOG_MCP__` → `SYSLOG_MCP_` ENV prefix |
| `.github/workflows/ci.yml` | New: fmt, clippy -D warnings, test, cargo audit |
| `Cargo.toml` | `tempfile = "3"` dev-dependency; version 0.1.5 → 0.1.6 |
| `Cargo.lock` | Updated |
| `.env.example` | Document `SYSLOG_MCP_MCP__API_TOKEN` |
| `.lavra/memory/recall.sh` | Remove stray `local` outside function |
| `docker-compose.yml` | Network: `jakenet` → `proxy` with `${DOCKER_NETWORK:-syslog_mcp}` |
| `CHANGELOG.md` | Add v0.1.6 section |

---

## Commands Executed

```bash
# Build verification after each wave
rtk cargo build       # confirmed clean each time
rtk cargo test        # 26 passed

# Wave commits
git commit -m "fix(syslog-mcp-ab8): run container as non-root user uid 10001"
git commit -m "chore(syslog-mcp-7ee): add GitHub Actions CI pipeline"
git commit -m "fix(syslog-mcp-75i): chunked DELETE + incremental FTS merge..."
git commit -m "fix(config): replace blocking to_socket_addrs with non-blocking SocketAddr::parse"
git commit -m "fix(syslog-mcp-gm3): restrict CORS to localhost + add optional bearer token auth"
git commit -m "fix(syslog-mcp-ct2): cap TCP connections at 512 with semaphore + 300s timeout"
git commit -m "fix(syslog-mcp-zu9): drop TCP lines exceeding max_message_size to prevent OOM"
git commit -m "fix(syslog-mcp-w5e): warn when CEF heuristic fires but all fields extract as None"
git commit -m "fix(syslog-mcp-1mg): remove stray local keyword outside function in recall.sh"
git commit -m "test(syslog-mcp-sd0): add db.rs unit tests for insert, search, purge, stats..."

# P1 fixes
git commit -m "fix(syslog-mcp-4yw): redact api_token from startup log"
git commit -m "fix(syslog-mcp-s9b): fix Dockerfile ENV prefix SYSLOG_MCP__ -> SYSLOG_MCP_"

# Release
git commit -m "chore: release v0.1.6 — security, stability, and CI"
git push
```

---

## Behavior Changes (Before/After)

| Area | Before | After |
|------|--------|-------|
| Container security | Runs as root | Runs as uid/gid 10001 |
| Bearer token in logs | Printed in plaintext at startup | `auth_enabled=true/false` only |
| Dockerfile DB path | `SYSLOG_MCP__` prefix silently ignored (default used) | `SYSLOG_MCP_STORAGE__DB_PATH` correctly applied |
| TCP connections | Unbounded, no line-length cap, no timeout | Capped at 512, 8KB line cap, 300s timeout |
| Retention purge | Single DELETE + WAL lock held | Chunked 10k rows + FTS incremental merge |
| Auth on MCP routes | No auth | Optional Bearer token; 401 if token set and missing/wrong |
| CORS | Wildcard `*` | localhost:3100 and 127.0.0.1:3100 only |
| CI | None | GitHub Actions: fmt, clippy, test, audit |

---

## Verification Evidence

| Command | Expected | Actual | Status |
|---------|----------|--------|--------|
| `rtk cargo build` | 0 errors | 0 errors, 0 warnings | PASS |
| `rtk cargo test` | all pass | 26 passed | PASS |
| `rtk git push` | branch pushed | `chore/add-lavra-project-config` pushed | PASS |

---

## Review Beads Created

### P1 (resolved this session)
- `syslog-mcp-4yw` — api_token plaintext in startup log — **CLOSED**
- `syslog-mcp-s9b` — Dockerfile ENV double-underscore prefix — **CLOSED**

### P2 (open)
- `syslog-mcp-i7m` — purge_old_logs holds pool connection across all chunks
- `syslog-mcp-c5p` — wall-clock TCP timeout not idle timeout
- `syslog-mcp-kp0` — `/health` behind auth breaks Docker healthchecks
- `syslog-mcp-rme` — non-constant-time Bearer token comparison
- `syslog-mcp-472` — auth 401 plain JSON not JSON-RPC envelope
- `syslog-mcp-7cw` — TCP semaphore cap hardcoded (not configurable)

### P3 (open)
- `syslog-mcp-iy1`, `syslog-mcp-m5h`, `syslog-mcp-9jk`, `syslog-mcp-76b`, `syslog-mcp-zqx`, `syslog-mcp-e5m`, `syslog-mcp-94p`

---

## Risks and Rollback

- **Auth middleware**: If `SYSLOG_MCP_MCP__API_TOKEN` is not set, auth is disabled and all routes are open (backward-compatible). Risk: low.
- **CORS restriction**: Non-browser clients (mcporter, curl) ignore CORS entirely — no breakage. Risk: low.
- **Non-root container**: `/data` volume ownership set to uid 10001 in Dockerfile. Existing bind-mounts with root-owned files will fail writes. Rollback: remove `USER 10001:10001` from Dockerfile.
- **Rollback full branch**: `git revert fff98def..HEAD` or `git reset --hard fff98def` (pre-branch SHA).

---

## Decisions Not Taken

- **SecretString wrapper type** for api_token: would prevent accidental Debug prints at the type level, but adds a dependency. Individual field logging achieves the same observable behavior with no new deps.
- **Idle TCP timeout** (vs wall-clock): more correct but more complex (requires tracking last-read time per connection). Deferred as P2 `syslog-mcp-c5p`.
- **`rustsec/audit-check` action** in CI: would be faster than `cargo install cargo-audit` but deferred as P3 `syslog-mcp-iy1`.

---

## Open Questions

- Does the Docker deployment need `SYSLOG_MCP_MCP__API_TOKEN` set in production `.env` to enable auth, or are P2 issues (non-constant-time compare, 401 format) a blocker first?
- `docker-compose.yml` network changed from `jakenet` to `proxy` with `${DOCKER_NETWORK:-syslog_mcp}` — confirm `proxy` network pre-exists on the homelab host.

---

## Next Steps

1. Fix P2 beads — especially `syslog-mcp-kp0` (`/health` behind auth) before enabling token auth in production
2. `/lavra-work syslog-mcp-kp0 syslog-mcp-rme syslog-mcp-472` — highest-impact P2s
3. Create PR from `chore/add-lavra-project-config` → `main`
