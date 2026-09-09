---
title: "Testing Guide -- cortex"
created: "2026-07-30"
updated: "2026-07-30"
---

# Testing Guide -- cortex

## Unit tests

```bash
cargo test
```

Shortcut: `just test`

Coverage summary:

```bash
just coverage       # cargo llvm-cov nextest --summary-only
just coverage-html  # cargo llvm-cov nextest --html
```

Install `cargo-llvm-cov` first if the command is missing:

```bash
cargo install cargo-llvm-cov --locked
```

Tests are colocated with source code in `#[cfg(test)]` modules:

| Module | Tests cover |
| --- | --- |
| `src/config.rs` | Env var overrides, defaults, validation (host format, storage budget relationships, pool size) |
| `src/db.rs` | Schema init, insert/search/tail/errors/hosts/stats, FTS5 queries, retention purge, storage budget enforcement, batch retry |
| `src/syslog.rs` | RFC 3164/5424 parsing, UniFi CEF extraction, severity mapping, facility mapping, malformed input |
| `src/mcp.rs` + `src/mcp/` | Health endpoint, auth middleware (valid/invalid/missing token, no-auth mode), RMCP tool dispatch, timestamp validation, MCP lifecycle |
| `src/main.rs` | Background interval timing |

### Running specific tests

```bash
cargo test test_search           # Run tests matching "test_search"
cargo test config::tests         # Run config module tests only
cargo test -- --nocapture        # Show println/tracing output
```

### Test database handling

Database tests use `tempfile::TempDir` for isolated SQLite instances. Each test gets a fresh database, preventing cross-test contamination. The `StorageConfig::for_test()` helper provides minimal config with pool_size=1 and WAL mode disabled.

## Live smoke tests

The canonical profile creates a run-owned Cortex topology:

```bash
just test-live
# or: bash tests/live/run-profile.sh smoke
```

Smoke covers live UDP/TCP/OTLP ingest plus its portable REST, CLI, browser,
admin/auth-negative, lifecycle, and cleanup assertions. Run `just live-mcp` for
the registry-derived every-action MCP qualification. Complete CLI/API/MCP and
owner-profile coverage is established by the aggregate suite, not smoke alone.
`scripts/smoke-test.sh` and `tests/test_live.sh` are thin compatibility wrappers.
See `docs/LIVE_QUALIFICATION.md` for specialist profiles and cadence.
When seeding is enabled, the smoke scripts import
`tests/fixtures/ai-session-smoke.jsonl` and assert that `sessions`,
`search_sessions`, `abuse`, `abuse_incidents`, `abuse_investigate`, `ai_correlate`, and `project_context` can retrieve real AI transcript
rows, not just empty response envelopes.
`scripts/smoke-ai-mcp.sh` additionally seeds a temporary transcript and calls
the HTTP MCP endpoint for `search_sessions`, `abuse`, `abuse_incidents`, `abuse_investigate`, `usage_blocks`,
`project_context`, `list_ai_tools`, and `list_ai_projects`.
The AI smoke scripts resolve `CORTEX_BIN` first, then `cortex` on `PATH`, then
the repo-local debug binary at `target/debug/cortex`, so repo-local builds do
not require an installed shell binary.

Action registry covered by live/script references: `search`, `filter`, `tail`, `errors`,
`hosts`, `map`, `host_state`, `fleet_state`, `correlate_state`, `topic_correlate`, `sessions`, `search_sessions`, `abuse`, `abuse_incidents`, `abuse_investigate`, `ai_correlate`, `usage_blocks`, `project_context`,
`list_ai_tools`, `list_ai_projects`, `correlate`, `stats`, `status`, `apps`,
`source_ips`, `timeline`, `patterns`, `context`, `get`, `ingest_rate`,
`silent_hosts`, `clock_skew`, `anomalies`, `compare`, `compose_status`,
`compose_doctor`, `unaddressed_errors`, `ack_error`, `unack_error`,
`notifications_recent`, `file_tails`, `notifications_test`, `llm_invocations`,
`similar_incidents`, `recurring_error_comparison`, `incident_context`, `graph`, `artifact_evidence`,
`artifact_evidence_record`, `skill_events`, `skill_incidents`, `skill_investigate`, `mcp_events`, `mcp_incidents`,
`mcp_investigate`, `hook_events`, `hook_incidents`, `hook_investigate`, `help`.

### mcporter-based testing

```bash
# List available tools
mcporter list cortex --config config/mcporter.json

# Call actions through the single cortex tool
mcporter call --config config/mcporter.json cortex.cortex action=stats
mcporter call --config config/mcporter.json cortex.cortex action=status
mcporter call --config config/mcporter.json cortex.cortex action=tail n=10
mcporter call --config config/mcporter.json cortex.cortex action=search query=error limit=5
mcporter call --config config/mcporter.json cortex.cortex action=hosts
mcporter call --config config/mcporter.json cortex.cortex action=host_state host_id=host-id
mcporter call --config config/mcporter.json cortex.cortex action=sessions
mcporter call --config config/mcporter.json cortex.cortex action=abuse terms=ai-smoke-authentication limit=5
mcporter call --config config/mcporter.json cortex.cortex action=abuse_incidents limit=3
mcporter call --config config/mcporter.json cortex.cortex action=abuse_investigate limit=1
mcporter call --config config/mcporter.json cortex.cortex action=correlate_state reference_time=2026-01-01T00:00:00Z window_minutes=10
mcporter call --config config/mcporter.json cortex.cortex action=ai_correlate project=/tmp/cortex-sessions-smoke limit=2 events_per_anchor=3
mcporter call --config config/mcporter.json cortex.cortex action=apps
mcporter call --config config/mcporter.json cortex.cortex action=source_ips
mcporter call --config config/mcporter.json cortex.cortex action=timeline
mcporter call --config config/mcporter.json cortex.cortex action=patterns
mcporter call --config config/mcporter.json cortex.cortex action=context host=host timestamp=2026-01-01T00:00:00Z
mcporter call --config config/mcporter.json cortex.cortex action=get id=1
mcporter call --config config/mcporter.json cortex.cortex action=ingest_rate
mcporter call --config config/mcporter.json cortex.cortex action=silent_hosts
mcporter call --config config/mcporter.json cortex.cortex action=clock_skew
mcporter call --config config/mcporter.json cortex.cortex action=file_tails op=status
mcporter call --config config/mcporter.json cortex.cortex action=anomalies
mcporter call --config config/mcporter.json cortex.cortex action=compare a_from=2026-01-01T00:00:00Z a_to=2026-01-01T01:00:00Z b_from=2026-01-01T01:00:00Z b_to=2026-01-01T02:00:00Z
mcporter call --config config/mcporter.json cortex.cortex action=compose_status
mcporter call --config config/mcporter.json cortex.cortex action=compose_doctor
mcporter call --config config/mcporter.json cortex.cortex action=graph mode=entity entity_type=host key=example-host
mcporter call --config config/mcporter.json cortex.cortex action=graph mode=around entity_type=host key=example-host depth=1
mcporter call --config config/mcporter.json cortex.cortex action=graph mode=explain entity_type=host key=example-host depth=2
mcporter call --config config/mcporter.json cortex.cortex action=graph mode=evidence evidence_id=12345
```

For graph proof UX smoke, use a real bounded evidence id from
`graph around --limit 5`, then assert:

- `relationship.src_entity_id` and `relationship.dst_entity_id` are preserved,
- `relationship.src_entity` and `relationship.dst_entity` are present,
- `source_log_summary` is either compact and bounded or null with
  `missing_source_reason`,
- response JSON contains no `raw` field and no `metadata_json`,
- auth-like strings, URL userinfo, home paths, private-key markers, and
  terminal controls are redacted/escaped.

### CLI-based testing (abuse investigation workflow)

The deterministic abuse incident/investigation workflow is also exercisable
directly through the `cortex` binary. All outputs are bounded; the investigation
`findings` are rule-based and local-only (never an external LLM analysis).

```bash
# Group abuse hits into scored incident candidates (bounded; capped result set)
cortex sessions incidents --limit 3 --json

# Expand the top incidents into deterministic evidence bundles + findings
cortex sessions investigate --limit 1 --json

# Heartbeat fleet state parity commands
cortex state host --host nashost --json
cortex state fleet --json
cortex correlate state --reference-time 2026-01-01T00:00:00Z --window-minutes 10 --json

# Graph lookup commands
cortex entity host nashost --json
cortex graph around host nashost --limit 25 --json
cortex graph explain host nashost --depth 2 --json
```

### curl-based testing

```bash
# Health check
curl http://localhost:3100/health

# Tail recent logs
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"tail","n":10}}}'

# Search
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"search","query":"error","limit":5}}}'

# Stats
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"stats"}}}'

# Status
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"cortex","arguments":{"action":"status"}}}'
```

## Testing checklist

- [ ] **All actions return expected shape** -- cortex search, cortex tail, cortex errors, cortex hosts, cortex host_state, cortex sessions, cortex correlate, cortex stats, cortex status, cortex help
- [ ] **AI session analytics return expected shape and seeded rows** -- cortex search_sessions, cortex abuse, cortex sessions_correlate, cortex usage_blocks, cortex project_context, cortex list_ai_tools, cortex list_ai_projects
- [ ] **Auth: valid token** -- 200 with correct Bearer token
- [ ] **Auth: invalid token** -- 401 Unauthorized
- [ ] **Auth: no token when required** -- 401 Unauthorized
- [ ] **Auth: token unset** -- `/mcp` accepts requests without `Authorization`; `/health` remains unauthenticated
- [ ] **Health endpoint** -- `GET /health` returns 200 with no auth
- [ ] **FTS5 query syntax** -- AND, OR, NOT, phrases, prefix matching
- [ ] **Time range filtering** -- from/to parameters parse ISO 8601 correctly
- [ ] **Severity filtering** -- all 8 levels work
- [ ] **Retention purge** -- logs older than retention_days are deleted
- [ ] **Storage budget** -- write blocking engages when limits are breached

## CI configuration

Tests run automatically in CI via GitHub Actions:

```yaml
# .github/workflows/ci.yml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test
```

## Test coverage

See `tests/TEST_COVERAGE.md` for detailed coverage documentation.

## See also

- [MCPORTER.md](MCPORTER.md) -- live smoke tests with mcporter
- [CICD.md](CICD.md) -- CI workflow configuration
- [LOGS.md](LOGS.md) -- error handling patterns tested here
