# Testing Guide -- syslog-mcp

## Unit tests

```bash
cargo test
```

Shortcut: `just test`

Tests are colocated with source code in `#[cfg(test)]` modules:

| Module | Tests cover |
| --- | --- |
| `src/config.rs` | Env var overrides, defaults, validation (host format, storage budget relationships, pool size) |
| `src/db.rs` | Schema init, insert/search/tail/errors/hosts/stats, FTS5 queries, retention purge, storage budget enforcement, batch retry |
| `src/syslog.rs` | RFC 3164/5424 parsing, UniFi CEF extraction, severity mapping, facility mapping, malformed input |
| `src/mcp.rs` | Health endpoint, auth middleware (valid/invalid/missing token, no-auth mode), tool dispatch, timestamp validation, MCP lifecycle |
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

Live tests run against a running syslog-mcp server:

```bash
just test-live
# or: bash tests/test_live.sh
```

The smoke test (`bin/smoke-test.sh`) exercises all 7 MCP tools via mcporter with 25 assertions.

### mcporter-based testing

```bash
# List available tools
mcporter list syslog-mcp --config config/mcporter.json

# Call individual tools
mcporter call --config config/mcporter.json syslog-mcp.get_stats
mcporter call --config config/mcporter.json syslog-mcp.tail_logs n=10
mcporter call --config config/mcporter.json syslog-mcp.search_logs query=error limit=5
mcporter call --config config/mcporter.json syslog-mcp.list_hosts
```

### curl-based testing

```bash
# Health check
curl http://localhost:3100/health

# Tail recent logs
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tail_logs","arguments":{"n":10}}}'

# Search
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_logs","arguments":{"query":"error","limit":5}}}'

# Stats
curl -s -X POST http://localhost:3100/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}'
```

## Testing checklist

- [ ] **All tools return expected shape** -- search_logs, tail_logs, get_errors, list_hosts, correlate_events, get_stats, syslog_help
- [ ] **Auth: valid token** -- 200 with correct Bearer token
- [ ] **Auth: invalid token** -- 401 Unauthorized
- [ ] **Auth: no token when required** -- 401 Unauthorized
- [ ] **Auth: no-auth mode** -- all endpoints accessible when `SYSLOG_MCP_TOKEN` is unset
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
