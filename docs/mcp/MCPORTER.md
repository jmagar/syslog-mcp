# Live Smoke Testing (mcporter) -- syslog-mcp

End-to-end verification against a running syslog-mcp server. Complements unit tests in [TESTS.md](TESTS.md).

## Purpose

`bin/smoke-test.sh` exercises the full MCP server stack: auth, tool dispatch, and response validation against a live syslog-mcp instance with 25 assertions.

## Location

```
bin/smoke-test.sh       # Full smoke test (25 assertions)
tests/test_live.sh          # Extended live integration tests
tests/mcporter/test-tools.sh  # mcporter-based tool tests
```

## Running

```bash
# Ensure server is running
just up

# Run smoke tests
just test-live
# or: bash bin/smoke-test.sh
```

## mcporter configuration

mcporter config is at `config/mcporter.json`:

```json
{
  "servers": {
    "syslog-mcp": {
      "transport": "http",
      "url": "http://localhost:3100/mcp"
    }
  }
}
```

## Manual mcporter commands

```bash
# List available tools
mcporter list syslog-mcp --config config/mcporter.json

# Call tools
mcporter call --config config/mcporter.json syslog-mcp.get_stats
mcporter call --config config/mcporter.json syslog-mcp.tail_logs n=10
mcporter call --config config/mcporter.json syslog-mcp.search_logs query=error limit=5
mcporter call --config config/mcporter.json syslog-mcp.list_hosts
mcporter call --config config/mcporter.json syslog-mcp.get_errors
mcporter call --config config/mcporter.json syslog-mcp.syslog_help
```

## Test assertions

The smoke test validates:
- Health endpoint returns `{"status": "ok"}`
- All 7 tools return valid JSON responses
- `search_logs` returns expected `count` and `logs` fields
- `tail_logs` respects the `n` parameter
- `get_errors` returns `summary` array
- `list_hosts` returns `hosts` array
- `correlate_events` returns `hosts` grouped by hostname
- `get_stats` returns numeric fields (total_logs, total_hosts, etc.)
- `syslog_help` returns non-empty markdown text

## Failure output

```
  PASS: health endpoint returns ok
  PASS: search_logs returns count field
  FAIL: tail_logs count should be <= 10, got 50
  ---
  25 assertions: 24 PASS, 1 FAIL
```

Exit code is non-zero if any assertion fails.

## See also

- [TESTS.md](TESTS.md) -- unit and integration tests
- [CICD.md](CICD.md) -- CI workflow configuration
