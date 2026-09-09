---
title: "Live Smoke Testing (mcporter) -- cortex"
created: "2026-07-30"
updated: "2026-07-30"
---

# Live Smoke Testing (mcporter) -- cortex

End-to-end verification against a running cortex server. Complements unit tests in [TESTS.md](TESTS.md).

## Purpose

The canonical live suite exercises mcporter generation and execution as one
part of the registry-derived MCP/CLI surface profile.

## Location

```
tests/live/run-profile.sh   # Canonical fail-closed profile entry point
scripts/smoke-test.sh       # Compatibility wrapper
tests/test_live.sh          # Compatibility wrapper
tests/mcporter/test-tools.sh  # mcporter-based tool tests
```

## Running

```bash
# Build a disposable topology and run smoke qualification
just test-live
# or: bash tests/live/run-profile.sh smoke
```

## mcporter configuration

mcporter config is at `config/mcporter.json`:

```json
{
  "mcpServers": {
    "cortex": {
      "transport": "http",
      "url": "http://localhost:3100/mcp"
    }
  }
}
```

## Manual mcporter commands

```bash
# List available tools
mcporter list cortex --config config/mcporter.json

# Call actions through the single cortex tool
mcporter call --config config/mcporter.json cortex.cortex action=stats
mcporter call --config config/mcporter.json cortex.cortex action=tail n=10
mcporter call --config config/mcporter.json cortex.cortex action=search query=error limit=5
mcporter call --config config/mcporter.json cortex.cortex action=hosts
mcporter call --config config/mcporter.json cortex.cortex action=errors
mcporter call --config config/mcporter.json cortex.cortex action=status
mcporter call --config config/mcporter.json cortex.cortex action=help
```

## Test assertions

The smoke test validates:
- Health endpoint returns `{"status": "ok"}`
- The single `cortex` tool is listed
- `cortex search` returns expected `count` and `logs` fields
- `cortex tail` respects the `n` parameter
- `cortex errors` returns `summary` array
- `cortex hosts` returns `hosts` array
- `cortex correlate` returns `hosts` grouped by hostname
- `cortex stats` returns numeric fields (total_logs, total_hosts, etc.)
- `cortex status` returns DB health and runtime/OTLP observability fields
- `cortex help` returns non-empty markdown text
- When `tests/fixtures/ai-session-smoke.jsonl` can be seeded into the same
  SQLite database as the server, AI analytics also prove non-empty
  `sessions`, `search_sessions`, and `project_context` results for the fixture.

## Failure output

```
  PASS: health endpoint returns ok
  PASS: cortex search returns count field
  FAIL: cortex tail count should be <= 10, got 50
  ---
  30 assertions: 29 PASS, 1 FAIL
```

Exit code is non-zero if any assertion fails.

## See also

- [TESTS.md](TESTS.md) -- unit and integration tests
- [CICD.md](CICD.md) -- CI workflow configuration
