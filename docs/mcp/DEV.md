# Development Workflow -- syslog-mcp

Day-to-day development guide for the syslog-mcp server.

## Quick start

```bash
git clone https://github.com/jmagar/syslog-mcp.git
cd syslog-mcp
cp .env.example .env
chmod 600 .env

just dev          # Start dev server (cargo run)
```

## Project structure

```
syslog-mcp/
  src/
    main.rs              # Entry point, task wiring, graceful shutdown
    config.rs            # Config: config.toml + env var overlay
    db.rs                # SQLite pool, FTS5, schema, retention, storage budget
    syslog.rs            # UDP/TCP listeners, RFC 3164/5424 parsing, batch writer
    mcp.rs               # Axum HTTP, JSON-RPC dispatch, all 7 tool handlers
  tests/                 # Live integration tests
  scripts/               # Smoke tests, backups, plugin checks
  hooks/                 # Claude Code hooks (pre-commit, sync-env)
  skills/syslog/         # Skill definition (SKILL.md)
  .claude-plugin/        # Claude Code plugin manifest
  .codex-plugin/         # Codex CLI plugin manifest
  gemini-extension.json  # Gemini CLI manifest
  docker-compose.yml     # Container deployment
  Dockerfile             # Container build
  config.toml            # Local dev config (not in Docker image)
  .env.example           # Environment variable template
  Justfile               # Task runner recipes
```

## Development cycle

1. **Edit source code** -- modify tool handlers in `src/mcp.rs`, database queries in `src/db.rs`, syslog parsing in `src/syslog.rs`.
2. **Run dev server** -- `just dev` compiles and runs the binary.
3. **Test interactively** -- call tools via curl:
   ```bash
   # Health (unauthenticated)
   curl http://localhost:3100/health

   # Tool call
   curl -s -X POST http://localhost:3100/mcp \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tail_logs","arguments":{"n":10}}}'
   ```
4. **Run checks**:
   ```bash
   just lint && just test
   ```
5. **Commit** with conventional prefix:
   ```bash
   git commit -m "feat(tools): add search filter by facility"
   ```

## Adding a new MCP tool

1. **Define the tool schema** -- add a JSON object to the `tool_definitions()` vec in `src/mcp.rs`.
2. **Add dispatch entry** -- add a match arm in `execute_tool()`.
3. **Implement handler** -- write an async function `tool_<name>()` that calls `run_db()` for database access.
4. **Add database query** -- implement the query function in `src/db.rs` with parameterized SQL.
5. **Add unit test** -- write `#[test]` or `#[tokio::test]` in the relevant module.
6. **Update syslog_help** -- add the tool to the help text in `tool_syslog_help()`.
7. **Update SKILL.md** -- add the tool to the skill documentation.
8. **Update plugin manifests** -- add the tool name to `.claude-plugin/plugin.json` tools array.

## Debugging

### Log levels

Set `RUST_LOG` in `.env` or environment:

| Level | Use case |
| --- | --- |
| `trace` | Full syslog parse output, SQL queries, batch details |
| `debug` | Request/response details, batch flush, queue depth |
| `info` | Startup, tool calls, retention purge, storage enforcement (default) |
| `warn` | Backpressure, oversized messages, connection limits |
| `error` | Failures, DB errors, channel closed |

Targeted filtering:

```bash
RUST_LOG=syslog_mcp=debug,tower_http=info cargo run
```

### mcporter testing

```bash
mcporter list syslog-mcp --config config/mcporter.json
mcporter call --config config/mcporter.json syslog-mcp.get_stats
mcporter call --config config/mcporter.json syslog-mcp.tail_logs n=10
```

### MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

Connect to `http://localhost:3100/mcp` with your bearer token.

## Code style

| Tool | Command | Purpose |
| --- | --- | --- |
| clippy | `just lint` | Lint with `-D warnings` |
| rustfmt | `just fmt` | Auto-format |
| cargo check | `just check` | Type check without building |
| cargo test | `just test` | Run test suite |

## Justfile recipes

| Recipe | Description |
| --- | --- |
| `just dev` | Start dev server (`cargo run`) |
| `just build` | Debug build |
| `just release` | Release build |
| `just check` | `cargo check` |
| `just lint` | `cargo clippy -- -D warnings` |
| `just fmt` | `cargo fmt` |
| `just test` | `cargo test` |
| `just up` | `docker compose up -d` |
| `just down` | `docker compose down` |
| `just restart` | `docker compose restart` |
| `just logs` | `docker compose logs -f` |
| `just health` | curl health endpoint |
| `just test-live` | Run live smoke tests |
| `just docker-build` | Build Docker image |
| `just setup` | Copy .env.example to .env |
| `just gen-token` | Generate bearer token |
| `just check-contract` | Validate plugin manifests |
| `just clean` | `cargo clean` |
| `just publish` | Bump version, tag, push |

## See also

- [CONNECT.md](CONNECT.md) -- client connection methods
- [PATTERNS.md](PATTERNS.md) -- code patterns
- [TESTS.md](TESTS.md) -- testing guide
