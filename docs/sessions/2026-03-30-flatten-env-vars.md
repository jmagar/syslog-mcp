# Session: Flatten env vars — drop figment, use SYSLOG_*/SYSLOG_MCP_* prefixes

**Date**: 2026-03-30
**Branch**: `chore/add-lavra-project-config`
**Commits**: `9d4b873` (refactor), `6d71cde` (chore cleanup)
**Version**: 0.1.8 → 0.1.9 → 0.1.10

## Session Overview

Replaced figment's nested `SYSLOG_MCP_SECTION__KEY` env var format with flat `SYSLOG_*` (listener) and `SYSLOG_MCP_*` (server/storage) prefixes. Also overhauled `docker-compose.yml` to use `env_file`, dynamic ports, named volumes, and external network.

## Timeline

1. **Docker-compose fixes** — Removed SWAG labels, added `external: true` to network, changed default from `jakenet` to `syslog_mcp`
2. **User requested env var flattening** — `SYSLOG_MCP_SYSLOG__UDP_BIND` and `SYSLOG_MCP_MCP__BIND` were unacceptable
3. **Plan created** — New env var mapping with two prefixes, merged UDP/TCP into single host+port
4. **Iterative plan refinement** — User requested: named volume default, `env_file: .env`, no hardcoded env vars in compose
5. **Implementation** — Rewrote `config.rs` (drop figment, manual env overlay), updated all consumers
6. **Interference recovery** — Another agent reverted Cargo.toml; re-applied `figment → toml` swap
7. **Verification** — 51 tests pass, clippy clean, compose validates
8. **Push** — Two commits: refactor (9d4b873) and state cleanup (6d71cde)

## Key Findings

- Figment only supports a single env prefix; two prefixes (`SYSLOG_` and `SYSLOG_MCP_`) require manual env var loading
- Docker Compose requires separate port lines for UDP and TCP — no shorthand for "both protocols"
- Named volume default in compose works even when user overrides with bind mount path — the unused volume declaration is harmless
- The `toml` crate handles TOML deserialization directly; combined with manual `std::env::var` calls it's simpler than figment for flat config

## Technical Decisions

| Decision | Rationale |
|----------|-----------|
| Drop figment for toml + manual env | Two prefixes needed; figment only supports one |
| Merge UDP/TCP into single host+port | User correctly noted they'd never differ |
| Split bind addresses into host + port | User wanted `SYSLOG_HOST` (no port) for clarity |
| Named volume default (`syslog-mcp-data`) | User preference over bind mount default |
| `env_file: .env` instead of `environment:` block | User wanted no env vars hardcoded in compose |

## Files Modified

| File | Purpose |
|------|---------|
| `src/config.rs` | Complete rewrite: flat structs, manual env overlay, `bind_addr()` helpers, storage budget fields + validation |
| `src/main.rs` | Use `bind_addr()` helpers instead of direct field access |
| `src/syslog.rs` | Merged `udp_bind`/`tcp_bind` into `bind_addr()`, renamed `flush_interval_ms` → `flush_interval` |
| `Cargo.toml` | `figment` → `toml` dep, version bumps |
| `config.toml` | Flattened: `udp_bind`/`tcp_bind`/`bind` → `host` + `port` per section, added storage budget fields |
| `docker-compose.yml` | `env_file`, dynamic ports, named volume, external network, removed SWAG labels |
| `Dockerfile` | `SYSLOG_MCP_STORAGE__DB_PATH` → `SYSLOG_MCP_DB_PATH` |
| `.env.example` | Complete rewrite with new var names |
| `.env` | Updated with new var names (gitignored) |
| `scripts/backup.sh` | Updated env var reference |
| `README.md` | Updated env var docs and auth references |
| `CLAUDE.md` | Updated config module description, env var section, gotchas |
| `CHANGELOG.md` | Added v0.1.9 entry |

## Behavior Changes (Before/After)

| Aspect | Before | After |
|--------|--------|-------|
| Syslog bind env var | `SYSLOG_MCP_SYSLOG__UDP_BIND=0.0.0.0:1514` | `SYSLOG_HOST=0.0.0.0` + `SYSLOG_PORT=1514` |
| MCP bind env var | `SYSLOG_MCP_MCP__BIND=0.0.0.0:3100` | `SYSLOG_MCP_HOST=0.0.0.0` + `SYSLOG_MCP_PORT=3100` |
| DB path env var | `SYSLOG_MCP_STORAGE__DB_PATH` | `SYSLOG_MCP_DB_PATH` |
| Auth token env var | `SYSLOG_MCP_MCP__API_TOKEN` | `SYSLOG_MCP_API_TOKEN` |
| Docker data volume | Bind mount `./data` | Named volume `syslog-mcp-data` (overridable) |
| Docker env vars | Hardcoded in `environment:` block | `env_file: .env` |
| Docker network | Implicitly created | `external: true` (must pre-exist) |
| Config crate | figment | toml |

## Verification Evidence

| Command | Expected | Actual | Status |
|---------|----------|--------|--------|
| `cargo test` | All pass | 51 passed | PASS |
| `cargo clippy` | No warnings | No issues found | PASS |
| `docker compose config --quiet` | No errors | No output (valid) | PASS |
| `cargo build` | Compiles | 1 crate compiled | PASS |

## Risks and Rollback

- **Breaking change**: All env vars renamed. Anyone using old `SYSLOG_MCP_SECTION__KEY` format must update their `.env`. Rollback: `git revert 9d4b873`
- **External network**: `docker compose up` now requires the network to exist first (`docker network create syslog_mcp`). Previous behavior created it implicitly.
- **Named volume**: Existing bind-mount users must set `SYSLOG_MCP_DATA_VOLUME=./data` in `.env` to preserve behavior.

## Decisions Not Taken

- **Keep figment with flat struct**: Would require a single prefix, can't do `SYSLOG_` and `SYSLOG_MCP_` separately
- **Default data volume to `./data` (bind mount)**: User explicitly wanted named volume default
- **Single port line for UDP+TCP**: Docker doesn't support it — protocol suffix required

## Open Questions

- Should old env var names be supported with deprecation warnings for a transition period?
- The `config.toml` TOML sections (`[syslog]`, `[storage]`, `[mcp]`) don't map to env var prefixes — is this confusing?

## Next Steps

- Update any deployment scripts/ansible that reference old env var names
- Consider PR from `chore/add-lavra-project-config` → `main`
- Test Docker deployment with named volume on production host
