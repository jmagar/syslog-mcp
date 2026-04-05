# Pre-commit Hook Configuration -- syslog-mcp

Hooks run as Claude Code lifecycle hooks via `hooks/hooks.json`.

## Hook configuration

Hooks are defined in `hooks/hooks.json` and enforced by Claude Code during sessions:

| Hook | Script | Purpose |
| --- | --- | --- |
| `sync-env` | `hooks/scripts/sync-env.sh` | Ensures `.env.example` documents all variables read by the server |
| `fix-env-perms` | `hooks/scripts/fix-env-perms.sh` | Sets `.env` to `chmod 600` if present |
| `ensure-ignore-files` | `hooks/scripts/ensure-ignore-files.sh` | Verifies `.gitignore` and `.dockerignore` contain required patterns |

## Manual checks

Run checks manually outside of Claude Code:

```bash
# Plugin manifest validation
just check-contract

# Docker security check
bash scripts/check-docker-security.sh

# No baked env vars in Docker image
bash scripts/check-no-baked-env.sh

# Outdated dependencies
bash scripts/check-outdated-deps.sh

# Ignore file patterns
bash scripts/ensure-ignore-files.sh
```

## Rust-specific checks

Before committing, run:

```bash
just lint        # cargo clippy -- -D warnings
just fmt         # cargo fmt
just test        # cargo test
```

These are not automated as git hooks but are enforced in CI.

## See also

- [CICD.md](CICD.md) -- CI workflow enforces lint and test
- [../GUARDRAILS.md](../GUARDRAILS.md) -- security patterns enforced by hooks
