# Hook Configuration -- syslog-mcp

Lifecycle hooks that run automatically during Claude Code sessions.

## File location

```
hooks/
  hooks.json                    # Hook definitions
  scripts/
    sync-env.sh                 # Sync .env.example with server variables
    fix-env-perms.sh            # Fix .env file permissions

```

## Hook definitions

Hooks are registered in `hooks/hooks.json` and executed by Claude Code at the appropriate lifecycle point.

### sync-env

Ensures `.env.example` documents all environment variables that the server reads. Detects new variables added to `src/config.rs` that are missing from `.env.example`.

### fix-env-perms

Sets `.env` to `chmod 600` (owner read/write only) if the file exists. Prevents accidental world-readable credential files.

### ensure-ignore-files

Verifies that `.gitignore` and `.dockerignore` contain required patterns:
- `.env`
- `*.secret`
- `credentials.*`
- `data/` (SQLite database files)

## Manual execution

Run hooks outside of Claude Code:

```bash
bash bin/sync-env.sh
bash bin/fix-env-perms.sh

```

## See also

- [../GUARDRAILS.md](../GUARDRAILS.md) -- security patterns enforced by hooks
- [../mcp/PRE-COMMIT.md](../mcp/PRE-COMMIT.md) -- pre-commit checks
