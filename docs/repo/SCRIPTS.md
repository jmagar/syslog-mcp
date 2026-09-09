---
title: "Scripts Reference -- cortex"
created: "2026-07-30"
updated: "2026-07-30"
---

# Scripts Reference -- cortex

Scripts used for maintenance, setup, and testing. The plugin ships no Claude
Code lifecycle hooks; `plugin-setup.sh` is invoked manually.

## Maintenance scripts (`scripts/`)

| Script | Purpose | Usage |
| --- | --- | --- |
| `smoke-test.sh` | Compatibility wrapper for the canonical live smoke profile | `bash scripts/smoke-test.sh` |
| `backup.sh` | WAL-safe SQLite backup using PRAGMA wal_checkpoint + .backup | `bash scripts/backup.sh` |
| `reset-db.sh` | Backup first, then destructive DB reset (stop server first) | `bash scripts/reset-db.sh` |





## Hook scripts

| Script | Purpose | Trigger |
| --- | --- | --- |
| `scripts/plugin-setup.sh` | Adapter that maps `CLAUDE_PLUGIN_OPTION_*` and delegates to `cortex setup pluginhook` | Manual setup / repair (no Claude Code hooks) |
| `scripts/block-env-commits.sh` | Blocks env credential commits when installed as a pre-commit hook | Git pre-commit |


## Test scripts (`tests/`)

| Script | Purpose | Usage |
| --- | --- | --- |
| `test_live.sh` | Extended live integration tests | `just test-live` |
| `mcporter/test-tools.sh` | mcporter-based tool tests | `bash tests/mcporter/test-tools.sh` |

## Script conventions

All bash scripts follow these patterns:
- `#!/bin/bash` shebang
- `set -euo pipefail` strict mode
- Quoted variables: `"$var"`
- Non-zero exit code on failure
- Human-readable output with PASS/FAIL indicators
- JSON output where appropriate (piped through `jq`)

## See also

- [RECIPES.md](RECIPES.md) -- Justfile recipes that invoke these scripts
- [../mcp/TESTS.md](../mcp/TESTS.md) -- testing guide
- [../mcp/MCPORTER.md](../mcp/MCPORTER.md) -- mcporter smoke testing
