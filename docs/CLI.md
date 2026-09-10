---
title: "Direct CLI Reference -- cortex"
created: 2026-05-07
updated: 2026-07-30
---

# Direct CLI Reference -- cortex

The `cortex` binary includes direct query and deployment-lifecycle commands for
humans and shell scripts. Query commands read the configured SQLite database and
call the same shared `SyslogService` methods used by the MCP tool. Compose
lifecycle commands inspect Docker/Compose directly and do not load the SQLite
query runtime.

Direct query CLI mode does not start syslog listeners, the HTTP MCP server, the
REST API, OTLP routes, retention purge, Docker ingest, or storage-budget cleanup
tasks. Keep `cortex serve mcp` running somewhere for ingestion.

## `cortex setup heartbeatagent`

```bash
cortex setup heartbeatagent install [--json]
cortex setup heartbeatagent check [--json]
cortex setup heartbeatagent remove [--json]
```

On macOS this manages the current user's LaunchAgent in the active `gui/$UID`
domain. See the authoritative [macOS heartbeat-agent operator
contract](SETUP.md#10-macos-heartbeat-agent) for lifecycle, capabilities,
security, migration, retention, recovery, and delivery proof.
`CORTEX_HEARTBEAT_TOKEN` is ingest; `CORTEX_API_TOKEN` is query-only.

## Breaking Command Migration

Version 3.0 intentionally removes the old implementation-shaped top-level CLI
commands. They fail fast with replacement guidance; there are no aliases or
compatibility shims.

| Removed command | Replacement |
| --- | --- |
| `cortex ai ...` | `cortex sessions ...` |
| `cortex source-ips ...` | `cortex hosts sources ...` |
| `cortex silent-hosts ...` | `cortex hosts silent ...` |
| `cortex service logs SERVICE ...` | `cortex compose logs SERVICE ...` |
| `cortex deploy ...` | `cortex setup deploy ...` |
| `cortex errors ...` | `cortex analysis errors ...` |
| `cortex incident ...` | `cortex analysis incident ...` |
| `cortex patterns ...` | `cortex analysis patterns ...` |
| `cortex anomalies ...` | `cortex analysis anomalies ...` |
| `cortex compare ...` | `cortex analysis compare ...` |
| `cortex correlate --reference-time ...` | `cortex correlate events --reference-time ...` |
| `cortex correlate-state ...` | `cortex correlate state ...` |
| `cortex topic-correlate ...` | `cortex correlate topic ...` |
| `cortex host-state ...` | `cortex state host ...` |
| `cortex fleet-state ...` | `cortex state fleet ...` |
| `cortex clock-skew ...` | `cortex state clockskew ...` |
| `cortex ingest-rate ...` | `cortex stats ingestrate ...` |
| `cortex sig ...` | `cortex alerts signatures ...` |
| `cortex notify ...` | `cortex alerts notifications ...` |
| `cortex shell ...` | `cortex ingest shell ...` |
| `cortex agent-command ...` | `cortex ingest shell agent ...` |
| `cortex inventory ...` | `cortex ingest inventory ...` |
| `cortex file-tail ...` | `cortex ingest filetail ...` |

The REST `/api/ai/*` namespace is also intentionally removed; use
`/api/sessions/*`.

## Configuration

CLI commands use the normal config loader:

1. `config.toml` in the working directory, when present
2. `CORTEX_*`, `CORTEX_*`, `CORTEX_API_*`, and `CORTEX_DOCKER_*` environment overrides

For local query use, the important setting is:

```bash
CORTEX_DB_PATH=/data/cortex.db
```

`CORTEX_TOKEN` is not used by direct CLI mode because it is local database
access, not HTTP access.

## `cortex ingest`

Ingestion commands group local shell history, agent command spools, the private
inventory cache, managed file-tail sources, and read-only Docker/syslog ingest
status checks.

### `cortex ingest filetail`

Manage Cortex-owned file-tail ingest sources. Sources are persisted beside the
configured database in `file-tails.json` and reconciled by the running
`cortex serve mcp` process.

```bash
cortex ingest filetail list [--json]
cortex ingest filetail status [--json]
cortex ingest filetail add PATH [--id ID] [--tag TAG] [--host HOST] [--facility FACILITY] [--severity SEVERITY] [--from-start] [--json]
cortex ingest filetail remove ID [--json]
cortex ingest filetail enable ID [--json]
cortex ingest filetail disable ID [--json]
```

The command maps to MCP action `file_tails` and REST `POST /api/file-tails`.
When `--http` or `CORTEX_USE_HTTP=true` is used, set both `CORTEX_API_TOKEN`
and `CORTEX_API_ADMIN_TOKEN`; the client sends the latter as
`X-Cortex-Admin-Token`.
By default `add` derives `id` and `tag` from the file name, assigns the stable
synthetic owner `file-tail-<id>`, and starts tailing at EOF. Pass `--host` when
the mounted file belongs to a real host that should participate in host filters
and correlation; Cortex never substitutes the server or container hostname.
Pass `--from-start` to ingest existing file contents.

### `cortex ingest syslog`

Inspect syslog listener configuration without starting listeners or sending test
frames.

```bash
cortex ingest syslog status [--json]
cortex ingest syslog test
```

`test` is reserved for a future safe local frame sender and currently exits with
an explicit deferred error.

### `cortex ingest docker`

Inspect Docker ingest configuration without exposing remote Docker endpoints.

```bash
cortex ingest docker status [--json]
cortex ingest docker sources [--json]
```

## Output

All commands print compact human-readable output by default. Add `--json` to
print the exact serialized `SyslogService` response shape. MCP uses the same
shape for matching actions; REST parity applies only to commands that also have
REST endpoints.

```bash
cortex stats --json
cortex search 'error AND nginx' --limit 5 --json
```

## Commands

### `cortex search`

Search logs with optional FTS5 query and filters. The query is a bare positional;
with no `--limit` the result count defaults to **50**.

```bash
cortex search "oom killer"                       # bare query, limit 50
cortex search 'error AND nginx' --host proxy --limit 10
cortex search --grep "smoke-test" --since 1h     # literal text, last hour
```

Flags:

| Flag | Description |
| --- | --- |
| positional query | Optional SQLite FTS5 query. Multiple words are joined with spaces. |
| `--grep TEXT` | Literal (FTS5-safe) substring; mutually exclusive with the positional query |
| `--host HOST` | Exact claimed hostname filter |
| `--source SOURCE` | Exact source identifier filter |
| `--severity LEVEL` | Syslog severity filter: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug` |
| `--app APP` | Application/process name filter |
| `--since TIME` | Start of window — relative (`1h`, `2d`, `yesterday`) or RFC3339 |
| `--until TIME` | End of window — relative or RFC3339 |
| `--limit N` | Maximum returned rows (default 50) |
| `--json` | Print JSON response |

### `cortex tail`

Return recent log entries, optionally filtered by host, source, or app. A bare
positional argument is a hostname (shorthand for `--host`); with no `-n`/`--limit`
the row count defaults to **50**.

```bash
cortex tail                       # 50 most recent across all hosts
cortex tail devhost                # bare positional → --host devhost
cortex tail nas --app kernel -n 100
```

Flags:

| Flag | Description |
| --- | --- |
| positional `HOST` | Hostname filter — shorthand for `--host` |
| `-n N`, `--limit N` | Number of rows to return (default 50) |
| `--host HOST` | Exact claimed hostname filter |
| `--source SOURCE` | Exact source identifier filter |
| `--app APP` | Application/process name filter |
| `--json` | Print JSON response |

### `cortex analysis errors`

Summarize error and warning counts by host and severity. With no `--since` the
window defaults to the **last hour**.

```bash
cortex analysis errors                     # last hour
cortex analysis errors --since 6h --limit 50
cortex analysis errors --since 2026-01-01T00:00:00Z --until 2026-01-02T00:00:00Z --json
```

Flags:

| Flag | Description |
| --- | --- |
| `--since TIME` | Start of window — relative (`1h`, `6h`, `yesterday`) or RFC3339 (default: last hour) |
| `--until TIME` | End of window — relative or RFC3339 |
| `--json` | Print JSON response |

### `cortex hosts`

List all known hosts with log counts and last-seen timestamps.

```bash
cortex hosts
cortex hosts --json
```

### `cortex ingest inventory`

Refresh and inspect the private homelab inventory cache under
`~/.cortex/inventory`.

```bash
cortex ingest inventory refresh --json
cortex ingest inventory status --json
```

`refresh` runs native Rust collectors for local host facts, Docker endpoints,
raw-but-redacted Compose YAML and reverse-proxy artifacts, Unraid, Tailscale,
UniFi, media services, and configured local project roots. Missing provider
credentials are warnings, not fatal errors for unrelated collectors. `status`
reads only the cache metadata and does not open SQLite.

Server-side refresh additionally projects the normalized inventory into the
investigation graph. It runs on the 5-minute baseline cadence and reacts to
local Compose/proxy config changes. Remote Docker container event streams over
SSH can be enabled explicitly with `CORTEX_INVENTORY_REMOTE_DOCKER_EVENTS=true`.

### `cortex sessions`

List AI transcript sessions grouped by project.

```bash
cortex sessions --project /home/jmagar/workspace/cortex --limit 20
```

Flags:

| Flag | Description |
| --- | --- |
| `--project PATH` | Exact project path filter |
| `--tool TOOL` | AI tool filter: `claude`, `codex`, or `gemini` |
| `--host HOST` | Filter by host |
| `--since TIME` | RFC3339 start timestamp |
| `--until TIME` | RFC3339 end timestamp |
| `--limit N` | Maximum returned rows |
| `--json` | Print JSON response |

### `cortex sessions search`

Ranked grouped session search across AI transcript rows.

```bash
cortex sessions search authentication --tool claude --limit 10
```

Human output now states that grouping is computed over the newest matching
candidate window. JSON includes `total_candidates`, `candidate_rows`,
`candidate_cap`, `candidate_window_truncated`, and `truncated`; when the
candidate window is truncated, narrow with `--project`, `--tool`, `--since`, or
`--until` for exact grouping within that filter.

### `cortex sessions abuse`

Detect abuse in AI transcript rows and return surrounding rows from the same
AI session.

```bash
cortex sessions abuse --project /home/jmagar/workspace/cortex --limit 10 --before 3 --after 3
cortex sessions abuse --tool codex --term dang --term heck --json
```

By default this uses the built-in abuse list and returns 2 rows before and
after each hit. Use repeated `--term WORD` flags to replace the built-in list
with a custom detector. JSON includes `candidate_rows`, `candidate_cap`,
`candidate_window_truncated`, `truncated`, and `matches[].{term,entry,before,after}`.

### `cortex sessions incidents`

Group abuse hits into scored incident candidates.

```bash
cortex sessions incidents --project /home/jmagar/workspace/cortex --limit 10
cortex sessions incidents --tool codex --term dang --term heck --json
```

Use `--window-minutes` to change how nearby abuse hits are grouped into one
incident. JSON includes `total_incidents`, `candidate_rows`, `candidate_cap`,
`candidate_window_truncated`, `truncated`, and `incidents[]`.

### `cortex sessions investigate`

Expand top incidents into deterministic evidence bundles without calling an LLM.

```bash
cortex sessions investigate --project /home/jmagar/workspace/cortex --limit 3
cortex sessions investigate --correlation-window-minutes 15 --json
```

Each evidence bundle includes the incident, anchor transcript rows, same-session
before/after context, nearby non-AI logs, and nearby warning-or-higher logs.
The public command expands at most 10 incidents per run.

### `cortex sessions assess`

Fetch one incident evidence bundle and run the local provider selected by `CORTEX_LLM` to produce a
Markdown frustration assessment.

```bash
cortex sessions incidents --limit 10
cortex sessions assess inc-f9a1d8e70cad13e6 --limit 3
CORTEX_LLM=gemini/gemini-3.1-flash-lite-preview cortex sessions assess inc-f9a1d8e70cad13e6 --json
cortex sessions assess inc-f9a1d8e70cad13e6 --dry-run
```

`assess` is local-only and rejects `--http` because it spawns the selected provider on the
local host. It can assess any incident ID returned by `cortex sessions incidents`
within the incident-list cap, even when that incident is outside the top 10
investigation bundles.

`--dry-run` previews the prompt/evidence bundle that would be sent to
the selected LLM — via `LlmRunner::dry_run` — without invoking the LLM. It still
writes an audit row to `llm_invocations` (status `dry_run`) but spawns no
subprocess, and prints `invocation_id`, `prompt_bytes`,
`evidence_counts`, and `would_exceed_prompt_limit` instead of an
assessment.

### `cortex sessions llminvocations`

List audit rows recorded by `LlmRunner` for every LLM invocation attempt
(dry runs, denials, and real provider calls alike).

```bash
cortex sessions llminvocations --limit 20
cortex sessions llminvocations --action ai_assess --status error --json
cortex sessions llminvocations --since 2026-06-01 --json
```

All flags are optional filters: `--since` (normalized time expression,
same parsing as other `sessions` commands), `--action` (exact match on
the recorded action name, e.g. `ai_assess`), `--status` (exact match on
the recorded status, e.g. `running`, `success`, `error`, `dry_run`,
`denied`), and `--limit` (defaults to 50, clamped to `1..=500`). This is
an **admin-scoped** action — it requires `cortex:admin`, not just
`cortex:read`.

### `cortex sessions skills`

List extracted AI skill-invocation events (Claude `attributionSkill`
structured fields, Codex `<skill><name>` transcript tags).

```bash
cortex sessions skills --project cortex --limit 20
cortex sessions skills --skill troubleshoot --since 1h --json
```

All flags are optional filters: `--skill`, `--plugin`, `--tool`,
`--project`, `--session-id`, `--host`, `--since`, `--until` (normalized
time expressions), and `--limit` (defaults to 50, clamped to `1..=500`).
This is a `cortex:read`-scoped action.

### `cortex sessions skills backfill`

Chunked, bounded, dry-run-capable backfill of `ai_skill_events` from
existing `logs` rows — catches up rows ingested before this phase shipped.

```bash
cortex sessions skills backfill --since 30d --limit 10000 --dry-run
cortex sessions skills backfill --limit 50000
```

`--since` (optional, normalized time expression) restricts the scan to
rows at or after that timestamp. `--limit` (optional, defaults to 10000,
hard-capped at 1,000,000) bounds the number of `logs` rows scanned in one
call. `--dry-run` reports `scanned`/`parse_errors`/`source_unavailable`
without inserting any rows — note it still reads the source transcript files
from disk to compute those counts, so it is not a zero-I/O preview; only the
DB write is skipped. Insertion is idempotent (`INSERT OR IGNORE` on
`UNIQUE(log_id, skill_name, event_kind, evidence_kind)`): re-running the
backfill is a no-op **as long as the source transcript files are unchanged**.
Because a Claude row's `skill_name` is re-derived from the file on each run
and is part of that uniqueness key, editing a transcript line in place between
runs can insert a second, differently-named event for the same `log_id`
(the `INSERT OR IGNORE` sees a new key, not a conflict). Transcript files are
append-only in practice, so this is an edge case, not a routine hazard. Only
one backfill can run at a time process-wide; a concurrent second call fails
fast with a "already running" error. Local mode only — this is a DB-heavy
batch job that runs against the local `CortexService`, not proxied over HTTP.

Codex rows are recovered directly from `logs.message` (the transcript text,
including `<skill><name>` tags, survives ingest-time scrubbing intact).
Claude rows are recovered by re-reading the specific line of the original
transcript file (via the shared `scanner::read_transcript_lines` helper, which
applies the same bounded, newline-delimited record semantics as the ingest
path), located via the persisted `ai_transcript_path` column and the `line_no`
recorded in `metadata_json` at ingest time — `logs.message` for a Claude row
is already-extracted plain text and never contains the raw
`attributionSkill`/`attributionPlugin` JSON. `source_unavailable` counts
Claude rows where that recovery wasn't possible: no `ai_transcript_path`/
`line_no` on the row (legacy rows ingested before that metadata existed),
the source file no longer exists, or the recorded line is out of range or
exceeds the record-size bound (file rotated/truncated/rewritten since
ingest). Those rows are skipped, not treated as an error; run with
`RUST_LOG=debug` to see the per-row reason (`log_id`, path, line number).
A non-zero `source_unavailable` after a real pass is expected for
pre-metadata legacy rows and for transcripts since deleted or rotated — those
are permanently unrecoverable via this command and need no action. An
unexpectedly high count on recently-ingested rows suggests the transcript
source directory moved; verify `ai_transcript_path` still resolves.

### `cortex sessions mcpevents`

List extracted AI MCP tool-call events (Claude `tool_use`/`tool_result`,
Codex `function_call`/`function_call_output`), classified via the
`mcp__<server>__<tool>` naming convention.

```bash
cortex sessions mcpevents --project cortex --limit 20
cortex sessions mcpevents --mcp-server labby --since 1h --json
```

All flags are optional filters: `--tool-name`, `--mcp-server`, `--mcp-tool`,
`--tool`, `--project`, `--session-id`, `--host`, `--is-error`, `--since`,
`--until` (normalized time expressions), and `--limit` (defaults to 50,
clamped to `1..=500`). This is a `cortex:read`-scoped action.

### `cortex sessions mcpevents backfill`

Chunked, bounded, dry-run-capable backfill of `ai_mcp_events` from existing
`logs` rows — catches up rows ingested before this phase shipped. Scans the
`raw` column (the original transcript JSON), not `message` (a scrubbed
summary).

```bash
cortex sessions mcpevents backfill --since 30d --limit 10000 --dry-run
cortex sessions mcpevents backfill --limit 50000
```

`--since` (optional, normalized time expression) restricts the scan to
rows at or after that timestamp. `--limit` (optional, defaults to 10000,
hard-capped at 1,000,000) bounds the number of `logs` rows scanned in one
call. `--dry-run` reports `scanned`/`parse_errors` without inserting any
rows. Insertion is idempotent, so re-running backfill is always safe. Only
one backfill can run at a time process-wide; a concurrent second call
fails fast with a "already running" error. Local mode only — this is a
DB-heavy batch job that runs against the local `CortexService`, not
proxied over HTTP.

### `cortex sessions mcpincidents`

Groups `ai_mcp_events` rows into incident candidates by `(mcp_server,
mcp_tool, tool, project, session_id, hostname, window_bucket)`.

```bash
cortex sessions mcpincidents --mcp-server labby --since 7d
cortex sessions mcpincidents --mcp-tool search --min-score 35 --json
```

### `cortex sessions mcpinvestigate`

Deep-dive investigation of MCP-usage incidents, server/tool-first (mirrors
`cortex sessions skillinvestigate`'s skill-first resolution rule).

```bash
cortex sessions mcpinvestigate labby
cortex sessions mcpinvestigate labby --since 7d --all --limit 5
```

### `cortex sessions hookincidents`

List hook failures and other negative signals. A bare positional is the hook
name; omit it to scan all hooks.

```bash
cortex sessions hookincidents
cortex sessions hookincidents format-on-save --since 7d
```

### `cortex sessions hookinvestigate`

Build an evidence bundle for one hook or incident through the same shared
service used by REST and MCP.

```bash
cortex sessions hookinvestigate format-on-save
cortex sessions hookinvestigate --incident-id INCIDENT_ID
```

### `cortex sessions mcpassess`

Low-level alias for `cortex assess mcp` — see the "Skill, MCP, and abuse
assessment" section in [README.md](../README.md) for the full flag
reference and LLM-guard behavior.

### `cortex sessions blocks`

Bucket AI activity into 5-hour UTC windows.

```bash
cortex sessions blocks --project /home/jmagar/workspace/cortex
```

When `--since` is omitted, usage blocks default to the last 30 days. Returned
JSON includes `total_blocks` and `truncated`; at most 1000 buckets are returned.

### `cortex sessions context`

Summarize one AI project path.

```bash
cortex sessions context --project /home/jmagar/workspace/cortex --limit 5
```

Recent representative entries are capped at 20 rows, and message snippets are
bounded to 256 characters for predictable MCP/CLI payload size.

### `cortex sessions correlate`

Cross-reference AI transcript rows against nearby non-AI logs.

```bash
cortex sessions correlate --project /home/jmagar/workspace/cortex --limit 5
cortex sessions correlate --ai-query deploy --log-query container --window-minutes 10 --severity-min warning --json
```

The AI side uses transcript rows as anchors. The related log side searches the
normal log corpus inside each anchor window and excludes AI transcript rows, so
the command surfaces host, Docker, OTLP, and syslog events around the session
without duplicating the transcript stream itself.

### `cortex sessions tools`

List distinct AI tools with counts.

```bash
cortex sessions tools --json
```

Returned JSON includes `total_tools` and `truncated`; at most 100 tools are
returned.

### `cortex sessions projects`

List distinct AI projects with counts.

```bash
cortex sessions projects --tool claude
```

Returned JSON includes `total_projects` and `truncated`; at most 200 projects
are returned.

### `cortex sessions index`

Explicitly scan local transcript roots (`~/.claude/projects`, `~/.codex/sessions`, `~/.gemini/tmp`) or one `--path`.

```bash
cortex sessions index
cortex sessions index --path ~/.claude/projects
cortex sessions index --since 2026-05-14T00:00:00Z
cortex sessions index --path ~/.codex/sessions --force
cortex sessions index --path ~/.gemini/tmp
```

Path policy is intentionally narrow. Recursive `--path` scans are accepted only
for known transcript roots (`~/.claude/projects`, `~/.codex/sessions`) or their
children, plus `~/.gemini/tmp` for Gemini chat files; one explicit `.jsonl` file
can be imported outside those roots.
`--path /`, `--path $HOME`, and the repo root are rejected before walking, and
symlinks are skipped. Directories are scanned only for supported transcript
files, unsupported files are counted but not parsed, and JSONL files are streamed
line-by-line with chunked SQLite transactions. Gemini chat files are imported
from `~/.gemini/tmp/*/chats/session-*.json`; when only `projectHash` is present,
the indexed project is `gemini://project/<hash>`. If storage guardrails cannot
recover enough space, indexing fails before committing additional chunks.

`--since TIME` skips files whose filesystem modification time is older than the
RFC3339 timestamp. `--force` clears existing import identities and previously
stored log rows for each scanned transcript path before reimporting, which is
the right option after parser fixes or scrubber changes.

### `cortex sessions add`

Ingest one explicit transcript file.

```bash
cortex sessions add --file ~/.claude/projects/example/session.jsonl
cortex sessions add --file ~/.codex/sessions/2026/05/14/session.jsonl --force
```

`--force` reimports that one transcript from scratch without leaving duplicate
log rows.

### `cortex sessions watch`

Watch local Claude/Codex/Gemini transcript roots and index stable changed
transcript files as they are written.

```bash
cortex sessions watch
cortex sessions watch --path ~/.claude/projects --no-initial-scan
cortex sessions watch --path ~/.gemini/tmp --no-initial-scan
cortex sessions watch --debounce-ms 750 --settle-ms 500 --max-retries 5 --json
```

The watcher is a host-local helper, not part of the Docker Compose runtime. It
reuses the same scanner root policy, file support checks, checkpoints,
append-offset indexing, duplicate suppression, parse-error persistence, and
storage guardrails as `cortex sessions index` and `cortex sessions add`. The watcher only
coalesces filesystem events, waits for files to stabilize, and retries
transient parse/storage/file errors up to the configured cap.

### `cortex sessions checkpoints`

Inspect structured scanner checkpoints without opening SQLite directly.

```bash
cortex sessions checkpoints --limit 20
cortex sessions checkpoints --errors --json
cortex sessions checkpoints --missing
```

The output shows source kind, imported record count, last successful checkpoint,
missing-source status, parse error count, and the last parser/indexing error
when present.

### `cortex sessions errors`

Inspect persisted transcript parser errors.

```bash
cortex sessions errors --limit 20
cortex sessions errors --json
```

Errors include source path, source kind, line number, timestamp, and a bounded
scrubbed preview so parser failures can be investigated without opening the
database directly.

### `cortex sessions prunecheckpoints`

Remove checkpoints for transcript files that no longer exist.

```bash
cortex sessions prunecheckpoints --missing --dry-run
cortex sessions prunecheckpoints --missing --limit 100
```

Pruning is deliberately limited to `--missing` checkpoints. It removes scanner
source metadata, import identities, and parse-error rows for missing files; it
does not delete already imported log rows.

### `cortex sessions doctor`

Summarize the local AI indexing state.

```bash
cortex sessions doctor
cortex sessions doctor --json
cortex sessions doctor --strict-permissions --json
```

The doctor reports the DB path in use, whether `~/.claude/projects` and
`~/.codex/sessions` exist, whether they are readable/writable by the current
user, owner uid/gid, mode, checkpoint counts, missing checkpoint counts,
imported record count, parse error count, and the newest indexed transcript.
Without `--strict-permissions`, this is a report-only command. With
`--strict-permissions`, it exits non-zero when either transcript root is
missing, unreadable, unwritable, or owned by another user.

### `cortex sessions watchstatus`

Inspect the supported user-systemd watcher without reading systemd internals by
hand.

```bash
cortex sessions watchstatus
cortex sessions watchstatus --json
```

The status command reports `syslog-sessions-watch.service` active/enabled state, main
PID, ExecStart, and the latest bounded journal lines. It uses the same user bus
fallback as setup commands, so it still works from shells or tool environments
that do not export `DBUS_SESSION_BUS_ADDRESS`.

### `cortex sessions smokewatch`

Run a bounded live smoke test of the host-local watcher. The command writes a
temporary Claude transcript under `~/.claude/projects`, waits for the watcher to
ingest it into the configured database, deletes the temp file, then waits for
the missing-checkpoint pruner to clear scanner metadata.

```bash
cortex sessions smokewatch
cortex sessions smokewatch --json
```

This is a live command. It requires `syslog-sessions-watch.service` to be running and
writing to the same `CORTEX_DB_PATH` used by the CLI process.

### `cortex ingest shell user`

Backfill local, human-typed shell history into the main log corpus.

```bash
cortex ingest shell user index --path ~/.zsh_history
cortex ingest shell user index --path ~/.zsh_history --shell zsh --json
cortex ingest shell user atuinindex --path ~/.local/share/atuin/history.db --json
```

The importer currently supports zsh extended history lines in the
`: <epoch>:<duration>;<command>` format. Plain history lines without timestamps
are counted as skipped because they cannot be correlated reliably. Commands are
scrubbed before storage, written with `source_kind="shell-history"`, and use
`source_ip` identities shaped like `shell-history://<hostname>/<user>/<shell>`.
Rows are deduped by source identity, timestamp, and scrubbed command text, and
the importer records a private byte-offset cursor under the cortex state
directory so repeated imports only read newly appended history.

### `cortex ingest shell agent`

Capture shell commands launched by agent tools, then ingest the private JSONL
spool into SQLite (or forward it to a remote Cortex — see `--server`/`--token`
below).

```bash
cortex setup shell agent install
export CLAUDE_CODE_SHELL_PREFIX="$HOME/.local/bin/cortex-agent-command-wrapper"

cortex ingest shell agent index --path ~/.local/state/cortex/agent-command.jsonl
cortex ingest shell agent index --path ~/.local/state/cortex/agent-command.jsonl --server https://cortex.example.test --token secret
cortex ingest shell agent wrap --spool ~/.local/state/cortex/agent-command.jsonl -- cargo test
```

The legacy `cortex ingest agent-command ...` grammar is removed. Use
`cortex ingest shell agent index|wrap`.

`CLAUDE_CODE_SHELL_PREFIX` is the Claude Code hook point for commands spawned by
Claude Code, including Bash tool calls, hook commands, and stdio MCP server
startup commands. The generated wrapper executes the original command, preserves
stdio and exit code, then appends one scrubbed JSONL record. It removes
`CLAUDE_CODE_SHELL_PREFIX` and sets an internal recursion guard for the child
process so the wrapper does not wrap itself.

The wrapper does not capture environment variables, stdout, or stderr by
default. Command strings are scrubbed for known token, secret flag, assignment,
Authorization header, URL-userinfo, `curl -u`, and private-key forms before they
reach the spool. The spool directory is created as `0700`, the spool file as
`0600`, symlink paths are rejected, and import refuses group/world writable
parents or spools. Wrapper appends and spool imports use the same advisory file
lock; after a successful import the spool is truncated so repeated imports do
not rescan already-ingested commands. Imported rows use
`source_kind="agent-command"`, `facility`
`agent`, `app_name`/`ai_tool` set to the agent name, `event_action="command"`,
and `source_ip` identities shaped like
`agent-command://<hostname>/<agent>/<session_id>`.

### `cortex setup sessionswatch`

Install, remove, or inspect the supported host-local user-systemd watcher for
near-real-time transcript ingestion.

```bash
cortex setup sessionswatch install
cortex setup sessionswatch check --json
cortex setup sessionswatch remove
```

Install resolves an absolute `cortex` binary and a concrete SQLite DB path,
writes a private environment file under `~/.config/cortex/`, runs one
initial `cortex sessions index --json` phase, disables the older polling timer, and
starts `syslog-sessions-watch.service` with `cortex sessions watch --no-initial-scan
--json`. The helper is intentionally outside the container because it must read
host-local Claude/Codex/Gemini transcript files; Docker Compose remains the
server/query deployment. Remove events from watched transcript files trigger a
bounded missing-checkpoint prune pass, which keeps scanner/checkpoint metadata
from accumulating entries for deleted local session files without deleting
already imported log rows.

Initial-index transcript data quality issues are warnings, not install-blocking
errors. The setup JSON includes `blocking_errors`, `data_quality_warnings`,
`service_enabled`, and `watcher_healthy` so automation can distinguish a broken
watcher from historical transcript cleanup work. When data-quality warnings are
reported, inspect them with:

```bash
cortex sessions errors --limit 20
cortex sessions checkpoints --errors
cortex sessions index --json
```

Storage-blocked writes, invalid JSON from the indexer, command failures, stale
unit content, permission failures, and failed `systemctl enable --now` phases
remain blocking errors. Installing the watch service disables the older
`syslog-sessions-index.timer` to avoid duplicate background ingestion loops.

### `cortex setup debugwrapper`

Install, remove, or inspect the host-local debug wrapper at
`~/.local/bin/cortex`.

```bash
cortex setup debugwrapper install
cortex setup debugwrapper check --json
cortex setup debugwrapper remove
```

The wrapper is intentionally machine-local. It `cd`s into the configured repo
or worktree, builds `cargo build --bin cortex` into `.cache/cargo`, then execs
the fresh debug binary. For non-server commands it defaults Docker ingest off
and bearer auth mode on, so regular CLI checks do not accidentally start
container-log ingestion or OAuth-only config paths. Override the source checkout
with `CORTEX_REPO=/path/to/cortex cortex ...`.

### `cortex setup debugcompose`

Install, remove, or inspect the local debug Compose override under
`~/.cortex/compose/docker-compose.override.yml`.

```bash
cortex setup debugcompose install
cortex setup debugcompose check --json
cortex setup debugcompose remove
```

The override is machine-local. It points the canonical Docker Compose project at
the current repo/worktree and builds the `cortex:local-debug` image with the
debug profile. This keeps `docker compose up -d --build` aligned with the same
code that the host debug wrapper builds. Existing setup environments may still
carry the legacy `COMPOSE_PROJECT_NAME=syslog-jmagar-lab` for container-label
compatibility; use `cortex compose ...` when possible because it resolves the
live owner before mutating the stack.

### `cortex setup doctor`

Run the repo-owned local setup checks as one command.

```bash
cortex setup doctor
cortex setup doctor --json
```

The doctor checks setup directories, `.env`, Compose assets, the debug wrapper,
the debug Compose override, transcript-root permissions, disabled legacy index
timer state, active/enabled watcher state, and container freshness via
`scripts/check-runtime-current.sh --allow-local-image`.

### `cortex update`

Update an already-configured Cortex deployment. Configure the update profile
once:

```bash
cortex update config server --host nashost --home /mnt/cache/appdata/cortex
cortex update config clients --hosts devhost,backuphost,edgehost --target https://cortex.example.invalid --docker
```

The profile lives at `~/.cortex/deployments.toml` by default. A successful
`cortex setup deploy remote --home PATH HOST` also records the server profile,
so a one-off low-level deploy can seed future `cortex update server` runs.
Re-running `cortex update config clients` replaces the host list and preserves
any omitted saved `--target`, `--docker`, or `--journald` choices.

After the profile exists, dry-run before live updates:

```bash
cortex update --dry-run
cortex update
cortex update server --dry-run
cortex update clients --dry-run
cortex update clients
```

`cortex update` defaults to `all`: it updates the configured server first, then
updates configured host-agent clients. `clients` and `agents` are aliases; both
refer to the host-local Cortex agents that forward logs, heartbeats, sessions,
shell history, and command events into the server. Client dry-runs resolve the
local binary and probe each configured host over SSH without deploying.
Live client updates preserve the existing remote heartbeat-agent env before
reinstalling. Because this is an update path for already configured agents, it
fails if the remote agent token cannot be read/preserved; use
`cortex setup deploy agent --heartbeat-token-file PATH` to seed or repair a client without exposing the token in process arguments.

### `cortex setup deploy`

Run the Compose-backed deployment workflow using operator-facing names.
`preflight` and `local` call the same setup engine as `cortex setup check`
and `cortex setup repair`; `remote` uses SSH plus the shared setup assets.

```bash
cortex setup deploy preflight
cortex setup deploy preflight --json
cortex setup deploy local
cortex setup deploy local --dry-run --json
cortex setup deploy remote nashost --dry-run
cortex setup deploy remote --home /mnt/cache/appdata/cortex nashost
cortex setup deploy remote nashost --json
```

`setup deploy preflight` and `setup deploy local --dry-run` do not mutate Docker state.
`setup deploy local` repairs `~/.cortex/.env`, rewrites managed Compose assets,
pulls the configured image, starts the stack, and checks `/health`.
`setup deploy remote` uses SSH and Docker Compose on the target host. Non-dry-run
remote deploy writes/replaces `.env`, the managed Compose YAML, and
`config/Dockerfile` under the selected remote home. The default remote home is
`~/.cortex`; use `--home PATH` for hosts whose runtime is stored elsewhere, such
as nashost's `/mnt/cache/appdata/cortex`. Non-dry-run remote deploy preserves
existing remote env values from `<home>/.env` or legacy `<home>/compose/.env`
but deliberately drops `CORTEX_VERSION` so the release-managed Compose template
owns the image tag. After migrating a legacy compose-local env file, remote
deploy archives it as `<home>/compose/.env.legacy`; `<home>/.env` is the
canonical runtime env. It is CLI-only, requires an explicit host argument, and
does not add REST or MCP deploy mutation surfaces.

### `cortex setup sessionstimer`

Install, remove, or inspect the optional host-local user-systemd polling
fallback that periodically runs `cortex sessions index`.

```bash
cortex setup sessionstimer install
cortex setup sessionstimer check --json
cortex setup sessionstimer remove
```

This helper is intentionally not part of the Docker container. It scans
host-local transcript roots (`~/.claude/projects`, `~/.codex/sessions`,
`~/.gemini/tmp`) using a
host `cortex` binary, then writes to the configured SQLite DB. Prefer
`cortex setup sessionswatch install` for normal use; the watcher install
disables this timer to avoid duplicate background ingestion loops.

### `cortex doctor binary`

Check whether the shell binary and running container line up with this repo.

```bash
cortex doctor binary
cortex doctor binary --json
```

The doctor reports the current executable, `cortex` resolved from `PATH`, repo
version, container version when Docker is available, and the result of
`scripts/check-runtime-current.sh`.

For a one-command live check of the AI transcript workflow, run:

```bash
bash scripts/smoke-ai.sh
bash scripts/smoke-ai-mcp.sh
```

The smoke scripts resolve `CORTEX_BIN` first, then `cortex` on `PATH`, then the
repo-local debug binary at `target/debug/cortex`.

With `syslog-sessions-watch.service` installed, new transcript lines usually become
searchable within a few seconds of the writer closing or flushing the file.
Imported transcript messages are scrubbed for known credential/token patterns
before storage and FTS indexing, but scrubbing is best-effort. Raw log actions
can still expose scrubbed AI messages and local `ai_transcript_path` values, so
do not expose the database or MCP endpoint to clients that should not see local
AI session content.

### `cortex correlate events`

Find related events around a reference timestamp. Results are grouped by host.
`--reference-time` or `--query` is required. If `--reference-time` is omitted,
the anchor is derived from the top AI-transcript session matching `--query`
(the matched session is included in the response as `matched_session`).

```bash
cortex correlate events --reference-time 2026-01-01T12:00:00Z --window-minutes 10
cortex correlate events 2026-01-01T12:00:00Z --severity-min err --query timeout --limit 50
cortex correlate events --query "qbittorrent keeps dying"  # anchor derived from AI session search
```

Flags:

| Flag | Description |
| --- | --- |
| positional reference time | RFC3339 center timestamp |
| `--reference-time TIME` | RFC3339 center timestamp. Required unless `--query` is given. |
| `--window-minutes N` | Minutes before and after the reference time |
| `--severity-min LEVEL` | Minimum severity to include |
| `--host HOST` | Exact claimed hostname filter |
| `--source SOURCE` | Exact source identifier filter |
| `--query FTS` | FTS5 query filtering correlated logs; also used to derive `--reference-time` via AI-session search when it's omitted |
| `--limit N` | Maximum total events |
| `--json` | Print JSON response |

### `cortex state host`

Return the latest bounded heartbeat state for one host. A bare positional
argument is a hostname (shorthand for `--host`).

```bash
cortex state host nashost          # bare positional → --host nashost
cortex state host --host-id host-a --limit 5 --json
```

Flags:

| Flag | Description |
| --- | --- |
| positional `HOST` | Hostname — shorthand for `--host` |
| `--host-id ID` | Authoritative heartbeat host identity |
| `--host HOST` | Self-reported hostname fallback (must resolve to one host) |
| `--since TIME` | Minimum `sampled_at` timestamp (ISO 8601) |
| `--limit N` | Number of samples (default 1, max 100) |
| `--json` | Print JSON response |

### `cortex state fleet`

Print a fleet-wide heartbeat snapshot with pressure flags and summary counts.

```bash
cortex state fleet
cortex state fleet --exclude-ok --sort freshness --json
```

Flags:

| Flag | Description |
| --- | --- |
| `--exclude-ok` | Omit hosts whose status is `ok` |
| `--include-ok` | Include `ok` hosts (default) |
| `--sort ORDER` | `pressure` (default), `freshness`, or `hostname` |
| `--json` | Print JSON response |

### `cortex correlate state`

Correlate non-AI logs with per-host heartbeat window summaries around a
reference time. Bounded by default; never performs a full-history scan.

```bash
cortex correlate state --reference-time 2026-01-01T12:00:00Z --window-minutes 10
cortex correlate state --reference-time 2026-01-01T12:00:00Z --host nashost --severity-min warning --json
```

Flags:

| Flag | Description |
| --- | --- |
| `--reference-time TIME` | RFC3339 center timestamp (required) |
| `--window-minutes N` | Minutes before and after (default 10, max 120) |
| `--host HOST` | host_id or unique hostname; omit for bounded cross-host plan |
| `--severity-min LEVEL` | Minimum log severity (default `info`) |
| `--limit N` | Maximum log rows per host (default 100, max 500) |
| `--json` | Print JSON response |

### `cortex entity`

Resolve a derived graph entity by canonical type/key or by alias. Ambiguous
aliases return candidates instead of silently choosing one.

```bash
cortex entity host nashost
cortex entity host:nashost --json
cortex entity logical_service plex
cortex entity service_instance nashost/plex
cortex entity --alias-type hostname --alias-key nashost
```

Canonical service identity is `logical_service` (`plex`) plus
`service_instance` (`nashost/plex`). Legacy nested service identities such as
`nashost:plex` or `nashost:plex:plex` are rejected with
`rejected_legacy_shape`.

Flags:

| Flag | Description |
| --- | --- |
| positional `TYPE KEY` | Exact graph entity type and key |
| positional `TYPE:KEY` | Forgiving exact lookup form |
| `--alias-type TYPE` | Alias type such as `hostname` or `heartbeat_host_id` |
| `--alias-key KEY` | Alias value to resolve |
| `--limit N` | Alias candidate cap |
| `--evidence-sample-limit N` | Accepted for response metadata symmetry |
| `--payload-budget BYTES` | Approximate response payload budget |
| `--json` | Print shared structured response |

### `cortex graph around`

Return a bounded one-hop neighborhood for a graph entity. Human output includes
relationship type, source/destination entity summaries, confidence/trust,
reason, evidence counts, safe samples, projection status, truncation reason,
and follow-up commands.

```bash
cortex graph around host nashost
cortex graph around host:nashost --limit 25
cortex graph around logical_service:plex
cortex graph around service_instance nashost/plex
cortex graph around --entity-id 42 --json
```

Service topics use `logical_service:plex` / `service_instance:nashost/plex`;
`nashost:plex` and `nashost:plex:plex` return `rejected_legacy_shape`.

Flags:

| Flag | Description |
| --- | --- |
| positional `TYPE KEY` | Entity to expand |
| positional `TYPE:KEY` | Forgiving entity form |
| `--entity-id ID` | Exact graph entity id to expand |
| `--alias-type TYPE` | Alias type for resolving the starting entity |
| `--alias-key KEY` | Alias value for resolving the starting entity |
| `--depth 1` | V1 supports one-hop only |
| `--limit N` | Relationship cap |
| `--evidence-sample-limit N` | Safe evidence samples per relationship |
| `--payload-budget BYTES` | Approximate response payload budget |
| `--json` | Print shared structured response |

### `cortex graph explain`

Generate a deterministic evidence-backed explanation over bounded graph
chains. Human output includes conservative confidence, cited relationship and
evidence ids, missing evidence, open questions, projection status, truncation
reason, and follow-up graph commands. Low-confidence output avoids causal
claims.

```bash
cortex graph explain host nashost
cortex graph explain host:nashost --depth 2 --beam-width 20
cortex graph explain --entity-id 42 --json
```

Flags:

| Flag | Description |
| --- | --- |
| positional `TYPE KEY` | Entity to explain |
| positional `TYPE:KEY` | Forgiving entity form |
| `--entity-id ID` | Exact graph entity id to explain |
| `--alias-type TYPE` | Alias type for resolving the starting entity |
| `--alias-key KEY` | Alias value for resolving the starting entity |
| `--depth N` | Explanation expansion depth, default 2, hard max 3 |
| `--beam-width N` | Relationships fetched per frontier entity |
| `--max-chains N` | Total candidate chain cap |
| `--evidence-sample-limit N` | Safe evidence samples per relationship |
| `--payload-budget BYTES` | Approximate response payload budget |
| `--json` | Print shared structured response |

### `cortex graph evidence`

Inspect the proof row behind one graph evidence id. Human output includes the
evidence id, owning relationship id, readable source/destination endpoints,
reason, trust, confidence, source ids, bounded source-log summary when present,
safe excerpt, metadata path, and follow-up graph/log commands.

```bash
cortex graph evidence 12345
cortex graph evidence 12345 --json
```

Flags:

| Flag | Description |
| --- | --- |
| positional `EVIDENCE_ID` | `graph_relationship_evidence.id` to inspect |
| `--payload-budget BYTES` | Approximate response payload budget |
| `--json` | Print shared structured response |

`source_log_summary` never includes the raw syslog frame or full
`metadata_json`. When a source log id points at a retained-out/deleted row,
the response keeps the evidence, relationship, and endpoint summaries while
returning `source_log_summary: null` and `missing_source_reason`.

### `cortex stats`

Print database and storage guardrail metrics.

```bash
cortex stats
cortex stats --json
```

### `cortex db status`

Print SQLite maintenance state for the configured database.

```bash
cortex db status
cortex db status --json
```

The status includes page counts, freelist count, page size, logical and physical
database size, WAL/SHM sidecar sizes when present, journal mode, auto-vacuum
mode, and no integrity scan. Use `cortex db integrity` for the full SQLite
integrity check on large databases.

### `cortex db integrity`

Run `PRAGMA integrity_check` against the configured database.

```bash
cortex db integrity
cortex db integrity --json
```

The command exits non-zero if SQLite reports anything other than `ok`.

### `cortex db checkpoint`

Run a WAL checkpoint.

```bash
cortex db checkpoint
cortex db checkpoint --mode full
cortex db checkpoint --mode truncate --json
```

Supported modes are `passive`, `full`, `restart`, and `truncate`. The command
exits non-zero if SQLite reports the checkpoint as busy.

### `cortex db vacuum`

Run SQLite vacuum maintenance.

```bash
cortex db vacuum
cortex db vacuum --pages 5000
cortex db vacuum --full
```

The default is `PRAGMA incremental_vacuum(1000)`. `--full` runs `VACUUM` and can
take longer on large databases.

### `cortex db backup`

Create a WAL-safe SQLite backup using the `sqlite3` CLI `.backup` command.

```bash
cortex db backup
cortex db backup --output ~/.cortex/backups
cortex db backup --output /tmp/syslog-copy.db --json
```

When `--output` is a directory or omitted, the command writes a timestamped
`syslog-YYYY-MM-DD-HHMMSS.db` backup. When `--output` has a file extension, it
is used as the exact destination file.

### `cortex compose`

Diagnose and manage the Docker Compose deployment without opening the SQLite
database.

```bash
cortex compose doctor
cortex compose status --json
cortex compose pull
cortex compose up
cortex compose restart
cortex compose logs --tail 20
cortex compose down --yes
```

Common target flags:

| Flag | Description |
| --- | --- |
| `--compose-file FILE` | Explicit Compose file |
| `--project-dir DIR` | Explicit Compose project directory |
| `--project-name NAME` | Compose project name, only safe with a file/dir or live labels |
| `--service NAME` | Compose service name, default `cortex` |
| `--container NAME` | Container name, default `cortex` |
| `--json` | Print JSON response |

Mutation flags:

| Flag | Description |
| --- | --- |
| `--dry-run` | Resolve and preflight without running Docker |
| `--allow-cwd-target` | Permit cwd `docker-compose.yml` fallback for mutation |
| `--yes` | Required for non-interactive destructive `down` |

`cortex compose` refuses ambiguous target discovery, mismatched requested
project/service selectors, cwd fallback without confirmation,
project-name-only mutations, missing Compose files, legacy service conflicts,
non-target listeners on syslog ports, and destructive service stop without
`--yes`. `down` is intentionally service-scoped (`docker compose stop
cortex`), not a project-wide `docker compose down`.

## Relationship to MCP

The direct CLI and MCP tool share the same business layer. Transport adapters
own argument parsing and rendering; shared defaults, limits, validation, audit
identity, and safety policy belong in `SyslogService` or service-owned request
models.

| CLI command | MCP action |
| --- | --- |
| `cortex search` | `cortex` with `action="search"` |
| `cortex filter` | `cortex` with `action="filter"` |
| `cortex tail` | `cortex` with `action="tail"` |
| `cortex analysis errors` | `cortex` with `action="errors"` |
| `cortex hosts` | `cortex` with `action="hosts"` |
| `cortex sessions` | `cortex` with `action="sessions"` |
| `cortex sessions search` | `cortex` with `action="search_sessions"` |
| `cortex sessions abuse` | `cortex` with `action="abuse"` |
| `cortex sessions incidents` | `cortex` with `action="abuse_incidents"` |
| `cortex sessions investigate` | `cortex` with `action="abuse_investigate"` |
| `cortex sessions correlate` | `cortex` with `action="ai_correlate"` |
| `cortex sessions blocks` | `cortex` with `action="usage_blocks"` |
| `cortex sessions context` | `cortex` with `action="project_context"` |
| `cortex sessions tools` | `cortex` with `action="list_ai_tools"` |
| `cortex sessions projects` | `cortex` with `action="list_ai_projects"` |
| `cortex sessions similar` | `cortex` with `action="similar_incidents"` |
| `cortex sessions incidentcontext` | `cortex` with `action="incident_context"` |
| `cortex sessions skills` | `cortex` with `action="skill_events"` |
| `cortex sessions mcpevents` | `cortex` with `action="mcp_events"` |
| `cortex correlate events` | `cortex` with `action="correlate"` |
| `cortex state host` | `cortex` with `action="host_state"` |
| `cortex state fleet` | `cortex` with `action="fleet_state"` |
| `cortex correlate state` | `cortex` with `action="correlate_state"` |
| `cortex apps` | `cortex` with `action="apps"` |
| `cortex artifactevents` | `cortex` with `action="artifact_evidence"` |
| `cortex hosts sources` | `cortex` with `action="source_ips"` |
| `cortex timeline` | `cortex` with `action="timeline"` |
| `cortex analysis patterns` | `cortex` with `action="patterns"` |
| `cortex context` | `cortex` with `action="context"` |
| `cortex get` | `cortex` with `action="get"` |
| `cortex stats ingestrate` | `cortex` with `action="ingest_rate"` |
| `cortex hosts silent` | `cortex` with `action="silent_hosts"` |
| `cortex state clockskew` | `cortex` with `action="clock_skew"` |
| `cortex analysis anomalies` | `cortex` with `action="anomalies"` |
| `cortex analysis compare` | `cortex` with `action="compare"` |
| `cortex alerts signatures` | `cortex` with `action="unaddressed_errors"` |
| `cortex alerts signatures ack` | `cortex` with `action="ack_error"` |
| `cortex alerts signatures unack` | `cortex` with `action="unack_error"` |
| `cortex alerts notifications` | `cortex` with `action="notifications_recent"` |
| `cortex alerts notifications test` | `cortex` with `action="notifications_test"` |
| `cortex stats` | `cortex` with `action="stats"` |
| `cortex compose status` | `cortex` with `action="compose_status"` (redacted read-only projection only) |
| `cortex compose doctor` | `cortex` with `action="compose_doctor"` (redacted read-only projection only) |

The MCP-only `status` and `help` actions are runtime/protocol helpers, not
direct database queries. Compose mutations (`up`, `down`, `restart`, `pull`,
`logs`) are CLI-only and are not exposed over MCP. Admin MCP actions such as
`ack_error`, `unack_error`, and `notifications_test` require `cortex:admin`
when auth is mounted.

Use direct CLI mode for terminal queries and scripts on a host that can read the
SQLite database. Use MCP HTTP or `cortex mcp` when an MCP client needs tool
access.

## See also

- [README.md](../README.md) -- project overview and quick examples
- [mcp/TOOLS.md](mcp/TOOLS.md) -- MCP action reference
- [mcp/TRANSPORT.md](mcp/TRANSPORT.md) -- HTTP and stdio MCP transports
- [CONFIG.md](CONFIG.md) -- config file and environment reference
