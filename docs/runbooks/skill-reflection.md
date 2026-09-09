---
title: Skill reflection with Codex app-server
created: 2026-09-08
updated: 2026-09-09
---

# Skill reflection with Codex app-server

`cortex assess skill` uses Codex app-server over stdio, not Gemini. The
existing LlmRunner still enforces its kill switch, action policy, timeout,
concurrency/rate limits, circuit breaker and invocation audit.

## Runtime requirements

- `CORTEX_CODEX_CMD`: Codex executable path; default `codex`.
- `CORTEX_CODEX_HOME`: authentication source directory containing `auth.json`.
  Defaults to `CODEX_HOME`, then `$HOME/.codex`.
- `CORTEX_CODEX_MODEL`: optional model override. Otherwise app-server selects
  its default; the CLI also accepts `--model`.

Authenticate a dedicated assessment Codex login on the runtime host first.
For a non-root container, provide an authentication-only directory writable by
its UID, with directory mode 0700 and file mode 0600. Do not mount a user's
complete Codex home into the worker or share this login with independent Codex
processes. Assessment workers serialize access using a file lock; other Codex
clients do not participate in that lock.

Each assessment creates temporary authentication-only state and an empty
working directory, starts an ephemeral read-only thread with approvals set to
never, no environments, and shell/web search disabled. Its auth file links to
the dedicated credential file, so rotated tokens survive success, errors and
cancellation. The worker retains its credential lock and temporary directories
until the child exits. This currently requires Unix and Codex's file credential
backend, which writes refreshes in place; a Codex upgrade that replaces the auth
symlink or no longer supports `thread/start` with `environments: []` must be
requalified before deployment. Experimental API support is enabled explicitly.
Provider errors, disconnects, interactive requests, unexpected tool items,
oversized output and unsuccessful turn completion are failures, not reports.

## Server usage

The Unraid plugin is not required. Replace `CORTEX_HOST` below with your
server's SSH alias. Run the CLI against the container's local database rather
than its HTTP mode:

```sh
ssh CORTEX_HOST 'docker exec -e CORTEX_USE_HTTP=false cortex cortex sessions skillincidents --since 7d --limit 5 --json'
ssh CORTEX_HOST 'docker exec -e CORTEX_USE_HTTP=false cortex cortex assess skill SKILL_NAME --since 7d --limit 1'
ssh CORTEX_HOST 'docker exec -e CORTEX_USE_HTTP=false cortex cortex sessions llminvocations --action skill_assess --limit 5 --json'
```

An empty incident result is not an all-clear. Check skill-event coverage before
widening the window. The remote ingest path projects recognized Codex skill
tags in the same transaction as its canonical log and replay receipt. It does
not infer skill usage from ordinary prose or fabricate missing Claude
attribution. Historical backfill is separate and should be bounded and
previewed with `sessions skills backfill --dry-run` before writing.

Codex capture recognizes both legacy name-only skill tags and current native
skill blocks containing `<name>` and a `SKILL.md` `<path>`. The current header
is sufficient even when the forwarding message budget truncates the skill
body. Catalog entries and bare file-path mentions are not invocation evidence.
Command-based reads are recorded separately as `codex_skill_read`, using a
native completed `CommandExecution` with exit code zero, nonempty output, and
exactly one parsed `read` of a `SKILL.md` file. Searches, failed commands, empty
outputs, and ambiguous multi-command shells are excluded. A read (including
a partial `sed` read) proves observed access, not that the skill was fully read
or followed. Repeated reads and inherited fork history are not independent
assessment runs.

The parser carries completed-read provenance separately from message text.
A user or assistant message containing a `cortex_skill_read` JSON marker is
not completed-read evidence. Known Codex/Claude plugin-cache paths retain
`plugin:skill` names; known user skill paths retain their skill name. Unknown
paths receive an `unresolved-skill-read-<digest>` identity, not a guessed global
basename. These unresolved reads do not qualify a named/plugin assessment.

Older agents dropped those command-completion records entirely. Recover them
on the original source host using the explicit `backfill_codex_skill_reads`
example, with `CORTEX_RECOVERY_TARGET`, `CORTEX_RECOVERY_TOKEN`, and a bounded
`CORTEX_RECOVERY_ROOT` such as the local `.codex/sessions` directory. It submits
only the missing read-evidence format, preserves source record identities,
and leaves the running agent's checkpoint untouched. Replaying the same files
is idempotent through the normal server receipts, including after session
renames or loss of supplemental title metadata. Titles are display metadata,
not immutable receipt evidence; a replay still rejects changed transcript
content. The updated agent captures future completed reads normally.

After exporting those environment variables from the operator's protected
agent environment (never paste the token into command-line arguments), run:

```sh
cargo run --example backfill_codex_skill_reads
```

Deploy the receiver and source agent update before recovery. Keep the database
backfill's `truncated` flag visible: its one-million-row cap is a bounded pass,
not proof that every historical record was reprocessed. Source-unavailable
Claude records require their original host files and are not repaired by the
Codex recovery example.

### Upgrading early completed-read projections

Early builds stored compact read summaries without separate provenance. Those
summaries cannot be retroactively verified from message text alone. The fixed
agent uses the `codex-skill-read-v2` record-identity domain for validated reads,
preserving the raw source revision but avoiding conflicts with old receipts.
Source-backed recovery therefore inserts a new verified record once; later
v2 replays are duplicates. Existing unverified projections are **not** silently
grandfathered or automatically deleted by the insert-only backfill command.

Before relying on reflection counts from an early deployment, back up the
database and inspect a bounded batch of old projections using the query below.
This example uses SQLite's CLI against the operator-selected database. The
first transaction is a preview and rolls back. To retire the inspected batch,
repeat it with the final `ROLLBACK` replaced by the displayed `DELETE` and
`COMMIT`. Do not delete source logs or receipts; source-host recovery needs
the original transcript files to rebuild verified evidence.

```sql
BEGIN IMMEDIATE;
CREATE TEMP TABLE legacy_read_projection_ids AS
SELECT s.id FROM ai_skill_events s JOIN logs l ON l.id = s.log_id
WHERE s.event_kind = 'codex_skill_read'
  AND COALESCE(CASE WHEN json_valid(l.metadata_json)
      THEN json_extract(l.metadata_json, '$.event_kind') END, '') <> 'codex_skill_read'
ORDER BY s.id LIMIT 500;
SELECT s.id, s.skill_name, s.timestamp FROM ai_skill_events s
JOIN legacy_read_projection_ids p ON p.id = s.id;
ROLLBACK;
-- After inspecting the batch, repeat in a fresh connection and finish with:
-- DELETE FROM ai_skill_events WHERE id IN (SELECT id FROM legacy_read_projection_ids);
-- COMMIT;
```

Repeat bounded batches until the preview is empty, then run source-host v2
recovery. Until that repair and coverage check are complete, old deployment
counts must be labelled unverified rather than combined with verified reads.

For coverage audits, compare source locators and logical `session_id` values,
not the number of rollout files or child-thread `id` values. Codex child tasks
can share their parent's logical session while retaining distinct transcript
files. A matching source proves some records arrived, not that the latest tail
is fully caught up; compare the agent checkpoint against complete local lines.

## Rollback

For deployments using a dedicated Compose override, to restore the prior
image, retain the override under a non-default filename and run Compose with
the original `docker-compose.yml` explicitly. No schema migration is included
in this change. A database rollback is not needed merely to restore the prior
image; keep the stopped-service database snapshot for recovery only.
