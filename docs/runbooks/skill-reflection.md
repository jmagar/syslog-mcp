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

Authenticate Codex on the runtime host first. For a non-root container, provide
an authentication-only directory readable by its UID, with directory mode 0700
and file mode 0600. Do not mount a user's complete Codex home into the worker.
Refresh this authentication source when host credentials are rotated.

Each assessment creates temporary authentication-only state and an empty
working directory, starts an ephemeral read-only thread with approvals set to
never and shell/web search disabled, and destroys that temporary state when
finished. Provider errors, disconnects, interactive requests, oversized output
and unsuccessful turn completion are failures, not successful reports.

## Tootie usage

The Unraid plugin is not required. Run the CLI against the container's local
database rather than its HTTP mode:

```sh
ssh tootie 'docker exec -e CORTEX_USE_HTTP=false cortex cortex sessions skillincidents --since 7d --limit 5 --json'
ssh tootie 'docker exec -e CORTEX_USE_HTTP=false cortex cortex assess skill SKILL_NAME --since 7d --limit 1'
ssh tootie 'docker exec -e CORTEX_USE_HTTP=false cortex cortex sessions llminvocations --action skill_assess --limit 5 --json'
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

Older agents dropped those command-completion records entirely. Recover them
on the original source host using the explicit `backfill_codex_skill_reads`
example, with `CORTEX_RECOVERY_TARGET`, `CORTEX_RECOVERY_TOKEN`, and a bounded
`CORTEX_RECOVERY_ROOT` such as the local `.codex/sessions` directory. It submits
only the missing read-evidence format, preserves source record identities,
and leaves the running agent's checkpoint untouched. Replaying the same files
is idempotent through the normal server receipts. The updated agent captures
future completed reads through its normal forwarding loop.

For coverage audits, compare source locators and logical `session_id` values,
not the number of rollout files or child-thread `id` values. Codex child tasks
can share their parent's logical session while retaining distinct transcript
files. A matching source proves some records arrived, not that the latest tail
is fully caught up; compare the agent checkpoint against complete local lines.

## Rollback

The tootie deployment uses a dedicated Compose override. To restore the prior
image, retain the override under a non-default filename and run Compose with
the original `docker-compose.yml` explicitly. No schema migration is included
in this change. A database rollback is not needed merely to restore the prior
image; keep the stopped-service database snapshot for recovery only.
