---
title: "agent observatory architecture"
created: 2026-07-31
updated: 2026-07-31
---

# Agent Observatory architecture

Status: proposed
Depends on: `docs/research/2026-07-31-agent-observatory.md`
Normative behavior: `docs/specs/agent-observatory.md` and `docs/contracts/agent-observatory.md`

## Architecture goal

Add a durable, live, repository-centered agent view without replacing Cortex's canonical ingest pipeline, database, authentication, or single-binary deployment.

The architecture introduces five cooperating subsystems:

1. repository/worktree reconciler
2. run projector
3. OTLP trace and metric ingestion
4. authenticated durable event stream
5. statically exported Next.js observatory application

## System context

```text
Claude/Codex/Gemini transcript files ─┐
agent-command wrapper ────────────────┤
shell history / Atuin ────────────────┤
MCP, hook, skill, LLM extraction ─────┤
OTLP logs ────────────────────────────┼──> existing durable Cortex source tables
heartbeats and host logs ─────────────┤                 │
                                     │                 ▼
Git repositories/worktrees ──────────┘         AgentRunProjector
                                                     │
OTLP traces/metrics ──> normalized OTLP tables ──────┤
Git watcher ──────────> repository tables ───────────┤
                                                     ▼
                          agent_runs / run_events / evidence / outbox
                                                     │
                         REST snapshots + authenticated fetch event stream
                                                     │
                                                     ▼
                       static Next.js + Aurora app embedded in cortex binary
```

## Design invariants

1. Existing source tables remain authoritative evidence.
2. Observatory rows are replayable materializations, not a second ingest truth.
3. Every derived row has a deterministic versioned key.
4. Every association records evidence kind, source identity, trust level, and confidence.
5. A crash before cursor commit replays safely; a crash after cursor commit cannot lose committed materialization.
6. Browser tokens live only in memory and are sent only in Authorization headers.
7. No production Node process is required.
8. Missing provider telemetry never proves a session is inactive.
9. Exact Git SHAs come only from Git object data, never command-string inference.
10. All new storage participates in retention, budget, backup, integrity, and diagnostics.

## Proposed Rust module map

```text
src/
  agent_observatory.rs                 public module and coordinator
  agent_observatory/
    config.rs                          intervals, caps, privacy and status windows
    identity.rs                        canonical tool names and versioned run/event keys
    models.rs                          domain structs shared by DB/service/API
    projector.rs                       source cursor loop and transactional projection
    classifier.rs                      source row to event kind and activity class
    attribution.rs                     run, repository and worktree evidence scoring
    lifecycle.rs                       deterministic run status reducer
    stream.rs                          broadcast hub and replay/reset semantics
    supervisor.rs                      startup, cancellation, health and restart behavior
  git_observer.rs                      public repository observer module
  git_observer/
    discovery.rs                       bounded repository discovery
    porcelain.rs                       worktree/status/log parsers
    reconcile.rs                       transactional repository/worktree snapshots
    watcher.rs                         notify control-path watches and coalescing
    commits.rs                         HEAD transition and exact commit import
    supervisor.rs                      recovery, overflow and periodic full reconcile
  otlp/
    traces.rs                          ExportTraceServiceRequest decoder and persistence
    metrics.rs                         ExportMetricsServiceRequest decoder and persistence
    normalization.rs                   shared resource/scope/session/project extraction
  app/models/agent_observatory.rs      API/service request and response models
  app/services/agent_observatory.rs    query and status service methods
  db/agent_observatory.rs              repositories, runs, events, outbox and queries
  db/otlp_traces.rs                    span persistence and queries
  db/otlp_metrics.rs                   metric-point persistence and queries
  api/agent_observatory.rs             REST and stream handlers
  web_app.rs                           generated static asset router
build.rs                               generate embedded asset table from web manifest
```

Tests live beside the module using the repository's sidecar convention.

## Durable run identity

### Native session

A top-level run is keyed by:

```text
v1|<len(host)>:<host>|<len(tool)>:<tool>|<len(native_session_id)>:<native_session_id>
```

The length-prefixed format follows Cortex's existing session-key pattern and avoids delimiter ambiguity without a new UUID dependency.

Canonical tool values are `claude`, `codex`, `gemini`, or `unknown:<normalized-source>`. The original provider value is retained in metadata.

### Subagents

A provider actor is a child record identified by native agent ID and optional agent type. A child actor belongs to a top-level run. It does not split the repository session into unrelated timelines. Events can target the top-level run and optionally an actor.

### Worktree relation

A run can touch multiple worktrees over time. The database therefore uses a relation history instead of a single immutable worktree foreign key. `agent_runs.primary_worktree_id` is a cached current selection derived from the highest-confidence active relation.

## Evidence scoring

Evidence is evaluated in descending strength:

| Evidence | Trust | Default confidence |
| --- | --- | ---: |
| provider hook with native session ID and cwd | verified | 1.00 |
| OTLP session ID plus exact project/worktree path | verified | 0.98 |
| agent command session ID plus cwd | verified | 0.98 |
| transcript session ID plus canonical project path | verified | 0.95 |
| provider lifecycle event plus host/process | verified | 0.95 |
| Atuin session plus cwd and overlapping run window | claimed | 0.85 |
| unique active run on host whose cwd contains worktree | correlated | 0.75 |
| timestamp-only proximity | inferred | at most 0.50 |

A timestamp-only match can enrich a timeline but cannot select a primary worktree or attribute an exact commit by itself.

## Projector architecture

### Why a projector

Cortex writes relevant evidence through many paths: transcript scanner, batch ingest, shell history, OTLP, hook/MCP/skill extraction, and future providers. Adding observatory writes to every path would couple collection to presentation and create inconsistent transactions. A projector provides one restart-safe normalization boundary.

### Source cursors

`agent_projection_cursors` stores one cursor per durable source:

- `logs`
- `mcp_events`
- `hook_events`
- `skill_events`
- `llm_invocations`
- `otel_spans`
- `otel_metric_points`
- `repository_observations`

The projector fetches a bounded ordered page, projects it inside one SQLite transaction, and advances that source cursor in the same transaction.

### Source completion matrix

The projector reads only durable canonical tables.  A source row never creates
an agent identity merely to satisfy a projection: records without a safe run
association are diagnosed and their source cursor is advanced without a run
event.  This keeps canonical collection independent from the optional AO view.

| Source | Durable order/cursor | Run identity / association | Provenance carried into event | Bounded query evidence |
| --- | --- | --- | --- | --- |
| Logs | `logs.id` | classified provider transcript or command identity | source log ID, scrub state, classifier variant | `page_agent_projection_logs`, row and byte cap |
| MCP | `ai_mcp_events.id` | asserted tool/session/host | call/result log IDs, provider sequence | `id > cursor ORDER BY id LIMIT` |
| Hooks | `ai_hook_events.id` | asserted tool/session/host | source log ID, trusted hash/evidence kind | `id > cursor ORDER BY id LIMIT` |
| Skills | `ai_skill_events.id` | asserted tool/session/host | source log ID and extracted evidence kind | `id > cursor ORDER BY id LIMIT` |
| LLM | `(finished_at,id)` | asserted tool/session where present | terminal-state cursor and bounded metadata | `idx_llm_invocations_finished_id` |
| OTLP spans | `otel_spans.id` | exact provider identity only | trace/span IDs and explicit match/no-match relation | `id > cursor ORDER BY id LIMIT` |
| OTLP metrics | `otel_metric_points.id` | asserted tool/session where present | point key, service, bounded attributes | `id > cursor ORDER BY id LIMIT` |
| Repository observations | `repository_observations.id` | pre-existing current run plus durable worktree evidence; ambiguity/no-match never creates a run | observation key, worktree/repository source, evidence kind/source/trust/confidence, correlated ceiling | primary-key `id > cursor ORDER BY id LIMIT` with bounded join by repository/worktree key |

### Idempotency

Every projected event has an `event_key`:

```text
v1:<source_kind>:<source_primary_key>:<projection_variant>
```

`agent_run_events.event_key` is unique. Replaying a page after a crash becomes `INSERT ... ON CONFLICT DO NOTHING` plus deterministic run/worktree upserts.

### Scheduling

- Wake on an in-process notify signal after known inserts.
- Poll at a bounded fallback interval, initially 500 ms.
- Process at most 500 source rows or 4 MiB of decoded payload per transaction.
- Yield between pages.
- Back off retry-safe SQLite busy errors with the repository's existing policy.
- Mark projector health degraded after repeated failure but never stop canonical ingestion.

### Event ordering

The UI ordering key is `(observed_at, source_order, source_id, event_id)`. Provider sequence numbers are preserved in payload and may refine display ordering within one timestamp. The durable event ID is monotonic ingestion order and doubles as stream replay cursor.

## Run lifecycle reducer

Lifecycle is recomputed from explicit evidence and current time:

1. explicit failed end -> `failed`
2. explicit successful end -> `completed`
3. open user/permission wait -> `waiting`
4. activity within `active_window_secs` -> `active`
5. activity within `stale_after_secs` -> `idle`
6. no explicit end and older than stale threshold -> `stale`
7. stale longer than `abandoned_after_secs` and no live process evidence -> `abandoned`

Default windows:

- active: 15 seconds
- stale: 5 minutes
- abandoned: 24 hours

Status is a materialized cache. Query code can detect stale reducer timestamps and recompute before returning a row.

## Repository and worktree observer

### Discovery

Reuse the existing default project roots and bounds, but move Git-specific discovery behind reusable APIs. A repository is keyed by host plus canonical common Git directory. A worktree is keyed by host plus canonical worktree path.

### Reconcile commands

All commands are bounded and run through the existing inventory process runner:

```text
git -C <repo> rev-parse --path-format=absolute --git-common-dir
git -C <repo> worktree list --porcelain -z
git -C <worktree> status --porcelain=v2 --branch -z
git -C <worktree> rev-parse HEAD
git -C <worktree> rev-parse --abbrev-ref HEAD
git -C <worktree> rev-list --left-right --count @{upstream}...HEAD
```

Unavailable upstreams produce null ahead/behind values, not errors.

### Watch set

Watch Git control paths, not the entire source tree:

- common-dir `HEAD`, `index`, `packed-refs`, `refs`, and `worktrees`
- each worktree's Git directory and HEAD/index references
- configured project-root directories for repository/worktree creation

Events are debounced and coalesced by repository. Notify overflow schedules a bounded full reconcile. A periodic reconcile, initially every 60 seconds, repairs missed events.

### Exact commit attribution

When a worktree HEAD changes from `old` to `new`:

1. verify both object IDs exist
2. enumerate `git rev-list --reverse old..new` with a cap
3. read exact metadata with one NUL-delimited `git show` format
4. persist commit rows
5. attach commits to active runs associated with that worktree
6. record evidence and confidence

If the transition is a rewind/rebase, persist the new observation and update reachability; do not delete historical commit evidence. If more than one run is active in the worktree, commit attribution remains correlated unless a command, hook, trace, or provider event identifies the actor.

The default design stores commit metadata and changed-file summaries, not full diffs or file contents.

## OTLP traces

`/v1/traces` accepts OTLP/HTTP protobuf under the same auth/body-limit model as logs. Each span stores:

- trace/span/parent IDs and trace state
- name, kind, start/end, duration, flags
- status code/message
- host, service, scope
- normalized session/tool/project fields
- bounded resource and span attributes
- bounded span events and links
- received time and optional projected run ID

The unique key is `(trace_id, span_id)`. Duplicate export is accepted idempotently. Invalid IDs or over-limit attributes produce partial-success diagnostics without crashing the request.

## OTLP metrics

`/v1/metrics` accepts gauges, sums, histograms, exponential histograms, and summaries. Query-critical metadata is flattened; the point value, buckets, quantiles, exemplars, and attributes are stored as bounded JSON.

Metric points are not converted into one SQLite column per provider metric. This avoids schema churn and supports Claude, Codex, Gemini, and future GenAI semantic conventions. A bounded run summary query computes totals and recent rates for known metric names.

## Durable stream

### Outbox

Every transaction that changes a run, worktree, event, span summary, or metric summary writes one compact `agent_stream_outbox` row. After commit, the coordinator publishes the outbox ID through a bounded Tokio broadcast channel.

### Replay

The stream handler:

1. authenticates through the existing `/api` bearer layer
2. reads `Last-Event-ID` or an explicit non-secret `after` cursor
3. replays durable outbox rows up to a hard cap
4. subscribes to broadcast
5. sends 15-second keepalive comments
6. fetches the durable row by ID before sending it

If the requested cursor predates retained outbox rows or replay exceeds the cap, emit `observatory.reset` with a reason and latest cursor. The client refetches snapshots and reconnects.

### Event names

- `run.created`
- `run.updated`
- `run.status`
- `run.event`
- `worktree.updated`
- `repository.updated`
- `telemetry.updated`
- `observatory.reset`

Payloads contain stable IDs and compact changed fields. Large transcript or telemetry content is fetched through paginated REST endpoints.

## REST and MCP boundary

REST owns browser-oriented pagination, detail projections, and streaming. MCP exposes equivalent read-only actions for agents. Both call the same `CortexService` methods and model types. No handler issues raw SQL.

Admin-only operations, such as forcing a reconcile or projector backfill, use explicit POST endpoints and existing admin-token checks. The first UI release does not expose those operations.

## Next.js application and embedding

### Source layout

```text
web/
  package.json
  pnpm-lock.yaml
  components.json
  aurora.lock.json
  next.config.ts
  app/
    layout.tsx
    page.tsx                 redirect/navigation shell for static routes
    agents/page.tsx
    investigate/page.tsx
    globals.css
  components/
    aurora/                  vendored Aurora blocks
    ui/aurora/               vendored Aurora primitives
    observatory/             feature composition and adapters
  hooks/
  lib/
  scripts/
  tests/
  e2e/
  public/fonts/aurora/
  out/                       generated, not hand-edited
```

Use `basePath: '/app'`, `output: 'export'`, and `trailingSlash: true`. No dynamic server APIs are permitted.

### Asset manifest

After `next build`, `web/scripts/build-embed-manifest.mjs`:

1. walks `web/out`
2. validates all paths and rejects source maps
3. calculates content type, cache class, ETag, and SHA-256
4. parses each HTML file with `parse5`
5. records hashes for inline scripts
6. writes deterministic `web/out/cortex-assets.json`

A standard-library root `build.rs` reads that manifest and generates an embedded asset table in `OUT_DIR`. `src/web_app.rs` performs route lookup, serves immutable hashed assets, no-store HTML, ETags, and route-specific CSP.

### CSP

- scripts: self plus exact SHA-256 hashes, never `unsafe-inline`
- styles: self; permit inline style attributes only as required by reviewed Aurora source
- connect: self plus configured development origin
- fonts/images: self, with narrowly required data/blob allowances
- objects/base/frame ancestors: none

A Playwright listener fails the build on any CSP console violation.

## Security and privacy

- Browser bearer token remains in React memory only.
- No URL token, cookie conversion, localStorage, sessionStorage, HTML injection, or service-worker cache.
- All source content passes existing scrubbing plus per-field size caps.
- Full prompts, tool input/output, shell commands, usernames, paths, and emails are controlled by explicit privacy settings.
- API list responses default to summaries; full event payload requires a detail request.
- Worktree paths can be returned to authenticated operators but are never embedded in graph labels sent to unauthenticated assets.
- Stream payloads are compact and redacted.
- Git subprocess inputs are canonical paths discovered by Cortex, never arbitrary client strings.

## Performance budgets

- projector added latency: p95 under 750 ms after source commit on an idle host
- Git reconcile: p95 under 250 ms per unchanged repository and bounded to configured concurrency
- run list: p95 under 150 ms for 100 rows on a 1 million log-row database
- event page: p95 under 200 ms for 200 events
- stream fanout: 256 concurrent clients, bounded queue, no unbounded task growth
- initial JS for `/app/agents`: target under 350 KiB compressed, heavy views dynamically imported
- timeline DOM: under 250 rendered rows regardless of history length
- no browser long task over 200 ms during a 100-event append burst

## Failure model

Canonical ingestion remains available when the projector, Git observer, stream, or UI is degraded. Health is exposed per subsystem with last success, lag, cursor, error, and queue depth. Supervisors restart retryable loops with bounded backoff. Terminal configuration failures surface through doctor/status and do not spin.

## Deployment sequence

1. ship schema and disabled projector
2. backfill and verify counts
3. enable projector and observer behind configuration flags
4. enable OTLP traces and metrics
5. ship REST/MCP contracts
6. embed Next app while preserving old investigation route
7. run dual-view acceptance
8. remove legacy static app only after parity and rollback gates

Rollback disables new supervisors and UI routes while preserving additive tables. Schema is forward-compatible and does not require destructive downgrade.
