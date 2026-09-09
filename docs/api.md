---
title: "cortex REST API"
created: 2026-05-18
updated: 2026-07-30
---

# cortex REST API

> Canonical reference for the always-on `/api/*` surface introduced by
> epic `cortex-0p8r` (v0.26). All endpoints require a bearer token
> (`Authorization: Bearer $CORTEX_API_TOKEN`); 401 is returned for
> missing/invalid tokens regardless of bind address.
> Routes marked **admin** additionally require
> `X-Cortex-Admin-Token: $CORTEX_API_ADMIN_TOKEN`; missing or invalid admin
> tokens return 403.
>
> CLI commands route here by default since v0.26 via
> `CORTEX_USE_HTTP=true` written to `~/.cortex/.env` by
> `cortex setup repair`. See [`docs/architecture.md`](architecture.md)
> for the caller → DB diagram and [`docs/rollout.md`](rollout.md) for
> the manual upgrade playbook.

---

## Endpoint matrix

93 method/path bindings total. Scope is `read` (mounted via `axum::routing::get`,
hits read-side `db_permits`) or `admin`. Database maintenance and integrity
checks share one process-wide maintenance gate; concurrent attempts receive a
busy response. Admin mutations are audited before the service call.
All responses are JSON; error bodies are `{"error": "<message>"}`
unless a route documents a structured diagnostic body.

### Core queries, discovery, and streams (13)

These existed before the epic; bead `.1` only added `/api/version`.
They are documented here for completeness because the CLI now routes
to them by default.

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/search` | read | query params: `query?`, `hostname?`, `source_ip?`, `severity?`, `app_name?`, `facility?`, `process_id?`, `from?`, `to?`, `limit?` (u32) | `SearchLogsResponse { count: usize, logs: [LogEntry] }` | 200, 400, 401, 503, 500 | Y | FTS5 search; `deny_unknown_fields` rejects typos. |
| GET | `/api/filter` | read | query params: `hostname?`, `source_ip?`, `source_kind?`, `tool?`, `project?`, `session_id?`, `container?`, `docker_host?`, `stream?`, `event_action?`, `severity?`, `app_name?`, `facility?`, `exclude_facility?`, `process_id?`, `from?`, `to?`, `received_from?`, `received_to?`, `limit?` (u32) | `SearchLogsResponse { count: usize, logs: [LogEntry] }` | 200, 400, 401, 503, 500 | Y | Structured filter-only retrieval; `query` and unknown fields are rejected. |
| GET | `/api/feed` | read | query: `after_id?` (i64), `host?`, `limit?` (u32, max 1000) | `FeedLogsResponse { logs: [LogEntryWithRaw], next_after_id: i64, has_more: bool }` | 200, 400, 401, 503, 500 | Y | Ascending cursor feed for external consumers. Omit `after_id` to start at the current high-water mark; pass `after_id=0` to replay retained history. |
| GET | `/api/tail` | read | query: `hostname?`, `source_ip?`, `app_name?`, `severity_min?`, `n?` (u32) | `SearchLogsResponse { count: usize, logs: [LogEntry] }` (tail order) | 200, 400, 401, 503, 500 | Y | `severity_min` honoured per RFC severity ordering. |
| GET | `/api/errors` | read | query: `from?`, `to?`, `group_by?` (`app_name` only) | `GetErrorsResponse { summary: [ErrorSummaryEntry] }` | 200, 400, 401, 503, 500 | Y | Counts by host (and optional secondary key). |
| GET | `/api/hosts` | read | (none) | `ListHostsResponse { hosts: [HostEntry] }` | 200, 401, 503, 500 | Y | Inventory of seen hostnames. |
| GET | `/api/correlate` | read | query: `reference_time` (REQUIRED, RFC 3339), `window_minutes?` (u32), `severity_min?`, `hostname?`, `source_ip?`, `query?`, `limit?` (u32) | `CorrelateEventsResponse { reference_time, window_minutes, window_from, window_to, severity_min, total_events, truncated, hosts_count, hosts: [CorrelatedHost] }` | 200, 400, 401, 503, 500 | Y | **Distinct from `/api/sessions/correlate`** — see disambiguation below. |
| GET | `/api/stats` | read | (none) | `DbStats { total_logs, total_hosts, oldest_log?, newest_log?, logical_db_size_mb, physical_db_size_mb, free_disk_mb?, max_db_size_mb, min_free_disk_mb, write_blocked, phantom_fts_rows? }` | 200, 401, 503, 500 | Y | Hot path; no PRAGMA per request. `phantom_fts_rows` is `null` by default — its `COUNT(*) FROM logs_fts` scan is skipped to stay fast on large DBs; computed only via the opt-in diagnostic path. |
| GET | `/api/version` | read | (none) | `VersionInfo { version, git_sha?, schema_version }` | 200, 401 | Y | **Cached at startup** — never touches SQLite per request (eng-review #A3). Returns 404 if older server lacks the route (see Versioning policy). |
| GET | `/api/capabilities` | read | (none) | typed Cortex capability map | 200, 401 | Y | Advertises rendered-session polling and native durable SSE, including item/byte/reconnect bounds. |
| GET | `/api/integration-profile` | read | (none) | `CortexIntegrationProfileV1` | 200, 401 | Y | Runtime identity conforming to `contracts/integration-profile.schema.json`; stable server ID, mounted auth modes/generation, route support, and SSE resume support are reported together. |
| GET | `/api/streams/logs` | read | query: `cursor?`, `host?`, `app?`, `severity?`; or `Last-Event-ID` | SSE snapshot, log events, typed control events | 200, 400, 401, 403, 410, 429, 503 | Y | Durable ascending `logs.id` replay. Cursors bind principal and filter lineage. Batches are capped at 100 items/128 KiB and individual messages at 64 KiB. |
| GET | `/api/streams/sessions` | read | query: `project`, `tool`, `session_id`, `host` (all REQUIRED), `cursor?`; or `Last-Event-ID` | SSE snapshot, session events, typed control events | 200, 400, 401, 403, 410, 429, 503 | Y | Same durable envelope and bounds as log streaming, restricted to one rendered-session identity. Retention gaps and cursor expiry require explicit resync. |

### Recurring error comparison (1)

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/recurring-error-comparison` | read | query: `signature_hash?`, `since?`, `until?`, `window_minutes?` (5..1440), `limit?` (1..50), `include_acknowledged?` | `RecurringErrorComparisonResponse { focal_from, focal_to, baseline_from, baseline_to, candidate_rows, candidate_cap, candidate_window_truncated, results_truncated, privacy_policy, comparisons }` | 200, 400, 401, 503, 500 | Y | Compares canonical recurring-error signatures in the focal window against the adjacent baseline. Candidates are capped at 512 before deterministic ranking; response text is irreversibly scrubbed and bounded. Each bundle has a replayable SHA-256 identity over canonical source keys, evidence revision, window, and privacy policy, plus bounded graph evidence handles and an explicit next graph query. Boundary/retention/projection gaps are markers, not silent zeroes; rankings are evidence-led and do not claim causation. MCP: `recurring_error_comparison` (`cortex:read`). |

### Agent Observatory (5 canonical routes plus 5 compatibility aliases)

All Agent Observatory endpoints are read-only, token-gated, cursor-paged, and
return source-attributed, redacted projection data. The `/api/agent-observatory/*`
spellings are canonical; the shorter forms remain explicitly contracted
compatibility routes.

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/agent-observatory/repositories` | read | `host?`, `query?`, `active_runs_only?`, `include_removed?`, `since?`, `until?`, `cursor?`, `limit?` | paged repositories | 200, 400, 401, 503, 500 | Y | Canonical repository inventory. `/api/repositories` is retained compatibility. |
| GET | `/api/agent-observatory/worktrees` | read | `repository_id` (required), `branch?`, `dirty?`, `include_removed?`, `cursor?`, `limit?` | paged worktrees | 200, 400, 401, 503, 500 | Y | `/api/repositories/{repository_id}/worktrees` is retained compatibility. |
| GET | `/api/agent-observatory/runs` | read | `repository_id?`, `worktree_id?`, `branch?`, repeated `status?` / `tool?`, `host?`, `query?`, `since?`, `until?`, `active_only?`, `cursor?`, `limit?` | paged runs | 200, 400, 401, 503, 500 | Y | `/api/agent-runs` is retained compatibility. |
| GET | `/api/agent-observatory/runs/{run_key}/events` | read | repeated `kind?`, `severity_min?`, `actor_key?`, `trace_id?`, `query?`, `since?`, `until?`, `include=payload?`, `order?`, `cursor?`, `limit?` | paged events | 200, 400, 401, 404, 503, 500 | Y | Payload inclusion remains bounded and scrubbed. `/api/agent-runs/{run_key}/events` is retained compatibility. |
| GET | `/api/agent-observatory/runs/{run_key}/telemetry` | read | `trace_id?`, `metric_name?`, nanosecond bounds, independent span/metric cursors and limits | spans and metrics | 200, 400, 401, 404, 503, 500 | Y | `/api/agent-runs/{run_key}/telemetry` is retained compatibility. |

### Artifact ecosystem evidence (2) — W16

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/artifact-evidence` | read | query: `eventKind?`, `artifactId?`, `revisionId?`, `contentDigest?`, `correlationId?`, `requestId?`, `targetId?`, `sourceSystem?`, `from?`/`since?`, `to?`/`until?`, `limit?` (1..500) | `ListArtifactEvidenceResponse { events, truncated }` | 200, 400, 401, 503, 500 | Y | Bounded source-attributed observations from the shared Cortex evidence path. Exact artifact/revision/digest/correlation/target filters are opaque evidence dimensions, not authority lookups. CLI: `cortex artifactevents`; MCP: `artifact_evidence` (`cortex:read`). |
| POST | `/api/artifact-evidence` | **admin** | body: `ArtifactEvidenceInput` (`schemaVersion=dinglebear.cortex-artifact-evidence/v1`, source + observed-at, closed event kind, at least one artifact/revision/digest/provenance subject, optional bounded refs/metadata; wire body max 32 KiB) | `RecordArtifactEvidenceResponse { cortexLogId, inserted, event }` | 200, 400, 401, **403**, **409**, **413**, **415**, 503, 500 | replay-safe | Requires normal bearer auth plus `X-Cortex-Admin-Token`. Persists through the canonical `logs` transaction path. Replay key is `(sourceSystem, sourceIssuer, eventId)`; exact replay returns `inserted=false`, conflicting reuse returns 409. Secret-bearing keys, secret-like references, raw request/result/tool/artifact bodies, malformed digests/timestamps, and oversized metadata fail closed. Cortex records license/trust/policy/share/lease/deployment fields only as source-attributed evidence. MCP write action: `artifact_evidence_record` (`cortex:admin`). |

### AI session queries (14) — bead `.2`

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/sessions` | read | query: `project?`, `tool?`, `hostname?`, `from?`, `to?`, `limit?` | `ListSessionsResponse { count, sessions: [AiSessionEntry] }` | 200, 400, 401, 503, 500 | Y | Inventory of indexed AI transcripts. |
| GET | `/api/sessions/rendered` | read | query: `project`, `tool`, `session_id`, `host` (all REQUIRED), `cursor?`, `limit?` | `RenderedSessionPageResponse` (`delivery=polling`, semantic events, durable next cursor, high-water mark, truncation and retry metadata) | 200, 400, 401, 503, 500 | Y | Keyset pagination by persisted `logs.id`, ascending. Maximum 200 events and 256 KiB per page; oversized event text is UTF-8-safely truncated with a parse warning. Schema: `contracts/rendered-session-page.schema.json`. Clients may hand its committed cursor to the native session stream. |
| GET | `/api/sessions/search` | read | query: `query` (REQUIRED), `project?`, `tool?`, `from?`, `to?`, `limit?` (u32) | `SearchSessionsResponse { total_candidates, candidate_rows, candidate_cap, candidate_window_truncated, truncated, sessions: [SearchedSessionEntry], limit_clamped_to? }` | 200, 400, 401, 503, 500 | Y | `limit` clamped at **100** — see Response size caps. |
| GET | `/api/sessions/abuse` | read | query: `project?`, `tool?`, `from?`, `to?`, `limit?`, `before?` (u32), `after?` (u32), **`terms?`** (repeated key: `?terms=foo&terms=bar`) | `AbuseSearchResponse { terms, candidate_rows, candidate_cap, candidate_window_truncated, truncated, matches: [AbuseMatch], limit_clamped_to? }` | 200, 400, 401, 503, 500 | Y | `limit` clamped at **500**. Decoded via `serde_qs::axum::QsQuery`, so `Vec<String>` is supported through repeated `terms=` keys (the CLI's `HttpClient` serializes the shared request type the same way). |
| GET | `/api/sessions/correlate` | read | query: `project?`, `tool?`, `session_id?`, `ai_query?`, `log_query?`, `hostname?`, `source_ip?`, `app_name?`, `from?`, `to?`, `window_minutes?` (u32), `severity_min?`, `limit?` (u32), `events_per_anchor?` (u32) | `AiCorrelateResponse { window_minutes, severity_min, total_anchors, anchor_rows, anchor_limit, anchors_truncated, related_limit_per_anchor, total_related_events, anchors: [AiCorrelationAnchor], events_per_anchor_clamped_to? }` | 200, 400, 401, 503, 500 | Y | `events_per_anchor` clamped at **50** — see Response size caps. Correlates AI transcript anchors against system logs. |
| GET | `/api/sessions/blocks` | read | query: `project?`, `tool?`, `from?`, `to?` | `UsageBlocksResponse { total_blocks, truncated, blocks: [UsageBlock] }` | 200, 400, 401, 503, 500 | Y | Time-bucketed usage. |
| GET | `/api/sessions/context` | read | query: `project` (REQUIRED, non-empty — handler 400s on empty per eng-review #A7), `tool?`, `limit?` | `ProjectContextResponse { project, tools, sessions, hostnames, first_seen?, last_seen?, event_count, recent_entries_truncated, recent_entries: [LogEntry] }` | 200, 400, 401, 503, 500 | Y | Empty `project=` rejected with explicit 400. |
| GET | `/api/sessions/tools` | read | query: `project?`, `from?`, `to?` | `ListAiToolsResponse { total_tools, truncated, tools: [AiToolEntry] }` | 200, 400, 401, 503, 500 | Y | Tool inventory. |
| GET | `/api/sessions/projects` | read | query: `tool?`, `from?`, `to?` | `ListAiProjectsResponse { total_projects, truncated, projects: [AiProjectEntry] }` | 200, 400, 401, 503, 500 | Y | Project inventory. |
| GET | `/api/sessions/skills` | read | query: `skill?`, `plugin?`, `tool?`, `project?`, `session_id?`, `hostname?`, `from?`, `to?`, `limit?` (u32) | `ListSkillEventsResponse { total, truncated, events: [SkillEventEntry] }` | 200, 400, 401, 503, 500 | Y | `limit` clamped at **500**. Extracted AI skill-invocation events (Claude `attributionSkill` structured fields, Codex `<skill><name>` transcript tags). Backed by the `ai_skill_events` table (migration 38); MCP action: `skill_events` (`cortex:read`); CLI: `cortex sessions skills`. `caller_ip` + query filters audit-logged via `tracing::info!` before the service call (lighter than the admin-scoped `warn!` above, since this route is `cortex:read` not `cortex:admin`). |
| GET | `/api/sessions/skill-incidents` | read | query: `skill?`, `plugin?`, `tool?`, `project?`, `session_id?`, `hostname?`, `from?`, `to?`, `limit?`, `window_minutes?`, **`signals?`** (repeated), `min_score?` (f64) | `AiSkillIncidentResponse { incidents, total_incidents, candidate_event_rows, candidate_cap, candidate_window_truncated, truncated }` | 200, 400, 401, 503, 500 | Y | Decoded via `serde_qs::axum::QsQuery` for `signals[]=`. Grouped skill-usage incident candidates; MCP action: `skill_incidents` (`cortex:read`); CLI: `cortex sessions skillincidents`. |
| GET | `/api/sessions/skill-investigate` | read | query: `incident_id?`, `skill?`, `plugin?`, `tool?`, `project?`, `from?`, `to?`, `limit?`, `window_minutes?`, `correlation_window_minutes?` | `AiSkillInvestigateResponse { evidence, total_incidents, truncated, other_matching_incidents, no_incident_low_severity_summary, no_data, suggested_filters }` | 200, 400, 401, 503, 500 | Y | Deterministic (never LLM) skill-usage-incident evidence bundles, skill-first. MCP action: `skill_investigate` (`cortex:read`); CLI: `cortex sessions skillinvestigate`. |
| GET | `/api/sessions/mcp-events` | read | query: `tool_name?`, `mcp_server?`, `mcp_tool?`, `tool?`, `project?`, `session_id?`, `hostname?`, `is_error?`, `from?`, `to?`, `limit?` | `ListMcpEventsResponse { total, truncated, events }` | 200, 400, 401, 503, 500 | Y | Extracted MCP tool-call events. MCP action: `mcp_events` (`cortex:read`); CLI: `cortex sessions mcpevents`. |
| GET | `/api/sessions/mcp-incidents` | read | query: `mcp_server?`, `mcp_tool?`, `tool_name?`, `tool?`, `project?`, `session_id?`, `hostname?`, `since?`, `until?`, `limit?`, `window_minutes?`, `signals?`, `min_score?` | `AiMcpIncidentResponse { incidents, total_incidents, candidate_event_rows, candidate_cap, candidate_window_truncated, truncated }` | 200, 400, 401, 503, 500 | Y | Grouped MCP tool-usage incidents. MCP action: `mcp_incidents` (`cortex:read`); CLI: `cortex sessions mcpincidents`. |
| GET | `/api/sessions/mcp-investigate` | read | query: `incident_id?`, `mcp_server?`, `mcp_tool?`, `tool_name?`, `tool?`, `project?`, `since?`, `until?`, `limit?`, `window_minutes?`, `correlation_window_minutes?` | `AiMcpInvestigateResponse { evidence, total_incidents, truncated, other_matching_incidents, no_incident_low_severity_summary, no_data, suggested_filters }` | 200, 400, 401, 503, 500 | Y | Deterministic MCP incident evidence bundles. MCP action: `mcp_investigate` (`cortex:read`); CLI: `cortex sessions mcpinvestigate`. |
| GET | `/api/sessions/hooks` | read | query: `hook_event?`, `hook_name?`, `hook_source?`, `status?`, `evidence_kind?`, `tool?`, `project?`, `session_id?`, `hostname?`, `from?`, `to?`, `limit?` (u32) | `ListHookEventsResponse { total, truncated, events: [HookEventEntry] }` | 200, 400, 401, 503, 500 | Y | `limit` clamped at **500**. Extracted/collected AI hook events: Claude runtime hook-execution attachments (`evidence_kind=runtime_transcript`) and Claude/Codex config/trust-state inventory (`evidence_kind=config_inventory`/`trusted_hash_state`). Backed by the `ai_hook_events` table (migration 40); MCP action: `hook_events` (`cortex:read`); CLI: `cortex sessions hookevents`. |
| GET | `/api/sessions/hook-incidents` | read | query: `hook_event?`, `hook_name?`, `hook_source?`, `tool?`, `project?`, `session_id?`, `hostname?`, `evidence_kind?`, `from?`, `to?`, `limit?`, `window_minutes?`, **`signals?`** (repeated), `min_score?` (f64) | `AiHookIncidentResponse { incidents, total_incidents, candidate_event_rows, candidate_cap, candidate_window_truncated, truncated }` | 200, 400, 401, 503, 500 | Y | Decoded via `serde_qs::axum::QsQuery` for `signals[]=`. Grouped hook-usage incident candidates (failures, timeouts, output-parse errors, too-frequent invocation, post-hook user correction). Each incident carries `has_runtime_evidence` so callers can tell proven execution from config-only evidence. MCP action: `hook_incidents` (`cortex:read`). |
| GET | `/api/sessions/hook-investigate` | read | query: `incident_id?`, `hook_event?`, `hook_name?`, `hook_source?`, `tool?`, `project?`, `from?`, `to?`, `limit?`, `window_minutes?`, `correlation_window_minutes?` | `AiHookInvestigateResponse { evidence, total_incidents, truncated, other_matching_incidents, no_incident_low_severity_summary, no_data, suggested_filters }` | 200, 400, 401, 503, 500 | Y | Deterministic (never LLM) hook-usage-incident evidence bundles, hook-first. Each `findings.evidence_basis` explicitly states whether the bundle is backed by runtime execution or config/trust-state evidence only. MCP action: `hook_investigate` (`cortex:read`); CLI: `cortex sessions hookinvestigate`. |

### AI diagnostic + admin (4) — bead `.3`

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/sessions/checkpoints` | read | query: `errors_only?` (bool), `missing_only?` (bool), `limit?` (u32). `deny_unknown_fields`. | service-shaped (list of checkpoint records with parse-error metadata) | 200, 400, 401, 503, 500 | Y | Diagnostic inventory of indexed AI transcript checkpoints. |
| GET | `/api/sessions/errors` | read | query: `limit?`. `deny_unknown_fields`. | service-shaped (list of recent transcript parse errors) | 200, 400, 401, 503, 500 | Y | Surfaces parse failures from the AI indexer. |
| POST | `/api/sessions/prune-checkpoints` | **admin** | body: `{ "dry_run": bool (REQUIRED), "missing_only"?: bool, "limit"?: u32 }`. `deny_unknown_fields`. | service-shaped (count of pruned/would-prune rows) | 200, 400, 401, **403**, **409**, 500 | **N** | Requires the admin header. Single-flight via `MAINTENANCE_PERMIT`; 409 on contention with `/api/db/vacuum` or `/api/db/checkpoint`. `dry_run` is **REQUIRED and explicit** — a missing key returns 400 (defends against `POST {}` mass-delete, eng-review C3). `caller_ip` audit-logged via `tracing::warn!` BEFORE the service call. |
| GET | `/api/sessions/llm-invocations` | **admin** | query: `limit?` (i64), `since?`, `action?`, `status?` | `Vec<LlmInvocationRow>` (id, started_at, finished_at, duration_ms, caller_surface, action, provider, model, program, incident_id, ai_tool, ai_project, ai_session_id, evidence_counts_json, prompt_bytes, output_bytes, status, error, metadata_json) | 200, 400, 401, **403**, 500 | Y | Requires `X-Cortex-Admin-Token`, unlike the plain-read routes above — `llm_invocations` exposes `LlmRunner` concurrency/rate-limit/circuit-breaker/kill-switch operational state, not just log content. `caller_ip` audit-logged via `tracing::warn!` before the service call, matching `ack_error`/`unack_error`. Backed by the `llm_invocations` audit table (migration 37); MCP action: `llm_invocations` (`cortex:admin`); CLI: `cortex sessions llminvocations`. |

### File-tail admin (1)

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/api/file-tails` | **admin** | body: `{ "op": "list" \| "add" \| "remove" \| "enable" \| "disable" \| "status", "id"?: string, "path"?: string, "tag"?: string, "host"?: string, "facility"?: string, "severity"?: string, "start_at_end"?: bool }`. `op` is required; `add` requires only `path`; `id` and `tag` derive from the file name and omitted `host` derives the stable synthetic owner `file-tail-<id>` rather than the server hostname. Remove/enable/disable require `id`. | `FileTailResponse { sources: [FileTailSource], statuses: [FileTailStatus] }` | 200, 400, 401, **403**, 500 | mixed | Requires normal `Authorization: Bearer $CORTEX_API_TOKEN` plus `X-Cortex-Admin-Token: $CORTEX_API_ADMIN_TOKEN`. Manages Cortex-owned local file-tail ingest sources stored in `<data-dir>/file-tails.json`. `add` paths must be existing non-symlink regular files under `CORTEX_FILE_TAIL_ALLOWED_ROOTS`; keep the documented default to `/file-tail-root` and set an explicit allowlist to opt into broader read-only roots. Set `host` when the mounted file belongs to a real host that should participate in host filters and correlation. CLI command: `cortex ingest filetail ...`; MCP action: `file_tails` (`cortex:admin`). |

### DB ops (7) — bead `.4`

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/db/status` | read | (none) | `DbMaintenanceStatus { db_path, page_count, freelist_count, page_size, logical_size_bytes, physical_size_bytes, wal_size_bytes?, shm_size_bytes?, sqlite_page_cache_mb, sqlite_page_cache_kib_per_connection, sqlite_mmap_mb, sqlite_mmap_bytes, heavy_read_concurrency, wal_checkpoint_mb, wal_checkpoint_threshold_bytes, cgroup_memory_status, cgroup_memory_max_bytes?, cgroup_memory_current_bytes?, cgroup_memory_peak_bytes?, auto_vacuum, journal_mode, integrity_ok?, integrity_messages: [String] }` | 200, 401, 503, 500 | Y | DIFFERENT shape from `/api/stats`: a maintenance-focused PRAGMA/cache/WAL/cgroup snapshot. Cgroup diagnostics expose a compact status plus numeric values only; cgroup file paths and read errors are not returned. Bypasses `MAINTENANCE_PERMIT`. |
| GET | `/api/db/integrity` | read | query: `quick?` (bool — default `false` runs full `PRAGMA integrity_check`; `true` runs `PRAGMA quick_check`). `deny_unknown_fields`. | `DbIntegrityResult` | 200, 400, 401, 503, 500 | Y | Full check can scan a multi-GB DB. Single-flight with other maintenance; concurrent attempts return busy. |
| POST | `/api/db/integrity/background` | **admin** | query: `quick?` (bool). | `DbIntegrityJobStarted { job_id, status }` | 200, 400, 401, **403**, 503, 500 | **N** | Requires the admin header. Starts one single-flight server-side background integrity job; poll `/api/db/integrity/jobs/{id}`. Concurrent maintenance is rejected. |
| GET | `/api/db/integrity/jobs/{id}` | read | path: `id` (i64). | `MaintenanceJobStatus` | 200, 401, 404, 503, 500 | Y | Polls a background integrity job. |
| POST | `/api/db/checkpoint` | **admin** | body: `{ "mode": "passive" \| "full" \| "restart" \| "truncate" }`. Validated handler-side BEFORE the service call (eng-review #A17). | `DbCheckpointResult { mode, busy, log_frames, checkpointed_frames, complete }` | 200, 400, 401, **403**, **409**, 500 | **N** | Requires the admin header. Single-flight via `MAINTENANCE_PERMIT`; 409 on contention. `caller_ip` audit-logged before service call. `passive` can return `complete=false` with 200 while active writers prevent a full drain; stricter modes still return 409 when incomplete. |
| POST | `/api/db/vacuum` | **admin** | body: `{ "full": bool, "force"?: bool, "incremental_pages"?: u32 }`. `force` is `Option<bool>` so the size pre-flight only relaxes on explicit `"force": true`. | `DbVacuumResult` (incl. `after_physical_size_bytes`) | 200, 400, 401, **403**, **409**, 500 | **N** | Requires the admin header. Single-flight via `MAINTENANCE_PERMIT`. Size pre-flight: `full && !force` reads the LIVE `page_count * page_size` (no cached snapshot) on every call and returns 409 if logical size > **2 GB**. `caller_ip` audit-logged before service call. See "VACUUM on large DBs" below. |
| POST | `/api/db/backup` | **admin** | body: `{ "output_path"?: string }` or empty body. | `DbBackupResult { db_path, backup_path, size_bytes }` | 200, 400, 401, **403**, **409**, 500 | **N** | Requires the admin header. Runs an online backup inside the server process; `output_path` is server-side, not a local shell path. Single-flight via `MAINTENANCE_PERMIT`. |

### Compose diagnostics (2)

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/compose/status` | read | (none) | `ComposeMcpStatus { container_name, ownership, runtime_state, health?, published_ports, diagnostics }` | 200, 401, 500 | Y | Redacted read-only projection. If the container cannot run Docker inspection, this still returns 200 with `runtime_state="docker_unavailable"` and diagnostic code `docker_unavailable`. |
| GET | `/api/compose/doctor` | read | (none) | `ComposeMcpStatus { container_name, ownership, runtime_state, health?, published_ports, diagnostics }` | 200, 401, **503**, 500 | Y | Strict readiness check. Healthy Compose-owned deployment returns 200; Docker/ownership/runtime unready states return 503 with the same structured projection, not a generic error envelope. |

### Investigation graph queries (4)

| Method | Path | Scope | Request | Response (top-level) | Status codes | Idempotent | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/graph/entity` | read | query: `entity_id?` or `entity_type` + `key` or `alias_type` + `alias_key`; `payload_budget?` | `GraphEntityLookupResponse { resolved_entity?, candidates, metadata }` | 200, 400, 401, 404, 503, 500 | Y | Resolves one graph entity by id, canonical key, or alias without rebuilding the projection. |
| GET | `/api/graph/around` | read | query: entity selector, `depth?` (1 only), `limit?`, `evidence_sample_limit?`, `payload_budget?` | `GraphAroundResponse { resolved_entity, entities, relationships, evidence, metadata }` | 200, 400, 401, 404, 503, 500 | Y | Bounded one-hop neighborhood with allowlisted evidence samples. |
| GET | `/api/graph/explain` | read | query: entity selector, `depth?` (clamped to 3), `beam_width?`, `max_chains?`, `evidence_sample_limit?`, `payload_budget?` | `GraphExplainResponse { resolved_entity, chains, narrative, open_questions, missing_evidence, next_queries, metadata }` | 200, 400, 401, 404, 503, 500 | Y | Deterministic evidence-backed explanation; weak evidence becomes open questions, not causal claims. |
| GET | `/api/graph/evidence` | read | query: `evidence_id` (REQUIRED, minimum 1), `payload_budget?` | `GraphEvidenceLookupResponse { evidence, relationship, src_entity, dst_entity, source_log_summary?, missing_source_reason?, metadata }` | 200, 400, 401, 404, 503, 500 | Y | Proof lookup for one evidence row. Source summaries are redacted/truncated and exclude raw frames and raw metadata. |

**Total: 93 method/path bindings** (current surface registry, including syslog,
surface-parity, AI, graph, compose, notification, error-ack, and DB routes;
includes the 3 hook routes above, added alongside the `ai_hook_events`
subsystem).

`cortex assess skill` / `cortex assess abuse` / `cortex assess hooks` are
CLI-only in this phase (no REST route) — see README "Skill, abuse, and hook
assessment". LLM assessment spawns Gemini on the local host via `LlmRunner`
and is never exposed over MCP or REST; this mirrors the existing
`cortex sessions assess` (no `/api/sessions/assess` route either).

---

## Versioning policy

`/api/version` returns `{ version, git_sha?, schema_version }` cached at
startup. Two version-skew rules:

- **404 on a known route name = "endpoint not on this server — upgrade."**
  Newer CLI calling an older container will see Axum's default 404 for
  routes added in later beads (`/api/db/vacuum`, `/api/sessions/prune-checkpoints`,
  etc.). The CLI maps that to a user-facing "upgrade the container or
  unset `CORTEX_USE_HTTP` to use direct DB" message.
- **`/api/capabilities` is additive and fail-closed.** Typed clients use it to
  distinguish bounded polling from native streaming. This release advertises
  rendered-session and log polling only; both native stream flags remain false.

---

## Performance

The HTTP transport adds roughly **~15-30 ms of round-trip overhead per
call on loopback** on top of the underlying service work (request parse,
auth check, response serialise, TCP send/recv). For one-off commands
this is invisible. For scripted loops it dominates fast queries.

Operators can measure the overhead on their own host by running the same
query 100× both ways. Direct (default-pre-v0.26 path):

```bash
# direct SQLite — bypasses /api/*
unset CORTEX_USE_HTTP
time for i in $(seq 1 100); do cortex hosts > /dev/null; done
```

HTTP:

```bash
# REST transport — same call, with auth + transport overhead
export CORTEX_USE_HTTP=true
# CORTEX_URL + CORTEX_API_TOKEN must already be set in env
time for i in $(seq 1 100); do cortex hosts > /dev/null; done
```

The difference between the two `real` times divided by 100 is the
per-call transport cost. Expect ~1.5–3.0 s of additional wall time over
100 invocations on the same host (i.e. 15–30 ms per call).

For batch loops that don't need cross-host coordination (e.g. iterating
over local hostnames inside a maintenance script on the deploy host),
operators can opt out of HTTP transport for the duration of the script:

```bash
( unset CORTEX_USE_HTTP; \
  for h in $(cortex hosts --json | jq -r '.hosts[].hostname'); do \
    cortex tail --host "$h" --n 50; \
  done )
```

Inside the subshell `CORTEX_USE_HTTP` is unset so each `cortex` call
goes straight to SQLite via `RuntimeCore::load_query_only`. The parent
shell environment is unaffected.

---

## Security / threat model

- **Bearer tokens in env.** `CORTEX_API_TOKEN` is passed via the
  container/CLI environment. On a Linux host any process running as the
  same user can read `/proc/<pid>/environ` and recover the token. The
  homelab acceptance is: the host is single-owner; nothing untrusted
  runs as the same user as the cortex container or the CLI. **Do
  not share container-host shell access with untrusted users** — this
  is the documented model, not a future bug to fix.
- **Token storage.** `setup repair` writes `~/.cortex/.env` with
  mode `0600` (`-rw-------`). Verify with `ls -l ~/.cortex/.env`
  before reporting a "leaked token" — a `0644` file is a configuration
  error, not a deliberate design.
- **TLS termination is external.** The `/api/*` surface speaks plain
  HTTP. Production deployments terminate TLS at SWAG (or any reverse
  proxy) and forward to the container over the internal bridge. The
  API itself **emits a startup warning** when bound to a non-loopback
  address while `CORTEX_PUBLIC_URL` does not begin with `https://`,
  so a misconfiguration is loud at first boot rather than silent
  in production.
- **API auth model.** `build_auth_layer` accepts the normal
  `CORTEX_API_TOKEN`; `AuthPolicy::Mounted` is enforced for `/api/*`
  regardless of bind address (eng-review C1). Routes marked **admin** require
  both the normal bearer and the `X-Cortex-Admin-Token` header; this covers
  file-tail management plus maintenance mutations such as session checkpoint
  pruning, DB background integrity, checkpoint, vacuum, and backup.

---

## `/api/correlate` vs `/api/sessions/correlate`

These are **distinct operations** and the names trip people up. Quick
disambiguation:

| Aspect | `/api/correlate` | `/api/sessions/correlate` |
| --- | --- | --- |
| Service method | `correlate_events` | `correlate_ai_logs` |
| Anchored on | A caller-supplied `reference_time` (RFC 3339) | AI transcript anchors matched by `ai_query`/`session_id`/etc. |
| Returns | Hosts within a time window around the anchor, grouped by hostname | AI anchor events plus correlated system logs per anchor |
| Use case | "What was happening across hosts around 03:17 UTC?" | "What syslog activity correlates with this AI session?" |
| Capped at | Single time window, single anchor | Multiple anchors; **`events_per_anchor` capped at 50** |

The router in `src/api.rs::router()` groups them under
`// --- syslog queries ---` and `// --- ai session queries ---`
block comments to keep maintainers oriented (eng-review pattern note).

---

## Response size caps

REST handlers clamp some caller-supplied limits on the way IN and mark
the clamp in the response. The caps are constants in `src/api.rs`:

| Endpoint | Field | Cap | Surfaced as |
| --- | --- | --- | --- |
| `/api/sessions/search` | `limit` | **500** (`REST_AI_LIMIT_CAP`) | `limit_clamped_to: 500` + `truncated: true` |
| `/api/sessions/abuse` | `limit` | **500** (`REST_AI_LIMIT_CAP`) | `limit_clamped_to: 500` + `truncated: true` |
| `/api/sessions/correlate` | `events_per_anchor` | **50** (`REST_CORRELATE_EVENTS_PER_ANCHOR_CAP`) | `events_per_anchor_clamped_to: 50` |

The MCP surface uses the service-layer clamps only; these REST caps are
the second line of defence so a misbehaving client can't tank the
container with a 100000-row request.

---

## VACUUM on large DBs

`POST /api/db/vacuum` enforces a **live 2 GB size pre-flight** when
`{"full": true, "force": <not true>}` — `db_logical_size_bytes()` reads
`page_count * page_size` fresh on every call so a long-running container
cannot defeat the guard with a stale startup snapshot. Two operational
caveats:

- The default-reverse-proxy HTTP timeout (Axum upstream / SWAG) is on
  the order of minutes. A `VACUUM` on a database larger than ~10 GB
  can exceed it and the client will see a 504 from the proxy even
  though the VACUUM is still running on the server. The server-side
  single-flight permit (`MAINTENANCE_PERMIT`) is still held, so
  retries will 409 until the original VACUUM commits.
- **Workaround for large DBs:** drop HTTP transport for this one call
  and run the vacuum through the service layer directly:

  ```bash
  ( unset CORTEX_USE_HTTP && cortex db vacuum --full --force )
  ```

  The subshell scoping keeps `CORTEX_USE_HTTP` set for everything else.
  Pair with a downtime/ingest-quiesce window since `full` blocks
  writers regardless of transport.

---

## Local-only commands

A handful of CLI subcommands intentionally stay on the direct-SQLite or
host-shell path even with `CORTEX_USE_HTTP=true`. The per-command
reasons (no taxonomy):

- `cortex sessions watch` — long-running daemon. HTTP would require a
  streaming bidirectional surface; the daemon is the writer for the
  same DB the container reads.
- `cortex sessions watchstatus` — wraps `systemctl --user show
  cortex-sessions-watch.service` on the host. The container has no view of
  the host systemd state.
- `cortex sessions index`, `cortex sessions add`, `cortex sessions doctor`,
  `cortex sessions smokewatch` — all touch the host filesystem (transcript
  paths, watcher state). The container can't see them.
- `cortex db backup` — writes a backup file to a host path. Passing
  the destination over HTTP would force a container-side filesystem
  the operator never asked for.

These all keep working when `CORTEX_USE_HTTP=true` because the CLI
dispatch table never routes them through the HTTP client.

---

## Operational option: weekly compose-doctor

The `compose doctor` subcommand runs the two drift diagnostics
(`data-mount`, `ai-watch-coord`) and exits non-zero on a canonical
mismatch. A simple way to surface ai-watch / data-mount drift without
manual invocation is a weekly user-systemd timer:

```ini
[Unit]
Description=cortex drift check

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cortex compose doctor --json
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
```

```ini
[Unit]
Description=run cortex drift check weekly

[Timer]
OnCalendar=Mon *-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

Pair with whatever push-notification path the operator already has
(Gotify, ntfy, email) keyed off `systemctl --user status
cortex-doctor.timer` exit codes. The `--json` output is stable
enough for jq/grep alerting.

---

## See also

- [`docs/architecture.md`](architecture.md) — caller → DB diagram and
  the three direct-SQLite consumers.
- [`docs/rollout.md`](rollout.md) — manual upgrade playbook for the
  v0.26 cutover.
- [`docs/CLI.md`](CLI.md) — direct CLI command reference.
- `src/api.rs` — router and handler source of truth.
- `src/app/models.rs` — typed request/response structs.
