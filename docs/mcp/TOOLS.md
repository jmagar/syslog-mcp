---
title: "MCP Tools Reference -- cortex"
created: "2026-07-30"
updated: "2026-08-04"
---

# MCP Tools Reference -- cortex

## Design Philosophy

cortex exposes one MCP tool named `cortex`. The required
`action` argument selects the operation:

| Action | Purpose |
| --- | --- |
| `search` | Full-text search with filters |
| `filter` | Structured filter-only log retrieval |
| `tail` | Recent log entries |
| `errors` | Error/warning summary by host and severity |
| `hosts` | Host registry with first/last seen |
| `map` | Cached homelab inventory plus live Cortex host/heartbeat overlay |
| `host_state` | Latest bounded heartbeat state for one host |
| `fleet_state` | Fleet-wide heartbeat snapshot with pressure flags and summary counts |
| `correlate_state` | Correlate logs with heartbeat window summaries around a reference time |
| `sessions` | AI transcript sessions by project |
| `search_sessions` | Ranked grouped session search |
| `abuse` | Abuse hits in AI transcripts with same-session context |
| `abuse_incidents` | Groups abuse hits into scored incident candidates |
| `abuse_investigate` | Expands incidents into deterministic evidence bundles |
| `ai_correlate` | AI transcript anchors cross-referenced against non-AI logs |
| `topic_correlate` | Resolve a topic to graph entities and correlate all related logs into a unified timeline |
| `usage_blocks` | AI activity in deterministic 5-hour windows |
| `project_context` | Summary for one AI project path |
| `list_ai_tools` | Distinct AI tools with counts |
| `list_ai_projects` | Distinct AI projects with counts |
| `correlate` | Cross-host event correlation in a time window; omit reference_time and pass query to derive the anchor from a matching AI session |
| `stats` | Database statistics and storage health |
| `status` | Lightweight runtime and DB health |
| `apps` | Distinct application names with log and host counts |
| `source_ips` | Distinct source identifiers with hostname breakdown |
| `timeline` | Bucketed counts over time |
| `patterns` | Near-duplicate message template clusters |
| `context` | Surrounding logs around a log id or timestamp |
| `get` | One log entry by id, including raw frame |
| `ingest_rate` | Recent ingest throughput and write-block state |
| `silent_hosts` | Hosts whose last_seen is older than a threshold |
| `clock_skew` | Per-host received_at minus timestamp distribution |
| `anomalies` | Recent vs baseline volume/error comparison |
| `compare` | Side-by-side comparison of two time ranges |
| `compose_status` | Redacted read-only Compose deployment diagnostics |
| `compose_doctor` | Strict Compose deployment health diagnostics |
| `unaddressed_errors` | List unacknowledged repeating error signatures |
| `ack_error` | Acknowledge an error signature to suppress it from future reports |
| `unack_error` | Revoke an acknowledgement so a signature reappears in reports |
| `file_tails` | Manage Cortex-owned file-tail ingest sources |
| `notifications_recent` | List recent notification firings |
| `notifications_test` | Send a test notification via Apprise |
| `llm_invocations` | Recent LLM invocation audit records (concurrency/rate-limit/circuit-breaker denials included) |
| `similar_incidents` | FTS5 cluster search — find historical incidents similar to a query |
| `recurring_error_comparison` | Compare recurring error signatures with redacted deterministic evidence bundles |
| `incident_context` | Full context bundle for a known time window — logs + AI sessions |
| `graph` | Resolve graph entities, neighborhoods, evidence-backed explanations, and evidence proof rows |
| `artifact_evidence` | Query bounded source-attributed artifact ecosystem evidence |
| `artifact_evidence_record` | Append one bounded source-attributed artifact ecosystem evidence event (admin) |
| `skill_events` | List extracted AI skill-invocation events |
| `skill_incidents` | Groups negative-signal transcript hits following a skill invocation into scored incident candidates |
| `skill_investigate` | Expands skill-usage incidents into deterministic evidence bundles, skill-first |
| `mcp_events` | List extracted AI MCP tool-call events |
| `mcp_incidents` | Groups negative-signal transcript hits following an MCP tool call into scored incident candidates |
| `mcp_investigate` | Expands MCP-usage incidents into deterministic evidence bundles, server/tool-first |
| `hook_events` | List extracted/collected AI hook events (runtime execution and config inventory) |
| `hook_incidents` | Groups hook failures/timeouts and other negative signals into scored incident candidates |
| `hook_investigate` | Expands hook-usage incidents into deterministic evidence bundles, hook-first |
| `help` | Markdown reference for all actions |

## cortex search

Full-text search across all syslog messages. Uses SQLite FTS5 with porter stemming.

Required argument: `action = "search"`

Optional arguments: `query`, `hostname`, `source_ip`, `severity`, `app_name`, `facility`, `process_id`, `from`, `to`, `limit`.

## cortex filter

Structured filter-only log retrieval. This action rejects `query`; use `search` for FTS5 message-body search.

Required argument: `action = "filter"`

Optional arguments: `hostname`, `source_ip`, `source_kind`, `tool`, `project`, `session_id`, `container`, `docker_host`, `stream`, `event_action`, `severity`, `app_name`, `facility`, `exclude_facility`, `process_id`, `from`, `to`, `received_from`, `received_to`, `limit`.

## cortex tail

Get the N most recent log entries. Equivalent to `tail -f` across all hosts.

Required argument: `action = "tail"`

Optional arguments: `hostname`, `source_ip`, `app_name`, `severity_min`, `n`.

## cortex errors

Get a summary of errors and warnings across all hosts in a time window, grouped by hostname and severity.

Required argument: `action = "errors"`

Optional arguments: `from`, `to`, `group_by`.

`group_by` currently supports `app_name` for hostname + app + severity grouping.

## cortex hosts

List all hosts that have sent syslog messages.

Required argument: `action = "hosts"`

## cortex map

Return a bounded homelab infrastructure snapshot from `~/.cortex/inventory`
plus live Cortex host/heartbeat overlay, or answer graph-backed topology
questions. The action is read-only and never triggers refresh; raw Compose,
proxy, and AdGuard artifact bodies are omitted. Safe normalized provider fields
are available under `services[].details` and `networks[].details`.
Server-side inventory refresh keeps the cache current on a 5-minute baseline
cadence, reacts to local Compose/proxy config changes, can opt into remote
Docker event streams over SSH, and projects topology evidence into the graph.

Required argument: `action = "map"`

Optional arguments: `host_limit` (default 100, max 500), `section_limit`
(default 100, max 250), and `include_sections` to restrict top-level sections.
Use `mode = "host_services"` with `host`, `mode = "domain_routes"` with
`domain`, `mode = "service_dependencies"` with `service` or `host` +
`service`, or `mode = "findings"` to get a `graph_answer` envelope with answer
status, topology rows or findings, safe evidence, map follow-ups, and graph
proof queries. `service_dependencies` targets resolve to `service_instance`
keys (`nashost/plex`); legacy `host:service` identities are rejected with
`rejected_legacy_shape`.

`mode = "findings"` supports `finding_limit`, `evidence_per_finding`, and
`finding_types` (`potential_public_route`, `risky_mounts`, `collector_health`).
Route findings prove configured reverse-proxy routes only; they do not claim
unauthenticated internet exposure without separate listener/perimeter evidence.
Risk and hygiene evidence is bounded and redacted.

## cortex host_state

Return latest bounded heartbeat state for one host.

Required argument: `action = "host_state"` plus either `host_id` or uniquely resolving `hostname`.

Optional arguments: `since`, `limit` (default 1, max 100).

## cortex correlate_state

Correlate non-AI logs with per-host heartbeat window summaries around a
reference time. Bounded by default; never performs a full-history scan.

Required argument: `action = "correlate_state"`, `reference_time` (ISO 8601).

Optional arguments: `window_minutes` (default 10, max 120), `host`
(host_id or unique hostname; omit for a bounded cross-host plan),
`severity_min` (default `info`), `limit` (max log rows per host, default 100,
max 500).

Response includes the resolved `window`, a `heartbeat_summary` plus matching
`logs` per host, and a `truncated` flag.

## cortex sessions

List AI transcript sessions grouped by project, tool, session, and host.

Required argument: `action = "sessions"`

Optional arguments: `project`, `tool`, `hostname`, `from`, `to`, `limit`.

## cortex search_sessions

Search AI transcript rows with FTS5 and return grouped session results ranked by relevance.

Required arguments: `action = "search_sessions"`, `query`

Optional arguments: `project`, `tool`, `from`, `to`, `limit`.

## cortex abuse

Detect abuse in AI transcript rows and return the hit plus surrounding rows
from the same AI session.

Required argument: `action = "abuse"`

Optional arguments: `project`, `tool`, `from`, `to`, `limit`, `before`, `after`, `terms`.

`terms` replaces the built-in abuse detector list when provided. `before`
and `after` default to 2 and are capped at 20.

## cortex abuse_incidents

Groups AI transcript abuse hits into scored incident candidates by `(project, tool, session_id, hostname)` within a configurable time window. Returns incidents ordered by priority score with labels: `low` / `medium` / `high` / `critical`.

Response includes `incidents`, `total_incidents`, `candidate_rows`, `candidate_cap`, `candidate_window_truncated`, `truncated`.

Optional arguments: `project`, `tool`, `from`, `to`, `limit` (default 20, max 100), `window_minutes` (default 10, max 120), `terms`.

## cortex abuse_investigate

Expands the top abuse incidents into deterministic evidence bundles. Each bundle includes transcript context before and after the incident, the abuse anchor entries, and nearby non-AI syslog/Docker logs in the correlation window.

Each bundle also carries a `findings` object — **deterministic, rule-based**
failure hypotheses derived locally from the evidence (never an external LLM
analysis). It contains `likely_failure_modes` (each with a stable `category`,
conservative `confidence`, and citing `evidence_ids`), `contributing_factors`,
templated `prevention_hints` tied to each category, and `open_questions`.
Categories include `command_failure`, `tool_timeout`,
`auth_or_permission_failure`, `stale_binary_or_version_drift`, `test_failure`,
`docker_or_service_runtime_failure`, `db_busy_or_performance_bottleneck`,
`unclear_instruction_or_scope_drift`, and `unknown`. When the signal is weak the
bundle reports `unknown` plus `open_questions` rather than overclaiming a cause.

Response includes `evidence` (array of bundles), `total_incidents`, `truncated`.

Optional arguments: `project`, `tool`, `from`, `to`, `limit` (default 3, max 10), `window_minutes`, `correlation_window_minutes` (default 5, max 120), `terms`.

## cortex sessions_correlate

Use AI transcript rows as timeline anchors and pull nearby non-AI syslog,
Docker, OTLP, and host events from the same database. Related logs explicitly
exclude AI transcript rows so session logs do not correlate with themselves.

Required argument: `action = "ai_correlate"`

Optional arguments: `project`, `tool`, `session_id`, `ai_query`, `log_query`,
`hostname`, `source_ip`, `app_name`, `from`, `to`, `window_minutes`,
`severity_min`, `limit`, `events_per_anchor`.

`limit` caps AI anchors at 50. `events_per_anchor` caps related non-AI rows at
200 per anchor. `window_minutes` searches before and after each AI timestamp.

## cortex usage_blocks

Bucket AI activity into deterministic 5-hour UTC windows.

Required argument: `action = "usage_blocks"`

Optional arguments: `project`, `tool`, `from`, `to`.

## cortex project_context

Summarize one AI project path with tools, sessions, hosts, counts, and recent representative entries.

Required arguments: `action = "project_context"`, `project`

Optional arguments: `tool`, `limit`.

## cortex list_ai_tools

List distinct AI tools with counts and first/last seen timestamps.

Required argument: `action = "list_ai_tools"`

Optional arguments: `project`, `from`, `to`.

## cortex list_ai_projects

List distinct AI projects with counts, tools used, and first/last seen timestamps.

Required argument: `action = "list_ai_projects"`

Optional arguments: `tool`, `since`, `until`.

The generated MCP schema rejects unsupported fields such as `limit` before
dispatch.

## cortex correlate

Search for related events across multiple hosts within a time window.

Required arguments: `action = "correlate"`, and either `reference_time` or `query`. If
`reference_time` is omitted, it's derived from the top AI-transcript session matching
`query` (an FTS5 search over `search_sessions`-style session content); the matched
session is returned as `matched_session` in the response.

Optional arguments: `window_minutes`, `severity_min`, `hostname`, `source_ip`, `query`, `limit`.

## cortex stats

Get database statistics including storage health, runtime ingest counters, queue depth, writer failure/drop state, and OTLP receiver counters.

Required argument: `action = "stats"`

## cortex status

Get lightweight runtime status without the full DB statistics query.

Required argument: `action = "status"`

## cortex compose_status

Get redacted read-only Docker Compose diagnostics for the canonical cortex deployment. MCP output omits host paths, mount sources, image ids, and raw command output.

Required argument: `action = "compose_status"`

Target override arguments such as `project_dir`, `compose_file`, `project_name`, `container`, and `container_name` are rejected.

## cortex compose_doctor

Run strict deployment-health checks for the canonical cortex Compose deployment. It returns the same redacted diagnostic shape as `compose_status` when healthy, and returns a tool error when Docker/Compose ownership or runtime checks are not ready for lifecycle work. Compose lifecycle mutations are CLI-only.

Required argument: `action = "compose_doctor"`

## cortex artifact_evidence

Query the durable W16 artifact-evidence stream. This is evidence/history, not an artifact registry or authority lookup. Artifact IDs, revisions, content digests, correlation/request ids, targets, and producer identity are treated as opaque observed dimensions.

Required argument: `action = "artifact_evidence"`

Optional arguments: `eventKind`, `artifactId`, `revisionId`, `contentDigest`, `correlationId`, `requestId`, `targetId`, `sourceSystem`, `since`/`from`, `until`/`to`, `limit` (max 500).

## cortex artifact_evidence_record

Append one `dinglebear.cortex-artifact-evidence/v1` observation through Cortex's canonical durable log transaction path. Requires `cortex:admin`. Exact replay is idempotent by `(sourceSystem, sourceIssuer, eventId)`; conflicting reuse fails closed. Metadata is bounded/redacted and secret-bearing keys, secret-like references, raw request/result/tool/artifact bodies, malformed timestamps, and malformed SHA-256 digests are rejected. Caller-supplied license/trust/policy/share/lease/deployment fields remain source-attributed evidence only.

Required arguments: `action = "artifact_evidence_record"`, `schemaVersion`, `eventId`, `eventKind`, `sourceSystem`, `sourceIssuer`, `observedAt`, plus at least one of `artifactId`, `revisionId`, `contentDigest`, or `provenanceRef`.

Optional bounded evidence dimensions: `requestId`, `correlationId`, `causationId`, `targetId`, `targetKind`, `loadoutId`, `shareGrantId`, `capabilityLeaseId`, `deploymentPlanId`, `runtimeId`, `pluginId`, `operationRef`, `outcome`, `metadata`.

## cortex skill_incidents

Groups `ai_skill_events` rows into incident candidates by `(skill_name,
skill_plugin, tool, project, session_id, hostname, window_bucket)`, scanning
the surrounding transcript for five deterministic negative-signal anchors:
`user_correction_after_skill`, `tool_failure_after_skill`,
`scope_or_source_confusion`, `ignored_skill_or_policy_instruction`, and
`overlong_loop_after_skill` (which requires both high tool-call volume AND a
co-occurring negative signal — long-but-successful work never triggers it
alone). Each incident carries a stable `incident_id` (`skill-inc-{hash}`), a
`priority_score`/`priority_label`, and `signal_counts`/`signals_present`.

Response includes `incidents`, `total_incidents`, `candidate_event_rows`,
`candidate_cap`, `candidate_window_truncated`, `truncated`.

Optional arguments: `skill`, `plugin`, `tool`, `project`, `session_id`,
`hostname`, `since`, `until`, `limit` (default 20, max 100), `window_minutes`
(default 10, max 120), `signals` (filter to these anchor categories only),
`min_score`.

## cortex skill_investigate

Deep-dive investigation of skill-usage incidents. When filtered by `skill` or
`plugin` (without an exact `incident_id`), resolves **skill-first**: looks up
all matching incidents, returns the top-priority one(s) in `evidence`
(count controlled by `limit`, default 1), and summarizes the rest into
`other_matching_incidents`. A single zero-signal match is still returned
(never an error) but flagged via `no_incident_low_severity_summary`. Each
evidence bundle includes the underlying skill events, the transcript rows
that triggered anchor signals, transcript context before/after, and nearby
non-AI logs split into tool-failure/user-correction/error subsets — every
collection carries an explicit truncation flag.

Each bundle also carries a `findings` object — **deterministic, rule-based**
failure hypotheses derived locally from the evidence (never an external LLM
analysis), following the same pattern as `abuse_investigate`'s `findings`.
Categories include `skill_scope_mismatch`, `missing_prerequisite_check`,
`wrong_source_of_truth`, `overly_broad_research_loop`,
`tool_policy_mismatch`, `missing_verification_step`,
`ambiguous_skill_trigger`, `stale_or_conflicting_skill_instruction`,
`assistant_overexplained_simple_answer`, and `unknown`.

Response includes `evidence`, `total_incidents`, `truncated`,
`other_matching_incidents`, `no_incident_low_severity_summary`, `no_data`,
`suggested_filters` (populated only when `no_data` is true).

Optional arguments: `incident_id`, `skill`, `plugin`, `tool`, `project`,
`since`, `until`, `limit`, `window_minutes` (default 10, max 120),
`correlation_window_minutes` (default 5, max 120).

## cortex mcp_events

List extracted AI MCP tool-call events (`ai_mcp_events` rows) — the raw,
unaggregated tool-call/tool-result stream classified via the
`mcp__<server>__<tool>` naming convention (general tool calls have
`mcp_server = null`).

Response includes `total`, `truncated`, `events`.

Optional arguments: `tool_name`, `mcp_server`, `mcp_tool`, `tool`, `project`,
`session_id`, `hostname`, `is_error`, `since`, `until`, `limit`.

## cortex mcp_incidents

Groups `ai_mcp_events` rows into incident candidates by `(mcp_server,
mcp_tool, tool, project, session_id, hostname, window_bucket)`, scanning the
surrounding transcript for six deterministic negative-signal anchors:
`repeated_call_failure`, `timeout_or_rate_limit`,
`auth_or_permission_failure`, `schema_or_validation_error`,
`unknown_tool_or_server`, and `user_correction_after_tool_call`. Each
incident carries a stable `incident_id` (`mcp-inc-{hash}`), a
`priority_score`/`priority_label`, and `signal_counts`/`signals_present`.

Response includes `incidents`, `total_incidents`, `candidate_event_rows`,
`candidate_cap`, `candidate_window_truncated`, `truncated`.

Optional arguments: `mcp_server`, `mcp_tool`, `tool_name`, `tool`, `project`,
`session_id`, `hostname`, `since`, `until`, `limit` (default 20, max 100),
`window_minutes` (default 10, max 120), `signals` (filter to these anchor
categories only), `min_score`.

## cortex mcp_investigate

Deep-dive investigation of MCP-usage incidents. When filtered by
`mcp_server`, `mcp_tool`, or `tool_name` (without an exact `incident_id`),
resolves **server/tool-first**: looks up all matching incidents, returns the
top-priority one(s) in `evidence` (count controlled by `limit`, default 1),
and summarizes the rest into `other_matching_incidents`. A single
zero-signal match is still returned (never an error) but flagged via
`no_incident_low_severity_summary`. Each evidence bundle includes the
underlying MCP events, the transcript rows that triggered anchor signals,
transcript context before/after, and nearby non-AI logs split into
tool-failure/user-correction/error subsets — every collection carries an
explicit truncation flag.

Each bundle also carries a `findings` object — **deterministic, rule-based**
failure hypotheses derived locally from the evidence (never an external LLM
analysis), following the same pattern as `skill_investigate`'s `findings`.
Categories include `wrong_mcp_tool_selected`, `mcp_server_unavailable`,
`mcp_auth_or_permission_failure`, `mcp_schema_mismatch`,
`mcp_timeout_or_rate_limit`, `mcp_result_misinterpreted`,
`missing_mcp_discovery_step`, `tool_surface_confusion`, and `unknown`.

Response includes `evidence`, `total_incidents`, `truncated`,
`other_matching_incidents`, `no_incident_low_severity_summary`, `no_data`,
`suggested_filters` (populated only when `no_data` is true).

Optional arguments: `incident_id`, `mcp_server`, `mcp_tool`, `tool_name`,
`tool`, `project`, `since`, `until`, `limit`, `window_minutes` (default 10,
max 120), `correlation_window_minutes` (default 5, max 120).

## cortex hook_events

Lists `ai_hook_events` rows — Claude runtime hook-execution attachments
(`evidence_kind = runtime_transcript`) and Claude/Codex config-inventory /
trusted-hash-state rows (`evidence_kind = config_inventory` /
`trusted_hash_state`). A configured/trusted hook is NOT proof it executed; the
`evidence_kind` and `status` (`configured` for config rows) columns make the
provenance explicit.

Optional arguments: `hook_event`, `hook_name`, `hook_source`, `status`,
`evidence_kind`, `tool`, `project`, `session_id`, `hostname`, `from`, `to`,
`limit` (default 50, max 500).

## cortex hook_incidents

Groups `ai_hook_events` rows into incident candidates by `(hook_event,
hook_name, hook_source, tool, project, session_id, hostname, window_bucket)`,
deriving six deterministic anchors: `hook_failed`, `hook_timed_out`,
`hook_output_parse_error`, `hook_invoked_too_often`,
`user_correction_after_hook`, and (via same-session config-vs-runtime
comparison) `hook_not_invoked`. Each incident carries `has_runtime_evidence`
so callers can tell runtime-proven incidents from config/trust-only ones.

Optional arguments: `hook_event`, `hook_name`, `hook_source`, `tool`,
`project`, `session_id`, `hostname`, `evidence_kind`, `since`, `until`,
`limit` (default 20, max 100), `window_minutes` (default 10, max 120),
`signals`, `min_score`.

## cortex hook_investigate

Deep-dive investigation of hook-usage incidents. When filtered by
`hook`/`hook-event` (without an exact `incident_id`), resolves **hook-first**:
returns the top-priority incident(s) in `evidence` and summarizes the rest into
`other_matching_incidents`. Each bundle carries `findings` with an explicit
`evidence_basis` string stating whether the incident rests on runtime hook
execution evidence or only config/trust-state evidence.

Optional arguments: `incident_id`, `hook_event`, `hook_name`, `hook_source`,
`tool`, `project`, `since`, `until`, `limit`, `window_minutes` (default 10,
max 120), `correlation_window_minutes` (default 5, max 120).

## cortex help

Return markdown documentation for all actions.

Required argument: `action = "help"`

## Error Responses

Action validation and execution errors use MCP tool results with
`isError: true`. Validation errors include the same JSON object in the text
content and `structuredContent` so clients can recover without parsing prose:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"kind\":\"invalid_param\",\"message\":\"...\",\"action\":\"project_context\",\"retryable\":false}"
    }
  ],
  "structuredContent": {
    "kind": "invalid_param",
    "message": "invalid project_context arguments: unknown field `since`",
    "action": "project_context",
    "retryable": false
  },
  "isError": true
}
```

JSON-RPC level errors are reserved for failures that prevent normal tool
execution and use standard codes, including:

- `-32602`: Malformed MCP method parameters that cannot be routed to normal tool execution
- `-32601`: Unknown method
- `-32001`: Unauthorized, missing, or invalid bearer token

## Transcript Visibility Policy

AI transcript rows imported through `cortex sessions index` or `cortex sessions add` are stored in the main `logs` table. They are therefore visible through raw log actions such as `search`, `tail`, `context`, and `get`. Scanner imports scrub known credential/token patterns before storage and FTS indexing, but local `ai_transcript_path` values remain visible. Treat MCP log-read access as access to scrubbed transcript content plus local path metadata.

OTLP AI metadata (`ai.tool`/`ai_tool`, `session.id`/`session_id`, `project.path`, `codebase.root_path`, and `session.cwd`) is producer-supplied, not network-verified identity. Oversized AI tool, project, and session values are rejected before storage; accepted OTLP metadata should be used for grouping/search convenience, not as an authorization or provenance boundary.

Rows can include `metadata_json`, a source-specific JSON payload. Syslog rows
record parser/source provenance, OTLP rows record resource/log attributes plus
trace/span ids, Docker rows record host/container/image/compose/action details,
and transcript rows record source kind, path, line number, record key, and scrub
status. This metadata is for debugging and correlation, not authorization.

## See Also

- [../CLI.md](../CLI.md) -- direct CLI commands backed by the same service methods
- [SCHEMA.md](SCHEMA.md) -- JSON Schema definitions for tool inputs
- [CORRELATION.md](CORRELATION.md) -- exact behavior of correlation-style actions
- [AUTH.md](AUTH.md) -- authentication required before tool calls
- [ENV.md](ENV.md) -- environment variables affecting tool behavior
