---
title: "MCP Actions Contract -- Current Production Surface"
created: 2026-05-16
updated: 2026-08-04
---

# MCP Actions Contract -- Current Production Surface

## Purpose

This contract summarizes the live MCP action surface for downstream consumers.
The implementation source of truth is the Rust action registry, not this
markdown file:

- `src/mcp/actions.rs::ACTION_SPECS` registers action names, scopes, costs, descriptions, and machine-readable input contracts.
- `src/mcp/actions.rs::action_names()` derives the schema enum.
- `src/mcp/schemas.rs::tool_definitions()` builds `tools/list` and `cortex://schema/mcp-tool`.
- `src/mcp/tools.rs::tool_cortex()` dispatches handlers.
- `src/app/models.rs` defines typed request and response payloads.

The MCP server exposes a single tool named `cortex`; every operation is selected
by the required string parameter `action`.

## Stability

Existing action names, required parameters, caps/defaults, and top-level
response keys are stable. Renaming, removing, or tightening them is a breaking
change. Adding optional parameters or optional response fields is non-breaking.

Most actions require `cortex:read` when auth is mounted. `ack_error`,
`unack_error`, `file_tails`, `notifications_test`, and `llm_invocations`
require `cortex:admin` (`llm_invocations` is read-only but admin-scoped
because it exposes `LlmRunner` circuit-breaker/kill-switch operational
state). `help` has no action-level scope requirement, though the
protected endpoint still requires transport auth when configured.

## Current Action Index

The live registry action count is generated in `tests/TEST_COVERAGE.md`. This
snapshot may lag `src/mcp/actions.rs::ACTION_SPECS`, the authoritative source:

| Action | Scope | Cost | Purpose |
| --- | --- | --- | --- |
| `search` | `cortex:read` | cheap | Full-text search over syslog messages |
| `filter` | `cortex:read` | cheap | Filter logs by indexed fields without FTS5 |
| `tail` | `cortex:read` | cheap | Most recent log entries |
| `errors` | `cortex:read` | cheap | Error/warning summary |
| `hosts` | `cortex:read` | cheap | Known source hostnames |
| `map` | `cortex:read` | moderate | Cached homelab inventory plus graph-backed topology answers |
| `host_state` | `cortex:read` | moderate | Latest bounded heartbeat state for one host |
| `fleet_state` | `cortex:read` | expensive | Fleet-wide heartbeat snapshot with pressure flags |
| `correlate` | `cortex:read` | moderate | Time-window event correlation |
| `correlate_state` | `cortex:read` | expensive | Correlate logs with heartbeat summaries around a reference time |
| `stats` | `cortex:read` | expensive | DB statistics and runtime observability |
| `status` | `cortex:read` | cheap | Lightweight health and runtime status |
| `apps` | `cortex:read` | cheap | Distinct application names with counts |
| `sessions` | `cortex:read` | cheap | AI transcript session inventory |
| `search_sessions` | `cortex:read` | cheap | FTS5 search over AI transcript sessions |
| `evidence_scope` | `cortex:read` | moderate | Historical Agent Observatory evidence for a Git branch or worktree |
| `abuse` | `cortex:read` | moderate | Abuse-term hits with same-session context |
| `abuse_incidents` | `cortex:read` | moderate | Grouped abuse incident candidates |
| `abuse_investigate` | `cortex:read` | expensive | Evidence bundles for abuse incidents |
| `ai_correlate` | `cortex:read` | moderate | AI transcript anchors with nearby non-AI logs |
| `topic_correlate` | `cortex:read` | moderate | Resolve a topic to graph entities and correlate all related logs into a unified timeline |
| `usage_blocks` | `cortex:read` | cheap | AI activity in 5-hour UTC blocks |
| `project_context` | `cortex:read` | moderate | AI project summary and recent entries |
| `list_ai_tools` | `cortex:read` | cheap | AI tools observed in transcripts |
| `list_ai_projects` | `cortex:read` | cheap | AI projects observed in transcripts |
| `source_ips` | `cortex:read` | cheap | Distinct source identifiers with counts |
| `timeline` | `cortex:read` | cheap | Bucketed log counts over time |
| `patterns` | `cortex:read` | expensive | Near-duplicate message template clusters |
| `context` | `cortex:read` | cheap | Logs surrounding a pivot id or timestamp |
| `get` | `cortex:read` | cheap | One log entry by id, including raw frame |
| `ingest_rate` | `cortex:read` | expensive | Recent ingest throughput and write-block state |
| `silent_hosts` | `cortex:read` | moderate | Hosts older than a staleness threshold |
| `clock_skew` | `cortex:read` | expensive | Per-host received_at minus timestamp distribution |
| `anomalies` | `cortex:read` | expensive | Recent vs baseline volume/error comparison |
| `compare` | `cortex:read` | expensive | Side-by-side comparison of two time ranges |
| `compose_status` | `cortex:read` | moderate | Redacted self Compose status projection |
| `compose_doctor` | `cortex:read` | expensive | Strict self Compose health diagnostics |
| `unaddressed_errors` | `cortex:read` | moderate | Unacknowledged repeating error signatures |
| `notifications_recent` | `cortex:read` | cheap | Recent notification firings |
| `similar_incidents` | `cortex:read` | moderate | FTS5 historical incident clusters |
| `incident_context` | `cortex:read` | moderate | Window bundle: log aggregates, errors, AI sessions |
| `graph` | `cortex:read` | moderate | Entity lookup and one-hop graph neighborhoods |
| `skill_events` | `cortex:read` | cheap | List extracted AI skill-invocation events |
| `skill_incidents` | `cortex:read` | moderate | Grouped skill-usage incident candidates |
| `skill_investigate` | `cortex:read` | expensive | Evidence bundles for skill-usage incidents, skill-first |
| `mcp_events` | `cortex:read` | cheap | List extracted AI MCP tool-call events |
| `mcp_incidents` | `cortex:read` | moderate | Grouped MCP-usage incident candidates |
| `mcp_investigate` | `cortex:read` | expensive | Evidence bundles for MCP-usage incidents, server/tool-first |
| `hook_events` | `cortex:read` | cheap | List extracted/collected AI hook events (runtime execution and config inventory) |
| `hook_incidents` | `cortex:read` | moderate | Grouped hook-usage incident candidates |
| `hook_investigate` | `cortex:read` | expensive | Evidence bundles for hook-usage incidents, hook-first |
| `ack_error` | `cortex:admin` | write | Acknowledge an error signature |
| `unack_error` | `cortex:admin` | write | Revoke an error acknowledgement |
| `file_tails` | `cortex:admin` | write | Manage local file-tail ingest sources |
| `notifications_test` | `cortex:admin` | write | Send a test Apprise notification |
| `llm_invocations` | `cortex:admin` | cheap | Recent LLM invocation audit records (concurrency/rate-limit/circuit-breaker denials included) |
| `help` | none | cheap | Markdown action reference |

## Schema Shape

The generated MCP schema is a hybrid action-dispatched JSON schema. The
`action` enum and exact input contracts are derived from `ACTION_SPECS`; shared
properties remain at the top level for discovery, while `oneOf` contains complete
strict object branches for migrated actions plus an explicit fallback branch for
unmigrated actions. `project_context` accepts only `project`, `tool`, and `limit`
with `project` required. `list_ai_projects` accepts only `tool`, `since`, and
`until`. Request structs retain `deny_unknown_fields` as the final boundary.

The runtime schema also includes cortex-specific metadata:

- `x-cortex-action-metadata`: action names, costs, and descriptions.
- `x-cortex-agent-guidance`: cost ordering and suggested first-pass actions.

## Response Envelope

Successful action responses are returned as one MCP text content block. The
text is pretty-printed JSON for the action-specific response struct.

Action validation and execution failures surface as MCP tool errors with
`isError: true`. Validation failures include matching JSON text and
`structuredContent` with `kind: "invalid_param"`, the action name, the
caller-safe validation message, and `retryable: false`. JSON-RPC errors are
reserved for failures that prevent the MCP request from reaching normal tool
execution.

## Correlation Notes

`correlate` is a general timestamp-window search over log rows. It is not the
AI-aware correlation path. Use:

- `ai_correlate` for AI transcript anchors plus nearby non-AI logs.
- `abuse_investigate` for deterministic abuse evidence bundles.
- `skill_investigate` for deterministic skill-usage-incident evidence bundles, skill-first.
- `hook_investigate` for deterministic hook-usage-incident evidence bundles, hook-first.
- `similar_incidents` for FTS5 historical incident clusters.
- `correlate` for a query-derived anchor (via AI-session search) when reference_time is omitted.
- `incident_context` for a caller-provided time-window bundle.

See `docs/mcp/CORRELATION.md` for inclusion rules, caps, defaults, and current
SQLite-only behavior.

## Drift Checks

The test suite enforces the main invariants:

- `src/mcp/schemas_tests.rs` checks that the schema action enum equals `action_names()`, every action appears in exactly one exact/fallback contract branch, and exact branches match runtime request fields.
- `src/mcp/tools_tests.rs::schema_actions_are_dispatchable` dispatches every registered action.
- `src/mcp/tools_tests.rs::public_action_references_cover_schema_registry` checks public docs and scripts for each registered action.

## References

- `docs/mcp/SCHEMA.md` -- schema source-of-truth map and common arguments.
- `docs/mcp/TOOLS.md` -- user-facing action reference.
- `docs/mcp/CORRELATION.md` -- correlation behavior and inclusion rules.
- `docs/mcp/RESOURCES.md` -- runtime schema resource.
