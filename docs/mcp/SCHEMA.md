---
title: "Tool Schema Documentation -- cortex"
created: "2026-07-30"
updated: "2026-08-04"
---

# Tool Schema Documentation -- cortex

## Source Of Truth

The live MCP JSON schema is built in Rust, not generated from this markdown file.

Current source of truth:

- `src/mcp/actions.rs::ACTION_SPECS` registers every action, its scope, cost, and description.
- `src/mcp/actions.rs::action_names()` derives the schema action enum from `ACTION_SPECS`.
- `src/mcp/schemas.rs::tool_definitions()` builds the MCP `tools/list` definition and the `cortex://schema/mcp-tool` resource from that action table.
- `src/mcp/tools.rs::tool_cortex()` dispatches the action handlers.
- `src/app/models.rs` defines request and response structs for typed action payloads.

`docs/mcp/SCHEMA.md` is a human-maintained reference for that generated runtime
schema with drift tests; it is not itself automatically generated. If it
disagrees with `src/mcp/actions.rs` or `src/mcp/schemas.rs`, the Rust source
wins.

## Current Actions

cortex exposes one MCP tool named `cortex`. The required `action` argument
selects one of the actions below. The mechanically generated current count is in `tests/TEST_COVERAGE.md`:

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
| `recurring_error_comparison` | `cortex:read` | moderate | Compare recurring error signatures with redacted deterministic evidence bundles |
| `incident_context` | `cortex:read` | moderate | Window bundle: log aggregates, errors, AI sessions |
| `graph` | `cortex:read` | moderate | Entity lookup and one-hop graph neighborhoods |
| `artifact_evidence` | `cortex:read` | cheap | Query bounded source-attributed artifact ecosystem evidence |
| `artifact_evidence_record` | `cortex:admin` | write | Append one bounded source-attributed artifact ecosystem evidence event |
| `skill_events` | `cortex:read` | cheap | List extracted AI skill-invocation events |
| `skill_incidents` | `cortex:read` | moderate | Grouped skill-usage incident candidates |
| `skill_investigate` | `cortex:read` | expensive | Evidence bundles for skill-usage incidents, skill-first |
| `mcp_events` | `cortex:read` | cheap | List extracted AI MCP tool-call events |
| `mcp_incidents` | `cortex:read` | moderate | Grouped MCP-usage incident candidates |
| `mcp_investigate` | `cortex:read` | expensive | Evidence bundles for MCP-usage incidents, server/tool-first |
| `hook_events` | `cortex:read` | cheap | List extracted/collected AI hook events (runtime + config inventory) |
| `hook_incidents` | `cortex:read` | moderate | Grouped hook-usage incident candidates |
| `hook_investigate` | `cortex:read` | expensive | Evidence bundles for hook-usage incidents, hook-first |
| `ack_error` | `cortex:admin` | write | Acknowledge an error signature |
| `unack_error` | `cortex:admin` | write | Revoke an error acknowledgement |
| `file_tails` | `cortex:admin` | write | Manage Cortex-owned file-tail ingest sources |
| `notifications_test` | `cortex:admin` | write | Send a test Apprise notification |
| `llm_invocations` | `cortex:admin` | cheap | Recent LLM invocation audit records (concurrency/rate-limit/circuit-breaker denials included) |
| `help` | none | cheap | Markdown action reference |

## Schema Pattern

The runtime tool definition is a hybrid action-dispatched JSON schema. Shared
properties remain at the root for backward-compatible discovery, while exact
per-action object branches are generated from `ACTION_SPECS` under `oneOf`:

```json
{
  "name": "cortex",
  "description": "Query cortex logs with action-based subcommands...",
  "x-cortex-action-metadata": [
    { "name": "search", "cost": "cheap", "description": "..." }
  ],
  "x-cortex-agent-guidance": {
    "cost_order": ["cheap", "moderate", "expensive", "write"],
    "first_pass": ["status", "errors", "tail", "search", "timeline", "context"],
    "escalate_only_when_scoped": [
      "stats",
      "patterns",
      "anomalies",
      "compare",
      "clock_skew",
      "ingest_rate",
      "compose_doctor"
    ]
  },
  "inputSchema": {
    "type": "object",
    "properties": {
      "action": {
        "type": "string",
        "enum": ["...derived from ACTION_SPECS..."]
      }
    },
    "required": ["action"],
    "oneOf": [
      {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "action": { "const": "project_context" },
          "project": { "type": "string" },
          "tool": { "type": "string" },
          "limit": { "type": "integer" }
        },
        "required": ["action", "project"]
      },
      {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "action": { "const": "list_ai_projects" },
          "tool": { "type": "string" },
          "since": { "type": "string" },
          "until": { "type": "string" }
        },
        "required": ["action"]
      },
      {
        "type": "object",
        "properties": {
          "action": { "enum": ["...unmigrated actions..."] }
        },
        "required": ["action"]
      }
    ]
  }
}
```

Root properties remain available because MCP clients receive one schema for the
`cortex` super-tool. `project_context` and `list_ai_projects` now have exact
machine-enforced field sets generated from the action registry. Unmigrated
actions use an explicit fallback branch that excludes those exact action names.
Runtime request structs still use `deny_unknown_fields` as the final validation
boundary.

## Common Arguments

| Argument | Used by |
| --- | --- |
| `query` | `search`, `search_sessions`, `correlate`, `similar_incidents` |
| `hostname` | `search`, `filter`, `tail`, `correlate`, `host_state`, `ai_correlate`, `apps`, `sessions`, `timeline`, `patterns`, `context`, `similar_incidents`, `incident_context` |
| `host_id` | Authoritative heartbeat identity for `host_state` |
| `host` | Optional host_id-or-hostname filter for `correlate_state` |
| `reference_time` | Required window center for `correlate_state`; for `correlate`, required unless `query` is given (then derived from an AI-session search) |
| `source_ip` | `search`, `filter`, `tail`, `correlate`, `ai_correlate` |
| `source_kind` | `filter` only; aliases Docker, file-tail, command-history, shell-history, transcript, and AI-tool rows |
| `project` | `filter`, `sessions`, `search_sessions`, `abuse`, `ai_correlate`, `usage_blocks`, `project_context`, `list_ai_tools` |
| `tool` | `filter`, `sessions`, `search_sessions`, `abuse`, `ai_correlate`, `usage_blocks`, `project_context`, `list_ai_projects` |
| `session_id` | `filter`, `ai_correlate` |
| `ai_query` | AI transcript anchor FTS5 query for `ai_correlate` |
| `log_query` | Related non-AI log FTS5 query for `ai_correlate` |
| `severity` | Exact severity filter for `search` and `filter` |
| `severity_min` | Severity floor for `tail`, `correlate`, `ai_correlate`, `timeline`, `patterns`, `similar_incidents`, `incident_context` |
| `app_name` | `search`, `filter`, `tail`, `ai_correlate`, `timeline`, `patterns`, `similar_incidents`, `incident_context` |
| `from`, `to` | Time range for search/session/AI/analytics actions; required for `incident_context` |
| `limit`, `offset` | Action-specific bounds; `offset` is for `apps` and `source_ips` pagination |
| `host_limit`, `per_host_limit`, `section_limit`, `include_sections` | Node and inventory-section bounds for `map`; `per_host_limit` is accepted for v1 compatibility and ignored by map v2 |
| `mode`, `host`, `domain`, `service`, `answer_limit`, `evidence_sample_limit`, `payload_budget` | Map snapshot mode and graph-backed map answer controls: `host_services`, `domain_routes`, and `service_dependencies` |
| `mode`, `entity_id`, `entity_type`, `key`, `alias_type`, `alias_key`, `depth`, `evidence_id`, `evidence_sample_limit`, `payload_budget` | Graph controls. Targeted modes require exactly one lookup strategy: `entity_id`, `entity_type` + `key`, or `alias_type` + `alias_key`. `evidence` requires `evidence_id`. Service identity is `logical_service` (`key=plex`) or `service_instance` (`key=nashost/plex`); legacy nested keys (`nashost:plex`, `nashost:plex:plex`, `plex/plex/plex`) are rejected with `rejected_legacy_shape`. |

## Correlation Arguments

See [CORRELATION.md](CORRELATION.md) for the full behavior matrix.

| Action | Key arguments |
| --- | --- |
| `correlate` | `reference_time` (or `query` alone, deriving the anchor from an AI-session search), `window_minutes`, `severity_min`, `hostname`, `source_ip`, `query`, `limit` |
| `ai_correlate` | `project`, `tool`, `session_id`, `ai_query`, `log_query`, `hostname`, `source_ip`, `app_name`, `from`, `to`, `window_minutes`, `severity_min`, `limit`, `events_per_anchor` |
| `abuse_investigate` | `project`, `tool`, `from`, `to`, `limit`, `window_minutes`, `correlation_window_minutes`, `terms` |
| `similar_incidents` | `query`, `hostname`, `app_name`, `severity_min`, `from`, `to`, `window_minutes`, `limit` |
| `recurring_error_comparison` | Optional `signature_hash`, `since`, `until`, `window_minutes`, `limit`, `include_acknowledged`; defaults to a bounded focal window ending now |
| `incident_context` | `from`, `to`, `hostname`, `app_name`, `query`, `severity_min`, `limit`; `query` applies FTS5 filtering to returned error logs |
| `graph` | `mode=entity|around|explain|evidence`; entity/around/explain require exactly one target lookup strategy (`entity_id`, `entity_type` + `key`, or `alias_type` + `alias_key`); `around` accepts `depth=1` only; `explain` accepts `depth=1..3`; `evidence` requires `evidence_id`; optional `limit`, `evidence_sample_limit`, `payload_budget` |
| `artifact_evidence` | Optional exact filters: `eventKind`, `artifactId`, `revisionId`, `contentDigest`, `correlationId`, `requestId`, `targetId`, `sourceSystem`, `since`/`until` (or `from`/`to` wire aliases), `limit`; all filters are validated by the shared service and responses are bounded |
| `artifact_evidence_record` | Required: `schemaVersion=dinglebear.cortex-artifact-evidence/v1`, `eventId`, `eventKind`, `sourceSystem`, `sourceIssuer`, `observedAt`, plus at least one artifact/revision/digest/provenance subject; optional bounded opaque references, `outcome`, and secret-safe bounded `metadata`; raw artifact/tool/request/result bodies are rejected |
| `file_tails` | `op` is required and enumerated as `list`, `add`, `remove`, `enable`, `disable`, or `status`; add requires only `path`, derives `id` and `tag` from the file name, and derives omitted `host` as stable synthetic owner `file-tail-<id>`; remove/enable/disable require `id`; optional `facility`, `severity`, `start_at_end` |

## Validation

Input validation is action-specific:

- `action` is required and must match `ACTION_SPECS`.
- Read actions require `cortex:read` when auth is mounted.
- Admin actions require `cortex:admin`.
- `help` has no scope gate, but auth policy still applies when the endpoint is protected.
- Numeric parameters are capped by each action.
- Timestamp parameters are parsed as RFC3339 and normalized where needed.
- FTS5 parameters use SQLite FTS5 syntax; quote hyphenated terms because bare `-` means NOT.
- Unknown parameters may be ignored by legacy extractor-style handlers, but typed payload handlers use `deny_unknown_fields` and reject unknown fields.

## Response Format

All MCP tool responses use one text content block containing pretty-printed JSON:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{\"count\": 3, \"logs\": [...]}"
    }
  ]
}
```

Action validation failures and execution failures return tool errors with
`isError: true`. Validation errors also include matching JSON text and
`structuredContent` containing `kind: "invalid_param"`, `action`, `message`,
and `retryable: false`. JSON-RPC errors are reserved for failures that prevent
normal tool execution.

## Drift Checks

The test suite enforces several schema/documentation invariants:

- `src/mcp/schemas_tests.rs` checks that the schema action enum equals `actions::action_names()`.
- `src/mcp/tools_tests.rs::schema_actions_are_dispatchable` dispatches every registered action.
- `src/mcp/tools_tests.rs::public_action_references_cover_schema_registry` checks public references for every registered action.

There is no checked-in generator that rewrites this markdown file today.

## See Also

- [TOOLS.md](TOOLS.md) -- action reference
- [CORRELATION.md](CORRELATION.md) -- correlation behavior and inclusion rules
- [PATTERNS.md](PATTERNS.md) -- code patterns for tool dispatch
- [RESOURCES.md](RESOURCES.md) -- runtime schema resource
