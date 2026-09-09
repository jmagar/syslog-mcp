use crate::app::topology_findings;
use crate::app::{PATTERN_SCAN_LIMIT_MAX, SEVERITY_LEVELS};
use serde_json::{Map, Value, json};

use super::actions;

/// Define the public MCP tool surface.
///
/// The action `enum` list is derived from [`actions::ACTION_SPECS`] so it
/// stays in sync with the scope-gating table automatically. Previously it was
/// a separate `CORTEX_ACTIONS` const that could drift.
pub(super) fn tool_definitions() -> Vec<Value> {
    let action_names: Vec<&str> = actions::action_names();
    let action_metadata: Vec<Value> = actions::ACTION_SPECS
        .iter()
        .map(|spec| {
            json!({
                "name": spec.name,
                "cost": spec.cost.as_str(),
                "description": spec.description,
            })
        })
        .collect();
    let action_desc = action_names
        .iter()
        .map(|n| format!("cortex {n}"))
        .collect::<Vec<_>>()
        .join(", ");
    let description = format!("Query cortex logs with action-based subcommands: {action_desc}.");
    // Derive the `source_kinds` enum from the canonical SourceKind list so the
    // wire schema can never drift from `crate::enrich::parser::SourceKind`.
    let source_kind_wire_names = crate::enrich::parser::SourceKind::all_wire_names();
    let mut tool = json!({
        "name": "cortex",
        "description": description,
        "x-cortex-action-metadata": action_metadata,
        "x-cortex-agent-guidance": {
            "cost_order": ["cheap", "moderate", "expensive", "write"],
            "first_pass": ["status", "errors", "tail", "search", "timeline", "context"],
            "escalate_only_when_scoped": ["stats", "patterns", "anomalies", "compare", "clock_skew", "ingest_rate", "compose_doctor"],
            "default_bounds": {
                "search_limit": 5,
                "summary_limit": 10,
                "context_before": 3,
                "context_after": 3,
                "timeline_bucket": "minute"
            }
        },
        "inputSchema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "action": {
                    "type": "string",
                    "enum": action_names,
                    "description": "Action to run. Supported actions are listed in the enum."
                },
                "query": {
                    "type": "string",
                    "description": "FTS5 query string. Required for action=similar_incidents (FTS5 match over system logs). Also used for action=search, search_sessions, and action=correlate: when reference_time is given, query filters the correlated logs; when reference_time is omitted, query is also matched against AI-transcript sessions (FTS5) to derive the anchor time from the top hit. Use topic for graph/topic correlation. Examples: 'kernel panic', 'OOM AND killer', '\"connection refused\"', 'error*'. Hyphen is the FTS5 NOT operator; search hyphenated terms as phrases, e.g. '\"smoke-test\"'. Use ai_query/log_query for action=ai_correlate."
                },
                "topic": {
                    "type": "string",
                    "description": "For action=topic_correlate, or action=correlate without reference_time: topic/entity string to resolve through the graph and correlate into a unified timeline. Service topics resolve to logical_service (`plex`) and its service_instance deployments (`nashost/plex`); legacy nested identities such as `nashost:plex` or `nashost:plex:plex` are rejected with rejected_legacy_shape."
                },
                "mode": {
                    "type": "string",
                    "enum": ["entity", "around", "explain", "evidence", "snapshot", "host_services", "domain_routes", "service_dependencies", "findings"],
                    "description": "For action=graph: entity resolves an entity by key or alias; around returns a bounded one-hop neighborhood; explain returns conservative evidence-backed chains; evidence resolves one evidence row by evidence_id. Defaults to around. For action=map: snapshot returns the inventory snapshot; host_services, domain_routes, service_dependencies, and findings add a graph_answer."
                },
                "evidence_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "For action=graph mode=evidence: graph_relationship_evidence id to inspect."
                },
                "entity_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "For action=graph mode=around or explain: exact graph entity id to expand."
                },
                "entity_type": {
                    "type": "string",
                    "enum": ["host", "container", "logical_service", "service_instance", "app", "source_ip", "ai_project", "ai_session", "error_signature", "compose_project", "config_artifact", "domain", "network", "reverse_proxy", "storage", "git_commit", "user", "device"],
                    "description": "For action=graph: entity type for exact canonical-key lookup. Service identity is logical_service (key like 'plex') or service_instance (key like 'nashost/plex'); legacy nested keys such as 'nashost:plex' or 'nashost:plex:plex' are rejected with rejected_legacy_shape."
                },
                "key": {
                    "type": "string",
                    "description": "For action=graph with entity_type: canonical key/display value to resolve. Values are normalized server-side."
                },
                "alias_type": {
                    "type": "string",
                    "description": "For action=graph: alias kind for alias lookup, e.g. hostname or heartbeat_host_id."
                },
                "alias_key": {
                    "type": "string",
                    "description": "For action=graph: alias value to resolve. Ambiguous aliases return candidates instead of guessing."
                },
                "host_id": {
                    "type": "string",
                    "description": "For action=host_state: exact heartbeat host_id. Takes precedence over host and is authoritative over host metadata."
                },
                "host": {
                    "type": "string",
                    "description": "For action=search, filter, tail, correlate, ai_correlate, apps, sessions, timeline, patterns, context, similar_incidents, or incident_context: exact hostname filter (use action=hosts to enumerate). For action=host_state: resolve a host by unique hostname; when host and host_id are omitted, the freshest host is selected. For action=correlate_state: optional host filter accepting a host_id or a unique hostname; when omitted, a bounded cross-host plan is used over all hosts with heartbeats in the window. For action=map mode=host_services or service_dependencies: target host. For action=file_tails op=add: optional source host assigned to tailed lines; the runtime hostname is used when omitted."
                },
                "domain": {
                    "type": "string",
                    "description": "For action=map mode=domain_routes: target domain, e.g. adguard.example.invalid."
                },
                "service": {
                    "type": "string",
                    "description": "For action=map mode=service_dependencies: target service_instance key (`host/name`, e.g. `nashost/plex`) or bare service name when host is also provided. Legacy `host:name` keys are rejected with rejected_legacy_shape."
                },
                "include_ok": {
                    "type": "boolean",
                    "description": "For action=fleet_state: when false, hosts whose status is 'ok' are excluded. Default true."
                },
                "sort": {
                    "type": "string",
                    "enum": ["pressure", "freshness", "hostname"],
                    "description": "For action=fleet_state: row ordering. 'pressure' (default) ranks late > partial > pressure > ok; 'freshness' orders by most-recent heartbeat; 'hostname' is alphabetical."
                },
                "project": {
                    "type": "string",
                    "description": "For action=filter, sessions, search_sessions, abuse, ai_correlate, usage_blocks, project_context, or list_ai_tools: exact project path, e.g. /home/jmagar/workspace/cortex."
                },
                "tool": {
                    "type": "string",
                    "enum": ["claude", "codex", "gemini"],
                    "description": "For action=filter, sessions, search_sessions, abuse, ai_correlate, usage_blocks, project_context, or list_ai_projects: AI tool filter."
                },
                "source": {
                    "type": "string",
                    "description": "For action=search, filter, tail, correlate, or ai_correlate: exact source identifier. Syslog uses IP:port; OTLP uses peer IP; Docker stream rows use docker://host/container/stream; Docker lifecycle rows use docker-event://host/container/action."
                },
                "source_kind": {
                    "type": "string",
                    "enum": ["docker-stream", "docker-event", "file-tail", "agent-command", "shell-history", "transcript", "claude", "codex", "gemini"],
                    "description": "For action=filter: structured source alias. syslog-udp, syslog-tcp, and otlp are rejected in v1 because transport is not indexed separately."
                },
                "source_kinds": {
                    "oneOf": [
                        {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": source_kind_wire_names.clone()
                            }
                        },
                        {
                            "type": "string",
                            "enum": source_kind_wire_names
                        }
                    ],
                    "description": "For action=topic_correlate, or action=correlate with topic: optional source-kind filters using exact kebab-case wire names such as syslog-udp, syslog-tcp, agent-command, docker-event, or docker-stream. String form is accepted for CLI bridges that cannot send arrays."
                },
                "severity": {
                    "type": "string",
                    "enum": SEVERITY_LEVELS,
                    "description": "For action=search or filter: syslog severity filter. For action=file_tails op=add: severity assigned to tailed lines."
                },
                "severity_min": {
                    "type": "string",
                    "enum": SEVERITY_LEVELS,
                    "description": "For action=tail, correlate, correlate_state, ai_correlate, timeline, patterns, similar_incidents, or incident_context: minimum severity to include. Defaults to 'warning' for incident_context and 'info' for correlate_state and ai_correlate."
                },
                "app": {
                    "type": "string",
                    "description": "For action=search, filter, tail, ai_correlate, timeline, patterns, similar_incidents, or incident_context: application name filter, e.g. sshd, dockerd, kernel."
                },
                "session_id": {
                    "type": "string",
                    "description": "For action=filter or ai_correlate: exact AI session id filter."
                },
                "ai_query": {
                    "type": "string",
                    "description": "For action=ai_correlate: FTS5 query over AI transcript anchor rows."
                },
                "log_query": {
                    "type": "string",
                    "description": "For action=ai_correlate: FTS5 query over related non-AI logs inside each anchor window."
                },
                "facility": {
                    "type": "string",
                    "description": "For action=search or filter: syslog facility filter, e.g. kern, auth, daemon, clockd. For action=file_tails op=add: facility assigned to tailed lines."
                },
                "exclude_facility": {
                    "type": "string",
                    "description": "For action=search or filter: exclude one syslog facility while retaining rows with unknown facility."
                },
                "process_id": {
                    "type": "string",
                    "description": "For action=search or filter: exact process_id filter."
                },
                "received_since": {
                    "type": "string",
                    "description": "For action=search or filter: filter rows with received_at >= this timestamp."
                },
                "received_until": {
                    "type": "string",
                    "description": "For action=search or filter: filter rows with received_at <= this timestamp."
                },
                "container": {
                    "type": "string",
                    "description": "For action=filter: Docker container/app name refiner."
                },
                "docker_host": {
                    "type": "string",
                    "description": "For action=filter with source_kind=docker-stream or docker-event: Docker host refiner."
                },
                "stream": {
                    "type": "string",
                    "enum": ["stdout", "stderr"],
                    "description": "For action=filter with source_kind=docker-stream: Docker log stream refiner."
                },
                "event_action": {
                    "type": "string",
                    "description": "For action=filter: Docker lifecycle/enrichment event action filter."
                },
                "until": {
                    "type": "string",
                    "description": "For action=search, filter, sessions, search_sessions, abuse, abuse_incidents, abuse_investigate, ai_correlate, usage_blocks, list_ai_tools, list_ai_projects, errors, timeline, patterns, apps, similar_incidents, recurring_error_comparison, or incident_context: end of time range as ISO 8601/RFC3339. For incident_context and recurring_error_comparison, defaults to now. For action=timeline: a bucket-sized default lookback bounds the query when since/until are omitted."
                },
                "status": {
                    "type": "string",
                    "description": "For action=llm_invocations: filter by invocation outcome status. One of: running, success, error, denied, rate_limited, circuit_open, disabled, dry_run, timeout, interrupted. 'interrupted' is a terminal status assigned by orphaned-row reconciliation at startup: init_pool rewrites any row still status='running' from a prior process into status='interrupted'."
                },
                "limit": {
                    "type": "integer",
                    "description": "For action=search: max results, default 50, max 1000. For action=filter: max results, default 100, max 1000. For action=errors: max summary rows, max 100. For action=sessions: max results, default 100, max 1000. For action=search_sessions: max grouped results, default 20, max 100 and returns total_candidates, candidate_rows, candidate_cap, candidate_window_truncated, and truncated. For action=abuse: max matches, default 20, max 100, each with same-session context. For action=abuse_incidents: max incidents, default 20, max 100; response includes total_incidents, candidate_rows, truncated. For action=abuse_investigate: max incidents to expand into evidence bundles, default 3, max 10. For action=ai_correlate: max AI anchors, default 10, max 50. For action=usage_blocks: max 5-hour usage buckets, default 1000, max 1000. For action=project_context: recent representative entries, default 5, max 20. For action=correlate: max total events, default 500, max 999. For action=topic_correlate: max timeline entries, default 200, max 1000. For action=correlate_state: max log rows per host, default 100, max 500. For action=host_state: max heartbeat samples, default 1, max 100. For action=patterns: alias for top_n, default 20, max 200. For action=clock_skew: max host rows, max 100. For action=apps or source_ips: page size, default 500, max 5000. For action=similar_incidents or recurring_error_comparison: default 10, max 50. For action=incident_context: max error log rows, default 50, max 200. For action=graph: alias candidate or relationship cap. For action=llm_invocations: max audit rows, default 50, max 500."
                },
                "answer_limit": {
                    "type": "integer",
                    "description": "For action=map graph-backed modes: graph relationship cap, default 100, max 500."
                },
                "depth": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 6,
                    "description": "For action=graph mode=around or explain: traversal depth. Around supports depth=1 only; explain clamps to 1..3. For action=topic_correlate, or action=correlate with topic: graph expansion depth, default 2, max 6."
                },
                "evidence_sample_limit": {
                    "type": "integer",
                    "description": "For action=graph mode=around or explain and action=map graph-backed modes: safe evidence samples per relationship, default 3 for around/map and 2 for explain, max 5."
                },
                "payload_budget": {
                    "type": "integer",
                    "description": "For action=graph and action=map graph-backed modes, including mode=findings: approximate graph payload budget in bytes, default 32768, clamped 4096..65536."
                },
                "finding_limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "description": "For action=map mode=findings: maximum findings returned, default 25, max 100."
                },
                "evidence_per_finding": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                    "description": "For action=map mode=findings: bounded safe evidence samples per finding, default 2, max 5."
                },
                "finding_types": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": topology_findings::TYPES
                    },
                    "description": "For action=map mode=findings: optional supported finding types to return."
                },
                "offset": {
                    "type": "integer",
                    "description": "For action=apps or source_ips: number of items to skip for pagination. Default 0. Use with limit to page through all results: if total > offset + limit, increment offset by limit to fetch the next page."
                },
                "n": {
                    "type": "integer",
                    "description": "For action=tail: number of recent entries, default 50, max 500."
                },
                "reference_time": {
                    "type": "string",
                    "description": "For action=correlate_state or correlate: center timestamp for the correlation window as ISO 8601/RFC3339. Defaults to now; action=correlate can instead pass query to derive an anchor from the top matching AI-transcript session."
                },
                "window_minutes": {
                    "type": "integer",
                    "description": "For action=correlate: minutes before and after reference_time to search, default 5, max 60. For action=correlate_state: minutes before and after reference_time, default 10, max 120. For action=ai_correlate: minutes before and after each AI anchor, default 5, max 120. For action=abuse_incidents or abuse_investigate: incident grouping window, default 10, max 120. For action=similar_incidents: cluster grouping window in minutes, default 30, clamp 5..=120. For action=recurring_error_comparison: focal window width when since is absent, default 60, clamp 5..=1440."
                },
                "correlation_window_minutes": {
                    "type": "integer",
                    "description": "For action=abuse_investigate: minutes before first and after last anchor for nearby non-AI log correlation, default 5, max 120."
                },
                "group_by": {
                    "type": "string",
                    "enum": ["app_name", "hostname", "host", "severity", "sev", "app"],
                    "description": "For action=errors: app_name. For action=timeline: hostname, severity, or app_name."
                },
                "bucket": {
                    "type": "string",
                    "enum": ["minute", "min", "m", "hour", "h", "day", "d", "week", "w", "month"],
                    "description": "For action=timeline: time bucket size (minute, hour, day, week, month)."
                },
                "scan_limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": PATTERN_SCAN_LIMIT_MAX,
                    "description": "For action=patterns: max messages to scan, default 10000, max 10000."
                },
                "top_n": {
                    "type": "integer",
                    "description": "For action=patterns: max templates to return, default 20, max 200. `limit` is accepted as an alias for agent/CLI ergonomics."
                },
                "log_id": {
                    "type": "integer",
                    "description": "For action=context: existing log id to anchor surrounding logs."
                },
                "timestamp": {
                    "type": "string",
                    "description": "For action=context: anchor timestamp when log_id is not provided."
                },
                "before": {
                    "type": "integer",
                    "description": "For action=context: entries before the reference, default 10, max 500. For action=abuse: same-session entries before each hit, default 2, max 20."
                },
                "after": {
                    "type": "integer",
                    "description": "For action=context: entries after the reference, default 10, max 500. For action=abuse: same-session entries after each hit, default 2, max 20."
                },
                "terms": {
                    "oneOf": [
                        {"type": "array", "items": {"type": "string"}},
                        {"type": "string"}
                    ],
                    "description": "For action=abuse: optional custom abuse terms. Defaults to the built-in abuse list. String form is accepted for CLI bridges that cannot send arrays."
                },
                "events_per_anchor": {
                    "type": "integer",
                    "description": "For action=ai_correlate: max non-AI related log events per AI anchor, default 25, max 200."
                },
                "id": {
                    "oneOf": [
                        {"type": "integer"},
                        {"type": "string"}
                    ],
                    "description": "For action=get: integer log id to fetch. For action=file_tails: string source id for op=add|remove|enable|disable."
                },
                "op": {
                    "type": "string",
                    "enum": ["list", "add", "remove", "enable", "disable", "status"],
                    "description": "For action=file_tails: required operation, one of list, add, remove, enable, disable, or status."
                },
                "path": {
                    "type": "string",
                    "description": "For action=file_tails op=add: local log file path to tail."
                },
                "tag": {
                    "type": "string",
                    "description": "For action=file_tails op=add: app/tag stored as app_name for tailed lines."
                },
                "start_at_end": {
                    "type": "boolean",
                    "description": "For action=file_tails op=add: true starts at EOF, false backfills existing file content."
                },
                "by_host": {
                    "type": "boolean",
                    "description": "For action=ingest_rate: include per-host buckets."
                },
                "silent_minutes": {
                    "type": "integer",
                    "description": "For action=silent_hosts: staleness threshold, default 30, max 10080."
                },
                "since": {
                    "type": "string",
                    "description": "For action=search, filter, sessions, search_sessions, abuse, abuse_incidents, abuse_investigate, ai_correlate, usage_blocks, list_ai_tools, list_ai_projects, errors, timeline, patterns, apps, similar_incidents, recurring_error_comparison, or incident_context: start of time range as ISO 8601/RFC3339. Defaults to one hour ago for errors and incident_context, 24 hours ago for patterns, and to until minus window_minutes for recurring_error_comparison when absent. Timeline applies a bucket-sized default lookback. For action=clock_skew or host_state: lower sample bound. For action=notifications_recent or llm_invocations: lower time bound."
                },
                "recent_minutes": {
                    "type": "integer",
                    "description": "For action=anomalies: recent window, default 15, max 1440."
                },
                "baseline_minutes": {
                    "type": "integer",
                    "description": "For action=anomalies: baseline window before recent window, default 360, max 10080."
                },
                "a_from": {
                    "type": "string",
                    "description": "For action=compare: first range start as ISO 8601/RFC3339. Omit all four range fields to compare the prior hour with the latest hour."
                },
                "a_to": {
                    "type": "string",
                    "description": "For action=compare: first range end as ISO 8601/RFC3339."
                },
                "b_from": {
                    "type": "string",
                    "description": "For action=compare: second range start as ISO 8601/RFC3339."
                },
                "b_to": {
                    "type": "string",
                    "description": "For action=compare: second range end as ISO 8601/RFC3339."
                },
                "include_acknowledged": {
                    "type": "boolean",
                    "description": "For action=unaddressed_errors or recurring_error_comparison: include already-acknowledged signatures. Default false."
                },
                "signature_hash": {
                    "type": "string",
                    "description": "For action=ack_error or unack_error: the SHA-256 signature hash to acknowledge or un-acknowledge. For action=recurring_error_comparison: restrict to one canonical signature hash."
                },
                "notes": {
                    "type": "string",
                    "description": "For action=ack_error: optional human-readable acknowledgement notes (max 4096 chars)."
                },
                "reason": {
                    "type": "string",
                    "description": "For action=unack_error: optional reason for removing acknowledgement (max 4096 chars)."
                }
            },
            "required": ["action"],
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "action": { "const": "graph" }
                        },
                        "required": ["action"]
                    },
                    "then": {
                        "properties": {
                            "mode": {
                                "enum": ["entity", "around", "explain", "evidence"]
                            },
                            "depth": {
                                "minimum": 1,
                                "maximum": 3
                            }
                        },
                        "oneOf": [
                            {
                                "properties": {
                                    "mode": { "enum": ["entity", "around", "explain"] }
                                },
                                "oneOf": [
                                    {
                                        "required": ["entity_id"],
                                        "not": {
                                            "anyOf": [
                                                { "required": ["entity_type"] },
                                                { "required": ["key"] },
                                                { "required": ["alias_type"] },
                                                { "required": ["alias_key"] }
                                            ]
                                        }
                                    },
                                    {
                                        "required": ["entity_type", "key"],
                                        "not": {
                                            "anyOf": [
                                                { "required": ["entity_id"] },
                                                { "required": ["alias_type"] },
                                                { "required": ["alias_key"] }
                                            ]
                                        }
                                    },
                                    {
                                        "required": ["alias_type", "alias_key"],
                                        "not": {
                                            "anyOf": [
                                                { "required": ["entity_id"] },
                                                { "required": ["entity_type"] },
                                                { "required": ["key"] }
                                            ]
                                        }
                                    }
                                ]
                            },
                            {
                                "properties": {
                                    "mode": { "const": "evidence" }
                                },
                                "required": ["mode", "evidence_id"],
                                "not": {
                                    "anyOf": [
                                        { "required": ["entity_id"] },
                                        { "required": ["entity_type"] },
                                        { "required": ["key"] },
                                        { "required": ["alias_type"] },
                                        { "required": ["alias_key"] }
                                    ]
                                }
                            }
                        ],
                        "allOf": [
                            {
                                "if": {
                                    "properties": {
                                        "mode": { "const": "around" }
                                    },
                                    "required": ["mode"]
                                },
                                "then": {
                                    "properties": {
                                        "depth": {
                                            "minimum": 1,
                                            "maximum": 1
                                        }
                                    }
                                }
                            },
                            {
                                "if": {
                                    "not": { "required": ["mode"] }
                                },
                                "then": {
                                    "properties": {
                                        "depth": {
                                            "minimum": 1,
                                            "maximum": 1
                                        }
                                    }
                                }
                            }
                        ]
                    }
                },
                {
                    "if": {
                        "properties": {
                            "action": { "const": "map" }
                        },
                        "required": ["action"]
                    },
                    "then": {
                        "properties": {
                            "mode": {
                                "enum": ["snapshot", "host_services", "domain_routes", "service_dependencies", "findings"]
                            }
                        }
                    }
                },
                {
                    "if": {
                        "properties": {
                            "action": { "const": "get" }
                        },
                        "required": ["action"]
                    },
                    "then": {
                        "properties": {
                            "id": { "type": "integer" }
                        },
                        "required": ["id"]
                    }
                },
                {
                    "if": {
                        "properties": {
                            "action": { "const": "file_tails" }
                        },
                        "required": ["action"]
                    },
                    "then": {
                        "properties": {
                            "id": { "type": "string" },
                            "op": { "enum": ["list", "add", "remove", "enable", "disable", "status"] }
                        },
                        "required": ["op"],
                        "allOf": [
                            {
                                "if": {
                                    "properties": {
                                        "op": { "const": "add" }
                                    },
                                    "required": ["op"]
                                },
                                "then": {
                                    "required": ["path"]
                                }
                            },
                            {
                                "if": {
                                    "properties": {
                                        "op": { "enum": ["remove", "enable", "disable"] }
                                    },
                                    "required": ["op"]
                                },
                                "then": {
                                    "required": ["id"]
                                }
                            }
                        ]
                    }
                },
                {
                    "if": {
                        "properties": {
                            "action": { "const": "topic_correlate" }
                        },
                        "required": ["action"]
                    },
                    "then": {
                        "required": ["topic"]
                    }
                }
            ]
        }
    });
    attach_action_contracts(&mut tool);
    vec![tool]
}

fn attach_action_contracts(tool: &mut Value) {
    let input_schema = tool
        .get_mut("inputSchema")
        .and_then(Value::as_object_mut)
        .expect("cortex tool inputSchema must be an object");
    let properties = input_schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("cortex tool properties must be an object")
        .clone();

    let mut branches = Vec::new();
    let mut legacy_actions = Vec::new();
    for spec in actions::ACTION_SPECS {
        match spec.input_contract {
            actions::ActionInputContract::LegacyFlat => legacy_actions.push(spec.name),
            actions::ActionInputContract::Exact { allowed, required } => {
                branches.push(exact_action_schema(
                    spec.name,
                    allowed,
                    required,
                    &properties,
                ));
            }
        }
    }
    if !legacy_actions.is_empty() {
        branches.push(json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": legacy_actions
                }
            },
            "required": ["action"]
        }));
    }

    input_schema.insert("oneOf".to_string(), Value::Array(branches));
}

fn exact_action_schema(
    action: &str,
    allowed: &[&str],
    required: &[&str],
    root_properties: &Map<String, Value>,
) -> Value {
    let mut properties = Map::new();
    properties.insert("action".to_string(), json!({ "const": action }));
    for field in allowed {
        let property = root_properties
            .get(*field)
            .cloned()
            .or_else(|| super::artifact_evidence_schema::exact_property_schema(field))
            .unwrap_or_else(|| panic!("exact action contract references unknown field: {}", field));
        properties.insert((*field).to_string(), property);
    }

    let mut required_fields = vec![Value::String("action".to_string())];
    required_fields.extend(
        required
            .iter()
            .map(|field| Value::String((*field).to_string())),
    );

    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required_fields
    })
}

#[cfg(test)]
#[path = "schemas_tests.rs"]
mod tests;
