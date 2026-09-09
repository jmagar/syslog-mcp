//! Single authoritative table of all MCP actions.
//!
//! Previously the action list was spread across three arrays in two files:
//! `CORTEX_ACTIONS` in `schemas.rs` (for the JSON schema `enum`),
//! `READ_ONLY_ACTIONS` and `ADMIN_ACTIONS` in `rmcp_server.rs` (for scope
//! gating). Adding a new action required editing all three in lockstep; drift
//! was a constant source of bugs.
//!
//! Now there is one metadata table: [`ACTION_SPECS`]. The schema, scope gates,
//! help text, and action metadata are computed from it.

use super::action_flags::{
    COMMON_LOG_FLAGS, Defaults, FlagSpec, HOOK_EVENTS_FLAGS, HOOK_INCIDENT_FLAGS,
    HOOK_INVESTIGATE_FLAGS, HOST_STATE_FLAGS, MCP_EVENTS_FLAGS, MCP_INCIDENT_FLAGS,
    MCP_INVESTIGATE_FLAGS, SKILL_EVENTS_FLAGS, SKILL_INCIDENT_FLAGS, SKILL_INVESTIGATE_FLAGS,
    TOPIC_CORRELATE_FLAGS,
};

/// The scope required to invoke a given action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scope {
    /// Read-only query. Requires `cortex:read`.
    Read,
    /// State-mutating or outbound-notification operation. Requires
    /// `cortex:admin`.
    Admin,
    /// Informational action — auth context required when policy is `Mounted`,
    /// but no scope gate. Currently only `help`.
    InfoOnly,
}

/// Expected relative cost for agent planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cost {
    /// Lightweight metadata or indexed query; safe as a first-pass action.
    Cheap,
    /// Bounded but may scan/aggregate more data; use after narrowing scope.
    Moderate,
    /// Broad scan, baseline comparison, or host-level diagnostic; use only
    /// when a cheap/moderate pass leaves a concrete question.
    Expensive,
    /// State-changing operation.
    Write,
}

impl Cost {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Cheap => "cheap",
            Self::Moderate => "moderate",
            Self::Expensive => "expensive",
            Self::Write => "write",
        }
    }
}

/// Executable handler bound to an action registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActionHandler {
    SearchLogs,
    FilterLogs,
    TailLogs,
    GetErrors,
    ListHosts,
    HomelabMap,
    HostState,
    FleetState,
    CorrelateEvents,
    CorrelateState,
    GetStats,
    GetStatus,
    ListApps,
    ListSessions,
    SearchSessions,
    SearchAbuse,
    AbuseIncidents,
    AbuseInvestigate,
    AiCorrelate,
    TopicCorrelate,
    UsageBlocks,
    ProjectContext,
    ListAiTools,
    ListAiProjects,
    ListSourceIps,
    Timeline,
    Patterns,
    Context,
    GetLog,
    IngestRate,
    SilentHosts,
    ClockSkew,
    Anomalies,
    Compare,
    ComposeStatus,
    ComposeDoctor,
    UnaddressedErrors,
    AckError,
    UnackError,
    NotificationsRecent,
    FileTails,
    NotificationsTest,
    LlmInvocations,
    SimilarIncidents,
    RecurringErrorComparison,
    IncidentContext,
    Graph,
    ArtifactEvidence,
    ArtifactEvidenceRecord,
    SkillEvents,
    SkillIncidents,
    SkillInvestigate,
    McpEvents,
    McpIncidents,
    McpInvestigate,
    HookEvents,
    HookIncidents,
    HookInvestigate,
    Help,
}

/// Machine-readable input contract for an MCP action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ActionInputContract {
    /// The action still relies on the shared flat schema and runtime parsing.
    LegacyFlat,
    /// The action advertises an exact allowed/required field set.
    Exact {
        /// Allowed fields other than the always-present `action` discriminator.
        allowed: &'static [&'static str],
        /// Required fields other than the always-required `action` discriminator.
        required: &'static [&'static str],
    },
}

/// Metadata for a single MCP action.
#[derive(Debug)]
pub(super) struct ActionSpec {
    /// Action name as passed in the `action` field of the MCP request.
    pub name: &'static str,
    /// Required scope (or `InfoOnly` for auth-but-no-scope actions).
    pub scope: Scope,
    /// Short human-readable description for schemas, prompts, and help text.
    pub description: &'static str,
    /// Relative cost for agent/tool planning.
    pub cost: Cost,
    /// Registry-owned executable handler for this action.
    pub handler: ActionHandler,
    /// Machine-readable public input contract used to generate JSON Schema.
    pub input_contract: ActionInputContract,
    /// CLI flags for this action (canonical names). Drives completion + help.
    pub flags: &'static [FlagSpec],
    /// Copy-paste example invocations.
    pub examples: &'static [&'static str],
    /// Canonical flag a bare positional argument binds to (`None` = the action
    /// takes no positional). E.g. `tail devhost` binds the positional to
    /// `--host`.
    pub positional: Option<&'static str>,
    /// Zero-flag defaults applied when the user omits `--limit` / `--since`.
    pub defaults: Defaults,
}

macro_rules! action_spec {
    // Exact short form: no CLI flag metadata, but a strict MCP input contract.
    ($name:literal, $scope:ident, $description:literal, $cost:ident, $handler:ident,
     exact: { allowed: $allowed:expr, required: $required:expr }) => {
        ActionSpec {
            name: $name,
            scope: Scope::$scope,
            description: $description,
            cost: Cost::$cost,
            handler: ActionHandler::$handler,
            input_contract: ActionInputContract::Exact {
                allowed: $allowed,
                required: $required,
            },
            flags: &[],
            examples: &[],
            positional: None,
            defaults: Defaults::new(),
        }
    };
    // Canonical form: flags + examples + positional + defaults.
    ($name:literal, $scope:ident, $description:literal, $cost:ident, $handler:ident,
     flags: $flags:expr, examples: $examples:expr,
     positional: $positional:expr, defaults: $defaults:expr) => {
        ActionSpec {
            name: $name,
            scope: Scope::$scope,
            description: $description,
            cost: Cost::$cost,
            handler: ActionHandler::$handler,
            input_contract: ActionInputContract::LegacyFlat,
            flags: $flags,
            examples: $examples,
            positional: $positional,
            defaults: $defaults,
        }
    };
    // Full form: flag + example metadata, no positional/defaults.
    ($name:literal, $scope:ident, $description:literal, $cost:ident, $handler:ident,
     flags: $flags:expr, examples: $examples:expr) => {
        action_spec!(
            $name, $scope, $description, $cost, $handler,
            flags: $flags, examples: $examples,
            positional: None, defaults: Defaults::new()
        )
    };
    // Short form: no flag/example metadata yet (defaults to empty).
    ($name:literal, $scope:ident, $description:literal, $cost:ident, $handler:ident) => {
        action_spec!(
            $name, $scope, $description, $cost, $handler,
            flags: &[], examples: &[],
            positional: None, defaults: Defaults::new()
        )
    };
}

/// The single authoritative table of all supported MCP actions.
///
/// # Maintenance
/// When adding a new action:
/// 1. Add an `ActionSpec` row here with the executable handler.
/// 2. Add the handler implementation branch in `src/mcp/tools.rs`.
///
/// # NOTE (PR 4, skill/abuse assessment)
/// `skill_assess` / `abuse_assess` LLM assessment is intentionally NOT
/// exposed as an MCP action or REST route. The guarded Gemini invocation
/// runs only through PR 1's `LlmRunner`
/// (`crate::app::llm_runner::LlmRunner::run`), spawns a subprocess on the
/// local host, and is only safe to trigger from a CLI process the operator
/// controls directly — see `src/cli/dispatch_sessions.rs`'s
/// `run_assess_skill`/`run_assess_abuse` `CliMode::Http(_) => bail!(...)`
/// guards. If skill or abuse assessment is ever exposed remotely, it MUST
/// pass `run_llm: false` to `run_skill_assessment_with_delta`/
/// `assess_top_abuse_incident_with_delta` — never call `LlmRunner::run`
/// from a network-triggered caller. See
/// `no_mcp_action_spec_invokes_gemini_assessment` in `actions_tests.rs`.
pub(super) const ACTION_SPECS: &[ActionSpec] = &[
    // ── Read-only queries ──────────────────────────────────────────────────
    action_spec!(
        "search",
        Read,
        "Full-text search over syslog messages",
        Cheap,
        SearchLogs,
        flags: COMMON_LOG_FLAGS,
        examples: &[
            "cortex search \"oom killer\"",
            "cortex search \"oom\" --host devhost --since 1h",
            "cortex search --grep \"smoke-test\" --limit 20",
        ],
        positional: Some("--query"),
        defaults: Defaults { limit: Some(50), since: None }
    ),
    action_spec!(
        "filter",
        Read,
        "Filter logs by indexed fields without a full-text query",
        Cheap,
        FilterLogs,
        flags: COMMON_LOG_FLAGS,
        examples: &["cortex filter --host nashost --severity err --since 6h"]
    ),
    action_spec!(
        "tail",
        Read,
        "Stream the most recent log entries",
        Cheap,
        TailLogs,
        flags: COMMON_LOG_FLAGS,
        examples: &["cortex tail devhost", "cortex tail --host devhost -n 100"],
        positional: Some("--host"),
        defaults: Defaults { limit: Some(50), since: None }
    ),
    action_spec!(
        "errors",
        Read,
        "List recent error-level log entries",
        Cheap,
        GetErrors,
        flags: COMMON_LOG_FLAGS,
        examples: &[
            "cortex analysis errors",
            "cortex analysis errors --since 6h --limit 50"
        ],
        positional: None,
        defaults: Defaults { limit: None, since: Some("1h") }
    ),
    action_spec!(
        "hosts",
        Read,
        "Enumerate all known source hostnames",
        Cheap,
        ListHosts,
        flags: &[],
        examples: &["cortex hosts"]
    ),
    action_spec!(
        "map",
        Read,
        "Map homelab inventory and answer graph-backed topology questions",
        Moderate,
        HomelabMap
    ),
    action_spec!(
        "host_state",
        Read,
        "Fetch latest bounded heartbeat state for a host",
        Moderate,
        HostState,
        flags: HOST_STATE_FLAGS,
        examples: &["cortex state host", "cortex state host devhost --since 30m"],
        positional: Some("--host"),
        defaults: Defaults::new()
    ),
    action_spec!(
        "fleet_state",
        Read,
        "Fleet-wide heartbeat snapshot with pressure flags",
        Expensive,
        FleetState
    ),
    action_spec!(
        "correlate",
        Read,
        "Correlate events around now, an explicit reference_time, or an AI-session query anchor",
        Moderate,
        CorrelateEvents,
        flags: &[],
        examples: &[
            "cortex correlate events 2026-06-16T04:00:00Z --window-minutes 15",
            "cortex correlate events --query \"qbittorrent keeps dying\""
        ]
    ),
    action_spec!(
        "correlate_state",
        Read,
        "Correlate logs with heartbeat summaries around now or a reference time",
        Expensive,
        CorrelateState
    ),
    action_spec!(
        "stats",
        Read,
        "Aggregate log statistics",
        Expensive,
        GetStats,
        flags: &[],
        examples: &["cortex stats"]
    ),
    action_spec!(
        "status",
        Read,
        "Server health and ingestion status",
        Cheap,
        GetStatus,
        flags: &[],
        examples: &["cortex status"]
    ),
    action_spec!(
        "apps",
        Read,
        "Enumerate all known application names",
        Cheap,
        ListApps,
        flags: &[],
        examples: &["cortex apps"]
    ),
    action_spec!(
        "sessions",
        Read,
        "List AI transcript sessions",
        Cheap,
        ListSessions
    ),
    action_spec!(
        "search_sessions",
        Read,
        "Full-text search over AI transcript sessions",
        Cheap,
        SearchSessions
    ),
    action_spec!(
        "abuse",
        Read,
        "Detect resource-abuse patterns in AI sessions",
        Moderate,
        SearchAbuse
    ),
    action_spec!(
        "abuse_incidents",
        Read,
        "List detected abuse incidents",
        Moderate,
        AbuseIncidents
    ),
    action_spec!(
        "abuse_investigate",
        Read,
        "Deep-dive investigation of an abuse incident",
        Expensive,
        AbuseInvestigate
    ),
    action_spec!(
        "ai_correlate",
        Read,
        "Correlate AI transcript events with syslog",
        Expensive,
        AiCorrelate
    ),
    action_spec!(
        "topic_correlate",
        Read,
        "Resolve a topic to graph entities and correlate all related logs into a unified timeline",
        Moderate,
        TopicCorrelate,
        flags: TOPIC_CORRELATE_FLAGS,
        examples: &[
            "cortex topic-correlate axon",
            "cortex topic-correlate axon --since 1h --limit 200",
            "cortex topic-correlate 'devhost dns adguard' --since 6h",
            "cortex topic-correlate axon --source-kinds docker-stream,agent-command",
        ],
        positional: Some("--topic"),
        defaults: Defaults { limit: Some(200), since: Some("1h") }
    ),
    action_spec!(
        "usage_blocks",
        Read,
        "Summarise AI session usage by project",
        Cheap,
        UsageBlocks
    ),
    action_spec!(
        "project_context",
        Read,
        "Full project context from AI transcripts",
        Expensive,
        ProjectContext,
        exact: {
            allowed: &["project", "tool", "limit"],
            required: &["project"]
        }
    ),
    action_spec!(
        "list_ai_tools",
        Read,
        "List AI tools observed in transcripts",
        Cheap,
        ListAiTools
    ),
    action_spec!(
        "list_ai_projects",
        Read,
        "List AI projects with transcript activity",
        Cheap,
        ListAiProjects,
        exact: {
            allowed: &["tool", "since", "until"],
            required: &[]
        }
    ),
    action_spec!(
        "source_ips",
        Read,
        "Enumerate unique source IP addresses",
        Cheap,
        ListSourceIps,
        flags: &[],
        examples: &["cortex hosts sources"]
    ),
    action_spec!(
        "timeline",
        Read,
        "Log volume over time (bucketed)",
        Cheap,
        Timeline,
        flags: &[],
        examples: &["cortex timeline --bucket hour --host devhost"]
    ),
    action_spec!(
        "patterns",
        Read,
        "Recurring message patterns",
        Expensive,
        Patterns,
        flags: &[],
        examples: &["cortex analysis patterns --limit 20"],
        positional: None,
        defaults: Defaults { limit: None, since: Some("24h") }
    ),
    action_spec!(
        "context",
        Read,
        "Contextual log entries around a pivot",
        Cheap,
        Context
    ),
    action_spec!("get", Read, "Fetch a single log entry by ID", Cheap, GetLog),
    action_spec!(
        "ingest_rate",
        Read,
        "Current log ingestion rate",
        Expensive,
        IngestRate
    ),
    action_spec!(
        "silent_hosts",
        Read,
        "Hosts that have gone silent",
        Moderate,
        SilentHosts
    ),
    action_spec!(
        "clock_skew",
        Read,
        "Detect clock skew between hosts",
        Expensive,
        ClockSkew
    ),
    action_spec!(
        "anomalies",
        Read,
        "Detect log-volume anomalies",
        Expensive,
        Anomalies
    ),
    action_spec!(
        "compare",
        Read,
        "Compare the latest hour with the prior hour, or two explicit time windows",
        Expensive,
        Compare
    ),
    action_spec!(
        "compose_status",
        Read,
        "Docker Compose stack status",
        Moderate,
        ComposeStatus
    ),
    action_spec!(
        "compose_doctor",
        Read,
        "Docker Compose coordination diagnostics",
        Expensive,
        ComposeDoctor
    ),
    action_spec!(
        "unaddressed_errors",
        Read,
        "List unacknowledged error signatures",
        Moderate,
        UnaddressedErrors
    ),
    action_spec!(
        "notifications_recent",
        Read,
        "Recent notification firings",
        Cheap,
        NotificationsRecent
    ),
    action_spec!(
        "similar_incidents",
        Read,
        "Find similar past incidents",
        Moderate,
        SimilarIncidents
    ),
    action_spec!(
        "recurring_error_comparison",
        Read,
        "Compare recurring error signatures with redacted, deterministic evidence bundles",
        Moderate,
        RecurringErrorComparison,
        exact: {
            allowed: &["signature_hash", "since", "until", "window_minutes", "limit", "include_acknowledged"],
            required: &[]
        }
    ),
    action_spec!(
        "incident_context",
        Read,
        "Full context for the last hour or an explicit incident window",
        Moderate,
        IncidentContext
    ),
    action_spec!(
        "graph",
        Read,
        "Resolve graph entities, neighborhoods, and evidence-backed explanations",
        Expensive,
        Graph
    ),
    action_spec!(
        "artifact_evidence",
        Read,
        "Query bounded artifact ecosystem evidence",
        Cheap,
        ArtifactEvidence,
        exact: {
            allowed: &[
                "eventKind",
                "artifactId",
                "revisionId",
                "contentDigest",
                "correlationId",
                "requestId",
                "targetId",
                "sourceSystem",
                "from",
                "to",
                "since",
                "until",
                "limit",
            ],
            required: &[]
        }
    ),
    action_spec!(
        "skill_events",
        Read,
        "List extracted AI skill-invocation events",
        Cheap,
        SkillEvents,
        flags: SKILL_EVENTS_FLAGS,
        examples: &[
            "cortex sessions skills --project cortex --limit 20",
            "cortex sessions skills --skill cortex-troubleshoot --since 1h",
        ]
    ),
    action_spec!(
        "skill_incidents",
        Read,
        "List detected skill-usage incidents (negative signals after a skill loaded)",
        Moderate,
        SkillIncidents,
        flags: SKILL_INCIDENT_FLAGS,
        examples: &[
            "cortex sessions skillincidents --skill lavra:lavra-plan --since 7d",
            "cortex sessions skillincidents --plugin lavra --min-score 35",
        ]
    ),
    action_spec!(
        "skill_investigate",
        Read,
        "Deep-dive investigation of a skill-usage incident, skill-first",
        Expensive,
        SkillInvestigate,
        flags: SKILL_INVESTIGATE_FLAGS,
        examples: &[
            "cortex sessions skillinvestigate lavra:lavra-plan",
            "cortex sessions skillinvestigate lavra:lavra-plan --since 7d",
            "cortex sessions skillinvestigate lavra:lavra-plan --tool codex --project /home/jmagar/workspace/cortex",
            "cortex sessions skillinvestigate --plugin lavra --all --limit 5",
        ],
        positional: Some("--skill"),
        defaults: Defaults::new()
    ),
    action_spec!(
        "mcp_events",
        Read,
        "List extracted AI MCP tool-call events",
        Cheap,
        McpEvents,
        flags: MCP_EVENTS_FLAGS,
        examples: &[
            "cortex sessions mcpevents --project cortex --limit 20",
            "cortex sessions mcpevents --mcp-server labby --since 1h",
        ]
    ),
    action_spec!(
        "mcp_incidents",
        Read,
        "List detected MCP-usage incidents (negative signals after a tool call)",
        Moderate,
        McpIncidents,
        flags: MCP_INCIDENT_FLAGS,
        examples: &[
            "cortex sessions mcpincidents --mcp-server labby --since 7d",
            "cortex sessions mcpincidents --mcp-tool search --min-score 35",
        ]
    ),
    action_spec!(
        "mcp_investigate",
        Read,
        "Deep-dive investigation of an MCP-usage incident, server/tool-first",
        Expensive,
        McpInvestigate,
        flags: MCP_INVESTIGATE_FLAGS,
        examples: &[
            "cortex sessions mcpinvestigate labby",
            "cortex sessions mcpinvestigate labby --since 7d",
            "cortex sessions mcpinvestigate labby --tool codex --project /home/jmagar/workspace/cortex",
            "cortex sessions mcpinvestigate --mcp-tool search --all --limit 5",
        ],
        positional: Some("--mcp-server"),
        defaults: Defaults::new()
    ),
    action_spec!(
        "hook_events",
        Read,
        "List extracted/collected AI hook events (runtime execution and config inventory)",
        Cheap,
        HookEvents,
        flags: HOOK_EVENTS_FLAGS,
        examples: &[
            "cortex sessions hookevents --hook format-on-save --since 1h",
            "cortex sessions hookevents --evidence-kind runtime_transcript",
        ]
    ),
    action_spec!(
        "hook_incidents",
        Read,
        "List detected hook-usage incidents (failures, timeouts, and other negative signals)",
        Moderate,
        HookIncidents,
        flags: HOOK_INCIDENT_FLAGS,
        examples: &[
            "cortex sessions hookincidents --hook format-on-save --since 7d",
            "cortex sessions hookincidents --hook-event PostToolUse --min-score 35",
        ]
    ),
    action_spec!(
        "hook_investigate",
        Read,
        "Deep-dive investigation of a hook-usage incident, hook-first",
        Expensive,
        HookInvestigate,
        flags: HOOK_INVESTIGATE_FLAGS,
        examples: &[
            "cortex sessions hookinvestigate format-on-save",
            "cortex sessions hookinvestigate format-on-save --since 7d",
            "cortex sessions hookinvestigate --hook-event PostToolUse --all --limit 5",
        ],
        positional: Some("--hook"),
        defaults: Defaults::new()
    ),
    // ── Admin / write actions ──────────────────────────────────────────────
    action_spec!(
        "artifact_evidence_record",
        Admin,
        "Append one bounded source-attributed artifact evidence event",
        Write,
        ArtifactEvidenceRecord,
        exact: {
            allowed: &[
                "schemaVersion",
                "eventId",
                "eventKind",
                "sourceSystem",
                "sourceIssuer",
                "observedAt",
                "artifactId",
                "revisionId",
                "contentDigest",
                "provenanceRef",
                "requestId",
                "correlationId",
                "causationId",
                "targetId",
                "targetKind",
                "loadoutId",
                "shareGrantId",
                "capabilityLeaseId",
                "deploymentPlanId",
                "runtimeId",
                "pluginId",
                "operationRef",
                "outcome",
                "metadata",
            ],
            required: &[
                "schemaVersion",
                "eventId",
                "eventKind",
                "sourceSystem",
                "sourceIssuer",
                "observedAt",
            ]
        }
    ),
    action_spec!(
        "ack_error",
        Admin,
        "Acknowledge an error signature",
        Write,
        AckError
    ),
    action_spec!(
        "unack_error",
        Admin,
        "Revoke an error signature acknowledgement",
        Write,
        UnackError
    ),
    action_spec!(
        "file_tails",
        Admin,
        "Manage Cortex-owned file-tail ingest sources",
        Write,
        FileTails
    ),
    action_spec!(
        "notifications_test",
        Admin,
        "Send a test notification via Apprise",
        Write,
        NotificationsTest
    ),
    action_spec!(
        "llm_invocations",
        Admin,
        "Recent LLM invocation audit records (concurrency/rate-limit/circuit-breaker denials included) — admin-scoped: exposes operational kill-switch/circuit-breaker state",
        Cheap,
        LlmInvocations
    ),
    // ── Informational (auth required, no scope gate) ───────────────────────
    action_spec!(
        "help",
        InfoOnly,
        "List available actions and their parameters",
        Cheap,
        Help
    ),
];

/// All action names in registration order. Used to populate the JSON schema
/// `enum` in `tool_definitions()` — derives from `ACTION_SPECS` so the schema
/// and scope table cannot drift.
pub fn action_names() -> Vec<&'static str> {
    ACTION_SPECS.iter().map(|s| s.name).collect()
}

#[cfg(test)]
pub(crate) fn expensive_action_names_for_test() -> Vec<&'static str> {
    ACTION_SPECS
        .iter()
        .filter(|spec| spec.cost == Cost::Expensive)
        .map(|spec| spec.name)
        .collect()
}

/// Find the executable handler for a registered action.
pub(super) fn handler_for(action: &str) -> Option<ActionHandler> {
    ACTION_SPECS
        .iter()
        .find(|s| s.name == action)
        .map(|s| s.handler)
}

/// CLI flag metadata for an action (canonical names), or `None` if unknown.
pub fn flags_for(action: &str) -> Option<&'static [FlagSpec]> {
    ACTION_SPECS
        .iter()
        .find(|s| s.name == action)
        .map(|s| s.flags)
}

/// Copy-paste example invocations for an action, or `None` if unknown.
pub fn examples_for(action: &str) -> Option<&'static [&'static str]> {
    ACTION_SPECS
        .iter()
        .find(|s| s.name == action)
        .map(|s| s.examples)
}

/// One-line description for an action, or `None` if unknown.
pub fn description_for(action: &str) -> Option<&'static str> {
    ACTION_SPECS
        .iter()
        .find(|s| s.name == action)
        .map(|s| s.description)
}

/// The canonical flag a bare positional binds to for `action` (`None` when the
/// action takes no positional or is unknown).
pub fn positional_for(action: &str) -> Option<&'static str> {
    ACTION_SPECS
        .iter()
        .find(|s| s.name == action)
        .and_then(|s| s.positional)
}

/// Zero-flag defaults for `action` (empty defaults when the action is unknown).
pub fn defaults_for(action: &str) -> Defaults {
    ACTION_SPECS
        .iter()
        .find(|s| s.name == action)
        .map(|s| s.defaults)
        .unwrap_or_default()
}

/// Map an action name to its required MCP scope string.
///
/// - `None` for `InfoOnly` actions (auth context required when Mounted, but no
///   scope gate).
/// - `Some("cortex:read")` / `Some("cortex:admin")` for normal actions.
/// - `Some("cortex:__deny__")` for unknown actions — a sentinel scope that is
///   never granted, so unknown actions are denied at the auth layer rather than
///   falling through to the dispatcher. Fail-closed.
pub(crate) fn required_scope_for(action: &str) -> Option<&'static str> {
    match ACTION_SPECS.iter().find(|s| s.name == action) {
        Some(spec) => match spec.scope {
            Scope::InfoOnly => None,
            Scope::Read => Some("cortex:read"),
            Scope::Admin => Some("cortex:admin"),
        },
        None => Some("cortex:__deny__"),
    }
}

#[cfg(test)]
#[path = "actions_tests.rs"]
mod tests;
