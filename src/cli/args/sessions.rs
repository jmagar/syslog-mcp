#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionsCommand {
    List(super::SessionsArgs),
    Search(SessionsSearchArgs),
    Abuse(SessionsAbuseArgs),
    Correlate(SessionsCorrelateArgs),
    Blocks(SessionsBlocksArgs),
    Context(SessionsContextArgs),
    Tools(SessionsListArgs),
    Projects(SessionsListArgs),
    Index(SessionsIndexArgs),
    Add(SessionsAddArgs),
    Watch(SessionsWatchArgs),
    Checkpoints(SessionsCheckpointsArgs),
    Errors(SessionsErrorsArgs),
    PruneCheckpoints(SessionsPruneCheckpointsArgs),
    Doctor(SessionsDoctorArgs),
    WatchStatus(super::OutputArgs),
    SmokeWatch(super::OutputArgs),
    SimilarIncidents(SessionsSimilarArgs),
    IncidentContext(SessionsIncidentContextArgs),
    Incidents(SessionsIncidentsArgs),
    Investigate(SessionsInvestigateArgs),
    Assess(SessionsAssessArgs),
    LlmInvocations(SessionsLlmInvocationsArgs),
    Skills(SessionsSkillsListArgs),
    SkillsBackfill(SessionsSkillsBackfillArgs),
    SkillIncidents(SessionsSkillIncidentsArgs),
    SkillInvestigate(SessionsSkillInvestigateArgs),
    HookEvents(SessionsHookEventsListArgs),
    HookIncidents(SessionsHookIncidentsArgs),
    HookInvestigate(SessionsHookInvestigateArgs),
    HooksBackfill(SessionsHooksBackfillArgs),
    /// Low-level alias for `cortex assess skill` — forwards to the exact
    /// same dispatch function (`dispatch::run_assess_skill`) so the two
    /// entry points never drift on behavior, only on discoverability.
    SkillAssess(super::assess::AssessSkillArgs),
    McpEvents(SessionsMcpEventsListArgs),
    McpEventsBackfill(SessionsMcpEventsBackfillArgs),
    McpIncidents(SessionsMcpIncidentsArgs),
    McpInvestigate(SessionsMcpInvestigateArgs),
    /// Low-level alias for `cortex assess mcp` — forwards to the exact same
    /// dispatch function (`dispatch::run_assess_mcp`) so the two entry
    /// points never drift on behavior, only on discoverability.
    McpAssess(super::assess::AssessMcpArgs),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsMcpIncidentsArgs {
    pub json: bool,
    pub mcp_server: Option<String>,
    pub mcp_tool: Option<String>,
    pub tool_name: Option<String>,
    pub tool: Option<String>,
    pub project: Option<String>,
    pub session_id: Option<String>,
    pub hostname: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub signals: Vec<String>,
    /// Validated (not just stored) at flag-scan time via `parse_f64_flag`
    /// — an invalid `--min-score` value is a hard CLI error rather than a
    /// silently-dropped filter, unlike the pre-existing
    /// `SessionsSkillIncidentsArgs.min_score`. Kept as `String` (not
    /// `f64`) purely so this struct can keep deriving `Eq`.
    pub min_score: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsMcpInvestigateArgs {
    /// Bare positional argument — an mcp_server, mcp_tool, or raw tool
    /// name (e.g. `labby`, `mcp__labby__search`). `None` when the caller
    /// used `--incident-id`, `--mcp-server`, or `--mcp-tool` instead.
    pub target: Option<String>,
    pub mcp_server: Option<String>,
    pub mcp_tool: Option<String>,
    pub tool_name: Option<String>,
    pub incident_id: Option<String>,
    pub tool: Option<String>,
    pub project: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub correlation_window_minutes: Option<u32>,
    pub all: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsMcpEventsListArgs {
    pub json: bool,
    pub tool_name: Option<String>,
    pub mcp_server: Option<String>,
    pub mcp_tool: Option<String>,
    pub tool: Option<String>,
    pub project: Option<String>,
    pub session_id: Option<String>,
    pub host: Option<String>,
    pub is_error: Option<bool>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsMcpEventsBackfillArgs {
    pub json: bool,
    pub since: Option<String>,
    pub limit: Option<u64>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsSkillIncidentsArgs {
    pub json: bool,
    pub skill: Option<String>,
    pub plugin: Option<String>,
    pub tool: Option<String>,
    pub project: Option<String>,
    pub session_id: Option<String>,
    pub hostname: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub signals: Vec<String>,
    /// Kept as `String` and parsed to `f64` at `into_request()` time,
    /// matching this repo's pattern of parsing typed values at the
    /// request-conversion boundary rather than during flag scanning (no
    /// shared f64 parser helper exists in `FlagCursor`/`parse_common.rs`).
    pub min_score: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsSkillInvestigateArgs {
    /// Bare positional argument — the skill name, e.g. `lavra:lavra-plan`.
    /// `None` when the caller used `--incident-id` or `--plugin` instead.
    pub skill: Option<String>,
    pub plugin: Option<String>,
    pub incident_id: Option<String>,
    pub tool: Option<String>,
    pub project: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub correlation_window_minutes: Option<u32>,
    /// Investigate multiple matching incidents instead of just the top one.
    pub all: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsSkillsListArgs {
    pub json: bool,
    pub skill: Option<String>,
    pub plugin: Option<String>,
    pub tool: Option<String>,
    pub project: Option<String>,
    pub session_id: Option<String>,
    pub host: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsSkillsBackfillArgs {
    pub json: bool,
    pub since: Option<String>,
    pub limit: Option<u64>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsHookEventsListArgs {
    pub json: bool,
    pub hook_event: Option<String>,
    pub hook_name: Option<String>,
    pub hook_source: Option<String>,
    pub status: Option<String>,
    pub evidence_kind: Option<String>,
    pub tool: Option<String>,
    pub project: Option<String>,
    pub session_id: Option<String>,
    pub host: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsHookIncidentsArgs {
    pub json: bool,
    pub hook_event: Option<String>,
    pub hook_name: Option<String>,
    pub hook_source: Option<String>,
    pub tool: Option<String>,
    pub project: Option<String>,
    pub session_id: Option<String>,
    pub hostname: Option<String>,
    pub evidence_kind: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub signals: Vec<String>,
    pub min_score: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsHookInvestigateArgs {
    pub hook_name: Option<String>,
    pub hook_event: Option<String>,
    pub hook_source: Option<String>,
    pub incident_id: Option<String>,
    pub tool: Option<String>,
    pub project: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub correlation_window_minutes: Option<u32>,
    pub all: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsHooksBackfillArgs {
    pub json: bool,
    pub since: Option<String>,
    pub limit: Option<u64>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsDoctorArgs {
    pub json: bool,
    pub strict_permissions: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsSearchArgs {
    pub query: String,
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsAbuseArgs {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub before: Option<u32>,
    pub after: Option<u32>,
    pub terms: Vec<String>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsCorrelateArgs {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub session_id: Option<String>,
    pub ai_query: Option<String>,
    pub log_query: Option<String>,
    pub host: Option<String>,
    pub source: Option<String>,
    pub app: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub window_minutes: Option<u32>,
    pub severity_min: Option<String>,
    pub limit: Option<u32>,
    pub events_per_anchor: Option<u32>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsBlocksArgs {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
    pub detail: SessionsOutputDetail,
    pub json: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum SessionsOutputDetail {
    #[default]
    Compact,
    Full,
}

impl SessionsOutputDetail {
    pub(crate) fn parse(value: &str, flag: &str) -> anyhow::Result<Self> {
        match value {
            "compact" => Ok(Self::Compact),
            "full" => Ok(Self::Full),
            _ => anyhow::bail!("{flag} must be compact or full"),
        }
    }

    pub(crate) fn is_compact(self) -> bool {
        matches!(self, Self::Compact)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsContextArgs {
    pub project: String,
    pub tool: Option<String>,
    pub limit: Option<u32>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsListArgs {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsIndexArgs {
    pub path: Option<String>,
    pub force: bool,
    pub since: Option<String>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsAddArgs {
    pub file: String,
    pub force: bool,
    pub json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionsWatchArgs {
    pub path: Option<String>,
    pub debounce_ms: u64,
    pub settle_ms: u64,
    pub max_retries: u8,
    pub no_initial_scan: bool,
    pub json: bool,
}

impl Default for SessionsWatchArgs {
    fn default() -> Self {
        Self {
            path: None,
            debounce_ms: 750,
            settle_ms: 500,
            max_retries: 5,
            no_initial_scan: false,
            json: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsCheckpointsArgs {
    pub errors_only: bool,
    pub missing_only: bool,
    pub limit: Option<u32>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsErrorsArgs {
    pub limit: Option<u32>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsPruneCheckpointsArgs {
    pub missing_only: bool,
    pub dry_run: bool,
    pub limit: Option<u32>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsSimilarArgs {
    pub query: String,
    pub host: Option<String>,
    pub app: Option<String>,
    pub severity_min: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub window_minutes: Option<u32>,
    pub limit: Option<u32>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsIncidentContextArgs {
    pub since: Option<String>,
    pub until: Option<String>,
    pub host: Option<String>,
    pub app: Option<String>,
    pub query: Option<String>,
    pub severity_min: Option<String>,
    pub limit: Option<u32>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsIncidentsArgs {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub terms: Vec<String>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsInvestigateArgs {
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<u32>,
    pub window_minutes: Option<u32>,
    pub correlation_window_minutes: Option<u32>,
    pub terms: Vec<String>,
    pub detail: SessionsOutputDetail,
    pub include_transcript: bool,
    pub max_bytes: Option<usize>,
    pub json: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsAssessArgs {
    pub incident_id: String,
    pub model: Option<String>,
    pub json: bool,
    pub project: Option<String>,
    pub tool: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub window_minutes: Option<u32>,
    pub correlation_window_minutes: Option<u32>,
    pub terms: Vec<String>,
    pub limit: Option<u32>,
    /// When true, preview the prompt/evidence bundle via
    /// `LlmRunner::dry_run` instead of invoking the selected LLM — see GH issue #94.
    pub dry_run: bool,
}

/// `cortex sessions llminvocations` — list recent LLM invocation audit
/// records (concurrency/rate-limit/circuit-breaker denials included).
/// Admin-scoped: in `CliMode::Http`, requires `CORTEX_API_ADMIN_TOKEN` to be
/// set client-side (see `get_json_with_admin` in `http_client.rs`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionsLlmInvocationsArgs {
    pub since: Option<String>,
    pub action: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub json: bool,
}
