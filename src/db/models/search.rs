use serde::Deserialize;

/// Parameters for searching logs.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SearchParams {
    pub query: Option<String>,
    pub host: Option<String>,
    pub source: Option<String>,
    pub source_ip_prefix: Option<String>,
    pub source_ip_prefixes: Option<Vec<String>>,
    pub severity: Option<String>,
    pub severity_in: Option<Vec<String>>,
    pub app: Option<String>,
    pub facility: Option<String>,
    pub exclude_facility: Option<String>,
    pub process_id: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub received_since: Option<String>,
    pub received_until: Option<String>,
    pub limit: Option<u32>,
    pub ai_tool: Option<String>,
    pub ai_project: Option<String>,
    pub ai_session_id: Option<String>,
    pub event_action: Option<String>,
    pub exclude_ai: bool,
}

impl SearchParams {
    /// True when a selective indexed equality filter can lead the query plan.
    /// Severity is excluded because its partitions can cover most of the table.
    pub(crate) fn has_indexed_equality_filter(&self) -> bool {
        self.host.is_some()
            || self.source.is_some()
            || self
                .source_ip_prefix
                .as_ref()
                .is_some_and(|prefix| !prefix.is_empty())
            || self
                .source_ip_prefixes
                .as_ref()
                .is_some_and(|prefixes| prefixes.iter().any(|prefix| !prefix.is_empty()))
            || self.app.is_some()
            || self.event_action.is_some()
            || self.ai_project.is_some()
    }
}
