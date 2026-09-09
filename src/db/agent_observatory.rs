use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;
use tokio::sync::broadcast;

#[path = "agent_observatory_commits.rs"]
mod commits;
pub use commits::{
    GitCommitReachabilityUpdate, GitCommitUpsert, GitRepositoryReconcileResult, list_git_commits,
};
#[cfg(test)]
pub use commits::{get_git_commit, reconcile_git_commits};
#[path = "agent_observatory_run_commits.rs"]
mod run_commits;
#[cfg(test)]
pub use run_commits::list_agent_run_commits;
pub use run_commits::{
    AgentRunCommitUpsert, commit_attribution_evidence, git_commit_by_repository_sha,
    upsert_agent_run_commit,
};
#[path = "agent_observatory_sources.rs"]
mod sources;
pub use sources::{
    AgentHookSourceRow, AgentLlmSourceRow, AgentMcpSourceRow, AgentOtelMetricSourceRow,
    AgentOtelSpanSourceRow, AgentRepositoryObservationSourceRow, AgentSkillSourceRow,
    AgentSourceKind, AgentSourceRecord, page_agent_sources,
};

#[path = "agent_observatory_projection.rs"]
mod projection;
pub use projection::{
    AgentActorUpsert, AgentProjectionOutboxInput, AgentProjectionRunMatch,
    AgentProjectionWriteInput, AgentProjectionWriteResult, AgentRunEventUpsert, AgentRunUpsert,
    AgentTraceRelationUpsert, AgentWorktreeEvidenceUpsert, find_active_projection_worktree,
    find_unique_overlapping_projection_run, find_unique_projection_run_by_session,
    write_agent_projection,
};
pub(crate) use projection::{
    AgentRepositoryObservationRunMatch, find_unique_projection_run_for_repository_observation,
    projection_event_has_summary, reconcile_unmatched_trace_relations,
    write_agent_existing_run_event, write_agent_existing_run_event_with_cursor,
    write_agent_projection_with_cursor, write_agent_trace_relation_without_run,
};

#[path = "agent_observatory_observations.rs"]
mod observations;
pub use observations::RepositoryObservationInput;
#[cfg(test)]
pub use observations::{list_repository_observations, record_repository_observations_if_changed};

#[path = "agent_observatory_queries.rs"]
mod queries;
pub use queries::{
    RepositoryReconcileResult, RepositoryUpsert, RepositoryWorktreeUpsert, get_repository_by_key,
    list_repository_worktrees,
};
#[cfg(test)]
pub use queries::{get_worktree_by_key, reconcile_repository};

#[path = "agent_observatory_read.rs"]
mod read;
pub use read::{
    AgentEventQuery, AgentRunQuery, ObservatoryEventRow, ObservatoryMetricRow,
    ObservatoryRepositoryRow, ObservatoryRunRow, ObservatorySpanRow, ObservatoryWorktreeRow,
    RepositoryQuery, RunTelemetryIdentity, TelemetryQuery, list_observatory_events,
    list_observatory_metrics, list_observatory_repositories, list_observatory_runs,
    list_observatory_spans, list_observatory_worktrees,
};

use crate::db::pool::DbPool;
use anyhow::{Context, Result};
use rusqlite::TransactionBehavior;

fn projection_wake_sender() -> &'static broadcast::Sender<()> {
    static PROJECTION_WAKE: OnceLock<broadcast::Sender<()>> = OnceLock::new();
    PROJECTION_WAKE.get_or_init(|| {
        let (sender, _) = broadcast::channel(16);
        sender
    })
}

pub(crate) fn projection_wake_receiver() -> broadcast::Receiver<()> {
    projection_wake_sender().subscribe()
}

pub(crate) fn notify_projection_work() {
    let _ = projection_wake_sender().send(());
}

pub(crate) fn advance_projection_cursor_in_tx(
    tx: &rusqlite::Transaction<'_>,
    source_name: &str,
    cursor: &str,
) -> Result<()> {
    let changed = tx.execute(
        "UPDATE agent_projection_cursors
            SET cursor_value = ?2,
                updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
          WHERE cursor_type = 'source' AND source_name = ?1",
        rusqlite::params![source_name, cursor],
    )?;
    anyhow::ensure!(changed == 1, "projection cursor is not initialized");
    Ok(())
}

pub(crate) fn projection_cursor(pool: &DbPool, source_name: &str) -> Result<String> {
    use rusqlite::OptionalExtension;

    // Read on a connection of its own and let it go: the common path finds the
    // cursor and never needs the write lock, and the seeding path below must not
    // queue on that lock while holding a connection.
    {
        let connection = pool.get().context("acquire database connection")?;
        if let Some(cursor) = connection
            .query_row(
                "SELECT cursor_value FROM agent_projection_cursors
                  WHERE cursor_type = 'source' AND source_name = ?1",
                [source_name],
                |row| row.get(0),
            )
            .optional()?
        {
            return Ok(cursor);
        }
    }

    let connection = crate::db::write_conn(pool).context("acquire database connection")?;
    connection.execute(
        "INSERT OR IGNORE INTO agent_projection_cursors
             (cursor_type, source_name, cursor_value) VALUES ('source', ?1, '')",
        [source_name],
    )?;
    Ok(connection.query_row(
        "SELECT cursor_value FROM agent_projection_cursors
          WHERE cursor_type = 'source' AND source_name = ?1",
        [source_name],
        |row| row.get(0),
    )?)
}

pub(crate) fn advance_projection_cursor(
    pool: &DbPool,
    source_name: &str,
    cursor: &str,
) -> Result<()> {
    let mut connection = crate::db::write_conn(pool).context("acquire database connection")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    advance_projection_cursor_in_tx(&tx, source_name, cursor)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn record_projection_health(
    pool: &DbPool,
    worker: &str,
    status: &str,
    detail: &str,
) -> Result<()> {
    let connection = crate::db::write_conn(pool).context("acquire database connection")?;
    connection.execute(
        "INSERT INTO agent_projection_cursors (cursor_type, source_name, cursor_value)
         VALUES ('health', ?1, json_object('status', ?2, 'detail', ?3, 'attempts', 1))
         ON CONFLICT(cursor_type, source_name) DO UPDATE SET
             cursor_value = json_object(
                 'status', ?2, 'detail', ?3,
                 'attempts', COALESCE(json_extract(agent_projection_cursors.cursor_value, '$.attempts'), 0) + 1
             ),
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        rusqlite::params![worker, status, detail],
    )?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn projection_health(pool: &DbPool, worker: &str) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    let connection = pool.get().context("acquire database connection")?;
    Ok(connection
        .query_row(
            "SELECT cursor_value FROM agent_projection_cursors
          WHERE cursor_type = 'health' AND source_name = ?1",
            [worker],
            |row| row.get(0),
        )
        .optional()?)
}

pub fn reconcile_git_repository_snapshot_with<F>(
    pool: &DbPool,
    repository: &RepositoryUpsert,
    worktrees: &[RepositoryWorktreeUpsert],
    commits: &[GitCommitUpsert],
    reachability: &[GitCommitReachabilityUpdate],
    observed_at: &str,
    build_observations: F,
) -> Result<GitRepositoryReconcileResult>
where
    F: FnOnce(&RepositoryReconcileResult) -> Result<Vec<RepositoryObservationInput>>,
{
    queries::validate_reconcile_repository(repository, worktrees, observed_at)?;
    commits::validate_reconcile_git_commits(commits, reachability, observed_at)?;
    let mut connection = crate::db::write_conn(pool).context("acquire database connection")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let topology = queries::reconcile_repository_tx(&tx, repository, worktrees, observed_at)?;
    let commits = commits::reconcile_git_commits_tx(
        &tx,
        &repository.repository_key,
        commits,
        reachability,
        observed_at,
    )?;
    let observation_inputs = build_observations(&topology)?;
    observations::validate_repository_observations(
        &repository.repository_key,
        &observation_inputs,
        observed_at,
    )?;
    let observations = observations::record_repository_observations_if_changed_tx(
        &tx,
        &repository.repository_key,
        &observation_inputs,
        observed_at,
    )?;
    tx.commit()?;
    Ok(GitRepositoryReconcileResult {
        topology,
        commits,
        observations,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumParseError {
    type_name: &'static str,
    value: String,
}

impl EnumParseError {
    pub(crate) fn new(type_name: &'static str, value: &str) -> Self {
        Self {
            type_name,
            value: value.to_string(),
        }
    }
}

impl fmt::Display for EnumParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {} value: {}",
            self.type_name, self.value
        )
    }
}

impl std::error::Error for EnumParseError {}

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($variant),+ }

        impl $name {
            #[cfg(test)]
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = EnumParseError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(EnumParseError::new(stringify!($name), value)),
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

string_enum!(RunStatus {
    Starting => "starting", Active => "active", Waiting => "waiting", Idle => "idle",
    Stale => "stale", Completed => "completed", Failed => "failed", Abandoned => "abandoned",
});

string_enum!(AgentEventKind {
    Lifecycle => "lifecycle", Transcript => "transcript", Command => "command",
    ShellHistory => "shell_history", GitStatus => "git_status", GitHead => "git_head",
    GitCommit => "git_commit", FileOperation => "file_operation", Mcp => "mcp", Hook => "hook",
    Skill => "skill", Llm => "llm", OtlpLog => "otlp_log", OtlpSpan => "otlp_span",
    OtlpMetric => "otlp_metric", Heartbeat => "heartbeat", Error => "error",
    ProviderEvent => "provider_event",
});

string_enum!(EvidenceTrustLevel {
    Verified => "verified", Claimed => "claimed", Correlated => "correlated",
    Inferred => "inferred", Refuted => "refuted",
});

string_enum!(RepositoryObservationKind {
    Discovered => "discovered", Status => "status", Head => "head", Branch => "branch",
    WorktreeAdded => "worktree_added", WorktreeRemoved => "worktree_removed",
    OverflowReconcile => "overflow_reconcile", PeriodicReconcile => "periodic_reconcile",
    Error => "error",
});

string_enum!(StreamEventName {
    RunCreated => "run.created", RunUpdated => "run.updated", RunStatus => "run.status",
    RunEvent => "run.event", WorktreeUpdated => "worktree.updated",
    RepositoryUpdated => "repository.updated", TelemetryUpdated => "telemetry.updated",
    ObservatoryReset => "observatory.reset",
});

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryRow {
    pub id: i64,
    pub repository_key: String,
    pub hostname: String,
    pub common_git_dir: String,
    pub primary_path: String,
    pub display_name: String,
    pub remote_url_hash: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub removed_at: Option<String>,
    pub metadata_json: String,
    pub created_at: String,
    pub updated_at: String,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryWorktreeRow {
    pub id: i64,
    pub worktree_key: String,
    pub repository_id: i64,
    pub hostname: String,
    pub path: String,
    pub git_dir: String,
    pub branch_ref: Option<String>,
    pub branch_name: Option<String>,
    pub head_sha: Option<String>,
    pub upstream_ref: Option<String>,
    pub detached: bool,
    pub bare: bool,
    pub locked: bool,
    pub lock_reason: Option<String>,
    pub prunable: bool,
    pub prune_reason: Option<String>,
    pub dirty: bool,
    pub staged_count: i64,
    pub unstaged_count: i64,
    pub untracked_count: i64,
    pub ahead: Option<i64>,
    pub behind: Option<i64>,
    pub status_hash: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub removed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryObservationRow {
    pub id: i64,
    pub observation_key: String,
    pub repository_id: i64,
    pub worktree_id: Option<i64>,
    pub observed_at: String,
    pub observation_kind: RepositoryObservationKind,
    pub old_head_sha: Option<String>,
    pub new_head_sha: Option<String>,
    pub summary: String,
    pub payload_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitCommitRow {
    pub id: i64,
    pub repository_id: i64,
    pub sha: String,
    pub parent_shas_json: String,
    pub author_name: Option<String>,
    pub author_email_hash: Option<String>,
    pub authored_at: Option<String>,
    pub committed_at: Option<String>,
    pub subject: String,
    pub changed_files: Option<i64>,
    pub insertions: Option<i64>,
    pub deletions: Option<i64>,
    pub changed_paths_json: String,
    pub first_observed_at: String,
    pub last_observed_at: String,
    pub reachable: bool,
    pub metadata_json: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentRunRow {
    pub id: i64,
    pub run_key: String,
    pub native_session_id: String,
    pub tool: String,
    pub provider_tool: Option<String>,
    pub hostname: String,
    pub parent_run_id: Option<i64>,
    pub previous_run_id: Option<i64>,
    pub primary_worktree_id: Option<i64>,
    pub transcript_path: Option<String>,
    pub process_id: Option<String>,
    pub status: RunStatus,
    pub status_reason: String,
    pub status_observed_at: String,
    pub started_at: String,
    pub last_activity_at: String,
    pub ended_at: Option<String>,
    pub first_source_log_id: Option<i64>,
    pub last_source_log_id: Option<i64>,
    pub last_event_id: Option<i64>,
    pub event_count: i64,
    pub error_count: i64,
    pub primary_branch: Option<String>,
    pub start_head_sha: Option<String>,
    pub current_head_sha: Option<String>,
    pub projection_version: i64,
    pub freshness_json: String,
    pub metadata_json: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentRunEventRow {
    pub id: i64,
    pub event_key: String,
    pub run_id: i64,
    pub actor_id: Option<i64>,
    pub worktree_id: Option<i64>,
    pub commit_id: Option<i64>,
    pub observed_at: String,
    pub ingested_at: String,
    pub event_kind: AgentEventKind,
    pub source_kind: String,
    pub source_id: String,
    pub source_log_id: Option<i64>,
    pub provider_sequence: Option<i64>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub payload_json: String,
    pub content_scrubbed: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentRunWorktreeEvidenceRow {
    pub id: i64,
    pub relation_key: String,
    pub run_id: i64,
    pub worktree_id: i64,
    pub evidence_kind: String,
    pub evidence_source: String,
    pub trust_level: EvidenceTrustLevel,
    pub confidence: f64,
    pub is_primary: bool,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub metadata_json: String,
}
