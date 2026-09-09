#[cfg(test)]
#[path = "db/agent_observatory_models_tests.rs"]
mod agent_observatory_models_tests;

pub mod agent_observatory;
mod analytics;
mod artifact_evidence;
pub mod entity_resolution;
pub(crate) mod error_signatures;
pub mod graph;
pub(crate) mod graph_confidence;
pub mod graph_findings;
pub mod graph_inventory;
mod graph_resolver_projection;
mod heartbeat;
mod hook_events;
mod hook_incident_evidence;
mod hook_incidents;
mod ingest;
pub(crate) use ingest::{TRANSIENT_SQLITE_RETRY_DELAYS_MS, is_transient_sqlite_lock};
mod ingest_health;
pub(crate) mod llm_invocations;
mod maintenance;
mod mcp_events;
mod mcp_incident_evidence;
mod mcp_incidents;
mod models;
pub(crate) mod notifications;
pub mod otlp_metrics;
pub mod otlp_traces;
mod pool;
mod queries;
pub(crate) use queries::page_agent_projection_logs;
#[cfg(test)]
pub(crate) use queries::stream_bounds_sql;
mod queries_hosts;
mod queries_service_instances;
mod skill_events;
mod skill_incident_evidence;
mod skill_incidents;
pub(crate) mod stream_health;

pub(crate) use analytics::PATTERN_SCAN_LIMIT_MAX;
pub use analytics::{
    AnomalyEntry, AppEntry, Bucket, ClockSkewEntry, ContextRef, IngestRateBuckets,
    IngestRatePerHost, ListAppsParams, ListSourceIpsParams, LogEntryWithRaw, PatternEntry,
    RangeSummary, SilentHostEntry, SourceIpEntry, SourceIpHostBreakdown, TimelineGroupBy,
    TimelinePoint, anomalies, clock_skew, context_around, feed_logs, fetch_log_by_id,
    get_ai_project_context, get_ai_usage_blocks, ingest_rate, ingest_rate_by_host, list_apps,
    list_source_ips, silent_hosts, summarize_range, timeline,
};
pub(crate) use analytics::{cluster_pattern_rows, fetch_pattern_rows};
pub use artifact_evidence::{
    ArtifactEvidenceAppendResult, ArtifactEvidenceEntry, ArtifactEvidenceParams,
    ArtifactEvidenceStoreError, ListArtifactEvidenceResult, list_artifact_evidence,
    record_artifact_evidence,
};
#[cfg(test)]
pub use graph::{
    ENTITY_TYPES, EVIDENCE_SOURCE_KINDS, REASON_CODES, RELATIONSHIP_TYPES, TRUST_LEVELS,
    is_known_entity_type, is_known_evidence_source_kind, is_known_reason_code,
    is_known_relationship_type, is_known_trust_level,
};
pub use graph_findings::{
    MountRelationshipFindingRow, PublicRouteFindingRow, list_mount_relationship_findings,
    list_public_route_findings,
};
pub use heartbeat::{
    HeartbeatHostLookup, HeartbeatHostState, HeartbeatLatestEntry, HeartbeatMetricSnapshot,
    HeartbeatSampleState, HeartbeatStateFlags, HeartbeatWindowSummary, heartbeat_host_state,
    heartbeat_latest_all, heartbeat_metric_snapshot_batch, heartbeat_window_summaries,
    stale_heartbeat_hosts,
};
pub(crate) use hook_events::insert_hook_events_in_tx;
pub use hook_events::{
    AiHookEventEntry, AiHookEventParams, HookEventInsert, ListHookEventsResult, insert_hook_events,
    list_hook_events,
};
pub use hook_incident_evidence::{
    AiHookInvestigateParams, HookIncidentEvidence, investigate_ai_hook_incidents,
};
pub use hook_incidents::{
    AiHookIncidentParams, HookIncident, HookSignalCounts, search_ai_hook_incidents,
};
pub use ingest::insert_logs_batch;
pub(crate) use ingest::{insert_logs_batch_borrowed, insert_logs_batch_in_tx};
pub use ingest_health::{IngestSourceKindHealth, ingest_source_kind_health};
pub use maintenance::{
    OrphanSweep, SystemDiskSpaceProbe, checkpoint_wal_and_incremental_vacuum, db_full_vacuum,
    db_incremental_vacuum, db_integrity_check, db_wal_checkpoint, enforce_storage_budget,
    enforce_storage_budget_with_state, exceeds_trigger, finish_maintenance_job,
    get_maintenance_job, get_storage_metrics, insert_maintenance_job,
    insert_maintenance_job_with_result, physical_size_bytes, purge_by_tag_window,
    purge_forward_receipts, purge_old_heartbeats, purge_old_llm_invocations, purge_old_logs,
    update_maintenance_job_progress, wal_checkpoint_complete,
};
pub(crate) use maintenance::{PragmaName, db_pragma_i64, db_pragma_string, sqlite_sidecar_path};
pub(crate) use mcp_events::insert_mcp_events_in_tx;
pub use mcp_events::{
    AiMcpEventEntry, AiMcpEventParams, ListMcpEventsResult, McpEventInsert, insert_mcp_events,
    list_mcp_events,
};
pub use mcp_incident_evidence::{
    AiMcpInvestigateParams, McpIncidentEvidence, investigate_ai_mcp_incidents,
};
pub use mcp_incidents::{
    AiMcpIncidentParams, McpIncident, McpSignalCounts, search_ai_mcp_incidents,
};
pub use models::StorageBudgetState;
pub use models::{
    AbuseIncident, AiAbuseMatch, AiAbuseParams, AiAbuseResult, AiCorrelateParams, AiIncidentParams,
    AiInvestigateParams, AiProjectContext, AiProjectContextParams, AiProjectInventoryEntry,
    AiRelatedLogsForAnchor, AiRelatedLogsParams, AiRelatedWindow, AiSessionEntry,
    AiToolInventoryEntry, AiUsageBlock, AiUsageBlocksParams, AiUsageBlocksResult, AppLogCount,
    CorrelatedSession, DbStats, DockerCheckpoint, DurableStreamPage, DurableStreamParams,
    DurableStreamRow, ErrorSummaryEntry, GraphRelatedLogEntry, HostEntry, IncidentCluster,
    IncidentContextParams, IncidentContextResult, IncidentEvidence, ListAiProjectsParams,
    ListAiProjectsResult, ListAiSessionsParams, ListAiToolsParams, ListAiToolsResult,
    LogBatchEntry, LogEntry, RenderedSessionEventRow, RenderedSessionPageParams,
    SearchAiSessionsParams, SearchAiSessionsResult, SearchParams, SearchedAiSessionEntry,
    SessionGraphInputs, SeverityCount, SimilarIncidentsParams, SimilarIncidentsResult,
    TopicGraphInputs,
};
#[cfg(test)]
pub use pool::KNOWN_SCHEMA_VERSION;
pub use pool::{
    DbPool, WriteConn, backfill_inventory_stats, init_pool, inventory_backfill_complete,
    read_schema_version_info, read_schema_version_info_conn, reconcile_interrupted_server_work,
    write_conn,
};
pub(crate) use pool::{WriteConnBusy, is_pool_acquire_failure, try_write_conn_for};
pub use queries::{
    RollupRefresh, SEVERITY_LEVELS, ai_session_rollup_status, correlate_session_graph,
    durable_stream_page, get_error_summary, get_stats, incident_context_summary,
    investigate_ai_incidents, list_ai_projects, list_ai_sessions, list_ai_tools, list_hosts,
    prune_expired_stream_lineage, prune_timeline_rollup, refresh_ai_session_rollup_if_stale,
    refresh_timeline_rollup, rendered_session_page, search_ai_abuse, search_ai_anchors,
    search_ai_incidents, search_ai_related_logs, search_ai_sessions, search_logs, severity_to_num,
    similar_incidents_clusters, tail_logs, timeline_rollup_status, topic_correlate_inputs,
};
pub(crate) use skill_events::insert_skill_events_in_tx;
pub use skill_events::{
    AiSkillEventEntry, AiSkillEventParams, ListSkillEventsResult, SkillEventInsert,
    insert_skill_events, list_skill_events,
};
pub use skill_incident_evidence::{
    AiSkillInvestigateParams, SkillIncidentEvidence, investigate_ai_skill_incidents,
};
pub use skill_incidents::{
    AiSkillIncidentParams, SkillIncident, SkillSignalCounts, search_ai_skill_incidents,
};
