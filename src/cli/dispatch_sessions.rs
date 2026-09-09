use super::dispatch::http_or_cancel;

use anyhow::{Result, bail};
use cortex::app::{
    AbuseSearchRequest, AiAssessRequest, AiCheckpointsRequest, AiCorrelateRequest,
    AiHookIncidentRequest, AiHookInvestigateRequest, AiIncidentRequest, AiInvestigateRequest,
    AiParseErrorsRequest, AiPruneCheckpointsRequest, HookAssessRequest, IncidentContextRequest,
    ListAiProjectsRequest, ListAiToolsRequest, ListHookEventsRequest, McpAssessRequest,
    ProjectContextRequest, SearchSessionsRequest, SimilarIncidentsRequest, SkillAssessRequest,
    UsageBlocksRequest,
};
use std::io::Write;

use super::output::common::print_json;
use super::output::logs::events::{
    print_hook_events_response, print_mcp_events_response, print_skill_events_response,
};
use super::output::logs::{
    UsageBlocksPrintOptions, print_abuse_search_response, print_ai_correlate_response,
    print_ai_projects_response, print_ai_tools_response, print_project_context_response,
    print_search_sessions_response, print_usage_blocks_response_with_options,
};
use super::output::sessions::hook_incidents::{
    print_ai_hook_incidents_response, print_ai_hook_investigate_response,
};
use super::output::sessions::mcp_incidents::{
    print_ai_mcp_incidents_response, print_ai_mcp_investigate_response,
};
use super::output::sessions::more::{
    AiInvestigatePrintOptions, print_ai_incidents_response,
    print_ai_investigate_response_with_options, print_incident_context_response,
    print_similar_incidents_response,
};
use super::output::sessions::skill_incidents::{
    print_ai_skill_incidents_response, print_ai_skill_investigate_response,
};
use super::output::sessions::{
    ensure_ai_doctor_success, ensure_index_success, print_ai_doctor_response,
    print_ai_parse_errors_response, print_ai_smoke_watch_response, print_checkpoints_response,
    print_index_response, print_prune_checkpoints_response, print_sessions_watch_status_response,
};
use super::sessions_watch::ai_smoke_watch;
use super::{
    AssessAbuseArgs, AssessHooksArgs, AssessMcpArgs, AssessSkillArgs, CliMode, OutputArgs,
    SessionsAbuseArgs, SessionsAddArgs, SessionsAssessArgs, SessionsBlocksArgs,
    SessionsCheckpointsArgs, SessionsContextArgs, SessionsCorrelateArgs, SessionsDoctorArgs,
    SessionsErrorsArgs, SessionsHookIncidentsArgs, SessionsHookInvestigateArgs,
    SessionsIncidentContextArgs, SessionsIncidentsArgs, SessionsIndexArgs, SessionsInvestigateArgs,
    SessionsListArgs, SessionsLlmInvocationsArgs, SessionsMcpEventsBackfillArgs,
    SessionsMcpEventsListArgs, SessionsMcpIncidentsArgs, SessionsMcpInvestigateArgs,
    SessionsPruneCheckpointsArgs, SessionsSearchArgs, SessionsSimilarArgs,
    SessionsSkillIncidentsArgs, SessionsSkillInvestigateArgs, SessionsSkillsBackfillArgs,
    SessionsSkillsListArgs, SessionsWatchArgs,
};

// ─── AI Arg → Request conversions (bead 0p8r.8) ─────────────────────────────

impl SessionsSearchArgs {
    pub(crate) fn into_request(self) -> SearchSessionsRequest {
        SearchSessionsRequest {
            query: self.query,
            project: self.project,
            tool: self.tool,
            since: self.since,
            until: self.until,
            limit: self.limit,
        }
    }
}

impl SessionsAbuseArgs {
    pub(crate) fn into_request(self) -> AbuseSearchRequest {
        AbuseSearchRequest {
            project: self.project,
            tool: self.tool,
            since: self.since,
            until: self.until,
            limit: self.limit,
            before: self.before,
            after: self.after,
            terms: self.terms,
        }
    }
}

impl SessionsCorrelateArgs {
    pub(crate) fn into_request(self) -> AiCorrelateRequest {
        AiCorrelateRequest {
            project: self.project,
            tool: self.tool,
            session_id: self.session_id,
            ai_query: self.ai_query,
            log_query: self.log_query,
            host: self.host,
            source: self.source,
            app: self.app,
            since: self.since,
            until: self.until,
            window_minutes: self.window_minutes,
            severity_min: self.severity_min,
            limit: self.limit,
            events_per_anchor: self.events_per_anchor,
        }
    }
}

impl SessionsBlocksArgs {
    pub(crate) fn into_request(self) -> UsageBlocksRequest {
        UsageBlocksRequest {
            project: self.project,
            tool: self.tool,
            since: self.since,
            until: self.until,
            limit: self.limit.map(|value| value.min(u32::MAX as usize) as u32),
        }
    }
}

impl SessionsContextArgs {
    pub(crate) fn into_request(self) -> ProjectContextRequest {
        ProjectContextRequest {
            project: self.project,
            tool: self.tool,
            limit: self.limit,
        }
    }
}

impl SessionsListArgs {
    pub(crate) fn into_tools_request(self) -> ListAiToolsRequest {
        ListAiToolsRequest {
            project: self.project,
            since: self.since,
            until: self.until,
        }
    }

    pub(crate) fn into_projects_request(self) -> ListAiProjectsRequest {
        ListAiProjectsRequest {
            tool: self.tool,
            since: self.since,
            until: self.until,
        }
    }
}

impl SessionsCheckpointsArgs {
    pub(crate) fn into_request(self) -> AiCheckpointsRequest {
        AiCheckpointsRequest {
            errors_only: self.errors_only,
            missing_only: self.missing_only,
            limit: self.limit,
        }
    }
}

impl SessionsErrorsArgs {
    pub(crate) fn into_request(self) -> AiParseErrorsRequest {
        AiParseErrorsRequest { limit: self.limit }
    }
}

impl SessionsPruneCheckpointsArgs {
    pub(crate) fn into_request(self) -> AiPruneCheckpointsRequest {
        AiPruneCheckpointsRequest {
            dry_run: self.dry_run,
            missing_only: self.missing_only,
            limit: self.limit,
        }
    }
}

impl SessionsSimilarArgs {
    pub(crate) fn into_request(self) -> SimilarIncidentsRequest {
        SimilarIncidentsRequest {
            query: self.query,
            host: self.host,
            app: self.app,
            severity_min: self.severity_min,
            since: self.since,
            until: self.until,
            window_minutes: self.window_minutes,
            limit: self.limit,
        }
    }
}

impl SessionsIncidentContextArgs {
    pub(crate) fn into_request(self) -> IncidentContextRequest {
        IncidentContextRequest {
            since: self.since,
            until: self.until,
            host: self.host,
            app: self.app,
            query: self.query,
            severity_min: self.severity_min,
            limit: self.limit,
        }
    }
}

// ─── AI per-command dispatch (bead 0p8r.8) ──────────────────────────────────
//
// HTTP-capable (10): search, abuse, correlate, blocks, context, tools,
//   projects, checkpoints, errors, prune_checkpoints.
// LOCAL-only (6): index, add, doctor, smoke_watch, watch_status, watch.
//   These bail in HTTP mode with an inline message per the bead table
//   (no shared helper — eng-review #S4).

pub(crate) async fn run_ai_search(mode: &CliMode, args: SessionsSearchArgs) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.search_sessions(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_search(&req)).await?,
    };
    print_search_sessions_response(&response, json)
}

pub(crate) async fn run_ai_abuse(mode: &CliMode, args: SessionsAbuseArgs) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.search_abuse(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_abuse(&req)).await?,
    };
    print_abuse_search_response(&response, json)
}

pub(crate) async fn run_ai_correlate(mode: &CliMode, args: SessionsCorrelateArgs) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.correlate().ai(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_correlate(&req)).await?,
    };
    print_ai_correlate_response(&response, json)
}

pub(crate) async fn run_ai_blocks(mode: &CliMode, args: SessionsBlocksArgs) -> Result<()> {
    let json = args.json;
    let detail = args.detail;
    let limit = args.limit;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.usage_blocks(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_blocks(&req)).await?,
    };
    print_usage_blocks_response_with_options(
        &response,
        json,
        UsageBlocksPrintOptions { detail, limit },
    )
}

pub(crate) async fn run_ai_context(mode: &CliMode, args: SessionsContextArgs) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.project_context(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_context(&req)).await?,
    };
    print_project_context_response(&response, json)
}

pub(crate) async fn run_ai_tools(mode: &CliMode, args: SessionsListArgs) -> Result<()> {
    let json = args.json;
    let req = args.into_tools_request();
    let response = match mode {
        CliMode::Local(service) => service.list_ai_tools(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_tools(&req)).await?,
    };
    print_ai_tools_response(&response, json)
}

pub(crate) async fn run_ai_projects(mode: &CliMode, args: SessionsListArgs) -> Result<()> {
    let json = args.json;
    let req = args.into_projects_request();
    let response = match mode {
        CliMode::Local(service) => service.list_ai_projects(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_projects(&req)).await?,
    };
    print_ai_projects_response(&response, json)
}

pub(crate) async fn run_ai_checkpoints(
    mode: &CliMode,
    args: SessionsCheckpointsArgs,
) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => {
            service
                .list_ai_checkpoints(req.errors_only, req.missing_only, req.limit)
                .await?
        }
        CliMode::Http(client) => http_or_cancel(client.ai_checkpoints(&req)).await?,
    };
    print_checkpoints_response(&response, json)
}

pub(crate) async fn run_ai_errors(mode: &CliMode, args: SessionsErrorsArgs) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.list_ai_parse_errors(req.limit).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_parse_errors(&req)).await?,
    };
    print_ai_parse_errors_response(&response, json)
}

pub(crate) async fn run_ai_prune_checkpoints(
    mode: &CliMode,
    args: SessionsPruneCheckpointsArgs,
) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.prune_ai_checkpoints_checked(req.clone()).await?,
        CliMode::Http(client) => http_or_cancel(client.prune_ai_checkpoints(&req)).await?,
    };
    print_prune_checkpoints_response(&response, json)
}

// ─── LOCAL-only session commands (6) — error in HTTP mode ───────────────────

pub(crate) async fn run_ai_skills_backfill(
    mode: &CliMode,
    args: SessionsSkillsBackfillArgs,
) -> Result<()> {
    let service = match mode {
        CliMode::Http(_) => bail!("sessions skills backfill runs local DB scans; omit --http"),
        CliMode::Local(service) => service,
    };
    let response = service
        .backfill_skill_events(cortex::app::SkillBackfillRequest {
            since: args.since,
            limit: args.limit,
            dry_run: args.dry_run,
        })
        .await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "scanned={} inserted={} skipped_duplicates={} parse_errors={} source_unavailable={} truncated={} dry_run={}",
            response.scanned,
            response.inserted,
            response.skipped_duplicates,
            response.parse_errors,
            response.source_unavailable,
            response.truncated,
            response.dry_run
        );
    }
    Ok(())
}

pub(crate) async fn run_ai_skills(mode: &CliMode, args: SessionsSkillsListArgs) -> Result<()> {
    let json = args.json;
    let req = cortex::app::ListSkillEventsRequest {
        skill: args.skill,
        plugin: args.plugin,
        tool: args.tool,
        project: args.project,
        session_id: args.session_id,
        hostname: args.host,
        from: args.since,
        to: args.until,
        limit: args.limit,
    };
    let response = match mode {
        CliMode::Local(service) => service.list_skill_events(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_skills(&req)).await?,
    };
    print_skill_events_response(&response, json)
}

pub(crate) async fn run_mcp_events_backfill(
    mode: &CliMode,
    args: SessionsMcpEventsBackfillArgs,
) -> Result<()> {
    let service = match mode {
        CliMode::Http(_) => bail!("sessions mcpevents backfill runs local DB scans; omit --http"),
        CliMode::Local(service) => service,
    };
    let response = service
        .backfill_mcp_events(cortex::app::McpBackfillRequest {
            since: args.since,
            limit: args.limit,
            dry_run: args.dry_run,
        })
        .await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "scanned={} inserted={} skipped_duplicates={} parse_errors={} truncated={} dry_run={}",
            response.scanned,
            response.inserted,
            response.skipped_duplicates,
            response.parse_errors,
            response.truncated,
            response.dry_run
        );
    }
    Ok(())
}

pub(crate) async fn run_mcp_events(mode: &CliMode, args: SessionsMcpEventsListArgs) -> Result<()> {
    let json = args.json;
    let req = cortex::app::ListMcpEventsRequest {
        tool_name: args.tool_name,
        mcp_server: args.mcp_server,
        mcp_tool: args.mcp_tool,
        tool: args.tool,
        project: args.project,
        session_id: args.session_id,
        hostname: args.host,
        is_error: args.is_error,
        from: args.since,
        to: args.until,
        limit: args.limit,
    };
    let response = match mode {
        CliMode::Local(service) => service.list_mcp_events(req).await?,
        CliMode::Http(client) => http_or_cancel(client.mcp_events(&req)).await?,
    };
    print_mcp_events_response(&response, json)
}

pub(crate) async fn run_ai_hook_events(
    mode: &CliMode,
    args: super::SessionsHookEventsListArgs,
) -> Result<()> {
    let json = args.json;
    let req = ListHookEventsRequest {
        hook_event: args.hook_event,
        hook_name: args.hook_name,
        hook_source: args.hook_source,
        status: args.status,
        evidence_kind: args.evidence_kind,
        tool: args.tool,
        project: args.project,
        session_id: args.session_id,
        hostname: args.host,
        from: args.since,
        to: args.until,
        limit: args.limit,
    };
    let response = match mode {
        CliMode::Local(service) => service.list_hook_events(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_hook_events(&req)).await?,
    };
    print_hook_events_response(&response, json)
}

impl SessionsHookIncidentsArgs {
    fn into_request(self) -> AiHookIncidentRequest {
        AiHookIncidentRequest {
            hook_event: self.hook_event,
            hook_name: self.hook_name,
            hook_source: self.hook_source,
            tool: self.tool,
            project: self.project,
            session_id: self.session_id,
            hostname: self.hostname,
            evidence_kind: self.evidence_kind,
            since: self.since,
            until: self.until,
            limit: self.limit,
            window_minutes: self.window_minutes,
            signals: self.signals,
            min_score: self.min_score.map(|value| {
                value
                    .parse::<f64>()
                    .expect("min_score validated at CLI-parse time")
            }),
        }
    }
}

impl SessionsHookInvestigateArgs {
    fn into_request(self) -> AiHookInvestigateRequest {
        AiHookInvestigateRequest {
            incident_id: self.incident_id,
            hook_event: self.hook_event,
            hook_name: self.hook_name,
            hook_source: self.hook_source,
            tool: self.tool,
            project: self.project,
            since: self.since,
            until: self.until,
            limit: if self.all {
                self.limit.or(Some(3))
            } else {
                self.limit.or(Some(1))
            },
            window_minutes: self.window_minutes,
            correlation_window_minutes: self.correlation_window_minutes,
        }
    }
}

pub(crate) async fn run_ai_hook_incidents(
    mode: &CliMode,
    args: SessionsHookIncidentsArgs,
) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.list_ai_hook_incidents(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_hook_incidents(&req)).await?,
    };
    print_ai_hook_incidents_response(&response, json)
}

pub(crate) async fn run_ai_hook_investigate(
    mode: &CliMode,
    args: SessionsHookInvestigateArgs,
) -> Result<()> {
    let json = args.json;
    if args.hook_name.is_none()
        && args.hook_event.is_none()
        && args.hook_source.is_none()
        && args.incident_id.is_none()
    {
        bail!(
            "sessions hookinvestigate requires a hook name (positional), --hook-event, \
             --hook-source, or --incident-id"
        );
    }
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.investigate_ai_hook_incidents(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_hook_investigate(&req)).await?,
    };
    print_ai_hook_investigate_response(&response, json)
}

pub(crate) async fn run_ai_hooks_backfill(
    mode: &CliMode,
    args: super::SessionsHooksBackfillArgs,
) -> Result<()> {
    let service = match mode {
        CliMode::Http(_) => bail!("sessions hooksbackfill runs local DB scans; omit --http"),
        CliMode::Local(service) => service,
    };
    let response = service
        .backfill_hook_events(cortex::app::HookBackfillRequest {
            since: args.since,
            limit: args.limit,
            dry_run: args.dry_run,
        })
        .await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "scanned={} inserted={} skipped_duplicates={} parse_errors={} truncated={} dry_run={}",
            response.scanned,
            response.inserted,
            response.skipped_duplicates,
            response.parse_errors,
            response.truncated,
            response.dry_run
        );
    }
    Ok(())
}

pub(crate) async fn run_ai_index(mode: &CliMode, args: SessionsIndexArgs) -> Result<()> {
    let service = match mode {
        CliMode::Http(_) => bail!("sessions index reads host ~/.claude/projects; omit --http"),
        CliMode::Local(service) => service,
    };
    let response = service
        .index_ai_roots(args.path, args.force, args.since)
        .await?;
    print_index_response(&response, args.json)?;
    ensure_index_success(&response)
}

pub(crate) async fn run_ai_add(mode: &CliMode, args: SessionsAddArgs) -> Result<()> {
    let service = match mode {
        CliMode::Http(_) => bail!("sessions add reads a host file path; omit --http"),
        CliMode::Local(service) => service,
    };
    let response = service.add_ai_file(args.file, args.force).await?;
    print_index_response(&response, args.json)?;
    ensure_index_success(&response)
}

pub(crate) async fn run_ai_doctor(mode: &CliMode, args: SessionsDoctorArgs) -> Result<()> {
    let service = match mode {
        CliMode::Http(_) => {
            bail!("sessions doctor checks host filesystem permissions; omit --http")
        }
        CliMode::Local(service) => service,
    };
    let response = service.ai_doctor().await?;
    print_ai_doctor_response(&response, args.json)?;
    ensure_ai_doctor_success(&response, args.strict_permissions)
}

pub(crate) async fn run_ai_smoke_watch(mode: &CliMode, args: OutputArgs) -> Result<()> {
    let service = match mode {
        CliMode::Http(_) => {
            bail!("sessions smokewatch writes synthetic transcript to host fs; omit --http")
        }
        CliMode::Local(service) => service,
    };
    let response = ai_smoke_watch(service).await?;
    print_ai_smoke_watch_response(&response, args.json)?;
    if !response.pruned_missing_checkpoint {
        bail!("AI watch smoke checkpoint was not pruned within 30s");
    }
    Ok(())
}

pub(crate) async fn run_sessions_watch_status(mode: &CliMode, args: OutputArgs) -> Result<()> {
    if matches!(mode, CliMode::Http(_)) {
        bail!("sessions watchstatus shells out to systemctl on host; omit --http");
    }
    let CliMode::Local(service) = mode else {
        unreachable!("http mode returned above");
    };
    let response = service.ai_watch_status().await?;
    print_sessions_watch_status_response(&response, args.json)
}

pub(crate) async fn run_sessions_watch(mode: &CliMode, args: SessionsWatchArgs) -> Result<()> {
    let service = match mode {
        CliMode::Http(_) => bail!("sessions watch is a long-running daemon; omit --http"),
        CliMode::Local(service) => service.clone(),
    };
    let options = cortex::ai_watch::WatchOptions {
        path: args.path.map(std::path::PathBuf::from),
        debounce: std::time::Duration::from_millis(args.debounce_ms),
        settle: std::time::Duration::from_millis(args.settle_ms),
        max_retries: args.max_retries,
        initial_scan: !args.no_initial_scan,
        json: args.json,
    };
    cortex::ai_watch::run(service, options).await
}

// ─── RAG v1 dispatch (LOCAL-only) ────────────────────────────────────────────

pub(crate) async fn run_ai_similar_incidents(
    mode: &CliMode,
    args: SessionsSimilarArgs,
) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Http(client) => http_or_cancel(client.similar_incidents(&req)).await?,
        CliMode::Local(service) => service.similar_incidents(req).await?,
    };
    print_similar_incidents_response(&response, json)
}

pub(crate) async fn run_ai_incident_context(
    mode: &CliMode,
    args: SessionsIncidentContextArgs,
) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Http(client) => http_or_cancel(client.incident_context(&req)).await?,
        CliMode::Local(service) => service.incident_context(req).await?,
    };
    print_incident_context_response(&response, json)
}

impl SessionsIncidentsArgs {
    pub(crate) fn into_request(self) -> AiIncidentRequest {
        AiIncidentRequest {
            project: self.project,
            tool: self.tool,
            since: self.since,
            until: self.until,
            limit: self.limit,
            window_minutes: self.window_minutes,
            terms: self.terms,
        }
    }
}

impl SessionsInvestigateArgs {
    pub(crate) fn into_request(self) -> AiInvestigateRequest {
        AiInvestigateRequest {
            incident_id: None,
            project: self.project,
            tool: self.tool,
            since: self.since,
            until: self.until,
            limit: self.limit,
            window_minutes: self.window_minutes,
            correlation_window_minutes: self.correlation_window_minutes,
            terms: self.terms,
        }
    }
}

pub(crate) async fn run_ai_incidents(mode: &CliMode, args: SessionsIncidentsArgs) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.list_ai_incidents(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_incidents(&req)).await?,
    };
    print_ai_incidents_response(&response, json)
}

pub(crate) async fn run_ai_investigate(
    mode: &CliMode,
    args: SessionsInvestigateArgs,
) -> Result<()> {
    let json = args.json;
    let print_options = AiInvestigatePrintOptions {
        detail: args.detail,
        include_transcript: args.include_transcript,
        max_bytes: args.max_bytes.unwrap_or(240),
    };
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.investigate_ai_incidents(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_investigate(&req)).await?,
    };
    print_ai_investigate_response_with_options(&response, json, print_options)
}

impl SessionsSkillIncidentsArgs {
    pub(crate) fn into_request(self) -> cortex::app::AiSkillIncidentRequest {
        cortex::app::AiSkillIncidentRequest {
            skill: self.skill,
            plugin: self.plugin,
            tool: self.tool,
            project: self.project,
            session_id: self.session_id,
            hostname: self.hostname,
            since: self.since,
            until: self.until,
            limit: self.limit,
            window_minutes: self.window_minutes,
            signals: self.signals,
            min_score: self
                .min_score
                .map(|s| s.parse::<f64>())
                .transpose()
                .ok()
                .flatten(),
        }
    }
}

impl SessionsSkillInvestigateArgs {
    pub(crate) fn into_request(self) -> cortex::app::AiSkillInvestigateRequest {
        cortex::app::AiSkillInvestigateRequest {
            incident_id: self.incident_id,
            skill: self.skill,
            plugin: self.plugin,
            tool: self.tool,
            project: self.project,
            since: self.since,
            until: self.until,
            limit: if self.all {
                self.limit.or(Some(3))
            } else {
                self.limit.or(Some(1))
            },
            window_minutes: self.window_minutes,
            correlation_window_minutes: self.correlation_window_minutes,
        }
    }
}

pub(crate) async fn run_ai_skill_incidents(
    mode: &CliMode,
    args: SessionsSkillIncidentsArgs,
) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.list_ai_skill_incidents(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_skill_incidents(&req)).await?,
    };
    print_ai_skill_incidents_response(&response, json)
}

pub(crate) async fn run_ai_skill_investigate(
    mode: &CliMode,
    args: SessionsSkillInvestigateArgs,
) -> Result<()> {
    let json = args.json;
    if args.skill.is_none() && args.plugin.is_none() && args.incident_id.is_none() {
        bail!(
            "sessions skillinvestigate requires a skill name (positional), --plugin, or \
             --incident-id, e.g. `cortex sessions skillinvestigate lavra:lavra-plan`"
        );
    }
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.investigate_ai_skill_incidents(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_skill_investigate(&req)).await?,
    };
    print_ai_skill_investigate_response(&response, json)
}

impl SessionsMcpIncidentsArgs {
    pub(crate) fn into_request(self) -> cortex::app::AiMcpIncidentRequest {
        cortex::app::AiMcpIncidentRequest {
            mcp_server: self.mcp_server,
            mcp_tool: self.mcp_tool,
            tool_name: self.tool_name,
            tool: self.tool,
            project: self.project,
            session_id: self.session_id,
            hostname: self.hostname,
            since: self.since,
            until: self.until,
            limit: self.limit,
            window_minutes: self.window_minutes,
            signals: self.signals,
            // Already validated as a well-formed f64 by
            // parse_sessions_mcp_incidents (parse_f64_flag) — this can
            // only fail if that invariant is broken, which is a bug worth
            // panicking on rather than silently dropping the filter.
            min_score: self.min_score.map(|s| {
                s.parse::<f64>()
                    .expect("min_score validated at CLI-parse time")
            }),
        }
    }
}

impl SessionsMcpInvestigateArgs {
    /// The bare positional `target` resolves to `mcp_server` when no
    /// `--mcp-server`/`--mcp-tool`/`--tool-name` flag was given, mirroring
    /// the skill-investigate positional-binds-to-skill-name contract.
    /// Callers wanting to target a bare tool name (not a server) should use
    /// `--tool-name` explicitly.
    pub(crate) fn into_request(self) -> cortex::app::AiMcpInvestigateRequest {
        let mcp_server = self.mcp_server.or_else(|| {
            if self.mcp_tool.is_none() && self.tool_name.is_none() {
                self.target.clone()
            } else {
                None
            }
        });
        cortex::app::AiMcpInvestigateRequest {
            incident_id: self.incident_id,
            mcp_server,
            mcp_tool: self.mcp_tool,
            tool_name: self.tool_name,
            tool: self.tool,
            project: self.project,
            since: self.since,
            until: self.until,
            limit: if self.all {
                self.limit.or(Some(3))
            } else {
                self.limit.or(Some(1))
            },
            window_minutes: self.window_minutes,
            correlation_window_minutes: self.correlation_window_minutes,
        }
    }
}

pub(crate) async fn run_mcp_incidents(
    mode: &CliMode,
    args: SessionsMcpIncidentsArgs,
) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.list_ai_mcp_incidents(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_mcp_incidents(&req)).await?,
    };
    print_ai_mcp_incidents_response(&response, json)
}

pub(crate) async fn run_mcp_investigate(
    mode: &CliMode,
    args: SessionsMcpInvestigateArgs,
) -> Result<()> {
    let json = args.json;
    if args.target.is_none()
        && args.mcp_server.is_none()
        && args.mcp_tool.is_none()
        && args.tool_name.is_none()
        && args.incident_id.is_none()
    {
        bail!(
            "sessions mcpinvestigate requires an mcp server/tool (positional), --mcp-server, \
             --mcp-tool, --tool-name, or --incident-id, e.g. `cortex sessions mcpinvestigate labby`"
        );
    }
    let req = args.into_request();
    let response = match mode {
        CliMode::Local(service) => service.investigate_ai_mcp_incidents(req).await?,
        CliMode::Http(client) => http_or_cancel(client.ai_mcp_investigate(&req)).await?,
    };
    print_ai_mcp_investigate_response(&response, json)
}

pub(crate) async fn run_ai_assess(mode: &CliMode, args: SessionsAssessArgs) -> Result<()> {
    let service = match mode {
        CliMode::Http(_) => {
            bail!("ai assess runs the LLM selected by CORTEX_LLM on the local host; omit --http")
        }
        CliMode::Local(service) => service,
    };
    let dry_run = args.dry_run;
    let json = args.json;
    let req = AiAssessRequest {
        incident_id: args.incident_id,
        model: args.model,
        project: args.project,
        tool: args.tool,
        since: args.since,
        until: args.until,
        window_minutes: args.window_minutes,
        correlation_window_minutes: args.correlation_window_minutes,
        terms: args.terms,
        limit: args.limit,
    };
    if dry_run {
        // GH issue #94: preview the prompt/evidence bundle via
        // `LlmRunner::dry_run` without invoking the selected LLM. Writes a
        // "dry_run"-status audit row but spawns no subprocess.
        let outcome = service.dry_run_assess(req).await?;
        if json {
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        } else {
            println!("[dry-run] invocation_id={}", outcome.invocation_id);
            println!("[dry-run] prompt_bytes={}", outcome.prompt_bytes);
            println!(
                "[dry-run] evidence: total_incidents={} evidence_bundle_count={} total_anchors={} truncated={}",
                outcome.evidence_counts.total_incidents,
                outcome.evidence_counts.evidence_bundle_count,
                outcome.evidence_counts.total_anchors,
                outcome.evidence_counts.truncated,
            );
            println!(
                "[dry-run] would_exceed_prompt_limit={}",
                outcome.would_exceed_prompt_limit
            );
        }
        return Ok(());
    }
    if json {
        let response = service.run_assess(req).await?;
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        let mut streamed = false;
        let response = service
            .run_assess_with_delta(req, |delta| {
                streamed = true;
                print!("{delta}");
                std::io::stdout().flush()?;
                Ok(())
            })
            .await?;
        if !streamed {
            println!("{}", response.assessment);
        } else if !response.assessment.ends_with('\n') {
            println!();
        }
        eprintln!(
            "\n[assessed incident={} anchors={} bundles={}]",
            response.incident_id,
            response.evidence_summary.total_anchors,
            response.evidence_summary.evidence_bundle_count,
        );
    }
    Ok(())
}

/// One printable line for a `llm_invocations` row, shared by both
/// `CliMode` branches below (`LlmInvocationRow`'s typed fields on the Local
/// branch, raw `serde_json::Value` fields on the Http branch — see the
/// cross-crate visibility note on `run_ai_llm_invocations`).
fn format_llm_invocation_line(
    started_at: &str,
    id: &str,
    action: &str,
    status: &str,
    duration_ms: Option<i64>,
) -> String {
    format!(
        "[{started_at}] {id} action={action} status={status} duration_ms={}",
        duration_ms
            .map(|d| d.to_string())
            .unwrap_or_else(|| "-".to_string()),
    )
}

// Eng review fix (pattern-recognition-specialist): `into_request` for CLI
// args belongs in `dispatch_sessions.rs`, not `args/sessions.rs` — every
// other sibling `Sessions*Args::into_request()` (11 of them, e.g.
// `SessionsIncidentsArgs`/`SessionsInvestigateArgs` immediately above)
// lives here, placed right before the `run_ai_*` function that consumes
// it. `args/sessions.rs` is otherwise pure struct/enum definitions with
// no business logic.
impl SessionsLlmInvocationsArgs {
    pub(crate) fn into_request(self) -> cortex::app::LlmInvocationsRequest {
        cortex::app::LlmInvocationsRequest {
            limit: self.limit,
            since: self.since,
            action: self.action,
            status: self.status,
        }
    }
}

/// `cortex sessions llminvocations` — list recent LLM invocation audit
/// records (concurrency/rate-limit/circuit-breaker denials included).
///
/// Admin-scoped: exposes operational kill-switch/circuit-breaker state, not
/// just log content. In `CliMode::Http`, requires `CORTEX_API_ADMIN_TOKEN`
/// to be set — the request fails with a clear error otherwise.
///
/// `LlmInvocationRow` lives in `pub(crate) mod db` in the `cortex` lib
/// crate, so it isn't nameable from this bin crate — but field access still
/// works via type inference on the Local branch, same as
/// `run_notify_recent`'s `FiringRow` handling above; the Http branch keeps
/// the raw JSON value for the same reason.
pub(crate) async fn run_ai_llm_invocations(
    mode: &CliMode,
    args: SessionsLlmInvocationsArgs,
) -> Result<()> {
    let json = args.json;
    let req = args.into_request();
    match mode {
        CliMode::Local(service) => {
            let rows = service.llm_invocations_checked(req).await?;
            if json {
                return print_json(&rows);
            }
            if rows.is_empty() {
                println!("No LLM invocations recorded.");
                return Ok(());
            }
            for row in &rows {
                println!(
                    "{}",
                    format_llm_invocation_line(
                        &row.started_at,
                        &row.id,
                        &row.action,
                        &row.status,
                        row.duration_ms,
                    )
                );
            }
        }
        CliMode::Http(client) => {
            let rows = http_or_cancel(client.ai_llm_invocations(&req)).await?;
            if json {
                return print_json(&rows);
            }
            let rows = rows.as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                println!("No LLM invocations recorded.");
                return Ok(());
            }
            for row in &rows {
                let get_str = |key: &str| row.get(key).and_then(|v| v.as_str()).unwrap_or("-");
                println!(
                    "{}",
                    format_llm_invocation_line(
                        get_str("started_at"),
                        get_str("id"),
                        get_str("action"),
                        get_str("status"),
                        row.get("duration_ms").and_then(|v| v.as_i64()),
                    )
                );
            }
        }
    }
    Ok(())
}

/// `cortex assess skill <skill>` — LLM-guarded skill-incident assessment.
/// Resolves the highest-priority (or all, with `--all`) matching skill
/// incident via `CortexService::run_skill_assessment_with_delta`, which
/// itself sources evidence from `investigate_ai_skill_incidents` (PR 3) and
/// runs the guarded LLM assessment through `LlmRunner` (PR 1). LLM
/// assessment is local-only — `--http` is rejected unless `--no-llm` is
/// also passed (mirrors `run_ai_assess`'s guard exactly).
pub(crate) async fn run_assess_skill(mode: &CliMode, args: AssessSkillArgs) -> Result<()> {
    let run_llm = !args.no_llm;
    if run_llm && let CliMode::Http(_) = mode {
        bail!(
            "cortex assess skill runs the LLM selected by CORTEX_LLM on the local host; omit --http or pass --no-llm"
        );
    }
    let req = SkillAssessRequest {
        skill: args.skill.clone(),
        plugin: args.plugin.clone(),
        model: args.model.clone(),
        project: args.project.clone(),
        tool: args.tool.clone(),
        since: args.since.clone(),
        until: args.until.clone(),
        window_minutes: args.window_minutes,
        correlation_window_minutes: args.correlation_window_minutes,
        limit: args.limit,
        all: args.all,
    };
    let response = match mode {
        CliMode::Local(service) => {
            if args.json {
                service
                    .run_skill_assessment_with_delta(req, run_llm, |_| Ok(()))
                    .await?
            } else {
                let mut streamed = false;
                let response = service
                    .run_skill_assessment_with_delta(req, run_llm, |delta| {
                        streamed = true;
                        print!("{delta}");
                        std::io::stdout().flush()?;
                        Ok(())
                    })
                    .await?;
                if streamed
                    && !response
                        .results
                        .iter()
                        .any(|r| r.assessment.as_deref().is_some_and(|a| a.ends_with('\n')))
                {
                    println!();
                }
                response
            }
        }
        // No REST/HTTP route exists for `assess skill` in this phase. If it
        // is ever exposed over HTTP it must call the deterministic-
        // findings-only path server-side (LLM assessment stays CLI-only) —
        // the HTTP client wiring itself is future work.
        CliMode::Http(_) => {
            bail!("cortex assess skill --http is not yet implemented; run locally")
        }
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }
    for result in &response.results {
        println!("# incident {}", result.incident_id);
        if let Some(assessment) = &result.assessment {
            println!("{assessment}");
        } else {
            println!("{}", serde_json::to_string_pretty(&result.findings)?);
        }
        println!();
    }
    if !response.other_matching_incidents.is_empty() {
        eprintln!(
            "[{} other matching incident(s) not assessed; pass --all or --limit N: {}]",
            response.other_matching_incidents.len(),
            response
                .other_matching_incidents
                .iter()
                .map(|s| s.incident_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if response.no_incident_low_severity_summary {
        eprintln!("[note: single low-signal incident — no negative signals detected]");
    }
    Ok(())
}

/// `cortex assess mcp <tool-or-server>` — LLM-guarded MCP-incident
/// assessment. Resolves the highest-priority (or all, with `--all`)
/// matching MCP incident via `CortexService::run_mcp_assessment_with_delta`,
/// which itself sources evidence from `investigate_ai_mcp_incidents` and
/// runs the guarded LLM assessment through `LlmRunner`. LLM assessment
/// is local-only — `--http` is rejected unless `--no-llm` is also passed
/// (mirrors `run_assess_skill`'s guard exactly).
pub(crate) async fn run_assess_mcp(mode: &CliMode, args: AssessMcpArgs) -> Result<()> {
    let run_llm = !args.no_llm;
    if run_llm && let CliMode::Http(_) = mode {
        bail!(
            "cortex assess mcp runs the LLM selected by CORTEX_LLM on the local host; omit --http or pass --no-llm"
        );
    }
    // The bare positional `target` resolves to `mcp_server` unless a
    // `--tool-name` was given (in which case the positional is ambiguous
    // and the explicit flag wins) — mirrors `SessionsMcpInvestigateArgs`'s
    // resolution rule.
    let mcp_server = args.server.clone().or_else(|| {
        if args.tool_name.is_none() {
            args.target.clone()
        } else {
            None
        }
    });
    let req = McpAssessRequest {
        mcp_server,
        mcp_tool: None,
        tool_name: args.tool_name.clone(),
        model: args.model.clone(),
        project: args.project.clone(),
        tool: args.tool.clone(),
        since: args.since.clone(),
        until: args.until.clone(),
        window_minutes: args.window_minutes,
        correlation_window_minutes: args.correlation_window_minutes,
        limit: args.limit,
        all: args.all,
    };
    let response = match mode {
        CliMode::Local(service) => {
            if args.json {
                service
                    .run_mcp_assessment_with_delta(req, run_llm, |_| Ok(()))
                    .await?
            } else {
                let mut streamed = false;
                let response = service
                    .run_mcp_assessment_with_delta(req, run_llm, |delta| {
                        streamed = true;
                        print!("{delta}");
                        std::io::stdout().flush()?;
                        Ok(())
                    })
                    .await?;
                if streamed
                    && !response
                        .results
                        .iter()
                        .any(|r| r.assessment.as_deref().is_some_and(|a| a.ends_with('\n')))
                {
                    println!();
                }
                response
            }
        }
        CliMode::Http(_) => {
            bail!("cortex assess mcp --http is not yet implemented; run locally")
        }
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }
    for result in &response.results {
        println!("# incident {}", result.incident_id);
        if let Some(assessment) = &result.assessment {
            println!("{assessment}");
        } else {
            println!("{}", serde_json::to_string_pretty(&result.findings)?);
        }
        println!();
    }
    if !response.other_matching_incidents.is_empty() {
        eprintln!(
            "[{} other matching incident(s) not assessed; pass --all or --limit N: {}]",
            response.other_matching_incidents.len(),
            response
                .other_matching_incidents
                .iter()
                .map(|s| s.incident_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if response.no_incident_low_severity_summary {
        eprintln!("[note: single low-signal incident — no negative signals detected]");
    }
    Ok(())
}

/// `cortex assess hooks` — resolve and assess the top hook incident (or all
/// with `--all`/`--limit`). LLM assessment is local-only, mirroring
/// `run_assess_skill`. When `--collect-config` is passed, a fresh point-in-time
/// hook config inventory is collected from the local host FIRST (local mode
/// only), so config/trust evidence is available alongside runtime evidence.
pub(crate) async fn run_assess_hooks(mode: &CliMode, args: AssessHooksArgs) -> Result<()> {
    let run_llm = !args.no_llm;
    if run_llm && let CliMode::Http(_) = mode {
        bail!(
            "cortex assess hooks runs the LLM selected by CORTEX_LLM on the local host; omit --http or pass --no-llm"
        );
    }

    // Optional live config-inventory collect-then-assess. Config inventory is a
    // point-in-time host read (not backfilled from transcript history), so this
    // is the intended way to make config/trust evidence available.
    if args.collect_config {
        match mode {
            CliMode::Local(service) => {
                let inserted = service.collect_hook_config_inventory().await?;
                eprintln!("[collected {inserted} hook config-inventory row(s) from local host]");
            }
            CliMode::Http(_) => {
                bail!(
                    "cortex assess hooks --collect-config reads local host config files; omit --http"
                )
            }
        }
    }

    let req = HookAssessRequest {
        hook_event: args.hook_event.clone(),
        hook_name: args.hook_name.clone(),
        hook_source: args.hook_source.clone(),
        model: args.model.clone(),
        project: args.project.clone(),
        tool: args.tool.clone(),
        since: args.since.clone(),
        until: args.until.clone(),
        window_minutes: args.window_minutes,
        correlation_window_minutes: args.correlation_window_minutes,
        limit: args.limit,
        all: args.all,
    };
    let response = match mode {
        CliMode::Local(service) => {
            if args.json {
                service
                    .run_hook_assessment_with_delta(req, run_llm, |_| Ok(()))
                    .await?
            } else {
                let mut streamed = false;
                let response = service
                    .run_hook_assessment_with_delta(req, run_llm, |delta| {
                        streamed = true;
                        print!("{delta}");
                        std::io::stdout().flush()?;
                        Ok(())
                    })
                    .await?;
                if streamed
                    && !response
                        .results
                        .iter()
                        .any(|r| r.assessment.as_deref().is_some_and(|a| a.ends_with('\n')))
                {
                    println!();
                }
                response
            }
        }
        CliMode::Http(_) => {
            bail!("cortex assess hooks --http is not yet implemented; run locally")
        }
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }
    for result in &response.results {
        println!("# incident {}", result.incident_id);
        // Always surface the runtime-vs-config evidence basis (GH #105
        // acceptance criterion) even in the human-readable path.
        println!("evidence basis: {}", result.findings.evidence_basis);
        if let Some(assessment) = &result.assessment {
            println!("{assessment}");
        } else {
            println!("{}", serde_json::to_string_pretty(&result.findings)?);
        }
        println!();
    }
    if !response.other_matching_incidents.is_empty() {
        eprintln!(
            "[{} other matching incident(s) not assessed; pass --all or --limit N: {}]",
            response.other_matching_incidents.len(),
            response
                .other_matching_incidents
                .iter()
                .map(|s| s.incident_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if response.no_incident_low_severity_summary {
        eprintln!("[note: single low-signal incident — no negative signals detected]");
    }
    Ok(())
}

/// `cortex assess abuse` — thin UX wrapper around the existing
/// abuse-incident assessment pipeline (`list_ai_incidents` +
/// `run_assess_with_delta`, itself already `LlmRunner`-guarded).
/// Auto-picks the top-priority matching incident when `--incident-id` is
/// omitted. LLM assessment is local-only, mirroring `run_assess_skill`'s
/// and `run_ai_assess`'s guard exactly.
pub(crate) async fn run_assess_abuse(mode: &CliMode, args: AssessAbuseArgs) -> Result<()> {
    let run_llm = !args.no_llm;
    let service = match mode {
        CliMode::Http(_) if run_llm => {
            bail!(
                "cortex assess abuse runs the LLM selected by CORTEX_LLM on the local host; omit --http or pass --no-llm"
            )
        }
        CliMode::Http(_) => {
            bail!("cortex assess abuse --http is not yet implemented for --no-llm; run locally")
        }
        CliMode::Local(service) => service,
    };
    let req = cortex::app::AbuseAssessRequest {
        incident_id: args.incident_id.clone(),
        model: args.model.clone(),
        project: args.project.clone(),
        tool: args.tool.clone(),
        since: args.since.clone(),
        until: args.until.clone(),
        window_minutes: args.window_minutes,
        correlation_window_minutes: args.correlation_window_minutes,
        terms: vec![],
        limit: args.limit,
    };
    let mut streamed = false;
    let response = service
        .assess_top_abuse_incident_with_delta(req, run_llm, |delta| {
            if args.json {
                return Ok(());
            }
            streamed = true;
            print!("{delta}");
            std::io::stdout().flush()?;
            Ok(())
        })
        .await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }
    if !streamed {
        if response.assessed.assessment.is_empty() {
            println!(
                "[deterministic-only: incident {} — pass without --no-llm for a full assessment]",
                response.assessed.incident_id
            );
        } else {
            println!("{}", response.assessed.assessment);
        }
    } else if !response.assessed.assessment.ends_with('\n') {
        println!();
    }
    eprintln!(
        "\n[assessed incident={} anchors={} bundles={}]",
        response.assessed.incident_id,
        response.assessed.evidence_summary.total_anchors,
        response.assessed.evidence_summary.evidence_bundle_count,
    );
    if !response.other_matching_incidents.is_empty() {
        eprintln!(
            "[{} other matching incident(s): {}]",
            response.other_matching_incidents.len(),
            response.other_matching_incidents.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "dispatch_sessions_tests.rs"]
mod tests;
