use anyhow::Result;
use cortex::app::{
    AbuseSearchResponse, AiCorrelateResponse, CorrelateEventsResponse, DbStats, GetErrorsResponse,
    ListAiProjectsResponse, ListAiToolsResponse, ListHostsResponse, ProjectContextResponse,
    SearchLogsResponse, SearchSessionsResponse, UsageBlocksResponse,
};

use super::super::SessionsOutputDetail;
use super::super::color::{cyan, muted, primary, severity, violet};
use super::common::{local_ts, print_json, print_log, truncate};
use super::graph::safe_display;

fn safe_session_title(title: Option<&str>, max: usize) -> String {
    truncate(
        &safe_session_field(title.unwrap_or("Untitled session")),
        max,
    )
}

fn safe_session_field(value: &str) -> String {
    safe_display(&cortex::command_log::scrub_command(value))
}

pub(crate) mod events;

pub(crate) fn print_search_response(response: &SearchLogsResponse, json: bool) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{} log(s)", cyan(&response.count.to_string()));
    for log in &response.logs {
        print_log(log);
    }
    Ok(())
}

pub(crate) fn print_errors_response(response: &GetErrorsResponse, json: bool) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{}", muted("HOST                 SEVERITY COUNT"));
    for row in &response.summary {
        println!(
            "{:<20} {:<8} {}",
            cyan(&row.hostname),
            severity(&row.severity),
            cyan(&row.count.to_string())
        );
    }
    Ok(())
}

pub(crate) fn print_hosts_response(response: &ListHostsResponse, json: bool) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{}", muted("HOST                 COUNT LAST SEEN"));
    for host in &response.hosts {
        println!(
            "{:<20} {:<5} {}",
            cyan(&host.hostname),
            cyan(&host.log_count.to_string()),
            muted(&local_ts(&host.last_seen))
        );
    }
    Ok(())
}

pub(crate) fn print_sessions_response(
    response: &cortex::app::ListSessionsResponse,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{} session(s)", cyan(&response.count.to_string()));
    if let Some(as_of) = &response.rollup_as_of {
        // Unbounded results are served from the periodically-refreshed rollup;
        // tell the operator how fresh the data is (bead cortex-2vre).
        println!("{}", muted(&format!("(as of rollup refresh {as_of})")));
    }
    println!(
        "{}",
        muted(&format!(
            "{:<32} {:<28} {:<10} {:<20} {:<15} COUNT",
            "TITLE", "PROJECT", "TOOL", "SESSION ID", "HOST"
        ))
    );
    for s in &response.sessions {
        println!(
            "{:<32} {:<28} {:<10} {:<20} {:<15} {}",
            primary(&safe_session_title(s.title.as_deref(), 31)),
            primary(&truncate(&safe_session_field(&s.project), 27)),
            violet(&safe_session_field(&s.tool)),
            muted(&truncate(&safe_session_field(&s.session_id), 19)),
            cyan(&safe_session_field(&s.hostname)),
            cyan(&s.event_count.to_string())
        );
    }
    Ok(())
}

pub(crate) fn print_search_sessions_response(
    response: &SearchSessionsResponse,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!(
        "{} grouped session(s) from {} newest matching row(s){}",
        cyan(&response.sessions.len().to_string()),
        cyan(&response.candidate_rows.to_string()),
        if response.truncated {
            " (truncated)"
        } else {
            ""
        }
    );
    if response.candidate_window_truncated {
        println!(
            "search window capped at {} matching rows; use --project, --tool, --since, or --until to narrow exact grouping",
            cyan(&response.candidate_cap.to_string())
        );
    }
    println!(
        "{}",
        muted(&format!(
            "{:<32} {:<10} {:<26} {:<18} {:<6} MATCH",
            "TITLE", "TOOL", "PROJECT", "SESSION ID", "EVENTS"
        ))
    );
    for session in &response.sessions {
        println!(
            "{:<32} {:<10} {:<26} {:<18} {:<6} {}",
            primary(&safe_session_title(session.title.as_deref(), 31)),
            violet(&safe_session_field(&session.tool)),
            primary(&truncate(&safe_session_field(&session.project), 25)),
            muted(&truncate(&safe_session_field(&session.session_id), 17)),
            cyan(&session.event_count.to_string()),
            cyan(&session.match_count.to_string())
        );
    }
    Ok(())
}

pub(crate) fn print_abuse_search_response(
    response: &AbuseSearchResponse,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!(
        "{} abuse match(es) from {} candidate row(s){}",
        cyan(&response.matches.len().to_string()),
        cyan(&response.candidate_rows.to_string()),
        if response.truncated {
            " (truncated)"
        } else {
            ""
        }
    );
    if response.candidate_window_truncated {
        println!(
            "abuse scan capped at {} candidate rows; use --project, --tool, --since, or --until to narrow it",
            cyan(&response.candidate_cap.to_string())
        );
    }
    println!(
        "{}: {}",
        muted("terms"),
        primary(&response.terms.join(", "))
    );
    for item in &response.matches {
        println!();
        println!(
            "match term={} id={} {}",
            primary(&item.term),
            cyan(&item.entry.id.to_string()),
            muted(&local_ts(&item.entry.timestamp))
        );
        for before in &item.before {
            println!("  {}:", muted("before"));
            print_log(before);
        }
        println!("  {}:", muted("hit"));
        print_log(&item.entry);
        for after in &item.after {
            println!("  {}:", muted("after"));
            print_log(after);
        }
    }
    Ok(())
}

pub(crate) fn print_ai_correlate_response(
    response: &AiCorrelateResponse,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!(
        "{} AI anchor(s), {} related non-AI event(s), +/-{}m, severity >= {}{}",
        cyan(&response.total_anchors.to_string()),
        cyan(&response.total_related_events.to_string()),
        cyan(&response.window_minutes.to_string()),
        primary(&response.severity_min),
        if response.anchors_truncated {
            " (anchors truncated)"
        } else {
            ""
        }
    );
    for anchor in &response.anchors {
        println!();
        println!(
            "AI anchor id={} {} window={}..{}{}",
            cyan(&anchor.entry.id.to_string()),
            muted(&local_ts(&anchor.entry.timestamp)),
            muted(&local_ts(&anchor.window_from)),
            muted(&local_ts(&anchor.window_to)),
            if anchor.related_truncated {
                " (related truncated)"
            } else {
                ""
            }
        );
        print_log(&anchor.entry);
        for log in &anchor.related {
            print_log(log);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UsageBlocksPrintOptions {
    pub detail: SessionsOutputDetail,
    pub limit: Option<usize>,
}

impl Default for UsageBlocksPrintOptions {
    fn default() -> Self {
        // Compact matches the CLI default for `ai blocks` (SessionsBlocksArgs). Leaving
        // this `Full` was a footgun: any call site using `..Default::default()`
        // would silently disable the intended capping/truncation.
        Self {
            detail: SessionsOutputDetail::Compact,
            limit: None,
        }
    }
}

pub(crate) fn print_usage_blocks_response_with_options(
    response: &UsageBlocksResponse,
    json: bool,
    options: UsageBlocksPrintOptions,
) -> Result<()> {
    let mut projected = response.clone();
    if let Some(limit) = options.limit {
        if projected.blocks.len() > limit {
            projected.blocks.truncate(limit);
            projected.truncated = true;
        }
    } else if options.detail.is_compact() && projected.blocks.len() > 25 {
        projected.blocks.truncate(25);
        projected.truncated = true;
    }
    if json {
        return print_json(&projected);
    }
    println!(
        "{} usage block(s) shown of {}{}",
        cyan(&projected.blocks.len().to_string()),
        cyan(&projected.total_blocks.to_string()),
        if projected.truncated {
            " (truncated)"
        } else {
            ""
        }
    );
    for block in &projected.blocks {
        println!(
            "{} {} {} {} events={} sessions={}",
            muted(&block.bucket_start),
            muted(&block.bucket_end),
            violet(&block.tool),
            primary(&truncate(&block.project, 30)),
            cyan(&block.event_count.to_string()),
            cyan(&block.session_count.to_string())
        );
    }
    Ok(())
}

pub(crate) fn print_project_context_response(
    response: &ProjectContextResponse,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{}: {}", muted("project"), primary(&response.project));
    println!(
        "{}: {}",
        muted("event_count"),
        cyan(&response.event_count.to_string())
    );
    println!("{}: {}", muted("tools"), violet(&response.tools.join(", ")));
    println!(
        "{}: {}",
        muted("sessions"),
        cyan(&response.sessions.len().to_string())
    );
    println!(
        "{}: {}",
        muted("hosts"),
        cyan(&response.hostnames.join(", "))
    );
    println!(
        "{}: {}{}",
        muted("recent_entries"),
        cyan(&response.recent_entries.len().to_string()),
        if response.recent_entries_truncated {
            " (truncated)"
        } else {
            ""
        }
    );
    for entry in &response.recent_entries {
        print_log(entry);
    }
    Ok(())
}

pub(crate) fn print_ai_tools_response(response: &ListAiToolsResponse, json: bool) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!(
        "{} tool(s) shown of {}{}",
        cyan(&response.tools.len().to_string()),
        cyan(&response.total_tools.to_string()),
        if response.truncated {
            " (truncated)"
        } else {
            ""
        }
    );
    println!("{}", muted("TOOL       EVENTS SESSIONS LAST SEEN"));
    for tool in &response.tools {
        println!(
            "{:<10} {:<6} {:<8} {}",
            violet(&tool.tool),
            cyan(&tool.event_count.to_string()),
            cyan(&tool.session_count.to_string()),
            muted(&local_ts(&tool.last_seen))
        );
    }
    Ok(())
}

pub(crate) fn print_ai_projects_response(
    response: &ListAiProjectsResponse,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!(
        "{} project(s) shown of {}{}",
        cyan(&response.projects.len().to_string()),
        cyan(&response.total_projects.to_string()),
        if response.truncated {
            " (truncated)"
        } else {
            ""
        }
    );
    println!(
        "{}",
        muted("PROJECT                          EVENTS SESSIONS TOOLS")
    );
    for project in &response.projects {
        println!(
            "{:<32} {:<6} {:<8} {}",
            primary(&truncate(&project.project, 32)),
            cyan(&project.event_count.to_string()),
            cyan(&project.session_count.to_string()),
            violet(&project.tools.join(","))
        );
    }
    Ok(())
}

pub(crate) fn print_correlate_response(
    response: &CorrelateEventsResponse,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!(
        "{} event(s) across {} host(s), window {} to {}, severity >= {}{}",
        cyan(&response.total_events.to_string()),
        cyan(&response.hosts_count.to_string()),
        muted(&response.window_from),
        muted(&response.window_to),
        primary(&response.severity_min),
        if response.truncated {
            " (truncated)"
        } else {
            ""
        }
    );
    for host in &response.hosts {
        println!();
        println!(
            "{} ({} event(s))",
            cyan(&host.hostname),
            cyan(&host.event_count.to_string())
        );
        for log in &host.events {
            print_log(log);
        }
    }
    Ok(())
}

pub(crate) fn print_stats_response(stats: &DbStats, json: bool) -> Result<()> {
    if json {
        return print_json(stats);
    }
    println!(
        "{}: {}",
        muted("total_logs"),
        cyan(&stats.total_logs.to_string())
    );
    println!(
        "{}: {}",
        muted("total_hosts"),
        cyan(&stats.total_hosts.to_string())
    );
    println!(
        "{}: {}",
        muted("oldest_log"),
        primary(stats.oldest_log.as_deref().unwrap_or("-"))
    );
    println!(
        "{}: {}",
        muted("newest_log"),
        primary(stats.newest_log.as_deref().unwrap_or("-"))
    );
    println!(
        "{}: {}",
        muted("logical_db_size_mb"),
        cyan(&stats.logical_db_size_mb.to_string())
    );
    println!(
        "{}: {}",
        muted("physical_db_size_mb"),
        cyan(&stats.physical_db_size_mb.to_string())
    );
    println!(
        "{}: {}",
        muted("free_disk_mb"),
        primary(stats.free_disk_mb.as_deref().unwrap_or("-"))
    );
    println!(
        "{}: {}",
        muted("max_db_size_mb"),
        cyan(&stats.max_db_size_mb.to_string())
    );
    println!(
        "{}: {}",
        muted("min_free_disk_mb"),
        cyan(&stats.min_free_disk_mb.to_string())
    );
    println!(
        "{}: {}",
        muted("write_blocked"),
        primary(&stats.write_blocked.to_string())
    );
    let phantom = stats
        .phantom_fts_rows
        .map_or_else(|| "skipped".to_string(), |v| v.to_string());
    println!("{}: {}", muted("phantom_fts_rows"), cyan(&phantom));
    println!(
        "{}: {}",
        muted("agent_docker_gate_blocked_count"),
        cyan(&stats.agent_docker_gate_blocked_count.to_string())
    );
    Ok(())
}

#[cfg(test)]
#[path = "logs_tests.rs"]
mod tests;
