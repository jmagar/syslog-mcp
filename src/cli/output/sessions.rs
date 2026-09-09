use anyhow::Result;
use cortex::app::{IncidentResponse, ServiceLogsResponse};
use cortex::scanner::{
    AiDoctorReport, CheckpointEntry, IndexResult, ParseErrorEntry, PruneCheckpointsResult,
    TranscriptRootStatus,
};

use super::super::color::{cyan, error, muted, primary, success, violet, warn};
use super::super::sessions_watch::AiSmokeWatchReport;
use super::common::{local_ts, print_json, truncate};
use cortex::app::AiWatchStatusReport;

#[path = "sessions/validation.rs"]
mod validation;
pub(crate) use validation::{ensure_ai_doctor_success, ensure_index_success};

pub(crate) fn print_checkpoints_response(response: &[CheckpointEntry], json: bool) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{} checkpoint(s)", cyan(&response.len().to_string()));
    println!(
        "{}",
        muted(&format!(
            "{:<12} {:<8} {:<6} {:<7} {:<7} PATH",
            "KIND", "RECORDS", "PARSE", "MISSING", "ERROR"
        ))
    );
    for checkpoint in response {
        let has_error = checkpoint.last_error.is_some();
        println!(
            "{:<12} {:<8} {:<6} {:<7} {:<7} {}",
            violet(&checkpoint.source_kind),
            cyan(&checkpoint.imported_records.to_string()),
            if checkpoint.parse_errors > 0 {
                warn(&checkpoint.parse_errors.to_string())
            } else {
                muted(&checkpoint.parse_errors.to_string())
            },
            if checkpoint.missing {
                warn("yes")
            } else {
                muted("-")
            },
            if has_error { error("yes") } else { muted("-") },
            primary(&truncate(&checkpoint.canonical_path, 80)),
        );
        if let Some(err) = &checkpoint.last_error {
            println!("    {}: {}", muted("error"), error(&truncate(err, 160)));
        }
    }
    Ok(())
}

pub(crate) fn print_ai_parse_errors_response(
    response: &[ParseErrorEntry],
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{} parse error(s)", error(&response.len().to_string()));
    println!(
        "{}",
        muted(&format!(
            "{:<24} {:<8} {:<8} {:<40} ERROR",
            "SEEN", "KIND", "LINE", "PATH"
        ))
    );
    for e in response {
        println!(
            "{:<24} {:<8} {:<8} {:<40} {}",
            muted(&truncate(&e.seen_at, 23)),
            violet(&truncate(&e.source_kind, 8)),
            cyan(&e.line_no.to_string()),
            primary(&truncate(&e.canonical_path, 39)),
            error(&truncate(&e.error, 100)),
        );
        if let Some(preview) = &e.record_preview {
            println!("    {}: {}", muted("preview"), truncate(preview, 160));
        }
    }
    Ok(())
}

pub(crate) fn print_prune_checkpoints_response(
    response: &PruneCheckpointsResult,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!(
        "matched={} pruned={} dry_run={}",
        cyan(&response.matched.to_string()),
        cyan(&response.pruned.to_string()),
        primary(&response.dry_run.to_string())
    );
    for path in &response.paths {
        println!("  {}", primary(path));
    }
    Ok(())
}

fn print_transcript_root(label: &str, root: &TranscriptRootStatus) {
    println!(
        "{}: {} ({}, readable={}, writable={}, owner={:?}:{:?}, mode={:?}, strict_ok={})",
        muted(label),
        primary(&root.path),
        if root.exists {
            success("exists")
        } else {
            warn("missing")
        },
        root.readable,
        root.writable,
        root.owner_uid,
        root.owner_gid,
        root.mode.map(|m| format!("{m:o}")),
        if root.strict_ok {
            success("true")
        } else {
            warn("false")
        }
    );
}

pub(crate) fn print_ai_doctor_response(response: &AiDoctorReport, json: bool) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{}: {}", muted("db_path"), primary(&response.db_path));
    let schema_status = if response.schema_current {
        success("current")
    } else {
        warn("behind")
    };
    println!(
        "{}: {}/{} ({})",
        muted("db_schema_version"),
        cyan(&response.db_schema_version.to_string()),
        cyan(&response.known_schema_version.to_string()),
        schema_status
    );
    println!(
        "{}: {}",
        muted("db_last_migration_at"),
        primary(response.db_last_migration_at.as_deref().unwrap_or("-"))
    );
    print_transcript_root("claude_root", &response.claude_root);
    print_transcript_root("codex_root", &response.codex_root);
    print_transcript_root("gemini_root", &response.gemini_root);
    println!(
        "{}: {}",
        muted("checkpoint_count"),
        cyan(&response.checkpoint_count.to_string())
    );
    println!(
        "{}: {}",
        muted("checkpoint_error_count"),
        if response.checkpoint_error_count > 0 {
            error(&response.checkpoint_error_count.to_string())
        } else {
            cyan(&response.checkpoint_error_count.to_string())
        }
    );
    println!(
        "{}: {}",
        muted("missing_checkpoint_count"),
        if response.missing_checkpoint_count > 0 {
            warn(&response.missing_checkpoint_count.to_string())
        } else {
            cyan(&response.missing_checkpoint_count.to_string())
        }
    );
    println!(
        "{}: {}",
        muted("imported_record_count"),
        cyan(&response.imported_record_count.to_string())
    );
    println!(
        "{}: {}",
        muted("parse_error_count"),
        if response.parse_error_count > 0 {
            error(&response.parse_error_count.to_string())
        } else {
            cyan(&response.parse_error_count.to_string())
        }
    );
    println!(
        "{}: {} {}",
        muted("newest_indexed"),
        muted(response.newest_indexed_at.as_deref().unwrap_or("-")),
        primary(response.newest_indexed_path.as_deref().unwrap_or("-"))
    );
    Ok(())
}

pub(crate) fn print_sessions_watch_status_response(
    response: &AiWatchStatusReport,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{}: {}", muted("service"), primary(&response.service));
    println!(
        "{}: {}",
        muted("active"),
        primary(response.active.as_deref().unwrap_or("-"))
    );
    println!(
        "{}: {}",
        muted("enabled"),
        primary(response.enabled.as_deref().unwrap_or("-"))
    );
    println!(
        "{}: {}",
        muted("main_pid"),
        cyan(
            &response
                .main_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_string())
        )
    );
    println!(
        "{}: {}",
        muted("exec_start"),
        primary(response.exec_start.as_deref().unwrap_or("-"))
    );
    println!(
        "{}: {}",
        muted("exec_main_start_timestamp"),
        muted(response.exec_main_start_timestamp.as_deref().unwrap_or("-"))
    );
    println!(
        "{}: {}",
        muted("process_start_time"),
        muted(response.process_start_time.as_deref().unwrap_or("-"))
    );
    match response.health.as_ref() {
        Some(h) => {
            println!(
                "{}: {}/{}",
                muted("db_schema_version"),
                cyan(&h.db_schema_version.to_string()),
                cyan(&h.known_schema_version.to_string())
            );
            let drift_str = h.schema_drift_detected.to_string();
            println!(
                "{}: {}",
                muted("schema_drift_detected"),
                if h.schema_drift_detected {
                    error(&drift_str)
                } else {
                    success(&drift_str)
                }
            );
            println!(
                "{}: {}",
                muted("last_successful_ingest_at"),
                muted(h.last_successful_ingest_at.as_deref().unwrap_or("-"))
            );
            println!(
                "{}: {}",
                muted("recent_failure_count"),
                if h.recent_failure_count > 0 {
                    error(&h.recent_failure_count.to_string())
                } else {
                    cyan(&h.recent_failure_count.to_string())
                }
            );
            if !h.stale_indicators.is_empty() {
                println!(
                    "{}: {}",
                    muted("stale_indicators"),
                    warn(&h.stale_indicators.join(", "))
                );
            }
            for provider in &h.provider_coverage {
                let lanes = provider
                    .lanes
                    .iter()
                    .map(|lane| format!("{}={}", lane.lane, lane.coverage))
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{}: {} sources={} successful={} failed={} [{}]",
                    muted("provider_coverage"),
                    primary(&provider.provider),
                    provider.source_count,
                    provider.successful_sources,
                    provider.failed_sources,
                    muted(&lanes)
                );
            }
        }
        None => {
            if let Some(err) = response.health_error.as_deref() {
                println!(
                    "{}: {}",
                    muted("health"),
                    warn(&format!("unavailable ({err})"))
                );
            } else {
                println!("{}: {}", muted("health"), warn("unavailable"));
            }
        }
    }
    if let Some(err) = response.journal_error.as_deref() {
        println!(
            "{}: {}",
            muted("latest_journal"),
            warn(&format!("(unavailable: {err})"))
        );
    } else if !response.latest_journal.is_empty() {
        println!("{}:", muted("latest_journal"));
        for line in &response.latest_journal {
            println!("  {line}");
        }
    }
    Ok(())
}

pub(crate) fn print_service_logs_response(report: &ServiceLogsResponse, json: bool) -> Result<()> {
    if json {
        return print_json(report);
    }
    if report.dropped_lines > 0 {
        eprintln!(
            "warning: {} malformed journal line(s) dropped",
            warn(&report.dropped_lines.to_string())
        );
    }
    if report.entries.is_empty() {
        println!("{}: 0 journal entries", primary(&report.service));
        return Ok(());
    }
    for entry in &report.entries {
        let timestamp = entry.timestamp.as_deref().unwrap_or("-");
        let ident = entry
            .syslog_identifier
            .as_deref()
            .or(entry.unit.as_deref())
            .unwrap_or("-");
        let message = entry.message.as_deref().unwrap_or("");
        println!("{} {}: {}", muted(timestamp), primary(ident), message);
    }
    Ok(())
}

pub(crate) fn print_incident_response(response: &IncidentResponse, json: bool) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!(
        "incident around {} +/- {}m: {} event(s){}",
        muted(&response.around),
        cyan(&response.window_minutes.to_string()),
        cyan(&response.event_count.to_string()),
        if response.truncated {
            " (truncated)"
        } else {
            ""
        }
    );
    for warning in &response.warnings {
        println!("{}: {}", warn("warn"), warning);
    }
    for event in &response.events {
        let host = event.host.as_deref().unwrap_or("-");
        let sev = event.severity.as_deref().unwrap_or("-");
        let app = event.app.as_deref().unwrap_or("-");
        println!(
            "{} {} {} {} {}: {}",
            muted(&local_ts(&event.timestamp)),
            primary(&event.source),
            cyan(host),
            super::super::color::severity(sev),
            primary(app),
            event.message
        );
    }
    Ok(())
}

pub(crate) fn print_ai_smoke_watch_response(
    response: &AiSmokeWatchReport,
    json: bool,
) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!("{}: {}", muted("session_id"), primary(&response.session_id));
    println!(
        "{}: {}",
        muted("transcript_path"),
        primary(&response.transcript_path.display().to_string())
    );
    println!(
        "{}: {}",
        muted("ingested"),
        cyan(&response.ingested.to_string())
    );
    println!(
        "{}: {}",
        muted("pruned_missing_checkpoint"),
        primary(&response.pruned_missing_checkpoint.to_string())
    );
    println!(
        "{}: {}",
        muted("missing_checkpoint_count"),
        if response.missing_checkpoint_count > 0 {
            warn(&response.missing_checkpoint_count.to_string())
        } else {
            cyan(&response.missing_checkpoint_count.to_string())
        }
    );
    Ok(())
}

pub(crate) fn print_index_response(response: &IndexResult, json: bool) -> Result<()> {
    if json {
        return print_json(response);
    }
    println!(
        "files={} ingested={} duplicates={} parse_errors={} skipped={} unsupported={} symlinks={} unsafe_paths={} storage_blocked_chunks={} dropped_metadata_fields={} checkpoint_updates={} scanned_bytes={} source_budget_cap_hits={} source_deadline_exceeded={} discovery_cap_hits={} discovery_deferred_roots={} scan_budget_cap_hit={} deferred_sources={} file_errors={}",
        cyan(&response.discovered_files.to_string()),
        cyan(&response.ingested.to_string()),
        muted(&response.skipped_dupes.to_string()),
        if response.parse_errors > 0 {
            error(&response.parse_errors.to_string())
        } else {
            muted(&response.parse_errors.to_string())
        },
        muted(&response.skipped_files.to_string()),
        muted(&response.unsupported_files.to_string()),
        muted(&response.skipped_symlinks.to_string()),
        muted(&response.skipped_unsafe_paths.to_string()),
        if response.storage_blocked_chunks > 0 {
            error(&response.storage_blocked_chunks.to_string())
        } else {
            muted(&response.storage_blocked_chunks.to_string())
        },
        muted(&response.dropped_metadata_fields.to_string()),
        cyan(&response.checkpoint_updates.to_string()),
        muted(&response.scanned_bytes.to_string()),
        if response.source_budget_cap_hits > 0 {
            warn(&response.source_budget_cap_hits.to_string())
        } else {
            muted(&response.source_budget_cap_hits.to_string())
        },
        if response.source_deadline_exceeded > 0 {
            warn(&response.source_deadline_exceeded.to_string())
        } else {
            muted(&response.source_deadline_exceeded.to_string())
        },
        if response.discovery_cap_hits > 0 {
            warn(&response.discovery_cap_hits.to_string())
        } else {
            muted(&response.discovery_cap_hits.to_string())
        },
        muted(&response.discovery_deferred_roots.to_string()),
        if response.scan_budget_cap_hit {
            warn("true")
        } else {
            muted("false")
        },
        muted(&response.deferred_sources.to_string()),
        if !response.file_errors.is_empty() {
            error(&response.file_errors.len().to_string())
        } else {
            muted(&response.file_errors.len().to_string())
        }
    );
    for e in &response.file_errors {
        eprintln!(
            "{}: {}: {}",
            error("index error"),
            primary(&e.path),
            e.error
        );
    }
    Ok(())
}

pub(crate) mod hook_incidents;
pub(crate) mod mcp_incidents;
pub(crate) mod more;
pub(crate) mod skill_incidents;

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;
