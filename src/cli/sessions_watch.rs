use anyhow::{Result, bail};
use cortex::app::CortexService;
use cortex::scanner::AiDoctorReport;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize)]

pub(crate) struct AiSmokeWatchReport {
    pub(crate) session_id: String,
    pub(crate) transcript_path: PathBuf,
    pub(crate) ingested: bool,
    pub(crate) pruned_missing_checkpoint: bool,
    pub(crate) missing_checkpoint_count: i64,
}

pub(crate) struct AiSmokeWatchTarget {
    pub(crate) tool: &'static str,
    #[allow(dead_code)] // retained in the target evidence and unit contract
    pub(crate) project: String,
    pub(crate) transcript_path: PathBuf,
    pub(crate) body: String,
}

pub(crate) async fn ai_smoke_watch(service: &CortexService) -> Result<AiSmokeWatchReport> {
    let doctor = service.ai_doctor().await?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let session_id = format!("syslogsmokewatch{stamp}{}", std::process::id());
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let target = smoke_watch_target(&doctor, &stamp, &session_id, &now)?;
    if let Some(parent) = target.transcript_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&target.transcript_path, &target.body)?;
    let canonical_transcript_path = target.transcript_path.canonicalize()?;

    let mut ingested = false;
    // notify's macOS backend can surface a newly-created transcript on its
    // polling fallback boundary at roughly 30 seconds. Leave a second full
    // boundary so a healthy watcher cannot lose a race with this probe.
    for _ in 0..60 {
        let response = service
            .search_sessions(cortex::app::SearchSessionsRequest {
                query: session_id.clone(),
                // The scanner canonicalizes worktree projects to their shared
                // repository root. The smoke session id is globally unique,
                // so filtering by the pre-ingest cwd would hide a successful
                // watcher ingest when Cortex is run from a linked worktree.
                project: None,
                tool: Some(target.tool.into()),
                since: None,
                until: None,
                limit: Some(5),
            })
            .await?;
        if response
            .sessions
            .iter()
            .any(|session| session.session_id == session_id)
        {
            ingested = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    if !ingested {
        let _ = std::fs::remove_file(&target.transcript_path);
        bail!("AI watch smoke file was not ingested within 60s");
    }

    std::fs::remove_file(&target.transcript_path)?;
    let canonical_transcript_path = canonical_transcript_path.to_string_lossy().to_string();
    let mut missing_checkpoint_count = i64::MAX;
    let mut pruned_missing_checkpoint = false;
    for _ in 0..60 {
        let result = service
            .prune_ai_checkpoints_checked(cortex::app::AiPruneCheckpointsRequest {
                dry_run: false,
                missing_only: true,
                limit: Some(500),
            })
            .await?;
        if result
            .paths
            .iter()
            .any(|path| path == &canonical_transcript_path)
        {
            pruned_missing_checkpoint = true;
        }
        let current_doctor = service.ai_doctor().await?;
        missing_checkpoint_count = current_doctor.missing_checkpoint_count;
        if pruned_missing_checkpoint {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    Ok(AiSmokeWatchReport {
        session_id,
        transcript_path: target.transcript_path,
        ingested,
        pruned_missing_checkpoint,
        missing_checkpoint_count,
    })
}

pub(crate) fn smoke_watch_target(
    doctor: &AiDoctorReport,
    stamp: &str,
    session_id: &str,
    now: &str,
) -> Result<AiSmokeWatchTarget> {
    let project = std::env::current_dir()
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/tmp/syslog-smoke-watch".to_string());
    if doctor.claude_root.exists && doctor.claude_root.readable && doctor.claude_root.writable {
        let root = PathBuf::from(&doctor.claude_root.path);
        let transcript_path = root.join(format!("syslog-smoke-watch-{stamp}.jsonl"));
        let body = serde_json::json!({
            "sessionId": session_id,
            "timestamp": now,
            "cwd": project.clone(),
            "content": format!("{session_id} live watcher smoke probe"),
        })
        .to_string()
            + "\n";
        return Ok(AiSmokeWatchTarget {
            tool: "claude",
            project,
            transcript_path,
            body,
        });
    }
    if doctor.codex_root.exists && doctor.codex_root.readable && doctor.codex_root.writable {
        let root = PathBuf::from(&doctor.codex_root.path);
        let transcript_path = root.join(format!("syslog-smoke-watch-{stamp}.jsonl"));
        let body = serde_json::json!({
            "type": "session_meta",
            "payload": {
                "id": session_id,
                "cwd": project.clone(),
            },
        })
        .to_string()
            + "\n"
            + &serde_json::json!({
                "type": "response_item",
                "timestamp": now,
                "payload": {
                    "id": session_id,
                    "content": [{
                        "type": "output_text",
                        "text": format!("{session_id} live watcher smoke probe"),
                    }],
                },
            })
            .to_string()
            + "\n";
        return Ok(AiSmokeWatchTarget {
            tool: "codex",
            project,
            transcript_path,
            body,
        });
    }
    bail!("no writable AI transcript root is available for smoke-watch");
}

pub(crate) fn systemctl_user_output(args: &[&str]) -> Result<String> {
    let mut command = crate::env::command("systemctl");
    command.arg("--user").args(args);
    let output = command.output()?;
    let output =
        if output.status.success() || crate::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
            output
        } else if systemctl_needs_user_bus_fallback(&output) {
            if let Some((runtime_dir, bus_address)) = inferred_user_bus_env() {
                crate::env::command("systemctl")
                    .env("XDG_RUNTIME_DIR", runtime_dir)
                    .env("DBUS_SESSION_BUS_ADDRESS", bus_address)
                    .arg("--user")
                    .args(args)
                    .output()?
            } else {
                output
            }
        } else {
            output
        };
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if output.status.success() || !stdout.is_empty() {
        return Ok(stdout);
    }
    if !output.status.success() {
        bail!(
            "systemctl --user {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(stdout)
}

fn systemctl_needs_user_bus_fallback(output: &std::process::Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr.contains("DBUS_SESSION_BUS_ADDRESS") || stderr.contains("user scope bus")
}

fn inferred_user_bus_env() -> Option<(PathBuf, String)> {
    let runtime_dir = PathBuf::from(format!("/run/user/{}", current_uid()));
    let bus = runtime_dir.join("bus");
    bus.exists()
        .then(|| (runtime_dir, format!("unix:path={}", bus.display())))
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(test)]
#[path = "sessions_watch_tests.rs"]
mod tests;
