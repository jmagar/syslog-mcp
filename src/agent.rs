pub mod ai_transcript;
pub mod docker;
pub mod journald;
pub mod self_update;
pub mod shell_history;
pub mod syslog_file;
pub mod syslog_sender;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinSet;
use tokio::time::sleep;

use syslog_file::FileTailSource;
use syslog_sender::SyslogSender;

const RESTART_DELAY_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub struct AgentStreamsConfig {
    pub docker: bool,
    /// Docker endpoint.  On Linux defaults to `unix:///var/run/docker.sock`;
    /// HTTP endpoints like `http://localhost:2375` are also accepted.
    pub docker_url: String,
    pub journald: bool,
    /// Optional host syslog file to tail and forward.  Used by containerized
    /// agents that cannot read the host journal directly.
    pub syslog_file: Option<PathBuf>,
    /// Arbitrary app log files to tail, each forwarded raw under a fixed tag
    /// (`CORTEX_AGENT_FILE_TAILS`).  Replaces host-side rsyslog imfile drop-ins
    /// for file-only sources (AdGuard query log, SWAG access, fail2ban, Plex).
    pub file_tails: Vec<FileTailSource>,
    /// TCP syslog target in `host:port` form.  Derived from the heartbeat
    /// target when not set explicitly.
    pub syslog_target: String,
    /// HTTP Cortex endpoint used for durable syslog receipts.
    pub syslog_forward_target: String,
    pub syslog_forward_token: Option<String>,
    pub syslog_forward_spool_path: PathBuf,
    pub hostname: String,
    /// Forward local AI transcript (Claude/Codex) changes to the central
    /// server via `POST /v1/ai-transcripts`. Unlike the other streams this
    /// does not go through `SyslogSender` — it POSTs directly to
    /// `ai_transcript_target` (the same base URL/token as heartbeats).
    pub ai_transcripts: bool,
    pub ai_transcript_target: String,
    pub ai_transcript_token: Option<String>,
    pub ai_transcript_checkpoint_path: PathBuf,
    /// Forward the local agent-command spool (see `cortex ingest shell agent
    /// wrap`) to the central server via `POST /v1/agent-commands`, on the
    /// same interval as AI-transcript forwarding. Reuses
    /// `command_log::forward_agent_command_spool`, which was previously only
    /// reachable via a manual `cortex shell agent index --server` call that
    /// nothing scheduled.
    pub agent_command_forward: bool,
    pub agent_command_spool_path: PathBuf,
    pub agent_command_target: String,
    pub agent_command_token: Option<String>,
    /// Forward local shell history (zsh/bash + atuin) to the central server
    /// via `POST /v1/shell-history`.
    pub shell_history_forward: bool,
    pub shell_history_target: String,
    pub shell_history_token: Option<String>,
    pub shell_history_checkpoint_path: PathBuf,
}

impl AgentStreamsConfig {
    /// Derive the syslog target from an HTTP heartbeat target URL.
    ///
    /// `http://devhost:3100` → `devhost:1514`
    pub fn syslog_target_from_heartbeat(heartbeat_target: &str) -> Option<String> {
        let s = heartbeat_target.trim_end_matches('/');
        let host_part = s
            .strip_prefix("http://")
            .or_else(|| s.strip_prefix("https://"))?;
        let host = host_part.split(':').next()?.split('/').next()?;
        if host.is_empty() {
            return None;
        }
        Some(format!("{host}:1514"))
    }
}

/// Spawn Docker and/or journald log-forwarding tasks.  Each task restarts
/// automatically on failure.  Returns when all tasks exit (i.e. only on
/// shutdown / panic).
pub async fn run_agent_streams(config: AgentStreamsConfig) -> Result<()> {
    if !config.docker
        && !config.journald
        && config.syslog_file.is_none()
        && config.file_tails.is_empty()
        && !config.ai_transcripts
        && !config.agent_command_forward
        && !config.shell_history_forward
    {
        return Ok(());
    }

    let sender = Arc::new(SyslogSender::new(
        config.syslog_forward_target.clone(),
        config.syslog_forward_token.clone(),
        config.syslog_forward_spool_path.clone(),
    ));
    let mut tasks: JoinSet<()> = JoinSet::new();

    if config.docker {
        let docker_url = config.docker_url.clone();
        let hostname = config.hostname.clone();
        let sender = Arc::clone(&sender);
        tasks.spawn(async move {
            loop {
                match docker::run_docker_forwarder(&docker_url, &hostname, Arc::clone(&sender))
                    .await
                {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::warn!(error = %e, "docker forwarder exited; restarting");
                        sleep(Duration::from_secs(RESTART_DELAY_SECS)).await;
                    }
                }
            }
        });
    }

    if config.journald {
        let hostname = config.hostname.clone();
        let sender = Arc::clone(&sender);
        tasks.spawn(async move {
            loop {
                match journald::run_journald_forwarder(&hostname, Arc::clone(&sender)).await {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::warn!(error = %e, "journald forwarder exited; restarting");
                        sleep(Duration::from_secs(RESTART_DELAY_SECS)).await;
                    }
                }
            }
        });
    }

    if let Some(path) = config.syslog_file {
        let hostname = config.hostname.clone();
        let sender = Arc::clone(&sender);
        tasks.spawn(async move {
            loop {
                match syslog_file::run_syslog_file_forwarder(&path, &hostname, Arc::clone(&sender))
                    .await
                {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            error = %e,
                            "syslog file forwarder exited; restarting"
                        );
                        sleep(Duration::from_secs(RESTART_DELAY_SECS)).await;
                    }
                }
            }
        });
    }

    // One tailing task per configured app log file, each forwarded raw under
    // its fixed tag.
    for source in config.file_tails {
        let hostname = config.hostname.clone();
        let sender = Arc::clone(&sender);
        tasks.spawn(async move {
            loop {
                match syslog_file::run_file_forwarder(
                    &source.path,
                    &hostname,
                    source.tag.as_deref(),
                    Arc::clone(&sender),
                )
                .await
                {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::warn!(
                            path = %source.path.display(),
                            tag = source.tag.as_deref().unwrap_or("<syslog>"),
                            error = %e,
                            "file forwarder exited; restarting"
                        );
                        sleep(Duration::from_secs(RESTART_DELAY_SECS)).await;
                    }
                }
            }
        });
    }

    if config.ai_transcripts {
        let forward_config = ai_transcript::AiTranscriptForwardConfig {
            roots: crate::scanner::default_transcript_roots(),
            target: config.ai_transcript_target.clone(),
            token: config.ai_transcript_token.clone(),
            hostname: config.hostname.clone(),
            checkpoint_path: config.ai_transcript_checkpoint_path.clone(),
            poll_interval: Duration::from_secs(15),
        };
        tasks.spawn(async move {
            loop {
                match ai_transcript::run(forward_config.clone()).await {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::warn!(error = %e, "ai transcript forwarder exited; restarting");
                        sleep(Duration::from_secs(RESTART_DELAY_SECS)).await;
                    }
                }
            }
        });
    }

    if config.agent_command_forward {
        let spool_path = config.agent_command_spool_path.clone();
        let target = config.agent_command_target.clone();
        let token = config.agent_command_token.clone();
        tasks.spawn(async move {
            loop {
                match crate::command_log::run_agent_command_forward_loop(
                    spool_path.clone(),
                    target.clone(),
                    token.clone(),
                    Duration::from_secs(30),
                )
                .await
                {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::warn!(error = %e, "agent command forward loop exited; restarting");
                        sleep(Duration::from_secs(RESTART_DELAY_SECS)).await;
                    }
                }
            }
        });
    }

    if config.shell_history_forward {
        let forward_config = shell_history::ShellHistoryForwardConfig {
            zsh_history_path: crate::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|h| h.join(".zsh_history"))
                .filter(|p| p.exists()),
            atuin_db_path: crate::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|h| h.join(".local/share/atuin/history.db"))
                .filter(|p| p.exists()),
            target: config.shell_history_target.clone(),
            token: config.shell_history_token.clone(),
            hostname: config.hostname.clone(),
            checkpoint_path: config.shell_history_checkpoint_path.clone(),
            poll_interval: Duration::from_secs(20),
        };
        tasks.spawn(async move {
            loop {
                match shell_history::run(forward_config.clone()).await {
                    Ok(()) => return,
                    Err(e) => {
                        tracing::warn!(error = %e, "shell history forwarder exited; restarting");
                        sleep(Duration::from_secs(RESTART_DELAY_SECS)).await;
                    }
                }
            }
        });
    }

    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
#[path = "agent_tests.rs"]
mod tests;
