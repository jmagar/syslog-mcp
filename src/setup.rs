use serde::Serialize;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::Instant;

// `setup install` ships the *publishable* template — the local-dev
// `docker-compose.yml` extends this file to build from source.
const COMPOSE_ASSET: &str = include_str!("../docker-compose.prod.yml");
const DOCKERFILE_ASSET: &str = include_str!("../config/Dockerfile");

mod debug_wrapper;
mod doctor;
mod firstrun;
mod heartbeat_agent;
pub mod heartbeat_agent_env;
mod launchd;
mod managed_units;
mod resolve;
mod sessions_index;
mod sessions_watch;
mod sessions_watch_health;
mod sessions_watch_legacy;
mod shell_agent;
mod shell_completions;
mod systemd;
mod transcript_roots;

pub use debug_wrapper::{run_debug_compose_setup, run_debug_wrapper_setup};
pub use doctor::run_setup_doctor;
pub use firstrun::run_setup;
pub(crate) use firstrun::{
    default_env_for_data_dir, dockerfile_asset, installed_compose_asset, parse_env, render_env,
};
pub use heartbeat_agent::run_heartbeat_agent_setup;
pub use sessions_index::run_sessions_index_timer_setup;
pub use sessions_watch::run_sessions_watch_service_setup;
pub use shell_agent::run_shell_agent_setup;
pub use shell_completions::run_shell_completions_setup;

// Test-only re-exports of private items accessed via `use super::*` in setup_tests.rs.
#[cfg(test)]
pub(crate) use debug_wrapper::{
    check_debug_compose_content_phase, check_debug_wrapper_content_phase, debug_compose_override,
    debug_wrapper_script,
};
#[cfg(test)]
pub(crate) use firstrun::{
    command_phase, ensure_env_file, ensure_network_phase, filesystem_phase, health_phase,
    run_compose_phase, write_compose_assets, write_env,
};
#[cfg(test)]
pub(crate) use managed_units::{cleanup_legacy_systemd, rewrite_stale_managed_unit_commands};
#[cfg(test)]
pub(crate) use sessions_index::{ai_index_script, ai_index_service_unit, ai_index_timer_unit};
#[cfg(test)]
pub(crate) use sessions_watch::{
    ai_index_output_status, ai_watch_env_file, ai_watch_service_unit,
    check_ai_watch_service_content_phase, run_ai_watch_initial_index_phase,
    summarize_ai_index_output, transcript_root_permissions_phase,
};
#[cfg(test)]
pub(crate) use systemd::{
    inferred_user_bus_env, systemctl_user_named_phase, systemctl_user_required_named_phase,
    systemctl_user_state,
};

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupMode {
    FirstRun,
    Check,
    Repair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionsIndexTimerAction {
    Install,
    Remove,
    Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionsWatchServiceAction {
    Install,
    Remove,
    Check,
    HealthCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellAgentAction {
    Install,
    Remove,
    Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellCompletionsAction {
    Install,
    Remove,
    Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatAgentAction {
    Install,
    Remove,
    Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugWrapperAction {
    Install,
    Remove,
    Check,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugComposeAction {
    Install,
    Remove,
    Check,
}

impl DebugComposeAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "debug-compose-install",
            Self::Remove => "debug-compose-remove",
            Self::Check => "debug-compose-check",
        }
    }
}

impl DebugWrapperAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "debug-wrapper-install",
            Self::Remove => "debug-wrapper-remove",
            Self::Check => "debug-wrapper-check",
        }
    }
}

impl SessionsWatchServiceAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "sessions-watch-service-install",
            Self::Remove => "sessions-watch-service-remove",
            Self::Check => "sessions-watch-service-check",
            Self::HealthCheck => "sessions-watch-service-health-check",
        }
    }
}

impl ShellAgentAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "shell-agent-install",
            Self::Remove => "shell-agent-remove",
            Self::Check => "shell-agent-check",
        }
    }
}

impl ShellCompletionsAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "shell-completions-install",
            Self::Remove => "shell-completions-remove",
            Self::Check => "shell-completions-check",
        }
    }
}

impl HeartbeatAgentAction {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Install => "heartbeat-agent-install",
            Self::Remove => "heartbeat-agent-remove",
            Self::Check => "heartbeat-agent-check",
        }
    }
}

impl SessionsIndexTimerAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "sessions-index-timer-install",
            Self::Remove => "sessions-index-timer-remove",
            Self::Check => "sessions-index-timer-check",
        }
    }
}

impl SetupMode {
    fn mutates(self) -> bool {
        !matches!(self, Self::Check)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::FirstRun => "first-run",
            Self::Check => "check",
            Self::Repair => "repair",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    Ok,
    Warn,
    Error,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupIssueKind {
    BlockingError,
    DataQualityWarning,
    RuntimeState,
    FileState,
    Command,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupPhase {
    pub name: &'static str,
    pub status: SetupStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_kind: Option<SetupIssueKind>,
    pub detail: String,
    pub elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupReport {
    pub mode: &'static str,
    pub elapsed_ms: u128,
    pub home: PathBuf,
    pub env_path: PathBuf,
    pub compose_dir: PathBuf,
    pub data_dir: PathBuf,
    pub health_url: String,
    pub mcp_url: String,
    pub phases: Vec<SetupPhase>,
    pub has_errors: bool,
    pub blocking_errors: usize,
    pub data_quality_warnings: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watcher_healthy: Option<bool>,
}

struct SetupReportInput {
    mode: &'static str,
    elapsed_ms: u128,
    home: PathBuf,
    env_path: PathBuf,
    compose_dir: PathBuf,
    data_dir: PathBuf,
    health_url: String,
    mcp_url: String,
}

pub(crate) struct PhaseTimer {
    name: &'static str,
    start: Instant,
}

impl PhaseTimer {
    pub(crate) fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Instant::now(),
        }
    }

    pub(crate) fn finish(self, status: SetupStatus, detail: impl Into<String>) -> SetupPhase {
        self.finish_with_issue(status, None, detail)
    }

    pub(crate) fn finish_with_issue(
        self,
        status: SetupStatus,
        issue_kind: Option<SetupIssueKind>,
        detail: impl Into<String>,
    ) -> SetupPhase {
        let elapsed_ms = self.start.elapsed().as_millis();
        let detail = detail.into();
        tracing::debug!(
            phase = self.name,
            elapsed_ms,
            status = ?status,
            detail = %detail,
            "setup phase complete"
        );
        SetupPhase {
            name: self.name,
            status,
            issue_kind,
            detail,
            elapsed_ms,
        }
    }
}

fn phases_have_errors(phases: &[SetupPhase]) -> bool {
    phases
        .iter()
        .any(|phase| matches!(phase.status, SetupStatus::Error))
}

fn report_summary(phases: &[SetupPhase]) -> (bool, usize, usize) {
    let blocking_errors = phases
        .iter()
        .filter(|phase| matches!(phase.status, SetupStatus::Error))
        .count();
    let data_quality_warnings = phases
        .iter()
        .filter(|phase| matches!(phase.issue_kind, Some(SetupIssueKind::DataQualityWarning)))
        .count();
    (blocking_errors > 0, blocking_errors, data_quality_warnings)
}

fn ai_watch_service_state(phases: &[SetupPhase]) -> (Option<bool>, Option<bool>) {
    let service_enabled = phase_is_ok(phases, AI_WATCH_SERVICE_ENABLED_PHASE);
    let watcher_healthy = phase_is_ok(phases, AI_WATCH_SERVICE_ACTIVE_PHASE);
    (service_enabled, watcher_healthy)
}

fn phase_is_ok(phases: &[SetupPhase], name: &str) -> Option<bool> {
    phases
        .iter()
        .find(|phase| phase.name == name)
        .map(|phase| matches!(phase.status, SetupStatus::Ok))
}

fn should_skip_ai_watch_systemd_enable(phases: &[SetupPhase]) -> bool {
    phases_have_errors(phases)
}

fn skipped_phase(name: &'static str, detail: impl Into<String>) -> SetupPhase {
    SetupPhase {
        name,
        status: SetupStatus::Skipped,
        issue_kind: None,
        detail: detail.into(),
        elapsed_ms: 0,
    }
}

const AI_WATCH_SERVICE_ENABLED_PHASE: &str = "sessions-watch-service-enabled";
const AI_WATCH_SERVICE_ACTIVE_PHASE: &str = "sessions-watch-service-active";

fn setup_report(input: SetupReportInput, phases: Vec<SetupPhase>) -> SetupReport {
    let (has_errors, blocking_errors, data_quality_warnings) = report_summary(&phases);
    let (service_enabled, watcher_healthy) = ai_watch_service_state(&phases);
    SetupReport {
        mode: input.mode,
        elapsed_ms: input.elapsed_ms,
        home: input.home,
        env_path: input.env_path,
        compose_dir: input.compose_dir,
        data_dir: input.data_dir,
        health_url: input.health_url,
        mcp_url: input.mcp_url,
        phases,
        has_errors,
        blocking_errors,
        data_quality_warnings,
        service_enabled,
        watcher_healthy,
    }
}

fn host_local_report_input(
    mode: &'static str,
    elapsed_ms: u128,
    home: PathBuf,
    env_path: PathBuf,
    compose_dir: PathBuf,
    data_dir: PathBuf,
) -> SetupReportInput {
    SetupReportInput {
        mode,
        elapsed_ms,
        home,
        env_path,
        compose_dir,
        data_dir,
        health_url: "host-local helper".to_string(),
        mcp_url: "host-local helper".to_string(),
    }
}

fn check_file_phase(name: &'static str, path: &Path, fix: &str) -> SetupPhase {
    let timer = PhaseTimer::start(name);
    if path.exists() {
        timer.finish(SetupStatus::Ok, format!("found {}", path.display()))
    } else {
        timer.finish(
            SetupStatus::Warn,
            format!("missing {}; {fix}", path.display()),
        )
    }
}

fn setup_path_value(path: &Path) -> io::Result<String> {
    let raw = path.display().to_string();
    if raw.is_empty()
        || raw.chars().any(|ch| {
            ch.is_control() || ch.is_whitespace() || matches!(ch, '"' | '\'' | '%' | '\\')
        })
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("unsupported character in setup path: {raw}"),
        ));
    }
    Ok(raw)
}

pub(crate) use resolve::{
    EnvResult, current_uid_gid, resolve_ai_watch_db_path, resolve_cortex_binary, user_home_dir,
    write_executable_file, write_private_file,
};
pub use resolve::{cortex_home_dir, default_agent_command_spool_path};
