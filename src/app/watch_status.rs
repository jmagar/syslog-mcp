//! ai watch-status host probing — service-layer implementation.
//!
//! All systemctl probes route through `self.os.probe_command()` and are
//! mockable in tests via `CortexService::with_os_adapter()`. The D-Bus env
//! setup lives in `apply_dbus_env()` in `os_adapter.rs`, called from both
//! `run_command` and `probe_command`.
//!
//! journalctl failures surface as `journal_error: Some(msg)` with
//! `latest_journal` empty, so callers can distinguish a fetch error from a
//! genuinely empty journal.
//!
//! Execution order: systemctl probes first (OS-only), then DB calls.
//! This ensures the operator receives host state even during DB outages.

use std::sync::LazyLock;

use regex::Regex;
use tracing::warn;

use super::ServiceResult;
use super::models::{AiIndexingOperatorHealth, AiWatchStatusReport};
use super::services::CortexService;

const SERVICE: &str = "cortex-sessions-watch.service";
const MAX_OPERATOR_STATUS_TEXT_CHARS: usize = 240;
const MAX_OPERATOR_JOURNAL_LINES: usize = 10;

// A status response is intentionally a summary, never an evidence or
// filesystem-inspection endpoint. Keep both Unix and home-relative locators
// out of its JSON and human output after secret scrubbing.
static OPERATOR_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:~|/)[^\s\]\[\(\)\{\}"']+"#).expect("static operator path regex")
});
static OPERATOR_SECRET_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b((?:token|api[_-]?key|secret|password)\s*(?:=|:)\s*)[^\s,;]+")
        .expect("static operator secret regex")
});

impl CortexService {
    /// Collect the ai watch-status report.
    ///
    /// Always returns `Ok`. All failure modes degrade gracefully:
    /// - Systemctl probes → `None` fields on failure
    /// - `ai_indexing_health` DB failure → `health: None` with a warning
    /// - journalctl failure → `latest_journal: []`, `journal_error: Some(msg)`
    /// - `spawn_blocking` JoinError → `process_start_time: None` with a warning
    pub async fn ai_watch_status(&self) -> ServiceResult<AiWatchStatusReport> {
        // --- Systemctl probes (OS-only, no DB dependency) ---
        // All 5 are independent — run in parallel so worst-case latency is one
        // timeout period (30s) instead of 5× (150s).
        let (active, enabled, main_pid_raw, exec_start, exec_main_start_timestamp) = tokio::join!(
            self.probe_systemctl(&["is-active", SERVICE]),
            self.probe_systemctl(&["is-enabled", SERVICE]),
            self.probe_systemctl(&["show", "-p", "MainPID", "--value", SERVICE]),
            self.probe_systemctl(&["show", "-p", "ExecStart", "--value", SERVICE]),
            self.probe_systemctl(&["show", "-p", "ExecMainStartTimestamp", "--value", SERVICE]),
        );
        let main_pid = main_pid_raw
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|&pid| pid > 0);

        // --- Process start time (systemctl, no DB) ---
        // ai_watcher_process_start_time() spawns systemctl via blocking I/O.
        // Offload to the blocking thread pool so the async executor is not stalled.
        let process_start_time = match tokio::task::spawn_blocking(
            crate::doctor::ai_watcher_process_start_time,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "ai_watcher_process_start_time task panicked or was cancelled");
                None
            }
        };

        // --- DB calls (after OS probes so a DB outage doesn't block host info) ---
        // Degrade to None rather than propagating the error — the operator
        // can still see host state (active, enabled, pid) even during a DB outage.
        let (health, health_error) = match self.ai_indexing_health(process_start_time.clone()).await
        {
            Ok(h) => (Some(AiIndexingOperatorHealth::from(h)), None),
            Err(e) => {
                let msg = operator_status_text(&e.to_string());
                warn!(error = %msg, "ai_indexing_health failed; health will be absent in report");
                (None, Some(msg))
            }
        };

        // --- journalctl via run_command (degrade to empty on failure) ---
        let journal_args: Vec<String> = [
            "--user",
            "-u",
            SERVICE,
            "-n",
            "10",
            "--no-pager",
            "--output",
            "short-iso",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let (latest_journal, journal_error) =
            match self.os.run_command("journalctl", &journal_args).await {
                Ok(raw) => (
                    raw.lines()
                        .take(MAX_OPERATOR_JOURNAL_LINES)
                        .map(operator_status_text)
                        .collect(),
                    None,
                ),
                Err(e) => {
                    let msg = operator_status_text(&e.to_string());
                    warn!(service = SERVICE, error = %msg, "journalctl probe failed");
                    (Vec::new(), Some(msg))
                }
            };

        Ok(AiWatchStatusReport {
            service: SERVICE.to_string(),
            active,
            enabled,
            main_pid,
            exec_start: exec_start.map(|value| operator_status_text(&value)),
            exec_main_start_timestamp,
            process_start_time,
            health,
            health_error,
            latest_journal,
            journal_error,
        })
    }

    /// Call `systemctl --user <args>` via `probe_command` and return trimmed
    /// stdout, or `None` when the command fails and stdout is empty.
    /// Non-zero exit with non-empty stdout (e.g., "inactive") is treated as
    /// success — that is the systemctl is-active contract.
    async fn probe_systemctl(&self, args: &[&str]) -> Option<String> {
        let args_owned: Vec<String> = std::iter::once("--user")
            .chain(args.iter().copied())
            .map(str::to_string)
            .collect();

        match self.os.probe_command("systemctl", &args_owned).await {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !stdout.is_empty() {
                    Some(stdout)
                } else if output.status.success() {
                    // Command succeeded but produced no output (e.g. property not set).
                    None
                } else {
                    // Non-zero exit with empty stdout — systemctl itself errored.
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    warn!(
                        args = ?args_owned,
                        stderr = %stderr,
                        "systemctl --user exited non-zero with empty stdout"
                    );
                    None
                }
            }
            Err(e) => {
                warn!(args = ?args_owned, error = %e, "systemctl --user spawn failed");
                None
            }
        }
    }
}

fn operator_status_text(value: &str) -> String {
    let scrubbed = crate::receiver::enrichment::scrub_ai_message(value, None);
    let secrets = OPERATOR_SECRET_VALUE.replace_all(&scrubbed, "$1[REDACTED]");
    let paths = OPERATOR_PATH.replace_all(&secrets, "[PATH]");
    let mut bounded = paths
        .chars()
        .take(MAX_OPERATOR_STATUS_TEXT_CHARS)
        .collect::<String>();
    if paths.chars().count() > MAX_OPERATOR_STATUS_TEXT_CHARS {
        bounded.push('…');
    }
    bounded
}

#[cfg(test)]
#[path = "watch_status_tests.rs"]
mod tests;
