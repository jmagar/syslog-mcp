use std::io::{self, ErrorKind};
use std::path::Path;
use std::time::Instant;

use super::firstrun::{ensure_private_dir, parse_env};
use super::sessions_watch_health::{
    build_and_run_health_check, check_doctor_timer_phases, disable_and_remove_doctor_timer,
    install_and_enable_doctor_timer,
};
pub(crate) use super::sessions_watch_legacy::{
    ai_index_timer_disabled_phase, legacy_ai_systemd_units_absent_phase,
};
use super::systemd::{systemctl_user_phase, systemctl_user_required_named_phase};
use super::{
    AI_WATCH_SERVICE_ACTIVE_PHASE, AI_WATCH_SERVICE_ENABLED_PHASE, PhaseTimer,
    SessionsWatchServiceAction, SetupIssueKind, SetupPhase, SetupReport, SetupStatus,
    check_file_phase, host_local_report_input, setup_path_value, setup_report,
    should_skip_ai_watch_systemd_enable, skipped_phase,
};

pub async fn run_sessions_watch_service_setup(
    action: SessionsWatchServiceAction,
) -> io::Result<SetupReport> {
    let started = Instant::now();
    let home = super::cortex_home_dir()?;
    let env_path = home.join(".env");
    let compose_dir = home.join("compose");
    let data_dir = home.join("data");
    let user_home = super::user_home_dir()?;
    let config_dir = user_home.join(".config/cortex");
    let watch_env_path = config_dir.join("sessions-watch.env");
    let state_dir = user_home.join(".local/state/cortex");
    let systemd_dir = user_home.join(".config/systemd/user");
    let service_path = systemd_dir.join("cortex-sessions-watch.service");
    let mut phases = Vec::new();

    match action {
        SessionsWatchServiceAction::Install => {
            let cortex_bin = super::resolve_cortex_binary()?;
            let db_path = super::resolve_ai_watch_db_path(&home, &user_home)?;
            phases.push(install_ai_watch_service_files(
                &watch_env_path,
                &service_path,
                &systemd_dir,
                &state_dir,
                &cortex_bin,
                &db_path,
                &user_home,
            )?);
            phases.push(transcript_root_permissions_phase(&user_home));
            phases.push(run_ai_watch_initial_index_phase(
                &cortex_bin,
                &watch_env_path,
            ));
            if should_skip_ai_watch_systemd_enable(&phases) {
                phases.push(skipped_phase(
                    "systemd-enable",
                    "skipped because earlier AI watch install checks failed",
                ));
                let elapsed_ms = started.elapsed().as_millis();
                return Ok(setup_report(
                    host_local_report_input(
                        action.as_str(),
                        elapsed_ms,
                        home,
                        env_path,
                        compose_dir,
                        data_dir,
                    ),
                    phases,
                ));
            }
            phases.push(systemctl_user_phase(&["daemon-reload"]));
            phases.push(systemctl_user_phase(&[
                "disable",
                "--now",
                "cortex-ai-watch.service",
                "cortex-ai-index.timer",
            ]));
            phases.push(legacy_ai_systemd_units_absent_phase());
            phases.push(systemctl_user_phase(&[
                "disable",
                "--now",
                "cortex-sessions-index.timer",
            ]));
            phases.push(ai_index_timer_disabled_phase());
            phases.push(systemctl_user_phase(&[
                "reset-failed",
                "cortex-sessions-watch.service",
            ]));
            phases.push(super::systemd::systemctl_user_required_phase(&[
                "enable",
                "--now",
                "cortex-sessions-watch.service",
            ]));
            phases.push(systemctl_user_required_named_phase(
                AI_WATCH_SERVICE_ENABLED_PHASE,
                &["is-enabled", "cortex-sessions-watch.service"],
            ));
            phases.push(systemctl_user_required_named_phase(
                AI_WATCH_SERVICE_ACTIVE_PHASE,
                &["is-active", "cortex-sessions-watch.service"],
            ));
            phases.extend(install_and_enable_doctor_timer(&systemd_dir, &cortex_bin)?);
        }
        SessionsWatchServiceAction::Remove => {
            phases.push(systemctl_user_phase(&[
                "disable",
                "--now",
                "cortex-ai-watch.service",
                "cortex-ai-index.timer",
            ]));
            phases.push(systemctl_user_phase(&[
                "disable",
                "--now",
                "cortex-sessions-watch.service",
            ]));
            phases.push(remove_ai_watch_service_files(
                &watch_env_path,
                &service_path,
            )?);
            phases.extend(disable_and_remove_doctor_timer(&systemd_dir)?);
            phases.push(systemctl_user_phase(&["daemon-reload"]));
        }
        SessionsWatchServiceAction::Check => {
            let cortex_bin = super::resolve_cortex_binary()?;
            let db_path = super::resolve_ai_watch_db_path(&home, &user_home)?;
            phases.push(check_file_phase(
                "sessions-watch-env",
                &watch_env_path,
                "run cortex setup sessionswatch install",
            ));
            phases.push(check_file_phase(
                "sessions-watch-service",
                &service_path,
                "run cortex setup sessionswatch install",
            ));
            phases.push(check_ai_watch_service_content_phase(
                &watch_env_path,
                &service_path,
                &state_dir,
                &cortex_bin,
                &db_path,
                &user_home,
            ));
            phases.push(transcript_root_permissions_phase(&user_home));
            phases.push(legacy_ai_systemd_units_absent_phase());
            phases.push(ai_index_timer_disabled_phase());
            phases.push(systemctl_user_required_named_phase(
                AI_WATCH_SERVICE_ENABLED_PHASE,
                &["is-enabled", "cortex-sessions-watch.service"],
            ));
            phases.push(systemctl_user_required_named_phase(
                AI_WATCH_SERVICE_ACTIVE_PHASE,
                &["is-active", "cortex-sessions-watch.service"],
            ));
            phases.extend(check_doctor_timer_phases(&systemd_dir, &cortex_bin));
        }
        SessionsWatchServiceAction::HealthCheck => phases.push(build_and_run_health_check().await),
    }

    let elapsed_ms = started.elapsed().as_millis();
    Ok(setup_report(
        host_local_report_input(
            action.as_str(),
            elapsed_ms,
            home,
            env_path,
            compose_dir,
            data_dir,
        ),
        phases,
    ))
}

fn install_ai_watch_service_files(
    env_path: &Path,
    service_path: &Path,
    systemd_dir: &Path,
    state_dir: &Path,
    cortex_bin: &Path,
    db_path: &Path,
    user_home: &Path,
) -> io::Result<SetupPhase> {
    let timer = PhaseTimer::start("sessions-watch-service-files");
    if let Some(env_dir) = env_path.parent() {
        ensure_private_dir(env_dir)?;
    }
    ensure_private_dir(state_dir)?;
    std::fs::create_dir_all(systemd_dir)?;
    write_private_file(env_path, &ai_watch_env_file(db_path))?;
    std::fs::write(
        service_path,
        ai_watch_service_unit(cortex_bin, env_path, db_path, state_dir, user_home),
    )?;
    Ok(timer.finish(
        SetupStatus::Ok,
        format!("wrote {}, {}", env_path.display(), service_path.display()),
    ))
}

fn remove_ai_watch_service_files(env_path: &Path, service_path: &Path) -> io::Result<SetupPhase> {
    let timer = PhaseTimer::start("sessions-watch-service-files");
    for path in [env_path, service_path] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(timer.finish(SetupStatus::Ok, "removed cortex AI watch service files"))
}

pub(crate) fn check_ai_watch_service_content_phase(
    env_path: &Path,
    service_path: &Path,
    state_dir: &Path,
    cortex_bin: &Path,
    db_path: &Path,
    user_home: &Path,
) -> SetupPhase {
    let timer = PhaseTimer::start("sessions-watch-service-content");
    let expected_env = ai_watch_env_file(db_path);
    let expected_unit = ai_watch_service_unit(cortex_bin, env_path, db_path, state_dir, user_home);
    let current_env = match std::fs::read_to_string(env_path) {
        Ok(raw) => raw,
        Err(error) => return timer.finish(SetupStatus::Error, error.to_string()),
    };
    let current_unit = match std::fs::read_to_string(service_path) {
        Ok(raw) => raw,
        Err(error) => return timer.finish(SetupStatus::Error, error.to_string()),
    };
    if current_env != expected_env {
        return timer.finish(
            SetupStatus::Error,
            format!(
                "{} does not match generated AI watch environment",
                env_path.display()
            ),
        );
    }
    if current_unit != expected_unit {
        return timer.finish(
            SetupStatus::Error,
            format!(
                "{} does not match generated AI watch unit",
                service_path.display()
            ),
        );
    }
    timer.finish(
        SetupStatus::Ok,
        "AI watch service files match generated content",
    )
}

pub(crate) fn ai_watch_env_file(db_path: &Path) -> String {
    let db_path = setup_path_value(db_path).expect("validated AI watch DB path");
    format!("CORTEX_DB_PATH={db_path}\nCORTEX_DOCKER_INGEST_ENABLED=false\nRUST_LOG=warn\n")
}

pub(crate) fn ai_watch_service_unit(
    cortex_bin: &Path,
    env_path: &Path,
    db_path: &Path,
    state_dir: &Path,
    user_home: &Path,
) -> String {
    let db_dir = db_path.parent().unwrap_or_else(|| Path::new("/"));
    let env_path = setup_path_value(env_path).expect("validated AI watch env path");
    let cortex_bin = setup_path_value(cortex_bin).expect("validated cortex binary path");
    let claude_root = setup_path_value(&user_home.join(".claude/projects"))
        .expect("validated Claude transcript root");
    let codex_root = setup_path_value(&user_home.join(".codex/sessions"))
        .expect("validated Codex transcript root");
    let gemini_root =
        setup_path_value(&user_home.join(".gemini/tmp")).expect("validated Gemini transcript root");
    let antigravity_root = setup_path_value(&user_home.join(".gemini/antigravity/brain"))
        .expect("validated Antigravity transcript root");
    let antigravity_cli_root = setup_path_value(&user_home.join(".gemini/antigravity-cli/brain"))
        .expect("validated Antigravity CLI transcript root");
    let user_local_bin =
        setup_path_value(&user_home.join(".local/bin")).expect("validated user local bin path");
    let user_cargo_bin =
        setup_path_value(&user_home.join(".cargo/bin")).expect("validated user cargo bin path");
    let cargo_target_dir = setup_path_value(&state_dir.join("cargo-target"))
        .expect("validated AI watch cargo target directory");
    let db_dir = setup_path_value(db_dir).expect("validated AI watch DB directory");
    let state_dir = setup_path_value(state_dir).expect("validated AI watch state directory");
    format!(
        "[Unit]\nDescription=cortex real-time local AI transcript watch\nDocumentation=https://github.com/dinglebear-ai/cortex\nAfter=default.target\nStartLimitIntervalSec=600\nStartLimitBurst=20\n\n[Service]\nType=simple\nEnvironmentFile={env_path}\nEnvironment=PATH={user_local_bin}:{user_cargo_bin}:/usr/local/bin:/usr/bin:/bin\nEnvironment=CARGO_TARGET_DIR={cargo_target_dir}\nWorkingDirectory=/\nExecStart={cortex_bin} sessions watch --no-initial-scan --json\nRestart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nBindReadOnlyPaths=-{claude_root} -{codex_root} -{gemini_root} -{antigravity_root} -{antigravity_cli_root}\nBindPaths={db_dir} {state_dir}\nReadWritePaths={db_dir} {state_dir}\n\n[Install]\nWantedBy=default.target\n"
    )
}

pub(crate) fn transcript_root_permissions_phase(user_home: &Path) -> SetupPhase {
    let timer = PhaseTimer::start("ai-transcript-root-permissions");
    let roots = [
        user_home.join(".claude/projects"),
        user_home.join(".codex/sessions"),
        user_home.join(".gemini/tmp"),
        user_home.join(".gemini/antigravity/brain"),
        user_home.join(".gemini/antigravity-cli/brain"),
    ];
    let failures: Vec<String> = roots
        .iter()
        .filter_map(|root| transcript_root_permission_error(root))
        .collect();
    if failures.is_empty() {
        timer.finish(
            SetupStatus::Ok,
            "AI transcript roots are owned/readable/writable",
        )
    } else {
        timer.finish(SetupStatus::Error, failures.join("; "))
    }
}

fn transcript_root_permission_error(root: &Path) -> Option<String> {
    let metadata = match std::fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => return Some(format!("{}: {error}", root.display())),
    };
    if !metadata.is_dir() {
        return Some(format!("{} is not a directory", root.display()));
    }
    if std::fs::read_dir(root).is_err() {
        return Some(format!("{} is not readable", root.display()));
    }
    let probe = root.join(format!(".cortex-write-check-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(probe);
        }
        Err(error) => return Some(format!("{} is not writable: {error}", root.display())),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid {
            return Some(format!(
                "{} owner uid {} != current uid {}",
                root.display(),
                metadata.uid(),
                current_uid
            ));
        }
    }
    None
}

pub(crate) fn run_ai_watch_initial_index_phase(cortex_bin: &Path, env_path: &Path) -> SetupPhase {
    let timer = PhaseTimer::start("sessions-watch-initial-index");
    let env = match std::fs::read_to_string(env_path) {
        Ok(raw) => parse_env(&raw),
        Err(error) => {
            return timer.finish(
                SetupStatus::Error,
                format!("read {}: {error}", env_path.display()),
            );
        }
    };
    let mut command = crate::env::command(cortex_bin);
    command.args(["sessions", "index", "--json"]);
    for (key, value) in env {
        command.env(key, value);
    }
    match command.output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let (status, issue_kind) = ai_index_output_status(&stdout);
            timer.finish_with_issue(status, issue_kind, summarize_ai_index_output(&stdout))
        }
        Ok(output) => timer.finish_with_issue(
            SetupStatus::Error,
            Some(SetupIssueKind::BlockingError),
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("initial AI index failed")
                .to_string(),
        ),
        Err(error) => timer.finish_with_issue(
            SetupStatus::Error,
            Some(SetupIssueKind::BlockingError),
            error.to_string(),
        ),
    }
}

pub(crate) fn summarize_ai_index_output(stdout: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout) else {
        return "invalid ai index JSON output".to_string();
    };
    let summary = format!(
        "indexed files={} ingested={} duplicates={} parse_errors={} storage_blocked={} dropped_metadata_fields={} file_errors={}",
        value
            .get("discovered_files")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        value
            .get("ingested")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        value
            .get("skipped_dupes")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        value
            .get("parse_errors")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        value
            .get("storage_blocked_chunks")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        value
            .get("dropped_metadata_fields")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        value
            .get("file_errors")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len),
    );
    let (status, _) = ai_index_output_status(stdout);
    if matches!(status, SetupStatus::Warn) {
        format!(
            "{summary}; inspect with `cortex sessions errors --limit 20`, `cortex sessions checkpoints --errors`, then rerun `cortex sessions index --json` after fixes"
        )
    } else {
        summary
    }
}

pub(crate) fn ai_index_output_status(stdout: &str) -> (SetupStatus, Option<SetupIssueKind>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout) else {
        return (SetupStatus::Error, Some(SetupIssueKind::BlockingError));
    };
    if value
        .get("storage_blocked_chunks")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        > 0
    {
        return (SetupStatus::Error, Some(SetupIssueKind::BlockingError));
    }
    if value
        .get("parse_errors")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        > 0
        || value
            .get("dropped_metadata_fields")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            > 0
        || value
            .get("file_errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|errors| !errors.is_empty())
    {
        return (SetupStatus::Warn, Some(SetupIssueKind::DataQualityWarning));
    }
    (SetupStatus::Ok, None)
}

// write_private_file lives in the parent module (setup.rs) to avoid duplication.
use super::write_private_file;

#[cfg(test)]
#[path = "sessions_watch_tests.rs"]
mod tests;
