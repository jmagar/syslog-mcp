use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use tracing::warn;

use crate::heartbeat_agent;

use super::firstrun::parse_env;
use super::heartbeat_agent_env::{atomic_private_write, load_private_agent_env};
use super::systemd::{systemctl_user_named_phase, systemctl_user_state};
use super::{
    HeartbeatAgentAction, PhaseTimer, SetupPhase, SetupReport, SetupStatus, check_file_phase,
    host_local_report_input, setup_path_value, setup_report, write_private_file,
};

const UNIT_NAME: &str = "cortex-heartbeat-agent.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceBackend {
    Systemd,
    Launchd,
    Compose,
    Unsupported,
}

pub(crate) fn select_backend(
    os: &str,
    systemd: bool,
    gui: bool,
    compose_supported: bool,
) -> ServiceBackend {
    if os == "macos" && gui {
        ServiceBackend::Launchd
    } else if os == "linux" && systemd {
        ServiceBackend::Systemd
    } else if compose_supported {
        ServiceBackend::Compose
    } else {
        ServiceBackend::Unsupported
    }
}

fn detected_backend() -> ServiceBackend {
    let systemd = has_systemd();
    let gui = crate::env::var("CORTEX_LAUNCHD_GUI_AVAILABLE")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(cfg!(target_os = "macos"));
    let compose = crate::env::var("CORTEX_HEARTBEAT_COMPOSE_SUPPORTED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(cfg!(target_os = "linux") && !systemd);
    select_backend(std::env::consts::OS, systemd, gui, compose)
}

pub async fn run_heartbeat_agent_setup(action: HeartbeatAgentAction) -> io::Result<SetupReport> {
    let started = Instant::now();
    let home = super::cortex_home_dir()?;
    let env_path = home.join("heartbeat-agent.env");
    let compose_dir = home.join("compose");
    let data_dir = home.join("data");
    let user_home = super::user_home_dir()?;
    let unit_dir = user_home.join(".config/systemd/user");
    let unit_path = unit_dir.join(UNIT_NAME);
    let host_id_path = home.join("heartbeat-host-id");
    let managed_bin = user_home.join(".local/lib/cortex/heartbeat-agent/cortex");
    let _lifecycle_lock = if matches!(
        action,
        HeartbeatAgentAction::Install | HeartbeatAgentAction::Remove
    ) {
        Some(super::heartbeat_agent_env::acquire_heartbeat_agent_lifecycle_lock()?)
    } else {
        None
    };
    let backend = detected_backend();
    let mut phases = Vec::new();

    match action {
        HeartbeatAgentAction::Install => {
            let source_bin = super::resolve_cortex_binary()?;
            let cortex_bin = install_managed_binary(&source_bin, &managed_bin)?;
            phases.push(write_heartbeat_agent_env(&env_path)?);
            if backend == ServiceBackend::Systemd {
                std::fs::create_dir_all(&unit_dir)?;
                phases.push(write_heartbeat_agent_unit(
                    &unit_path,
                    &cortex_bin,
                    &env_path,
                    &host_id_path,
                )?);
                phases.push(systemctl_user_named_phase(
                    "heartbeat-agent-daemon-reload",
                    &["daemon-reload"],
                ));
                phases.push(systemctl_user_named_phase(
                    "heartbeat-agent-enabled",
                    &["enable", "--now", UNIT_NAME],
                ));
            } else if backend == ServiceBackend::Launchd {
                phases.extend(install_launchd(
                    &home,
                    &user_home,
                    &cortex_bin,
                    &env_path,
                    &host_id_path,
                )?);
            } else if backend == ServiceBackend::Compose {
                // No systemd (e.g. Unraid) — install as a Docker Compose service.
                let compose_dir = home.join("compose");
                std::fs::create_dir_all(&compose_dir)?;
                phases.push(write_heartbeat_agent_compose(
                    &compose_dir,
                    &cortex_bin,
                    &env_path,
                    &host_id_path,
                )?);
                phases.push(docker_compose_up_phase(&compose_dir));
            } else {
                return Err(io::Error::new(
                    ErrorKind::Unsupported,
                    "no supported heartbeat-agent service backend",
                ));
            }
        }
        HeartbeatAgentAction::Remove => {
            if backend == ServiceBackend::Launchd {
                let uid = effective_uid();
                super::launchd::bootout(uid, super::launchd::LABEL)?;
                phases.push(remove_file_phase(
                    "heartbeat-agent-plist",
                    &super::launchd::plist_path(&user_home),
                )?);
            } else if backend == ServiceBackend::Compose {
                phases.push(docker_compose_down_phase(&compose_dir));
            } else if backend == ServiceBackend::Systemd {
                phases.push(systemctl_user_named_phase(
                    "heartbeat-agent-disabled",
                    &["disable", "--now", UNIT_NAME],
                ));
                phases.push(remove_file_phase("heartbeat-agent-unit", &unit_path)?);
                phases.push(systemctl_user_named_phase(
                    "heartbeat-agent-daemon-reload",
                    &["daemon-reload"],
                ));
            }
            phases.push(remove_file_phase(
                "heartbeat-agent-managed-binary",
                &managed_bin,
            )?);
        }
        HeartbeatAgentAction::Check => {
            let cortex_bin = managed_bin.clone();
            phases.push(check_lifecycle_state(&home, backend));
            if backend == ServiceBackend::Systemd {
                phases.push(check_file_phase(
                    "heartbeat-agent-env",
                    &env_path,
                    "run cortex setup heartbeatagent install",
                ));
                phases.push(check_file_phase(
                    "heartbeat-agent-unit",
                    &unit_path,
                    "run cortex setup heartbeatagent install",
                ));
                phases.push(check_heartbeat_agent_content(
                    &unit_path,
                    &cortex_bin,
                    &env_path,
                    &host_id_path,
                ));
                phases.push(heartbeat_agent_enabled_phase());
                phases.push(heartbeat_agent_active_phase());
            } else if backend == ServiceBackend::Launchd {
                phases.extend(check_launchd(
                    &user_home,
                    &cortex_bin,
                    &env_path,
                    &host_id_path,
                ));
            } else if backend == ServiceBackend::Compose {
                phases.push(check_file_phase(
                    "heartbeat-agent-compose",
                    &compose_dir.join("docker-compose.yml"),
                    "run cortex setup heartbeatagent install",
                ));
            } else {
                phases.push(
                    PhaseTimer::start("heartbeat-agent-backend")
                        .finish(SetupStatus::Error, "unsupported backend"),
                );
            }
            phases.extend(check_capabilities_and_delivery(&env_path, backend));
        }
    }

    Ok(setup_report(
        host_local_report_input(
            action.as_str(),
            started.elapsed().as_millis(),
            home,
            env_path,
            compose_dir,
            data_dir,
        ),
        phases,
    ))
}

fn enabled(values: &std::collections::BTreeMap<String, String>, key: &str) -> bool {
    values
        .get(key)
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn check_capabilities_and_delivery(env_path: &Path, backend: ServiceBackend) -> Vec<SetupPhase> {
    let values = match load_private_agent_env(env_path) {
        Ok(values) => values,
        Err(error) => {
            return vec![PhaseTimer::start("heartbeat-agent-capabilities").finish(
                SetupStatus::Error,
                format!("managed env unreadable: {error}"),
            )];
        }
    };
    let state = |key| {
        if enabled(&values, key) {
            "enabled"
        } else {
            "disabled"
        }
    };
    let journald = if backend == ServiceBackend::Launchd {
        "n/a"
    } else {
        state("CORTEX_AGENT_JOURNALD")
    };
    let ledger = format!(
        "heartbeat=enabled; transcripts={}; docker={}; journald={journald}; shell_history={}; agent_commands={}; file_tails={}; syslog_file={}; auto_update={}",
        state(heartbeat_agent::AI_TRANSCRIPT_FORWARD_ENV),
        state("CORTEX_AGENT_DOCKER"),
        state("CORTEX_AGENT_SHELL_HISTORY_FORWARD"),
        state("CORTEX_AGENT_COMMAND_FORWARD"),
        if values
            .get("CORTEX_AGENT_FILE_TAILS")
            .is_some_and(|v| !v.trim().is_empty())
        {
            "enabled"
        } else {
            "disabled"
        },
        if values
            .get("CORTEX_AGENT_SYSLOG_FILE")
            .is_some_and(|v| !v.trim().is_empty())
        {
            "enabled"
        } else {
            "disabled"
        },
        state("CORTEX_AGENT_AUTO_UPDATE"),
    );
    let mut phases =
        vec![PhaseTimer::start("heartbeat-agent-capabilities").finish(SetupStatus::Ok, ledger)];
    if enabled(&values, heartbeat_agent::AI_TRANSCRIPT_FORWARD_ENV) {
        let checkpoint = values
            .get("CORTEX_AGENT_AI_TRANSCRIPT_CHECKPOINT")
            .map(PathBuf::from)
            .or_else(|| {
                super::cortex_home_dir()
                    .ok()
                    .map(|home| home.join("ai-transcript-forward-checkpoint.json"))
            });
        let (status, detail) = match checkpoint.and_then(|path| std::fs::metadata(path).ok()) {
            Some(metadata) => match metadata
                .modified()
                .ok()
                .and_then(|time| SystemTime::now().duration_since(time).ok())
            {
                Some(age) if age <= Duration::from_secs(120) => (
                    SetupStatus::Ok,
                    format!("checkpoint-fresh; age_secs={}", age.as_secs()),
                ),
                Some(age) => (
                    SetupStatus::Warn,
                    format!("checkpoint-stale; age_secs={}", age.as_secs()),
                ),
                None => (SetupStatus::Warn, "checkpoint-age-unavailable".to_string()),
            },
            None => (SetupStatus::Warn, "checkpoint-missing".to_string()),
        };
        phases
            .push(PhaseTimer::start("heartbeat-agent-transcript-delivery").finish(status, detail));
    }
    phases
}

fn write_heartbeat_agent_env(env_path: &Path) -> io::Result<SetupPhase> {
    let timer = PhaseTimer::start("heartbeat-agent-env");
    if let Some(parent) = env_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = if env_path.exists() {
        load_private_agent_env(env_path)?
    } else {
        Default::default()
    };
    let existing_value = |key: &str| existing.get(key).cloned();
    let target = crate::env::var("CORTEX_HEARTBEAT_TARGET")
        .ok()
        .or_else(|| existing_value("CORTEX_HEARTBEAT_TARGET"))
        .or_else(|| read_setup_env_value("CORTEX_HEARTBEAT_TARGET"))
        .unwrap_or_else(|| heartbeat_agent::DEFAULT_TARGET.to_string());
    let token = crate::env::var("CORTEX_HEARTBEAT_TOKEN")
        .ok()
        .or_else(|| existing_value("CORTEX_HEARTBEAT_TOKEN"))
        .or_else(|| read_setup_env_value("CORTEX_TOKEN"))
        .or_else(|| read_setup_env_value("CORTEX_HEARTBEAT_TOKEN"));
    let docker = crate::env::var("CORTEX_AGENT_DOCKER")
        .ok()
        .or_else(|| existing_value("CORTEX_AGENT_DOCKER"))
        .unwrap_or_else(|| "false".to_string());
    let journald = crate::env::var("CORTEX_AGENT_JOURNALD")
        .ok()
        .or_else(|| existing_value("CORTEX_AGENT_JOURNALD"))
        .unwrap_or_else(|| "false".to_string());
    let docker_url = crate::env::var("CORTEX_AGENT_DOCKER_URL")
        .ok()
        .or_else(|| existing_value("CORTEX_AGENT_DOCKER_URL"))
        .unwrap_or_else(|| heartbeat_agent::DEFAULT_DOCKER_URL.to_string());
    let rust_log = crate::env::var("RUST_LOG")
        .ok()
        .or_else(|| existing_value("RUST_LOG"))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "warn".to_string());
    let syslog_file = crate::env::var("CORTEX_AGENT_SYSLOG_FILE")
        .ok()
        .or_else(|| existing_value("CORTEX_AGENT_SYSLOG_FILE"));
    let syslog_target = crate::env::var("CORTEX_SYSLOG_TARGET")
        .ok()
        .or_else(|| existing_value("CORTEX_SYSLOG_TARGET"));
    let mut body = format!(
        "CORTEX_HEARTBEAT_TARGET={}\nRUST_LOG={}\nCORTEX_AGENT_DOCKER={}\nCORTEX_AGENT_DOCKER_URL={}\nCORTEX_AGENT_JOURNALD={}\n",
        shell_safe_value(&target)?,
        shell_safe_value(&rust_log)?,
        shell_safe_value(&docker)?,
        shell_safe_value(&docker_url)?,
        shell_safe_value(&journald)?,
    );
    if let Some(syslog_file) = syslog_file.filter(|value| !value.trim().is_empty()) {
        body.push_str(&format!(
            "CORTEX_AGENT_SYSLOG_FILE={}\n",
            shell_safe_value(&syslog_file)?
        ));
    }
    if let Some(syslog_target) = syslog_target.filter(|value| !value.trim().is_empty()) {
        body.push_str(&format!(
            "CORTEX_SYSLOG_TARGET={}\n",
            shell_safe_value(&syslog_target)?
        ));
    }
    if let Some(token) = token.filter(|value| !value.trim().is_empty()) {
        body.push_str(&format!(
            "CORTEX_HEARTBEAT_TOKEN={}\n",
            shell_safe_value(&token)?
        ));
    }
    let transcript_forward = crate::env::var(heartbeat_agent::AI_TRANSCRIPT_FORWARD_ENV)
        .ok()
        .or_else(|| existing_value(heartbeat_agent::AI_TRANSCRIPT_FORWARD_ENV))
        .or_else(|| crate::env::var(heartbeat_agent::AI_TRANSCRIPT_FORWARD_LEGACY_ENV).ok())
        .filter(|value| !value.trim().is_empty());
    if let Some(value) = transcript_forward {
        body.push_str(&format!(
            "{}={}\n",
            heartbeat_agent::AI_TRANSCRIPT_FORWARD_ENV,
            shell_safe_value(&value)?
        ));
    }
    for key in heartbeat_agent::OPTIONAL_ENV_KEYS {
        if matches!(
            *key,
            heartbeat_agent::AI_TRANSCRIPT_FORWARD_ENV
                | heartbeat_agent::AI_TRANSCRIPT_FORWARD_LEGACY_ENV
        ) {
            continue;
        }
        if let Some(value) = crate::env::var(key)
            .ok()
            .or_else(|| existing_value(key))
            .or_else(|| {
                if *key == "CORTEX_AGENT_AI_TRANSCRIPT_CHECKPOINT" {
                    super::cortex_home_dir()
                        .ok()
                        .map(|home| home.join("agent-ai-transcript-checkpoint.json"))
                        .filter(|path| path.is_file())
                        .map(|path| path.to_string_lossy().into_owned())
                } else {
                    None
                }
            })
            .filter(|v| !v.trim().is_empty())
        {
            body.push_str(&format!("{key}={}\n", shell_safe_value(&value)?));
        }
    }
    write_private_file(env_path, &body)?;
    Ok(timer.finish(SetupStatus::Ok, format!("wrote {}", env_path.display())))
}

fn write_heartbeat_agent_unit(
    unit_path: &Path,
    cortex_bin: &Path,
    env_path: &Path,
    host_id_path: &Path,
) -> io::Result<SetupPhase> {
    let timer = PhaseTimer::start("heartbeat-agent-unit");
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    atomic_private_write(
        unit_path,
        heartbeat_agent_unit(cortex_bin, env_path, host_id_path)?.as_bytes(),
        0o600,
    )?;
    Ok(timer.finish(SetupStatus::Ok, format!("wrote {}", unit_path.display())))
}

fn check_heartbeat_agent_content(
    unit_path: &Path,
    cortex_bin: &Path,
    env_path: &Path,
    host_id_path: &Path,
) -> SetupPhase {
    let timer = PhaseTimer::start("heartbeat-agent-content");
    let expected = match heartbeat_agent_unit(cortex_bin, env_path, host_id_path) {
        Ok(expected) => expected,
        Err(error) => return timer.finish(SetupStatus::Error, error.to_string()),
    };
    match std::fs::read_to_string(unit_path) {
        Ok(current) if current == expected => timer.finish(
            SetupStatus::Ok,
            "heartbeat agent unit matches generated content",
        ),
        Ok(_) => timer.finish(
            SetupStatus::Error,
            format!(
                "{} does not match generated heartbeat agent unit",
                unit_path.display()
            ),
        ),
        Err(error) => timer.finish(SetupStatus::Error, error.to_string()),
    }
}

fn heartbeat_agent_enabled_phase() -> SetupPhase {
    let timer = PhaseTimer::start("heartbeat-agent-enabled");
    match systemctl_user_state("is-enabled", UNIT_NAME).as_deref() {
        Some("enabled") => timer.finish(SetupStatus::Ok, "enabled"),
        Some(state) => timer.finish(SetupStatus::Warn, state),
        None => timer.finish(SetupStatus::Warn, "unknown"),
    }
}

fn heartbeat_agent_active_phase() -> SetupPhase {
    let timer = PhaseTimer::start("heartbeat-agent-active");
    match systemctl_user_state("is-active", UNIT_NAME).as_deref() {
        Some("active") => timer.finish(SetupStatus::Ok, "active"),
        Some(state) => timer.finish(SetupStatus::Warn, state),
        None => timer.finish(SetupStatus::Warn, "unknown"),
    }
}

fn remove_file_phase(name: &'static str, path: &Path) -> io::Result<SetupPhase> {
    let timer = PhaseTimer::start(name);
    match std::fs::remove_file(path) {
        Ok(()) => Ok(timer.finish(SetupStatus::Ok, format!("removed {}", path.display()))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(timer.finish(
            SetupStatus::Ok,
            format!("{} already absent", path.display()),
        )),
        Err(error) => Err(error),
    }
}

fn heartbeat_agent_unit(
    cortex_bin: &Path,
    env_path: &Path,
    host_id_path: &Path,
) -> io::Result<String> {
    let read_write_dir = setup_path_value(host_id_path.parent().unwrap_or_else(|| Path::new("/")))?;
    let read_write_bin_dir =
        setup_path_value(cortex_bin.parent().unwrap_or_else(|| Path::new("/")))?;
    // The agent-command-forward stream (--agent-command-forward) needs
    // read-write access to the spool's directory too, which normally lives
    // outside `~/.cortex`/`~/.local/bin` (default `~/.local/state/cortex`) —
    // without this, `ProtectHome=read-only` blocks it from ever opening the
    // spool for the truncate-after-forward step.
    let mut read_write_paths_set = vec![read_write_dir.clone(), read_write_bin_dir.clone()];
    if let Ok(spool_path) = super::default_agent_command_spool_path()
        && let Some(spool_dir) = spool_path.parent()
        && let Ok(spool_dir) = setup_path_value(spool_dir)
        && !read_write_paths_set.contains(&spool_dir)
    {
        read_write_paths_set.push(spool_dir);
    }
    let read_write_paths = read_write_paths_set.join(" ");
    let cortex_bin = setup_path_value(cortex_bin)?;
    let env_path = setup_path_value(env_path)?;
    let host_id_path = setup_path_value(host_id_path)?;
    Ok(format!(
        "[Unit]\nDescription=cortex heartbeat agent\nDocumentation=https://github.com/dinglebear-ai/cortex\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=300\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart={cortex_bin} heartbeat agent --env-file {env_path} --host-id-path {host_id_path}\nRestart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths={}\n\n[Install]\nWantedBy=default.target\n",
        read_write_paths
    ))
}

/// Returns true when systemd --user is available on this host.
fn has_systemd() -> bool {
    crate::env::command("systemctl")
        .args(["--user", "--no-pager", "status"])
        .output()
        .map(|o| o.status.code() != Some(127))
        .unwrap_or(false)
}

fn write_heartbeat_agent_compose(
    compose_dir: &Path,
    cortex_bin: &Path,
    env_path: &Path,
    host_id_path: &Path,
) -> io::Result<SetupPhase> {
    let timer = PhaseTimer::start("heartbeat-agent-compose");
    let compose_path = compose_dir.join("docker-compose.yml");
    let content = heartbeat_agent_compose(cortex_bin, env_path, host_id_path)?;
    atomic_private_write(&compose_path, content.as_bytes(), 0o600)?;
    Ok(timer.finish(SetupStatus::Ok, format!("wrote {}", compose_path.display())))
}

fn docker_compose_up_phase(compose_dir: &Path) -> SetupPhase {
    let timer = PhaseTimer::start("heartbeat-agent-docker-up");
    let result = crate::env::command("docker")
        .args(["compose", "up", "-d", "--remove-orphans"])
        .current_dir(compose_dir)
        .output();
    match result {
        Ok(out) if out.status.success() => timer.finish(SetupStatus::Ok, "container started"),
        Ok(out) => timer.finish(
            SetupStatus::Warn,
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("docker compose up failed")
                .to_string(),
        ),
        Err(e) => timer.finish(SetupStatus::Warn, e.to_string()),
    }
}

fn heartbeat_agent_compose(
    _cortex_bin: &Path,
    env_path: &Path,
    host_id_path: &Path,
) -> io::Result<String> {
    let data_dir = host_id_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/"));
    // The agent runs the published image with the binary baked in — no host
    // binary is staged or bind-mounted. `user: "0:0"` overrides the image's
    // unprivileged server user (the agent reads root-owned host files), and the
    // image's server health probe is disabled (the agent runs no HTTP server).
    let image = format!("ghcr.io/dinglebear-ai/cortex:{}", env!("CARGO_PKG_VERSION"));
    let env_path = setup_path_value(env_path)?;
    let host_id_path = setup_path_value(host_id_path)?;
    let data_dir = setup_path_value(data_dir)?;
    Ok(format!(
        "services:\n  cortex-heartbeat-agent:\n    image: {image}\n    restart: unless-stopped\n    network_mode: host\n    user: \"0:0\"\n    healthcheck:\n      disable: true\n    volumes:\n      - {data_dir}:{data_dir}\n    command:\n      - cortex\n      - heartbeat\n      - agent\n      - --env-file\n      - {env_path}\n      - --host-id-path\n      - {host_id_path}\n"
    ))
}

fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn install_managed_binary(source: &Path, destination: &Path) -> io::Result<PathBuf> {
    let bytes = std::fs::read(source)?;
    atomic_private_write(destination, &bytes, 0o755)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(destination.to_path_buf())
}

fn install_launchd(
    home: &Path,
    user_home: &Path,
    binary: &Path,
    env: &Path,
    host_id: &Path,
) -> io::Result<Vec<SetupPhase>> {
    let mut phases = Vec::new();
    let uid = effective_uid();
    let legacy_plist = super::launchd::legacy_plist_path(user_home);
    let legacy_loaded = super::launchd::print(uid, super::launchd::LEGACY_LABEL)?.is_some();
    let journal = home.join("heartbeat-agent-migration.json");
    atomic_private_write(&journal,serde_json::to_string_pretty(&serde_json::json!({"version":1,"step":"inventory","legacy_plist":legacy_plist.exists(),"legacy_loaded":legacy_loaded,"canonical_bootstrap":false,"cleanup":false})).unwrap().as_bytes(),0o600)?;
    if legacy_loaded {
        super::launchd::bootout(uid, super::launchd::LEGACY_LABEL)?;
        phases.push(
            PhaseTimer::start("heartbeat-agent-legacy-stop")
                .finish(SetupStatus::Ok, "exact legacy job stopped"),
        );
    }
    let plist = super::launchd::plist_path(user_home);
    let log_dir = home.join("logs");
    std::fs::create_dir_all(&log_dir)?;
    super::launchd::rotate_log(&log_dir.join("heartbeat-agent.log"), 10 * 1024 * 1024)?;
    let content = super::launchd::render_plist(
        binary,
        env,
        host_id,
        &log_dir.join("heartbeat-agent.log"),
        &log_dir.join("heartbeat-agent.error.log"),
    );
    super::launchd::install_plist(&plist, &content)?;
    if let Err(error) = super::launchd::bootstrap(uid, &plist) {
        let _ = super::launchd::bootout(uid, super::launchd::LABEL);
        if legacy_loaded && legacy_plist.exists() {
            let _ = super::launchd::bootstrap(uid, &legacy_plist);
        }
        atomic_private_write(&journal,serde_json::to_string_pretty(&serde_json::json!({"version":1,"step":"rollback","error":"canonical launch failed","legacy_restored":legacy_loaded})).unwrap().as_bytes(),0o600)?;
        return Err(error);
    }
    let state = super::launchd::print(uid, super::launchd::LABEL)?
        .ok_or_else(|| io::Error::other("canonical launchd job did not remain loaded"))?;
    if !state.contains("pid =") && !state.contains("state = running") {
        let _ = super::launchd::bootout(uid, super::launchd::LABEL);
        if legacy_loaded && legacy_plist.exists() {
            let _ = super::launchd::bootstrap(uid, &legacy_plist);
        }
        return Err(io::Error::other(
            "canonical launchd job has no running process",
        ));
    }
    atomic_private_write(&journal,serde_json::to_string_pretty(&serde_json::json!({"version":1,"step":"ready_for_live_proof","legacy_plist":legacy_plist.exists(),"legacy_loaded":legacy_loaded,"canonical_bootstrap":true,"cleanup":false})).unwrap().as_bytes(),0o600)?;
    phases.push(PhaseTimer::start("heartbeat-agent-launchd").finish(
        SetupStatus::Ok,
        "canonical job loaded and running; legacy assets retained until live proof",
    ));
    Ok(phases)
}

fn check_launchd(user_home: &Path, binary: &Path, env: &Path, host_id: &Path) -> Vec<SetupPhase> {
    let mut p = Vec::new();
    let uid = effective_uid();
    let plist = super::launchd::plist_path(user_home);
    p.push(check_file_phase(
        "heartbeat-agent-plist",
        &plist,
        "run cortex setup heartbeatagent install",
    ));
    let expected = super::launchd::render_plist(
        binary,
        env,
        host_id,
        &super::cortex_home_dir()
            .unwrap_or_default()
            .join("logs/heartbeat-agent.log"),
        &super::cortex_home_dir()
            .unwrap_or_default()
            .join("logs/heartbeat-agent.error.log"),
    );
    let status = match std::fs::read_to_string(&plist) {
        Ok(v) if v == expected => SetupStatus::Ok,
        Ok(_) => SetupStatus::Error,
        Err(_) => SetupStatus::Error,
    };
    p.push(
        PhaseTimer::start("heartbeat-agent-content")
            .finish(status, "launchd plist content observation"),
    );
    let canonical = super::launchd::print(uid, super::launchd::LABEL)
        .ok()
        .flatten();
    let legacy = super::launchd::print(uid, super::launchd::LEGACY_LABEL)
        .ok()
        .flatten();
    let (status, detail) = match (canonical.is_some(), legacy.is_some()) {
        (true, false) => (SetupStatus::Ok, "canonical loaded"),
        (true, true) => (
            SetupStatus::Error,
            "critical: canonical and exact legacy jobs both loaded",
        ),
        (false, true) => (SetupStatus::Warn, "legacy loaded; canonical absent"),
        (false, false) => (SetupStatus::Warn, "no heartbeat agent loaded"),
    };
    p.push(PhaseTimer::start("heartbeat-agent-service").finish(status, detail));
    p
}

fn check_lifecycle_state(home: &Path, backend: ServiceBackend) -> SetupPhase {
    let timer = PhaseTimer::start("heartbeat-agent-lifecycle");
    let journal = home.join("heartbeat-agent-migration.json");
    let lock_held = match super::heartbeat_agent_env::heartbeat_agent_lifecycle_lock_held() {
        Ok(held) => held,
        Err(error) => {
            return timer.finish(SetupStatus::Warn, format!("lock-state unreadable: {error}"));
        }
    };
    let lock_detail = if lock_held {
        "lock-active"
    } else {
        "lock-inactive"
    };
    match std::fs::read_to_string(&journal) {
        Ok(raw) => {
            let step = serde_json::from_str::<serde_json::Value>(&raw)
                .ok()
                .and_then(|v| v.get("step").and_then(|v| v.as_str()).map(str::to_owned))
                .unwrap_or_else(|| "corrupt".into());
            let canonical_recovered = backend == ServiceBackend::Launchd
                && step == "rollback"
                && super::launchd::print(effective_uid(), super::launchd::LABEL)
                    .ok()
                    .flatten()
                    .is_some()
                && super::launchd::print(effective_uid(), super::launchd::LEGACY_LABEL)
                    .ok()
                    .flatten()
                    .is_none();
            let (status, migration_detail) = match (step.as_str(), canonical_recovered) {
                ("rollback", true) => (SetupStatus::Ok, "recovered-canonical"),
                ("rollback" | "corrupt", false) => (SetupStatus::Warn, step.as_str()),
                _ => (SetupStatus::Ok, step.as_str()),
            };
            timer.finish(
                status,
                format!("{lock_detail}; migration={migration_detail}"),
            )
        }
        Err(e) if e.kind() == ErrorKind::NotFound => timer.finish(
            SetupStatus::Ok,
            format!("{lock_detail}; no migration journal"),
        ),
        Err(e) => timer.finish(
            SetupStatus::Warn,
            format!("{lock_detail}; journal unreadable: {e}"),
        ),
    }
}

fn docker_compose_down_phase(compose_dir: &Path) -> SetupPhase {
    let timer = PhaseTimer::start("heartbeat-agent-docker-down");
    match crate::env::command("docker")
        .args(["compose", "down", "--remove-orphans"])
        .current_dir(compose_dir)
        .output()
    {
        Ok(o) if o.status.success() => timer.finish(SetupStatus::Ok, "container removed"),
        Ok(_) => timer.finish(SetupStatus::Error, "docker compose down failed"),
        Err(e) => timer.finish(SetupStatus::Error, e.to_string()),
    }
}

fn read_setup_env_value(key: &str) -> Option<String> {
    let path = super::cortex_home_dir().ok()?.join(".env");
    match std::fs::read_to_string(&path) {
        Ok(raw) => parse_env(&raw).remove(key),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => {
            warn!(path = %path.display(), error = %error, "could not read env file for heartbeat setup");
            None
        }
    }
}

fn shell_safe_value(value: &str) -> io::Result<String> {
    if value
        .chars()
        .any(|ch| ch.is_control() || ch == '\n' || ch == '\r')
    {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "heartbeat environment value contains unsupported characters",
        ));
    }
    Ok(value.to_string())
}

#[cfg(test)]
#[path = "heartbeat_agent_tests.rs"]
mod tests;
