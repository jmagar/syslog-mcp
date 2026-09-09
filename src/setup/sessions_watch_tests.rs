use super::*;
use serial_test::serial;

struct EnvGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = crate::env::var_os(name);
        crate::env::set_test_var(name, value);
        Self { name, previous }
    }

    fn remove(name: &'static str) -> Self {
        let previous = crate::env::var_os(name);
        crate::env::remove_test_var(name);
        Self { name, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => {
                crate::env::set_test_var(self.name, value);
            }
            None => {
                crate::env::remove_test_var(self.name);
            }
        }
    }
}

#[cfg(unix)]
fn write_executable(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, body).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

fn path_with_prepended(dir: &std::path::Path) -> std::ffi::OsString {
    let mut paths = vec![dir.to_path_buf()];
    if let Some(existing) = crate::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    std::env::join_paths(paths).unwrap()
}

#[test]
fn ai_watch_service_unit_tolerates_contention_burst() {
    let cortex_bin = std::path::Path::new("/home/user/.local/bin/cortex");
    let env_path = std::path::Path::new("/home/user/.config/cortex/sessions-watch.env");
    let db_path = std::path::Path::new("/home/user/.cortex/data/cortex.db");
    let state_dir = std::path::Path::new("/home/user/.local/state/cortex");
    let user_home = std::path::Path::new("/home/user");

    let unit = ai_watch_service_unit(cortex_bin, env_path, db_path, state_dir, user_home);

    // A short 5-crash budget over 300s is exactly what caused the 2026-06-29
    // incident: a burst of transient lock-contention crashes exhausted the
    // limit and the unit stayed `failed` for 3 days with no auto-restart.
    // Widen the budget so a contention burst doesn't trip permanent failure.
    assert!(
        unit.contains("StartLimitBurst=20"),
        "expected StartLimitBurst=20, got unit:\n{unit}"
    );
    assert!(
        unit.contains("StartLimitIntervalSec=600"),
        "expected StartLimitIntervalSec=600, got unit:\n{unit}"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn health_check_action_returns_ok_report_when_service_active() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    write_executable(
        &bin_dir.join("systemctl"),
        "#!/bin/sh\ncase \"$*\" in\n  *is-active*cortex-sessions-watch.service*) printf 'active\\n' ;;\n  *) printf 'inactive\\n' ;;\nesac\nexit 0\n",
    );
    let _path = EnvGuard::set("PATH", path_with_prepended(&bin_dir));
    // No CORTEX_NOTIFICATIONS_APPRISE_URL(S) set — health check must not
    // require notifications config to run, only to fire an alert.
    let _enabled = EnvGuard::remove("CORTEX_NOTIFICATIONS_ENABLED");

    let report = run_sessions_watch_service_setup(SessionsWatchServiceAction::HealthCheck)
        .await
        .unwrap();

    assert!(!report.has_errors, "expected no errors, got: {report:?}");
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn run_ai_watch_service_setup_install_check_and_remove_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let cortex_home = home.join(".cortex");
    let bin_dir = dir.path().join("bin");
    let db_path = cortex_home.join("data/cortex.db");
    std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(home.join(".claude/projects")).unwrap();
    std::fs::create_dir_all(home.join(".codex/sessions")).unwrap();
    std::fs::create_dir_all(home.join(".gemini/tmp")).unwrap();
    std::fs::create_dir_all(home.join(".gemini/antigravity/brain")).unwrap();
    std::fs::create_dir_all(home.join(".gemini/antigravity-cli/brain")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    write_executable(
        &bin_dir.join("cortex"),
        "#!/bin/sh\nif [ \"$1 $2\" = \"sessions index\" ]; then printf '{\"discovered_files\":2,\"ingested\":1,\"skipped_dupes\":1,\"parse_errors\":0,\"storage_blocked_chunks\":0,\"dropped_metadata_fields\":0,\"file_errors\":[]}\\n'; exit 0; fi\nexit 0\n",
    );
    write_executable(
        &bin_dir.join("systemctl"),
        "#!/bin/sh\ncase \"$*\" in\n  *is-active*cortex-sessions-index.timer*) printf 'inactive\\n' ;;\n  *is-enabled*cortex-sessions-index.timer*) printf 'disabled\\n' ;;\n  *is-enabled*cortex-sessions-watch.service*) printf 'enabled\\n' ;;\n  *is-active*cortex-sessions-watch.service*) printf 'active\\n' ;;\n  *) printf 'ok\\n' ;;\nesac\nexit 0\n",
    );

    let _home = EnvGuard::set("HOME", &home);
    let _cortex_home = EnvGuard::set("CORTEX_HOME", &cortex_home);
    let _db_path = EnvGuard::set("CORTEX_DB_PATH", &db_path);
    let _path = EnvGuard::set("PATH", path_with_prepended(&bin_dir));

    let install = run_sessions_watch_service_setup(SessionsWatchServiceAction::Install)
        .await
        .unwrap();
    assert_eq!(install.mode, "sessions-watch-service-install");
    assert!(install.phases.iter().any(
        |phase| phase.name == "sessions-watch-service-files" && phase.status == SetupStatus::Ok
    ));
    assert!(install.phases.iter().any(
        |phase| phase.name == "sessions-watch-initial-index" && phase.status == SetupStatus::Ok
    ));
    assert!(
        install
            .phases
            .iter()
            .any(|phase| phase.name == AI_WATCH_SERVICE_ACTIVE_PHASE && phase.detail == "active")
    );
    let env_path = home.join(".config/cortex/sessions-watch.env");
    let service_path = home.join(".config/systemd/user/cortex-sessions-watch.service");
    assert!(env_path.is_file());
    assert!(service_path.is_file());
    let service = std::fs::read_to_string(&service_path).unwrap();
    assert!(service.contains("ExecStart="));
    assert!(service.contains("sessions watch --no-initial-scan --json"));
    assert!(service.contains("ProtectHome=read-only"));
    assert!(service.contains(".gemini/tmp"));
    assert!(service.contains(".gemini/antigravity/brain"));
    assert!(service.contains(".gemini/antigravity-cli/brain"));

    let check = run_sessions_watch_service_setup(SessionsWatchServiceAction::Check)
        .await
        .unwrap();
    assert_eq!(check.mode, "sessions-watch-service-check");
    assert!(check.phases.iter().any(|phase| {
        phase.name == "sessions-watch-service-content" && phase.status == SetupStatus::Ok
    }));
    assert!(
        check
            .phases
            .iter()
            .any(|phase| phase.name == AI_WATCH_SERVICE_ENABLED_PHASE && phase.detail == "enabled")
    );

    let remove = run_sessions_watch_service_setup(SessionsWatchServiceAction::Remove)
        .await
        .unwrap();
    assert_eq!(remove.mode, "sessions-watch-service-remove");
    assert!(!env_path.exists());
    assert!(!service_path.exists());
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn run_ai_watch_service_setup_rejects_relative_db_path_before_writing_files() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let cortex_home = home.join(".cortex");
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&cortex_home).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    write_executable(&bin_dir.join("cortex"), "#!/bin/sh\nexit 0\n");

    let _home = EnvGuard::set("HOME", &home);
    let _cortex_home = EnvGuard::set("CORTEX_HOME", &cortex_home);
    let _db_path = EnvGuard::set("CORTEX_DB_PATH", "relative/cortex.db");
    let _path = EnvGuard::set("PATH", path_with_prepended(&bin_dir));

    let error = run_sessions_watch_service_setup(SessionsWatchServiceAction::Install)
        .await
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(error.to_string().contains("must be absolute"));
    assert!(!home.join(".config/cortex/sessions-watch.env").exists());
}

#[test]
#[serial]
fn ai_watch_db_path_resolution_prefers_plugin_db_when_no_env_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let cortex_home = home.join(".cortex");
    let plugin_db = home.join(".claude/plugins/data/syslog-jmagar-lab/cortex.db");
    std::fs::create_dir_all(plugin_db.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&cortex_home).unwrap();
    std::fs::write(&plugin_db, "").unwrap();

    let _db_path = EnvGuard::remove("CORTEX_DB_PATH");

    let resolved = super::super::resolve_ai_watch_db_path(&cortex_home, &home).unwrap();

    assert_eq!(resolved, plugin_db);
}
