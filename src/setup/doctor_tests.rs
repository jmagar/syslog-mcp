use super::*;
use crate::setup::{PhaseTimer, SetupIssueKind};
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

struct CwdGuard {
    previous: std::path::PathBuf,
}

impl CwdGuard {
    fn set(path: &Path) -> Self {
        let previous = std::env::current_dir().unwrap();
        std::env::set_current_dir(path).unwrap();
        Self { previous }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.previous).unwrap();
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
fn downgrade_dev_phase_converts_errors_to_warnings_without_issue_kind() {
    let phase = PhaseTimer::start("debug-wrapper-content").finish_with_issue(
        SetupStatus::Error,
        Some(SetupIssueKind::BlockingError),
        "stale wrapper",
    );

    let downgraded = downgrade_dev_phase(phase, "production binary installed");

    assert!(matches!(downgraded.status, SetupStatus::Warn));
    assert_eq!(downgraded.issue_kind, None);
    assert_eq!(downgraded.detail, "production binary installed");
    assert_eq!(downgraded.name, "debug-wrapper-content");
}

#[test]
fn downgrade_dev_phase_preserves_non_error_statuses() {
    let phase = PhaseTimer::start("debug-compose-content").finish(SetupStatus::Ok, "matches");

    let unchanged = downgrade_dev_phase(phase, "should not replace detail");

    assert!(matches!(unchanged.status, SetupStatus::Ok));
    assert_eq!(unchanged.detail, "matches");
}

#[test]
fn runtime_current_phase_reports_missing_script_as_error() {
    let dir = tempfile::tempdir().unwrap();

    let phase = runtime_current_phase(dir.path());

    assert!(matches!(phase.status, SetupStatus::Error));
    assert!(phase.detail.contains("scripts/check-runtime-current.sh"));
    assert!(phase.detail.contains("missing"));
}

#[cfg(unix)]
#[test]
fn runtime_current_phase_uses_last_stdout_line_on_success() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("scripts/check-runtime-current.sh");
    std::fs::create_dir_all(script.parent().unwrap()).unwrap();
    std::fs::write(&script, "#!/bin/sh\nprintf 'first\\ncurrent ok\\n'\n").unwrap();
    let mut perms = std::fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script, perms).unwrap();

    let phase = runtime_current_phase(dir.path());

    assert!(matches!(phase.status, SetupStatus::Ok));
    assert_eq!(phase.detail, "current ok");
}

#[cfg(unix)]
#[test]
fn runtime_current_phase_combines_stdout_and_stderr_on_script_failure() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("scripts/check-runtime-current.sh");
    std::fs::create_dir_all(script.parent().unwrap()).unwrap();
    write_executable(
        &script,
        "#!/bin/sh\nprintf 'stdout detail\\n'\nprintf 'stderr detail\\n' >&2\nexit 9\n",
    );

    let phase = runtime_current_phase(dir.path());

    assert!(matches!(phase.status, SetupStatus::Error));
    assert!(phase.detail.contains("stdout detail"));
    assert!(phase.detail.contains("stderr detail"));
}

#[cfg(unix)]
#[tokio::test]
#[serial]
async fn run_setup_doctor_collects_temp_home_sections_without_live_services() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let cortex_home = home.join(".cortex");
    let repo = dir.path().join("repo");
    let bin_dir = dir.path().join("bin");
    let db_path = cortex_home.join("data/cortex.db");
    std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    std::fs::create_dir_all(home.join(".claude/projects")).unwrap();
    std::fs::create_dir_all(home.join(".codex/sessions")).unwrap();
    std::fs::create_dir_all(home.join(".gemini/tmp")).unwrap();
    std::fs::create_dir_all(home.join(".gemini/antigravity/brain")).unwrap();
    std::fs::create_dir_all(home.join(".gemini/antigravity-cli/brain")).unwrap();
    std::fs::create_dir_all(repo.join("scripts")).unwrap();
    std::fs::create_dir_all(&bin_dir).unwrap();
    write_executable(
        &repo.join("scripts/check-runtime-current.sh"),
        "#!/bin/sh\nprintf 'runtime current\\n'\n",
    );
    write_executable(&bin_dir.join("cortex"), "#!/bin/sh\nexit 0\n");
    write_executable(
        &bin_dir.join("systemctl"),
        "#!/bin/sh\ncase \"$*\" in\n  *is-active*cortex-sessions-index.timer*) printf 'inactive\\n' ;;\n  *is-enabled*cortex-sessions-index.timer*) printf 'disabled\\n' ;;\n  *is-enabled*cortex-sessions-watch.service*) printf 'disabled\\n' ;;\n  *is-active*cortex-sessions-watch.service*) printf 'inactive\\n' ;;\n  *) printf 'ok\\n' ;;\nesac\nexit 0\n",
    );

    let _cwd = CwdGuard::set(&repo);
    let _home = EnvGuard::set("HOME", &home);
    let _cortex_home = EnvGuard::set("CORTEX_HOME", &cortex_home);
    let _db_path = EnvGuard::set("CORTEX_DB_PATH", &db_path);
    let _path = EnvGuard::set("PATH", path_with_prepended(&bin_dir));

    let report = run_setup_doctor(false, false).await.unwrap();

    assert_eq!(report.mode, "doctor");
    assert_eq!(report.home, cortex_home);
    assert!(
        report
            .phases
            .iter()
            .any(|phase| phase.name == "runtime-current" && phase.status == SetupStatus::Ok)
    );
    assert!(
        report
            .phases
            .iter()
            .any(|phase| phase.name == "ai-transcript-root-permissions"
                && phase.status == SetupStatus::Ok)
    );
    assert!(
        report
            .phases
            .iter()
            .any(|phase| phase.name == "sessions-watch-service-content")
    );
    assert!(
        report
            .phases
            .iter()
            .any(|phase| phase.name == "stale-agent-command-units")
    );
}

#[test]
fn stale_agent_command_grammar_detects_old_grammar_in_exec_start() {
    let unit_text = "\
[Unit]\nDescription=agent command drain\n\n[Service]\nExecStart=/usr/local/bin/cortex ingest agent-command ingest-spool --path /home/jmagar/.local/state/cortex/agent-command.jsonl\n";
    assert!(agent_command_unit_uses_stale_grammar(unit_text));
}

#[test]
fn stale_agent_command_grammar_accepts_current_grammar_in_exec_start() {
    let unit_text = "\
[Unit]\nDescription=agent command drain\n\n[Service]\nExecStart=/usr/local/bin/cortex ingest shell agent index --path /home/jmagar/.local/state/cortex/agent-command.jsonl\n";
    assert!(!agent_command_unit_uses_stale_grammar(unit_text));
}

#[test]
fn stale_agent_command_grammar_ignores_unrelated_unit_text() {
    let unit_text = "\
[Unit]\nDescription=some other timer\n\n[Service]\nExecStart=/usr/bin/true\n";
    assert!(!agent_command_unit_uses_stale_grammar(unit_text));
}

#[test]
fn stale_agent_command_grammar_ignores_mentions_outside_exec_start() {
    // A unit whose Description/comment merely *mentions* the old grammar
    // string must NOT be flagged — only the actual ExecStart= invocation
    // counts. This is the false-positive this task's ExecStart-anchored
    // check exists specifically to prevent.
    let unit_text = "\
[Unit]\nDescription=watches for agent-command ingest-spool usage in logs\n\n[Service]\nExecStart=/usr/bin/true\n";
    assert!(!agent_command_unit_uses_stale_grammar(unit_text));
}

#[test]
fn stale_agent_command_grammar_ignores_non_cortex_binary() {
    let unit_text = "\
[Unit]\nDescription=unrelated\n\n[Service]\nExecStart=/usr/bin/some-other-tool agent-command ingest-spool\n";
    assert!(!agent_command_unit_uses_stale_grammar(unit_text));
}

#[test]
fn stale_agent_command_fix_requires_yes() {
    let stale = vec!["cortex-agent-command-ingest.timer".to_string()];
    assert!(
        !should_disable(true, false, &stale),
        "fix without yes must not disable"
    );
    assert!(
        should_disable(true, true, &stale),
        "fix with yes should disable"
    );
    assert!(
        !should_disable(false, true, &stale),
        "yes alone without fix must not disable"
    );
}

// ENV-003: transcript forwarding env migration tests

#[test]
fn transcript_forward_migration_detects_legacy_only() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "CORTEX_AGENT_AI_TRANSCRIPTS=true\n").unwrap();

    let result = check_transcript_forward_env_migration(&env_path, false, false);

    assert!(matches!(result.status, SetupStatus::Warn));
    assert!(result.detail.contains("deprecated"));
    assert!(result.detail.contains("CORTEX_AGENT_AI_TRANSCRIPTS"));
    assert!(result.detail.contains("CORTEX_AGENT_AI_TRANSCRIPT_FORWARD"));
}

#[test]
fn transcript_forward_migration_detects_both_equal() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "CORTEX_AGENT_AI_TRANSCRIPTS=true\nCORTEX_AGENT_AI_TRANSCRIPT_FORWARD=true\n",
    )
    .unwrap();

    let result = check_transcript_forward_env_migration(&env_path, false, false);

    assert!(matches!(result.status, SetupStatus::Warn));
    assert!(result.detail.contains("duplicate"));
}

#[test]
fn transcript_forward_migration_detects_conflicting_values() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "CORTEX_AGENT_AI_TRANSCRIPTS=true\nCORTEX_AGENT_AI_TRANSCRIPT_FORWARD=false\n",
    )
    .unwrap();

    let result = check_transcript_forward_env_migration(&env_path, false, false);

    assert!(matches!(result.status, SetupStatus::Error));
    assert!(result.detail.contains("conflicting"));
}

#[test]
fn transcript_forward_migration_ok_when_new_only() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "CORTEX_AGENT_AI_TRANSCRIPT_FORWARD=true\n").unwrap();

    let result = check_transcript_forward_env_migration(&env_path, false, false);

    assert!(matches!(result.status, SetupStatus::Ok));
}

#[test]
fn transcript_forward_migration_ok_when_neither_set() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "CORTEX_API_TOKEN=secret\n").unwrap();

    let result = check_transcript_forward_env_migration(&env_path, false, false);

    assert!(matches!(result.status, SetupStatus::Ok));
}

#[test]
fn transcript_forward_migration_ok_when_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");

    let result = check_transcript_forward_env_migration(&env_path, false, false);

    assert!(matches!(result.status, SetupStatus::Ok));
}

#[test]
fn transcript_forward_migration_fix_requires_yes() {
    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "CORTEX_AGENT_AI_TRANSCRIPTS=true\n").unwrap();

    let result = check_transcript_forward_env_migration(&env_path, true, false);

    // Should still warn without --yes
    assert!(matches!(result.status, SetupStatus::Warn));
    assert!(result.detail.contains("--yes"));
}

#[cfg(unix)]
#[test]
fn transcript_forward_migration_fix_fails_closed_for_legacy_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "CORTEX_AGENT_AI_TRANSCRIPTS=true\n").unwrap();
    let mut perms = std::fs::metadata(&env_path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&env_path, perms).unwrap();

    let result = check_transcript_forward_env_migration(&env_path, true, true);

    assert!(matches!(result.status, SetupStatus::Error));
    assert!(result.detail.contains("automatic rewrite is disabled"));

    let content = std::fs::read_to_string(&env_path).unwrap();
    assert_eq!(content, "CORTEX_AGENT_AI_TRANSCRIPTS=true\n");

    // Verify permissions remain private
    let new_perms = std::fs::metadata(&env_path).unwrap().permissions();
    assert_eq!(new_perms.mode() & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn transcript_forward_migration_fix_preserves_comment_and_assignment() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    // A comment mentioning the legacy key as a substring, plus the real
    // legacy assignment. A whole-file str::replace would rewrite both;
    // the line-anchored migration must touch only the actual assignment.
    std::fs::write(
        &env_path,
        "# migrated from CORTEX_AGENT_AI_TRANSCRIPTS=true\nCORTEX_AGENT_AI_TRANSCRIPTS=true\n",
    )
    .unwrap();
    let mut perms = std::fs::metadata(&env_path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&env_path, perms).unwrap();

    let result = check_transcript_forward_env_migration(&env_path, true, true);

    assert!(matches!(result.status, SetupStatus::Error));

    let content = std::fs::read_to_string(&env_path).unwrap();
    assert_eq!(
        content,
        "# migrated from CORTEX_AGENT_AI_TRANSCRIPTS=true\nCORTEX_AGENT_AI_TRANSCRIPTS=true\n"
    );

    // Verify permissions remain private
    let new_perms = std::fs::metadata(&env_path).unwrap().permissions();
    assert_eq!(new_perms.mode() & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn transcript_forward_migration_fix_preserves_equal_assignments() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        "CORTEX_AGENT_AI_TRANSCRIPTS=true\nCORTEX_AGENT_AI_TRANSCRIPT_FORWARD=true\n",
    )
    .unwrap();
    let mut perms = std::fs::metadata(&env_path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&env_path, perms).unwrap();

    let result = check_transcript_forward_env_migration(&env_path, true, true);

    assert!(matches!(result.status, SetupStatus::Error));

    let content = std::fs::read_to_string(&env_path).unwrap();
    assert_eq!(
        content,
        "CORTEX_AGENT_AI_TRANSCRIPTS=true\nCORTEX_AGENT_AI_TRANSCRIPT_FORWARD=true\n"
    );

    // Verify permissions remain private
    let new_perms = std::fs::metadata(&env_path).unwrap().permissions();
    assert_eq!(new_perms.mode() & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn transcript_forward_migration_fix_errors_on_conflict() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let original = "CORTEX_AGENT_AI_TRANSCRIPTS=true\nCORTEX_AGENT_AI_TRANSCRIPT_FORWARD=false\n";
    std::fs::write(&env_path, original).unwrap();
    let mut perms = std::fs::metadata(&env_path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&env_path, perms).unwrap();

    let result = check_transcript_forward_env_migration(&env_path, true, true);

    assert!(matches!(result.status, SetupStatus::Error));
    assert!(result.detail.contains("conflicting"));

    // File should not be modified
    let content = std::fs::read_to_string(&env_path).unwrap();
    assert_eq!(content, original);
}

#[cfg(unix)]
#[test]
fn transcript_forward_migration_repeated_fix_attempts_preserve_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let env_path = dir.path().join(".env");
    std::fs::write(&env_path, "CORTEX_AGENT_AI_TRANSCRIPTS=true\n").unwrap();
    let mut perms = std::fs::metadata(&env_path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&env_path, perms).unwrap();

    // Every run fails closed without mutating operator configuration.
    let result1 = check_transcript_forward_env_migration(&env_path, true, true);
    assert!(matches!(result1.status, SetupStatus::Error));

    let content1 = std::fs::read_to_string(&env_path).unwrap();
    assert_eq!(content1, "CORTEX_AGENT_AI_TRANSCRIPTS=true\n");

    let result2 = check_transcript_forward_env_migration(&env_path, true, true);
    assert!(matches!(result2.status, SetupStatus::Error));

    let content2 = std::fs::read_to_string(&env_path).unwrap();
    assert_eq!(content1, content2);
}
