use super::*;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
            Some(value) => crate::env::set_test_var(self.name, value),
            None => crate::env::remove_test_var(self.name),
        }
    }
}

fn write_executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

fn prepend_path(dir: &Path) -> EnvGuard {
    let previous = crate::env::var_os("PATH").unwrap_or_default();
    let mut new_path = std::ffi::OsString::from(dir.as_os_str());
    new_path.push(":");
    new_path.push(previous);
    EnvGuard::set("PATH", new_path)
}

fn write_local_binary(dir: &Path) -> PathBuf {
    let local_binary = dir.join("cortex");
    std::fs::write(&local_binary, "binary").unwrap();
    local_binary
}

fn write_successful_scp(dir: &Path) {
    write_executable(&dir.join("scp"), "#!/bin/sh\nexit 0\n");
}

fn write_logging_scp(dir: &Path) {
    write_executable(
        &dir.join("scp"),
        r#"#!/bin/sh
printf 'scp %s\n' "$*" >> "$CORTEX_TEST_AGENT_DEPLOY_LOG"
exit 0
"#,
    );
}

#[test]
fn parse_ssh_config_skips_wildcards_and_github() {
    let config = "Host *\n  ServerAliveInterval 60\n\nHost devhost\n  HostName 198.51.100.1\n\nHost github.com\n  User git\n\nHost nashost edgehost\n  User jmagar\n";
    let hosts = parse_ssh_config_hosts(config);
    assert_eq!(hosts, vec!["devhost", "nashost", "edgehost"]);
}

#[test]
fn parse_ssh_config_deduplicates() {
    let config = "Host devhost\nHost devhost\nHost nashost\n";
    let hosts = parse_ssh_config_hosts(config);
    assert_eq!(hosts, vec!["devhost", "nashost"]);
}

#[test]
fn parse_ssh_config_skips_unsafe_hosts() {
    let config = "Host devhost\nHost -bad\nHost ok-host\n";
    let hosts = parse_ssh_config_hosts(config);
    assert_eq!(hosts, vec!["devhost", "ok-host"]);
}

#[test]
fn shell_quote_escapes_single_quotes() {
    assert_eq!(shell_quote("hello"), "'hello'");
    assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
}

#[test]
fn host_probe_label_formats_reachable_with_agent() {
    let probe = HostProbe {
        host: "devhost".to_string(),
        reachable: true,
        cortex_version: Some("1.17.0".to_string()),
        agent_active: Some(true),
    };
    let label = probe.display_label();
    assert!(label.contains("✓"));
    assert!(label.contains("1.17.0"));
    assert!(label.contains("agent:active"));
}

#[test]
fn host_probe_label_formats_unreachable() {
    let probe = HostProbe {
        host: "winhost".to_string(),
        reachable: false,
        cortex_version: None,
        agent_active: None,
    };
    let label = probe.display_label();
    assert!(label.contains("✗"));
}

#[test]
fn parse_host_selection_accepts_all_and_dedupes_numbers() {
    assert_eq!(parse_host_selection("all", 3).unwrap(), vec![0, 1, 2]);
    assert_eq!(parse_host_selection("2, 1 2", 3).unwrap(), vec![0, 1]);
}

#[test]
fn parse_host_selection_rejects_empty_invalid_and_out_of_range() {
    assert!(parse_host_selection("", 3).is_err());
    assert!(parse_host_selection("wat", 3).is_err());
    assert!(parse_host_selection("0", 3).is_err());
    assert!(parse_host_selection("4", 3).is_err());
}

#[test]
fn unraid_constants_wire_socket_and_host_syslog() {
    assert_eq!(UNRAID_CONTAINER_SYSLOG, "/host/var/log/syslog");
    assert_eq!(
        crate::heartbeat_agent::DEFAULT_DOCKER_URL,
        "unix:///var/run/docker.sock"
    );
}

#[test]
#[serial]
fn deploy_syslog_target_derives_from_heartbeat_url() {
    let _guard = EnvGuard::remove("CORTEX_SYSLOG_TARGET");

    assert_eq!(
        deploy_syslog_target(Some("https://cortex.example.test:3100")),
        Some("cortex.example.test:1514".to_string())
    );
}

#[test]
#[serial]
fn deploy_syslog_target_prefers_nonblank_env_override() {
    let _guard = EnvGuard::set("CORTEX_SYSLOG_TARGET", "syslog.example.test:1514");

    assert_eq!(
        deploy_syslog_target(Some("https://cortex.example.test:3100")),
        Some("syslog.example.test:1514".to_string())
    );
}

#[test]
#[serial]
fn deploy_syslog_target_ignores_blank_env_and_falls_back_to_heartbeat() {
    let _guard = EnvGuard::set("CORTEX_SYSLOG_TARGET", "  ");

    assert_eq!(
        deploy_syslog_target(Some("https://cortex.example.test:3100/path")),
        Some("cortex.example.test:1514".to_string())
    );
}

#[test]
#[serial]
fn is_unraid_uses_ssh_probe_output() {
    let dir = tempfile::tempdir().unwrap();
    write_executable(
        &dir.path().join("ssh"),
        "#!/bin/sh\ncase \"$*\" in\n  *unraid-host*) printf 'yes\\n'; exit 0 ;;\n  *linux-host*) printf 'no\\n'; exit 0 ;;\n  *) exit 1 ;;\nesac\n",
    );
    let _path = prepend_path(dir.path());

    assert!(is_unraid("unraid-host"));
    assert!(!is_unraid("linux-host"));
    assert!(!is_unraid("unknown-host"));
}

#[test]
#[serial]
fn which_cortex_returns_nonempty_success_and_ignores_blank_or_failure() {
    let dir = tempfile::tempdir().unwrap();
    let cortex_path = PathBuf::from("/tmp/cortex-from-test");
    write_executable(
        &dir.path().join("which"),
        "#!/bin/sh\ncase \"$CORTEX_TEST_WHICH_MODE\" in\n  ok) printf '%s\\n' \"$CORTEX_TEST_CORTEX_PATH\"; exit 0 ;;\n  blank) printf '\\n'; exit 0 ;;\n  fail) exit 1 ;;\n  *) exit 2 ;;\nesac\n",
    );
    let _path = prepend_path(dir.path());
    let _cortex_path = EnvGuard::set("CORTEX_TEST_CORTEX_PATH", &cortex_path);

    {
        let _mode = EnvGuard::set("CORTEX_TEST_WHICH_MODE", "ok");
        assert_eq!(which_cortex(), Some(cortex_path.clone()));
    }
    {
        let _mode = EnvGuard::set("CORTEX_TEST_WHICH_MODE", "blank");
        assert_eq!(which_cortex(), None);
    }
    {
        let _mode = EnvGuard::set("CORTEX_TEST_WHICH_MODE", "fail");
        assert_eq!(which_cortex(), None);
    }
}

#[test]
#[serial]
fn find_local_binary_prefers_installed_cortex_from_path() {
    let dir = tempfile::tempdir().unwrap();
    let cortex_path = dir.path().join("cortex");
    write_executable(&cortex_path, "#!/bin/sh\nexit 0\n");
    write_executable(
        &dir.path().join("which"),
        "#!/bin/sh\n[ \"$1\" = cortex ] || exit 1\nprintf '%s\\n' \"$CORTEX_TEST_CORTEX_PATH\"\n",
    );
    let _path = prepend_path(dir.path());
    let _cortex_path = EnvGuard::set("CORTEX_TEST_CORTEX_PATH", &cortex_path);
    let _mode = EnvGuard::remove("CORTEX_TEST_WHICH_MODE");

    assert_eq!(find_local_binary(), Some(cortex_path));
}

#[test]
#[serial]
fn deploy_agent_to_linux_host_runs_install_sequence_with_env_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("commands.log");
    let stdin_log = dir.path().join("stdin.log");
    let local_binary = write_local_binary(dir.path());
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
printf 'ssh %s\n' "$*" >> "$CORTEX_TEST_AGENT_DEPLOY_LOG"
case "$*" in
  *"/etc/unraid-version"*) printf 'no\n'; exit 0 ;;
  *"cat >"*) cat >> "$CORTEX_TEST_AGENT_DEPLOY_STDIN"; exit 0 ;;
  *) exit 0 ;;
esac
"#,
    );
    write_logging_scp(dir.path());
    let _path = prepend_path(dir.path());
    let _log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_LOG", &log);
    let _stdin_log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_STDIN", &stdin_log);
    let _syslog = EnvGuard::remove("CORTEX_SYSLOG_TARGET");

    let result = deploy_agent_to_host(
        "linux-host",
        &local_binary,
        &AgentDeployConfig {
            target: Some("https://cortex.example.test:3100".to_string()),
            token: Some("heartbeat token".to_string()),
            require_token: false,
            docker: Some(true),
            journald: Some(true),
        },
    );

    assert!(result.ok, "{result:?}");
    assert_eq!(result.host, "linux-host");
    let log = std::fs::read_to_string(log).unwrap();
    assert!(log.contains("mkdir -p ~/.local/bin"));
    assert!(log.contains("linux-host:.local/bin/cortex.new"));
    assert!(log.contains("mv -f ~/.local/bin/cortex.new ~/.local/bin/cortex"));
    assert!(!log.contains("heartbeat token"));
    assert!(log.contains("~/.local/bin/cortex setup heartbeatagent install"));
    let env_position = log.find("cat > ~/.cortex/heartbeat-agent.env.new").unwrap();
    let install_position = log
        .find("CORTEX_SETUP_PRESERVE_HEARTBEAT_ENV=1 ~/.local/bin/cortex setup heartbeatagent install")
        .unwrap();
    assert!(env_position < install_position);
    let stdin = std::fs::read_to_string(stdin_log).unwrap_or_default();
    assert!(stdin.contains("CORTEX_HEARTBEAT_TARGET=https://cortex.example.test:3100"));
    assert!(stdin.contains("CORTEX_HEARTBEAT_TOKEN=heartbeat token"));
    assert!(stdin.contains("CORTEX_AGENT_DOCKER=true"));
    assert!(stdin.contains("CORTEX_AGENT_JOURNALD=true"));
    assert!(stdin.contains("CORTEX_SYSLOG_TARGET=cortex.example.test:1514"));
}

#[test]
#[serial]
fn deploy_agent_to_linux_host_preserves_persisted_env_without_token_profile() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("commands.log");
    let stdin_log = dir.path().join("stdin.log");
    let local_binary = write_local_binary(dir.path());
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
printf 'ssh %s\n' "$*" >> "$CORTEX_TEST_AGENT_DEPLOY_LOG"
case "$*" in
	  *"/etc/unraid-version"*) printf 'no\n'; exit 0 ;;
	  *"cat >"*) cat >> "$CORTEX_TEST_AGENT_DEPLOY_STDIN"; exit 0 ;;
	  *"heartbeat-agent.env"*)
	    printf 'CORTEX_HEARTBEAT_TARGET=https://old.example\n'
	    printf 'CORTEX_HEARTBEAT_TOKEN=preserved-token\n'
	    printf 'CORTEX_AGENT_DOCKER=true\n'
	    printf 'CORTEX_AGENT_JOURNALD=true\n'
	    printf 'CORTEX_SYSLOG_TARGET=old-syslog.example:1514\n'
	    printf 'CORTEX_AGENT_FILE_TAILS=/var/log/app.log:app\n'
	    printf 'CORTEX_AGENT_AI_TRANSCRIPTS=true\n'
	    printf 'CORTEX_AGENT_COMMAND_FORWARD=true\n'
	    printf 'CORTEX_AGENT_SHELL_HISTORY_FORWARD=true\n'
	    printf 'CORTEX_AGENT_AUTO_UPDATE=false\n'
	    exit 0
	    ;;
	  *) exit 0 ;;
	esac
"#,
    );
    write_logging_scp(dir.path());
    let _path = prepend_path(dir.path());
    let _log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_LOG", &log);
    let _stdin_log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_STDIN", &stdin_log);

    let result = deploy_agent_to_host("linux-host", &local_binary, &AgentDeployConfig::default());

    assert!(result.ok, "{result:?}");
    let log = std::fs::read_to_string(log).unwrap();
    assert!(!log.contains("preserved-token"));
    let stdin = std::fs::read_to_string(stdin_log).unwrap();
    assert!(stdin.contains("CORTEX_HEARTBEAT_TARGET=https://old.example"));
    assert!(stdin.contains("CORTEX_HEARTBEAT_TOKEN=preserved-token"));
    assert!(stdin.contains("CORTEX_AGENT_DOCKER=true"));
    assert!(stdin.contains("CORTEX_AGENT_JOURNALD=true"));
    assert!(stdin.contains("CORTEX_SYSLOG_TARGET=old-syslog.example:1514"));
    assert!(stdin.contains("CORTEX_AGENT_FILE_TAILS=/var/log/app.log:app"));
    assert!(stdin.contains("CORTEX_AGENT_AI_TRANSCRIPT_FORWARD=true"));
    assert!(!stdin.contains("CORTEX_AGENT_AI_TRANSCRIPTS="));
}

#[test]
#[serial]
fn deploy_agent_to_linux_host_fails_when_existing_env_read_fails() {
    let dir = tempfile::tempdir().unwrap();
    let local_binary = write_local_binary(dir.path());
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
case "$*" in
  *"/etc/unraid-version"*) printf 'no\n'; exit 0 ;;
  *"heartbeat-agent.env"*) exit 13 ;;
  *) exit 0 ;;
esac
"#,
    );
    write_successful_scp(dir.path());
    let _path = prepend_path(dir.path());

    let result = deploy_agent_to_host("linux-host", &local_binary, &AgentDeployConfig::default());

    assert!(!result.ok);
    assert!(result.detail.contains("heartbeat-agent.env"));
    assert!(result.detail.contains("exited non-zero"));
}

#[test]
#[serial]
fn deploy_agent_requires_token_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let local_binary = write_local_binary(dir.path());
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
case "$*" in
  *"/etc/unraid-version"*) printf 'no\n'; exit 0 ;;
  *) exit 0 ;;
esac
"#,
    );
    write_successful_scp(dir.path());
    let _path = prepend_path(dir.path());

    let result = deploy_agent_to_host(
        "linux-host",
        &local_binary,
        &AgentDeployConfig {
            require_token: true,
            ..AgentDeployConfig::default()
        },
    );

    assert!(!result.ok);
    assert!(result.detail.contains("CORTEX_HEARTBEAT_TOKEN"));
}

#[test]
#[serial]
fn deploy_agent_rejects_unsafe_host_before_ssh() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("commands.log");
    let local_binary = write_local_binary(dir.path());
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
printf 'ssh %s\n' "$*" >> "$CORTEX_TEST_AGENT_DEPLOY_LOG"
exit 0
"#,
    );
    write_successful_scp(dir.path());
    let _path = prepend_path(dir.path());
    let _log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_LOG", &log);

    let result = deploy_agent_to_host(
        "-oProxyCommand=touch /tmp/pwned",
        &local_binary,
        &AgentDeployConfig::default(),
    );

    assert!(!result.ok);
    assert!(result.detail.contains("unsafe ssh host"));
    assert!(!log.exists());
}

#[test]
#[serial]
fn deploy_agent_reports_first_remote_failure() {
    let dir = tempfile::tempdir().unwrap();
    let local_binary = write_local_binary(dir.path());
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
case "$*" in
  *"/etc/unraid-version"*) printf 'no\n'; exit 0 ;;
  *"mkdir -p"*) exit 42 ;;
  *) exit 0 ;;
esac
"#,
    );
    write_successful_scp(dir.path());
    let _path = prepend_path(dir.path());

    let result = deploy_agent_to_host("linux-host", &local_binary, &AgentDeployConfig::default());

    assert!(!result.ok);
    assert!(result.detail.contains("mkdir -p ~/.local/bin"));
    assert!(result.detail.contains("exited non-zero"));
}

#[test]
#[serial]
fn deploy_agent_redacts_secret_envs_from_failure_detail() {
    let dir = tempfile::tempdir().unwrap();
    let local_binary = write_local_binary(dir.path());
    // The `cat >` branch must drain stdin, exactly as real ssh forwards stdin to
    // a remote `cat` that reads to EOF. A shim that exits without reading races
    // the deploy's write: whichever side loses, the deploy stops at the env
    // write with a broken pipe and never reaches the install command below.
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
case "$*" in
  *"/etc/unraid-version"*) printf 'no\n'; exit 0 ;;
  *"cat >"*) cat > /dev/null; exit 0 ;;
  *"setup heartbeatagent install"*) exit 42 ;;
  *) exit 0 ;;
esac
"#,
    );
    write_successful_scp(dir.path());
    let _path = prepend_path(dir.path());

    let result = deploy_agent_to_host(
        "linux-host",
        &local_binary,
        &AgentDeployConfig {
            target: Some("https://cortex.example.test".to_string()),
            token: Some("super secret token".to_string()),
            require_token: false,
            docker: None,
            journald: None,
        },
    );

    assert!(!result.ok, "{result:?}");
    assert!(
        !result.detail.contains("super secret token"),
        "the heartbeat token leaked into the failure detail: {:?}",
        result.detail
    );
    assert!(
        result.detail.contains("setup heartbeatagent install"),
        "the failure detail must name the command that failed, got: {:?}",
        result.detail
    );
}

/// Larger than any pipe buffer, so a remote that never reads stdin is
/// guaranteed to break the pipe while the write is still in flight — the
/// scheduling race that made the deploy report `Broken pipe (os error 32)`
/// instead of the failing command, deterministically.
const UNREADABLE_STDIN_INPUT_LEN: usize = 1 << 20;

#[test]
#[serial]
fn ssh_run_with_stdin_reports_the_command_when_the_remote_exits_non_zero() {
    let dir = tempfile::tempdir().unwrap();
    write_executable(&dir.path().join("ssh"), "#!/bin/sh\nexit 42\n");
    let _path = prepend_path(dir.path());

    let error = ssh_run_with_stdin(
        "linux-host",
        "cat > ~/.cortex/heartbeat-agent.env.new",
        &vec![b'x'; UNREADABLE_STDIN_INPUT_LEN],
    )
    .unwrap_err();

    let detail = error.to_string();
    assert!(
        detail.contains("cat > ~/.cortex/heartbeat-agent.env.new"),
        "the exit status must win over the broken pipe, got: {detail:?}"
    );
    assert!(detail.contains("exited non-zero"), "got: {detail:?}");
}

#[test]
#[serial]
fn ssh_run_with_stdin_fails_when_a_successful_remote_never_took_the_input() {
    let dir = tempfile::tempdir().unwrap();
    write_executable(&dir.path().join("ssh"), "#!/bin/sh\nexit 0\n");
    let _path = prepend_path(dir.path());

    let error = ssh_run_with_stdin(
        "linux-host",
        "cat > ~/.cortex/heartbeat-agent.env.new",
        &vec![b'x'; UNREADABLE_STDIN_INPUT_LEN],
    )
    .unwrap_err();

    let detail = error.to_string();
    assert!(
        detail.contains("cat > ~/.cortex/heartbeat-agent.env.new"),
        "got: {detail:?}"
    );
    assert!(
        detail.contains("exited before accepting its piped input"),
        "a remote that exits 0 without reading never wrote the env file, \
         so the deploy must not continue, got: {detail:?}"
    );
}

#[test]
#[serial]
fn deploy_agent_install_failure_leaves_new_env_ready_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("commands.log");
    let stdin_log = dir.path().join("stdin.log");
    let local_binary = write_local_binary(dir.path());
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
printf 'ssh %s\n' "$*" >> "$CORTEX_TEST_AGENT_DEPLOY_LOG"
case "$*" in
  *"/etc/unraid-version"*) printf 'no\n'; exit 0 ;;
  *"cat >"*) cat >> "$CORTEX_TEST_AGENT_DEPLOY_STDIN"; exit 0 ;;
  *"setup heartbeatagent install"*) exit 42 ;;
  *) exit 0 ;;
esac
"#,
    );
    write_successful_scp(dir.path());
    let _path = prepend_path(dir.path());
    let _log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_LOG", &log);
    let _stdin_log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_STDIN", &stdin_log);

    let result = deploy_agent_to_host(
        "linux-host",
        &local_binary,
        &AgentDeployConfig {
            target: Some("https://new.example.test:3100".to_string()),
            token: Some("new-token".to_string()),
            ..AgentDeployConfig::default()
        },
    );

    assert!(!result.ok);
    let log = std::fs::read_to_string(log).unwrap();
    let env_position = log.find("cat > ~/.cortex/heartbeat-agent.env.new").unwrap();
    let install_position = log
        .find("CORTEX_SETUP_PRESERVE_HEARTBEAT_ENV=1 ~/.local/bin/cortex setup heartbeatagent install")
        .unwrap();
    assert!(env_position < install_position);
    assert!(!log.contains("systemctl --user restart"));
    let stdin = std::fs::read_to_string(stdin_log).unwrap();
    assert!(stdin.contains("CORTEX_HEARTBEAT_TARGET=https://new.example.test:3100"));
    assert!(stdin.contains("CORTEX_HEARTBEAT_TOKEN=new-token"));
}

#[test]
#[serial]
fn deploy_agent_env_install_failure_never_starts_service() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("commands.log");
    let local_binary = write_local_binary(dir.path());
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
printf 'ssh %s\n' "$*" >> "$CORTEX_TEST_AGENT_DEPLOY_LOG"
case "$*" in
  *"/etc/unraid-version"*) printf 'no\n'; exit 0 ;;
  *"cat > ~/.cortex/heartbeat-agent.env.new"*) cat > /dev/null; exit 42 ;;
  *) exit 0 ;;
esac
"#,
    );
    write_successful_scp(dir.path());
    let _path = prepend_path(dir.path());
    let _log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_LOG", &log);

    let result = deploy_agent_to_host(
        "linux-host",
        &local_binary,
        &AgentDeployConfig {
            target: Some("https://new.example.test:3100".to_string()),
            token: Some("new-token".to_string()),
            ..AgentDeployConfig::default()
        },
    );

    assert!(!result.ok);
    let log = std::fs::read_to_string(log).unwrap();
    assert!(log.contains("cat > ~/.cortex/heartbeat-agent.env.new"));
    assert!(!log.contains("setup heartbeatagent install"));
    assert!(!log.contains("systemctl --user restart"));
}

#[test]
fn redact_secret_envs_redacts_custom_secret_keys() {
    let redacted =
        redact_secret_envs("PLEX_TOKEN='plex secret' API_KEY=apikey OTHER_SECRET='secret value'");

    assert!(!redacted.contains("plex secret"));
    assert!(!redacted.contains("apikey"));
    assert!(!redacted.contains("secret value"));
    assert!(redacted.contains("PLEX_TOKEN=<redacted>"));
    assert!(redacted.contains("API_KEY=<redacted>"));
    assert!(redacted.contains("OTHER_SECRET=<redacted>"));
}

#[test]
#[serial]
fn deploy_agent_to_unraid_writes_persistent_env_and_docker_container() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("commands.log");
    let stdin_log = dir.path().join("stdin.log");
    let local_binary = write_local_binary(dir.path());
    write_executable(
        &dir.path().join("ssh"),
        r#"#!/bin/sh
printf 'ssh %s\n' "$*" >> "$CORTEX_TEST_AGENT_DEPLOY_LOG"
case "$*" in
  *"/etc/unraid-version"*) printf 'yes\n'; exit 0 ;;
  *"cat >"*) cat >> "$CORTEX_TEST_AGENT_DEPLOY_STDIN"; exit 0 ;;
  *) exit 0 ;;
esac
"#,
    );
    write_logging_scp(dir.path());
    let _path = prepend_path(dir.path());
    let _log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_LOG", &log);
    let _stdin_log = EnvGuard::set("CORTEX_TEST_AGENT_DEPLOY_STDIN", &stdin_log);

    let result = deploy_agent_to_host(
        "unraid-host",
        &local_binary,
        &AgentDeployConfig {
            target: Some("https://cortex.example.test".to_string()),
            token: Some("secret".to_string()),
            require_token: false,
            docker: Some(false),
            journald: Some(true),
        },
    );

    assert!(result.ok, "{result:?}");
    let log = std::fs::read_to_string(log).unwrap();
    assert!(log.contains("heartbeat-agent.env"));
    assert!(!log.contains("CORTEX_HEARTBEAT_TOKEN"));
    assert!(!log.contains("secret"));
    let stdin = std::fs::read_to_string(stdin_log).unwrap_or_default();
    assert!(stdin.contains("CORTEX_HEARTBEAT_TARGET=https://cortex.example.test"));
    assert!(stdin.contains("CORTEX_HEARTBEAT_TOKEN=secret"));
    assert!(stdin.contains("CORTEX_AGENT_DOCKER=false"));
    assert!(stdin.contains("CORTEX_AGENT_JOURNALD=false"));
    assert!(log.contains("--env-file /mnt/user/appdata/cortex/heartbeat-agent.env"));
    assert!(log.contains("docker rm -f cortex-heartbeat-agent"));
    assert!(log.contains("--restart unless-stopped"));
    assert!(log.contains("-v /var/run/docker.sock:/var/run/docker.sock"));
    // Containerized agents run the published image with the binary baked in:
    // no host binary is scp'd or bind-mounted; the image is pulled and pinned to
    // this build's version, run as root with the server health probe disabled.
    assert!(!log.contains("cortex.new"));
    assert!(!log.contains(":/opt/cortex/bin"));
    assert!(!log.contains("ubuntu:24.04"));
    assert!(log.contains(&format!(
        "docker pull ghcr.io/dinglebear-ai/cortex:{}",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(log.contains(&format!(
        "ghcr.io/dinglebear-ai/cortex:{}",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(log.contains("--user 0:0"));
    assert!(log.contains("--no-healthcheck"));
    assert!(log.contains("cortex heartbeat agent"));
    assert!(log.contains("--host-id-path /mnt/user/appdata/cortex/heartbeat-host-id"));
}

fn env_get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

#[test]
fn resolve_agent_env_flagless_upgrade_preserves_everything() {
    // The whole point: `cortex setup deploy agent` with NO flags keeps the host's
    // existing token, target, docker setting, and custom Plex file-tail.
    let persisted = vec![
        (
            "CORTEX_HEARTBEAT_TARGET".into(),
            "https://cortex.example.invalid".into(),
        ),
        ("CORTEX_SYSLOG_TARGET".into(), "198.51.100.1:1514".into()),
        ("CORTEX_AGENT_DOCKER".into(), "true".into()),
        ("CORTEX_HEARTBEAT_TOKEN".into(), "the-secret".into()),
        (
            "CORTEX_AGENT_FILE_TAILS".into(),
            "/host/plex-logs/Plex Media Server.log:plex".into(),
        ),
    ];
    let env = resolve_agent_env(&persisted, &AgentDeployConfig::default());
    assert_eq!(env_get(&env, "CORTEX_HEARTBEAT_TOKEN"), Some("the-secret"));
    assert_eq!(
        env_get(&env, "CORTEX_HEARTBEAT_TARGET"),
        Some("https://cortex.example.invalid")
    );
    assert_eq!(
        env_get(&env, "CORTEX_SYSLOG_TARGET"),
        Some("198.51.100.1:1514")
    );
    // Preserved as true — NOT reset to the false default.
    assert_eq!(env_get(&env, "CORTEX_AGENT_DOCKER"), Some("true"));
    // The file-tail (value has a space AND a colon) round-trips intact.
    assert_eq!(
        env_get(&env, "CORTEX_AGENT_FILE_TAILS"),
        Some("/host/plex-logs/Plex Media Server.log:plex")
    );
}

#[test]
fn resolve_agent_env_flags_override_persisted() {
    let persisted = vec![
        (
            "CORTEX_HEARTBEAT_TARGET".into(),
            "https://old.example".into(),
        ),
        ("CORTEX_HEARTBEAT_TOKEN".into(), "old-token".into()),
        ("CORTEX_AGENT_DOCKER".into(), "true".into()),
    ];
    let cfg = AgentDeployConfig {
        target: Some("https://new.example".into()),
        token: Some("new-token".into()),
        require_token: false,
        docker: Some(false),
        journald: None,
    };
    let env = resolve_agent_env(&persisted, &cfg);
    assert_eq!(
        env_get(&env, "CORTEX_HEARTBEAT_TARGET"),
        Some("https://new.example")
    );
    assert_eq!(env_get(&env, "CORTEX_HEARTBEAT_TOKEN"), Some("new-token"));
    assert_eq!(env_get(&env, "CORTEX_AGENT_DOCKER"), Some("false"));
}

#[test]
fn resolve_agent_env_first_deploy_defaults_and_omits_absent_token() {
    let env = resolve_agent_env(&[], &AgentDeployConfig::default());
    // No token anywhere → omitted entirely (no empty/garbage token written).
    assert_eq!(env_get(&env, "CORTEX_HEARTBEAT_TOKEN"), None);
    assert_eq!(env_get(&env, "CORTEX_AGENT_DOCKER"), Some("false"));
    assert_eq!(env_get(&env, "RUST_LOG"), Some("warn"));
}

#[test]
fn resolve_linux_agent_env_preserves_auth_and_flags_without_defaults() {
    let persisted = vec![
        (
            "CORTEX_HEARTBEAT_TARGET".into(),
            "https://cortex.example.invalid".into(),
        ),
        ("CORTEX_HEARTBEAT_TOKEN".into(), "the-secret".into()),
        ("CORTEX_AGENT_DOCKER".into(), "true".into()),
        ("CORTEX_AGENT_JOURNALD".into(), "true".into()),
        ("CORTEX_SYSLOG_TARGET".into(), "198.51.100.1:1514".into()),
        (
            "CORTEX_AGENT_FILE_TAILS".into(),
            "/var/log/app.log:app".into(),
        ),
        ("CORTEX_AGENT_AI_TRANSCRIPTS".into(), "true".into()),
        ("CORTEX_AGENT_COMMAND_FORWARD".into(), "true".into()),
        ("CORTEX_AGENT_SHELL_HISTORY_FORWARD".into(), "true".into()),
        ("CORTEX_AGENT_AUTO_UPDATE".into(), "false".into()),
    ];
    let env = resolve_linux_agent_env(&persisted, &AgentDeployConfig::default());

    assert_eq!(
        env_get(&env, "CORTEX_HEARTBEAT_TARGET"),
        Some("https://cortex.example.invalid")
    );
    assert_eq!(env_get(&env, "CORTEX_HEARTBEAT_TOKEN"), Some("the-secret"));
    assert_eq!(env_get(&env, "CORTEX_AGENT_DOCKER"), Some("true"));
    assert_eq!(env_get(&env, "CORTEX_AGENT_JOURNALD"), Some("true"));
    assert_eq!(
        env_get(&env, "CORTEX_SYSLOG_TARGET"),
        Some("198.51.100.1:1514")
    );
    assert_eq!(
        env_get(&env, "CORTEX_AGENT_FILE_TAILS"),
        Some("/var/log/app.log:app")
    );
    assert_eq!(
        env_get(&env, "CORTEX_AGENT_AI_TRANSCRIPT_FORWARD"),
        Some("true")
    );
    assert_eq!(env_get(&env, "CORTEX_AGENT_AI_TRANSCRIPTS"), None);
    assert_eq!(env_get(&env, "CORTEX_AGENT_COMMAND_FORWARD"), Some("true"));
    assert_eq!(
        env_get(&env, "CORTEX_AGENT_SHELL_HISTORY_FORWARD"),
        Some("true")
    );
    assert_eq!(env_get(&env, "CORTEX_AGENT_AUTO_UPDATE"), Some("false"));
}

#[test]
fn resolve_linux_agent_env_stays_empty_for_first_flagless_deploy() {
    assert!(resolve_linux_agent_env(&[], &AgentDeployConfig::default()).is_empty());
}

#[test]
fn parse_env_file_splits_on_first_equals_and_skips_blanks_and_comments() {
    let parsed = parse_env_file("A=1\n\n# comment\nB=x=y z\nBAD-KEY=nope\n9BAD=nope\n");
    assert_eq!(
        parsed,
        vec![
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "x=y z".to_string()),
        ]
    );
}

#[test]
fn render_env_file_rejects_values_with_cross_parser_ambiguity() {
    for value in [
        " leading",
        "trailing ",
        "a\\b",
        "a\"b",
        "a'b",
        "a#b",
        "a\nb",
        "a\tb",
        "a\0b",
    ] {
        let error = render_env_file(&[("TOKEN".into(), value.into())]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
    assert_eq!(
        render_env_file(&[("TOKEN".into(), "spaces inside = are okay".into())]).unwrap(),
        "TOKEN=spaces inside = are okay\n"
    );
}

#[test]
fn preserved_custom_mount_flags_keeps_only_nonstandard_mounts() {
    let inspect = format!(
        "{appdata}\t{appdata}\trw\n\
         /var/run/docker.sock\t/var/run/docker.sock\trw\n\
         /var/log/syslog\t{syslog}\tro\n\
         /mnt/cache/appdata/plex/Logs\t/host/plex-logs\tro\n",
        appdata = UNRAID_APPDATA,
        syslog = UNRAID_CONTAINER_SYSLOG,
    );
    let flags = preserved_custom_mount_flags(&inspect);
    // Only the custom Plex-logs mount survives; the 3 standard ones are dropped.
    assert_eq!(flags.len(), 1, "got: {flags:?}");
    assert!(flags[0].contains("/mnt/cache/appdata/plex/Logs:/host/plex-logs:ro"));
}

#[test]
fn preserved_custom_mount_flags_empty_on_first_deploy() {
    assert!(preserved_custom_mount_flags("").is_empty());
    assert!(parse_env_file("").is_empty());
}
