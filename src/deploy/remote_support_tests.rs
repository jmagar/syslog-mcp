use super::*;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serial_test::serial;

/// Larger than any pipe buffer, so a remote that never reads stdin is
/// guaranteed to break the pipe while the write is still in flight. This makes
/// the early-exit race deterministic instead of scheduling-dependent.
const PIPE_OVERFLOW_LEN: usize = 1 << 20;

const SSH_AUTH_FAILURE: &str = "Permission denied (publickey).";

struct PathGuard(Option<std::ffi::OsString>);

impl PathGuard {
    fn prepend(dir: &Path) -> Self {
        let previous = crate::env::var_os("PATH");
        let mut path = std::ffi::OsString::from(dir.as_os_str());
        path.push(":");
        path.push(previous.clone().unwrap_or_default());
        crate::env::set_test_var("PATH", path);
        Self(previous)
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        match &self.0 {
            Some(value) => crate::env::set_test_var("PATH", value),
            None => crate::env::remove_test_var("PATH"),
        }
    }
}

/// Install `body` as the `ssh` the runner resolves, via a prepended PATH.
fn fake_ssh(body: &str) -> (tempfile::TempDir, PathGuard) {
    let dir = tempfile::tempdir().unwrap();
    let ssh = dir.path().join("ssh");
    std::fs::write(&ssh, body).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    let guard = PathGuard::prepend(dir.path());
    (dir, guard)
}

/// A remote that rejects the session before reading anything, as ssh does on
/// an auth failure: it prints its reason to stderr and exits 255.
fn auth_failing_ssh() -> (tempfile::TempDir, PathGuard) {
    fake_ssh(&format!(
        "#!/bin/sh\nprintf '%s\\n' '{SSH_AUTH_FAILURE}' >&2\nexit 255\n"
    ))
}

fn oversized_script() -> String {
    format!("{}\n", "#".repeat(PIPE_OVERFLOW_LEN))
}

#[test]
#[serial]
fn early_remote_exit_returns_exit_status_and_ssh_stderr_not_broken_pipe() {
    let (_dir, _path) = auth_failing_ssh();

    let output = SshRemoteRunner
        .run("linux-host", &oversized_script(), None)
        .expect("the exit status must win over the broken pipe");

    assert!(!output.status_success);
    assert_eq!(output.exit_code, Some(255));
    assert!(
        output.stderr.contains(SSH_AUTH_FAILURE),
        "ssh's stderr must be captured, got: {:?}",
        output.stderr
    );
}

#[test]
#[serial]
fn early_remote_exit_during_piped_stdin_still_returns_ssh_stderr() {
    let (_dir, _path) = auth_failing_ssh();

    let output = SshRemoteRunner
        .run(
            "linux-host",
            "cat > /dev/null",
            Some(&"x".repeat(PIPE_OVERFLOW_LEN)),
        )
        .expect("the exit status must win over the broken pipe");

    assert_eq!(output.exit_code, Some(255));
    assert!(output.stderr.contains(SSH_AUTH_FAILURE), "{output:?}");
}

#[test]
#[serial]
fn early_remote_exit_phase_detail_names_the_status_and_cause() {
    let (_dir, _path) = auth_failing_ssh();

    let phase = remote_phase(
        &mut SshRemoteRunner,
        "linux-host",
        "remote-env",
        &oversized_script(),
        None,
    )
    .unwrap();

    assert!(matches!(phase.status, SetupStatus::Error));
    assert_eq!(phase.detail, format!("exit status 255: {SSH_AUTH_FAILURE}"));
    assert!(!phase.detail.contains("Broken pipe"), "{:?}", phase.detail);
}

#[test]
#[serial]
fn successful_remote_that_never_took_the_script_is_an_error() {
    let (_dir, _path) = fake_ssh("#!/bin/sh\nprintf 'motd banner\\n' >&2\nexit 0\n");

    let error = SshRemoteRunner
        .run("linux-host", &oversized_script(), None)
        .expect_err("a remote that exits 0 without reading never ran the script");

    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    let detail = error.to_string();
    assert!(detail.contains("ssh linux-host"), "got: {detail:?}");
    assert!(
        detail.contains("exited successfully before accepting its piped script"),
        "got: {detail:?}"
    );
    assert!(detail.contains("motd banner"), "got: {detail:?}");
}

#[test]
#[serial]
fn remote_that_drains_stdin_returns_its_output() {
    // Healthy remote: reads everything, as `sh -s` forwarding to a reader does,
    // and reports how many bytes arrived.
    let (_dir, _path) = fake_ssh("#!/bin/sh\nwc -c | tr -d ' '\n");
    let script = oversized_script();
    let input = "y".repeat(PIPE_OVERFLOW_LEN);

    let output = SshRemoteRunner
        .run("linux-host", &script, Some(&input))
        .unwrap();

    assert!(output.status_success, "{output:?}");
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(
        output.stdout.trim(),
        (script.len() + input.len()).to_string()
    );
}

#[test]
#[serial]
fn remote_that_fills_stderr_before_reading_does_not_deadlock() {
    // The remote writes more than a pipe buffer of stderr before it reads
    // stdin. Writing stdin before draining stderr would deadlock both sides.
    let (_dir, _path) =
        fake_ssh("#!/bin/sh\nhead -c 262144 /dev/zero >&2\ncat > /dev/null\nprintf 'done\\n'\n");

    let output = SshRemoteRunner
        .run("linux-host", &oversized_script(), None)
        .unwrap();

    assert!(output.status_success, "exit={:?}", output.exit_code);
    assert_eq!(output.stderr.len(), 262_144);
    assert_eq!(output.stdout, "done\n");
}
