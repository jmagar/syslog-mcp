use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use super::format::redact_sensitive;
use super::types::{CommandOutput, CommandRunner, ComposeInvocation, TimeoutCleanupStatus};

pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(&self, invocation: &ComposeInvocation) -> Result<CommandOutput> {
        use std::process::Stdio;
        use std::sync::{Arc, Mutex};
        use std::thread;

        #[cfg(unix)]
        use std::os::unix::process::CommandExt;

        let mut command = crate::env::command(&invocation.program);
        command.args(&invocation.args);
        for (key, value) in &invocation.env {
            command.env(key, value);
        }
        if let Some(dir) = &invocation.current_dir {
            command.current_dir(dir);
        }
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = command.spawn().map_err(|e| {
            anyhow!(
                "failed to spawn {} {}: {e}",
                invocation.program,
                invocation.args.join(" ")
            )
        })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("missing stdout pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("missing stderr pipe"))?;
        let stdout_buf = Arc::new(Mutex::new((Vec::new(), false)));
        let stderr_buf = Arc::new(Mutex::new((Vec::new(), false)));

        let out_handle = drain_pipe(
            stdout,
            Arc::clone(&stdout_buf),
            invocation.output_limit_bytes,
        );
        let err_handle = drain_pipe(
            stderr,
            Arc::clone(&stderr_buf),
            invocation.output_limit_bytes,
        );

        let started = Instant::now();
        let mut timed_out = false;
        let mut timeout_cleanup = None;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if started.elapsed() >= invocation.timeout {
                timed_out = true;
                let terminate_sent = terminate_child(&mut child);
                thread::sleep(Duration::from_millis(500));
                let mut kill_sent = false;
                let (status, reaped) = if let Some(status) = child.try_wait()? {
                    (Some(status), true)
                } else {
                    kill_sent = force_kill_child(&mut child);
                    let status = wait_for_child_after_kill(&mut child, Duration::from_secs(2))?;
                    let reaped = status.is_some();
                    (status, reaped)
                };
                timeout_cleanup = Some(TimeoutCleanupStatus {
                    terminate_sent,
                    kill_sent,
                    reaped,
                });
                break status;
            }
            thread::sleep(Duration::from_millis(25));
        };

        if timeout_cleanup.as_ref().map(|c| c.reaped).unwrap_or(true) {
            join_pipe(out_handle, "stdout")?;
            join_pipe(err_handle, "stderr")?;
        }

        let (stdout, stdout_truncated) = take_buffer(stdout_buf)?;
        let (stderr, stderr_truncated) = take_buffer(stderr_buf)?;

        Ok(CommandOutput {
            exit_status: status.and_then(|status| status.code()),
            stdout: redact_sensitive(&String::from_utf8_lossy(&stdout)),
            stderr: redact_sensitive(&String::from_utf8_lossy(&stderr)),
            stdout_truncated,
            stderr_truncated,
            timed_out,
            timeout_cleanup,
        })
    }
}

fn wait_for_child_after_kill(
    child: &mut std::process::Child,
    cap: Duration,
) -> Result<Option<std::process::ExitStatus>> {
    use std::thread;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if started.elapsed() >= cap {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn drain_pipe<R: std::io::Read + Send + 'static>(
    mut reader: R,
    target: std::sync::Arc<std::sync::Mutex<(Vec<u8>, bool)>>,
    limit: usize,
) -> std::thread::JoinHandle<std::io::Result<()>> {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let mut guard = target.lock().expect("pipe buffer mutex poisoned");
                    append_pipe_chunk(&mut guard, &chunk, n, limit);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })
}

#[cfg(test)]
pub(super) fn drain_pipe_for_test<R: std::io::Read + Send + 'static>(
    reader: R,
    target: std::sync::Arc<std::sync::Mutex<(Vec<u8>, bool)>>,
    limit: usize,
) -> std::thread::JoinHandle<std::io::Result<()>> {
    drain_pipe(reader, target, limit)
}

fn join_pipe(handle: std::thread::JoinHandle<std::io::Result<()>>, stream: &str) -> Result<()> {
    handle
        .join()
        .map_err(|_| anyhow!("{stream} pipe reader panicked"))?
        .map_err(|error| anyhow!("failed to read {stream} pipe: {error}"))
}

fn append_pipe_chunk(target: &mut (Vec<u8>, bool), chunk: &[u8], n: usize, limit: usize) {
    let remaining = limit.saturating_sub(target.0.len());
    if remaining > 0 {
        let keep = remaining.min(n);
        target.0.extend_from_slice(&chunk[..keep]);
        if keep < n {
            target.1 = true;
        }
    } else {
        target.1 = true;
    }
}

fn take_buffer(
    buffer: std::sync::Arc<std::sync::Mutex<(Vec<u8>, bool)>>,
) -> Result<(Vec<u8>, bool)> {
    let guard = buffer
        .lock()
        .map_err(|_| anyhow!("pipe buffer mutex poisoned"))?;
    Ok((guard.0.clone(), guard.1))
}

#[cfg(unix)]
fn terminate_child(child: &mut std::process::Child) -> bool {
    let pid = child.id() as i32;
    unsafe { libc::kill(-pid, libc::SIGTERM) == 0 }
}

#[cfg(unix)]
fn force_kill_child(child: &mut std::process::Child) -> bool {
    let pid = child.id() as i32;
    unsafe { libc::kill(-pid, libc::SIGKILL) == 0 }
}

#[cfg(not(unix))]
fn terminate_child(child: &mut std::process::Child) -> bool {
    child.kill().is_ok()
}

#[cfg(not(unix))]
fn force_kill_child(child: &mut std::process::Child) -> bool {
    child.kill().is_ok()
}
