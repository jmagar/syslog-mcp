//! Bounded, text-only assessment over Codex app-server's stdio protocol.
//! The caller owns timeout, concurrency, rate limits and audit via LlmRunner.
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{path::PathBuf, process::Stdio};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

const MAX_FRAME: u64 = 2 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct CodexAssessConfig {
    pub program: String,
    pub model: Option<String>,
    pub source_home: PathBuf,
}

impl CodexAssessConfig {
    #[cfg(test)]
    pub fn from_env(model: Option<String>) -> Self {
        Self {
            program: crate::env::var("CORTEX_CODEX_CMD").unwrap_or_else(|_| "codex".into()),
            model,
            source_home: crate::env::var_os("CORTEX_CODEX_HOME")
                .or_else(|| crate::env::var_os("CODEX_HOME"))
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(crate::env::var_os("HOME").unwrap_or_default()).join(".codex")
                }),
        }
    }
}

fn thread_params(cwd: &std::path::Path, model: &Option<String>) -> Value {
    json!({
        "cwd": cwd, "model": model, "ephemeral": true,
        "approvalPolicy": "never", "sandbox": "read-only",
        "environments": [], "dynamicTools": [],
        "developerInstructions": "Analyze only the supplied passive evidence. Return Markdown. Do not use tools, access files, browse, execute commands or change any state.",
        "config": {"features.shell_tool": false, "web_search": "disabled"}
    })
}

async fn send(writer: &mut tokio::process::ChildStdin, value: Value) -> Result<()> {
    writer
        .write_all(serde_json::to_string(&value)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn receive<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Result<Value> {
    let mut bytes = Vec::new();
    let n = reader
        .take(MAX_FRAME + 1)
        .read_until(b'\n', &mut bytes)
        .await?;
    if n == 0 {
        bail!("Codex app-server disconnected before assessment completed");
    }
    if n as u64 > MAX_FRAME {
        bail!("Codex app-server frame exceeds assessment limit");
    }
    let value: Value = serde_json::from_slice(&bytes).context("invalid Codex app-server frame")?;
    if value.get("error").is_some() {
        // Avoid putting provider response content or echoed prompts in the audit error.
        bail!("Codex app-server rejected the assessment request");
    }
    if value.get("method").is_some() && value.get("id").is_some() {
        bail!("Codex app-server requested an interactive operation during text-only assessment");
    }
    Ok(value)
}

async fn response(reader: &mut BufReader<tokio::process::ChildStdout>, id: u64) -> Result<Value> {
    loop {
        let value = receive(reader).await?;
        if value.get("id").and_then(Value::as_u64) == Some(id) {
            return value
                .get("result")
                .cloned()
                .context("missing app-server result");
        }
    }
}

pub(crate) async fn run<F>(
    prompt: &str,
    config: &CodexAssessConfig,
    max_output_bytes: usize,
    mut on_delta: F,
) -> Result<String>
where
    F: FnMut(&str) -> Result<()> + Send,
{
    let home = tempfile::Builder::new()
        .prefix("cortex-codex-home-")
        .tempdir()?;
    let cwd = tempfile::Builder::new()
        .prefix("cortex-codex-assess-")
        .tempdir()?;
    // Alias the authoritative file instead of copying rotating OAuth state.
    // Codex owns refresh persistence; Cortex never copies credentials back over
    // an operator's newer login. The rest of CODEX_HOME remains isolated.
    link_auth_file(&config.source_home, home.path())?;
    let mut child = tokio::process::Command::new(&config.program)
        .args(["app-server", "--listen", "stdio://"])
        .env_clear()
        .env("PATH", crate::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("CODEX_HOME", home.path())
        .current_dir(cwd.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("could not start Codex app-server")?;
    let mut writer = child.stdin.take().context("missing app-server stdin")?;
    let mut reader = BufReader::new(child.stdout.take().context("missing app-server stdout")?);
    send(&mut writer, json!({"id":1,"method":"initialize","params":{"clientInfo":{"name":"cortex_assessment","version":env!("CARGO_PKG_VERSION")},"capabilities":{"experimentalApi":true}}})).await?;
    response(&mut reader, 1).await?;
    send(&mut writer, json!({"method":"initialized","params":{}})).await?;
    send(
        &mut writer,
        json!({"id":2,"method":"thread/start","params":thread_params(cwd.path(), &config.model)}),
    )
    .await?;
    let started = response(&mut reader, 2).await?;
    let thread_id = started
        .pointer("/thread/id")
        .and_then(Value::as_str)
        .context("app-server did not return a thread ID")?;
    send(&mut writer, json!({"id":3,"method":"turn/start","params":{"threadId":thread_id,"input":[{"type":"text","text":prompt}]}})).await?;
    let mut output = String::new();
    loop {
        let value = receive(&mut reader).await?;
        match value.get("method").and_then(Value::as_str) {
            Some("item/agentMessage/delta") => {
                let delta = value
                    .pointer("/params/delta")
                    .and_then(Value::as_str)
                    .context("missing assessment delta")?;
                append_delta(&mut output, delta, max_output_bytes)?;
                on_delta(delta)?;
            }
            Some("turn/completed") => {
                if value.pointer("/params/turn/status").and_then(Value::as_str) != Some("completed")
                {
                    bail!("Codex assessment turn did not complete successfully");
                }
                if output.trim().is_empty() {
                    bail!("Codex assessment returned no text");
                }
                child.kill().await?;
                child.wait().await?;
                return Ok(output);
            }
            Some("item/started" | "item/completed") => validate_item(&value)?,
            _ => {}
        }
    }
}

fn append_delta(output: &mut String, delta: &str, max_output_bytes: usize) -> Result<()> {
    if output.len().saturating_add(delta.len()) > max_output_bytes {
        bail!("Codex assessment output exceeds limit");
    }
    output.push_str(delta);
    Ok(())
}

fn validate_item(value: &Value) -> Result<()> {
    match value.pointer("/params/item/type").and_then(Value::as_str) {
        Some("userMessage" | "agentMessage" | "reasoning") => Ok(()),
        _ => bail!("Codex app-server emitted tool activity during text-only assessment"),
    }
}

fn link_auth_file(source_home: &std::path::Path, isolated_home: &std::path::Path) -> Result<()> {
    let source = source_home.join("auth.json").canonicalize().context(
        "Codex assessment requires auth.json in CORTEX_CODEX_HOME; authenticate Codex first",
    )?;
    if !source.is_file() {
        bail!("Codex auth.json must be a regular file");
    }
    let target = isolated_home.join("auth.json");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&source, &target)
        .context("could not link the authoritative Codex authentication file")?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&source, &target).context(
        "could not link Codex auth.json; enable Windows Developer Mode for symlink support",
    )?;
    #[cfg(not(any(unix, windows)))]
    bail!("shared Codex authentication is unsupported on this platform");
    Ok(())
}

#[cfg(test)]
#[path = "codex_assessment_tests.rs"]
mod tests;

#[cfg(all(test, any(unix, windows)))]
#[path = "codex_auth_tests.rs"]
mod auth_tests;
