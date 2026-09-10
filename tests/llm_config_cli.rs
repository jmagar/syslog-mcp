#![cfg(unix)]

use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cortex"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("CORTEX_HOME", home)
        .env("CORTEX_DB_PATH", home.join("test.db"))
        .env("CORTEX_USE_HTTP", "false")
        .env("NO_COLOR", "1")
        .current_dir(home);
    command
}

fn json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("complete stdout must be a single JSON document")
}

fn fixture() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::create_dir(home.join(".gemini")).unwrap();
    std::fs::write(home.join(".gemini/settings.json"), "{}").unwrap();
    let provider = home.join("fake-gemini");
    std::fs::write(
        &provider,
        r#"#!/bin/sh
cat >/dev/null
printf '%s\n' '{"type":"message","role":"assistant","content":"Markdown assessment"}'
printf '%s\n' '{"type":"result","status":"success"}'
"#,
    )
    .unwrap();
    std::fs::set_permissions(&provider, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(home.join(".env"), format!(
        "CORTEX_LLM=gemini/managed-model\nCORTEX_HEADLESS_GEMINI_CMD={}\nCORTEX_HEADLESS_GEMINI_HOME={}\n",
        provider.display(), home.display()
    )).unwrap();
    let transcript = home.join("session.jsonl");
    std::fs::write(&transcript, "{\"sessionId\":\"llm-config-test\",\"type\":\"user\",\"timestamp\":\"2026-09-09T00:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"this shit failed again\"}}\n").unwrap();
    let added = json(
        command(home)
            .args(["sessions", "add", "--file"])
            .arg(&transcript)
            .arg("--json")
            .output()
            .unwrap(),
    );
    assert_eq!(added["ingested"], 1);
    let listed = json(
        command(home)
            .args(["sessions", "incidents", "--json"])
            .output()
            .unwrap(),
    );
    let id = listed["incidents"][0]["incident_id"]
        .as_str()
        .expect("seeded incident")
        .to_owned();
    (dir, id)
}

#[test]
fn managed_llm_selection_reaches_real_cli_and_json_never_streams_markdown() {
    let (dir, incident) = fixture();
    let home = dir.path();
    let result = json(
        command(home)
            .args(["assess", "abuse", "--incident-id", &incident, "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(result["assessed"]["assessment"], "Markdown assessment");
    let conn = rusqlite::Connection::open(home.join("test.db")).unwrap();
    let recorded: (String, String) = conn
        .query_row(
            "SELECT provider, model FROM llm_invocations WHERE status='success'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(recorded, ("gemini-cli".into(), "managed-model".into()));

    json(
        command(home)
            .env("CORTEX_LLM", "codex/process-model")
            .args(["sessions", "assess", &incident, "--dry-run", "--json"])
            .output()
            .unwrap(),
    );
    let recorded: (String, String) = conn
        .query_row(
            "SELECT provider, model FROM llm_invocations WHERE status='dry_run'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        recorded,
        ("codex-app-server".into(), "process-model".into())
    );
}

#[test]
fn invalid_managed_selector_fails_llm_only_and_preserves_deterministic_cli() {
    let (dir, incident) = fixture();
    let home = dir.path();
    std::fs::write(home.join(".env"), "CORTEX_LLM=invalid\n").unwrap();
    let output = command(home)
        .args(["sessions", "assess", &incident, "--dry-run", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid CORTEX_LLM"));
    let result = json(
        command(home)
            .args([
                "assess",
                "abuse",
                "--incident-id",
                &incident,
                "--no-llm",
                "--json",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(result["assessed"]["assessment"], "");
    let conn = rusqlite::Connection::open(home.join("test.db")).unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM llm_invocations", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
