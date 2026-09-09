use super::*;
use serial_test::serial;

struct EnvGuard {
    name: &'static str,
    old: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let old = crate::env::var_os(name);
        crate::env::set_test_var(name, value);
        Self { name, old }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.old {
            Some(value) => crate::env::set_test_var(self.name, value),
            None => crate::env::remove_test_var(self.name),
        }
    }
}

#[test]
fn embedded_assessment_skill_has_injection_defense() {
    assert!(!SKILL_MD.trim().is_empty());
    assert!(SKILL_MD.contains("untrusted input"));
    assert!(SKILL_MD.contains("Never attribute blame without citing specific evidence"));
    assert!(SKILL_MD.contains("Real frustration with incidental profanity"));
    assert!(SKILL_MD.contains("Trend evidence unavailable"));
    assert!(SKILL_MD
        .contains("Never infer recurrence, isolation, or system-wide behavior from a single incident without comparison evidence"));
    assert!(SKILL_MD.contains("Never combine \"Trend evidence unavailable\""));
    assert!(SKILL_MD.contains("write exactly: **Trend evidence unavailable.**"));
    assert!(SKILL_MD.contains("Never write \"no systemic failure\""));
    assert!(SKILL_MD.contains("Never collapse \"real frustration with incidental profanity\""));
    assert!(SKILL_MD.contains("The executive summary must preserve the same uncertainty level"));
}

#[test]
fn assessment_prompt_references_skill_and_wraps_evidence() {
    let prompt = build_assessment_prompt(r#"{"incident_id":"inc-1"}"#);
    assert!(prompt.contains("frustration-assessment"));
    assert!(prompt.contains("Do not write files"));
    assert!(prompt.contains("Use this skill after running"));
    assert!(prompt.contains("<untrusted-evidence"));
    assert!(prompt.contains(r#""incident_id":"inc-1""#));
}

#[test]
fn gemini_command_spec_uses_stdin_stream_json() {
    let config = GeminiAssessConfig {
        program: "gemini".into(),
        model: "gemini-test".into(),
        source_home: None,
        timeout_secs: 5,
    };
    let spec = config.command_spec().unwrap();
    assert_eq!(spec.program, "gemini");
    assert_eq!(spec.output_mode, "stream-json");
    assert!(
        spec.args
            .windows(2)
            .any(|w| w == ["--prompt", GEMINI_STDIN_PROMPT_STUB])
    );
    assert!(
        spec.args
            .windows(2)
            .any(|w| w == ["--approval-mode", "plan"])
    );
    assert!(spec.args.windows(2).any(|w| w == ["--extensions", "none"]));
    assert!(
        spec.args
            .windows(2)
            .any(|w| w == ["--output-format", "stream-json"])
    );
    assert!(
        spec.args
            .windows(2)
            .any(|w| w == ["--model", "gemini-test"])
    );
}

#[test]
fn isolated_gemini_home_clears_side_effect_settings_and_installs_skill() {
    let source = tempfile::tempdir().unwrap();
    let gemini_dir = source.path().join(".gemini");
    fs::create_dir_all(&gemini_dir).unwrap();
    fs::write(
        gemini_dir.join("settings.json"),
        r#"{
            "security": {"auth": {"selectedType": "oauth-personal"}},
            "mcpServers": {"danger": {}},
            "hooks": {"SessionStart": []},
            "context": {"fileName": ["GEMINI.md"]},
            "admin": {"enabled": true}
        }"#,
    )
    .unwrap();
    fs::write(gemini_dir.join("oauth_creds.json"), "{}").unwrap();

    let config = GeminiAssessConfig {
        program: "gemini".into(),
        model: "gemini-test".into(),
        source_home: Some(source.path().to_path_buf()),
        timeout_secs: 5,
    };
    let home = prepare_gemini_home(&config).unwrap();
    let isolated = home.path().join(".gemini");
    assert!(isolated.join("oauth_creds.json").is_file());
    assert!(
        isolated
            .join("skills")
            .join(SKILL_NAME)
            .join("SKILL.md")
            .is_file()
    );

    let settings: Value =
        serde_json::from_slice(&fs::read(isolated.join("settings.json")).unwrap()).unwrap();
    assert_eq!(settings["mcpServers"], json!({}));
    assert_eq!(settings["hooks"], json!({}));
    assert_eq!(settings["context"], json!({ "fileName": [] }));
    assert!(settings.get("admin").is_none());
    assert_eq!(
        settings["security"]["auth"]["selectedType"],
        json!("oauth-personal")
    );
}

#[test]
fn stream_parser_accepts_deltas_and_result_text() {
    let mut parser = GeminiStreamState::default();
    let mut streamed = String::new();
    parser
        .handle_line(
            r#"{"type":"message","role":"assistant","content":[{"text":"Hello "},{"text":"world"}]}"#,
            &mut |delta| {
                streamed.push_str(delta);
                Ok(())
            },
        )
        .unwrap();
    parser
        .handle_line(r#"{"type":"result","status":"success"}"#, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(streamed, "Hello world");
    assert_eq!(parser.finish().unwrap(), "Hello world");
}

#[test]
fn stream_parser_rejects_unexpected_tool_call() {
    let mut parser = GeminiStreamState::default();
    let err = parser
        .handle_line(
            r#"{"type":"tool_use","tool_name":"shell","parameters":{"cmd":"date"}}"#,
            &mut |_| Ok(()),
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("unexpected tool call"));
}

#[test]
fn stream_parser_recovers_markdown_from_write_file_tool_call() {
    let mut parser = GeminiStreamState::default();
    parser
        .handle_line(
            r##"{"type":"tool_use","tool_name":"write_file","parameters":{"file_path":"/tmp/syslog-gemini-headless-x/.gemini/tmp/session/plans/frustration_assessment.md","content":"# Frustration Assessment\n\nRecovered report."}}"##,
            &mut |_| Ok(()),
        )
        .unwrap();
    parser
        .handle_line(r#"{"type":"result","status":"success"}"#, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(
        parser.finish().unwrap(),
        "# Frustration Assessment\n\nRecovered report."
    );
}

#[test]
fn stream_parser_prefers_write_file_assessment_over_preamble() {
    let mut parser = GeminiStreamState::default();
    let mut streamed = String::new();
    parser
        .handle_line(
            r#"{"type":"message","role":"assistant","content":[{"text":"I will write the assessment now."}]}"#,
            &mut |delta| {
                streamed.push_str(delta);
                Ok(())
            },
        )
        .unwrap();
    parser
        .handle_line(
            r##"{"type":"tool_use","tool_name":"write_file","parameters":{"file_path":"/tmp/syslog-gemini-headless-x/.gemini/tmp/session/plans/frustration_assessment.md","content":"# Frustration Assessment\n\nRecovered report."}}"##,
            &mut |_| Ok(()),
        )
        .unwrap();
    parser
        .handle_line(r#"{"type":"result","status":"success"}"#, &mut |_| Ok(()))
        .unwrap();
    assert_eq!(streamed, "I will write the assessment now.");
    assert_eq!(
        parser.finish().unwrap(),
        "# Frustration Assessment\n\nRecovered report."
    );
}

#[tokio::test]
#[serial]
async fn gemini_assessment_timeout_kills_and_reaps_child() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir_all(source.path().join(".gemini")).unwrap();
    fs::write(source.path().join(".gemini").join("settings.json"), "{}").unwrap();
    let script = source.path().join("fake-gemini.sh");
    fs::write(&script, "#!/usr/bin/env bash\nsleep 5\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }

    let config = GeminiAssessConfig {
        program: script.display().to_string(),
        model: "gemini-test".into(),
        source_home: Some(source.path().to_path_buf()),
        timeout_secs: 1,
    };
    let err = run_gemini_assessment("prompt", &config, |_| Ok(()))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("timed out after 1 seconds"));
    assert!(err.contains("cleanup:"));
}

#[tokio::test]
#[serial]
async fn gemini_assessment_reports_child_stderr_before_stdin_pipe_error() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir_all(source.path().join(".gemini")).unwrap();
    fs::write(source.path().join(".gemini").join("settings.json"), "{}").unwrap();
    let script = source.path().join("fake-gemini.sh");
    fs::write(
        &script,
        "#!/usr/bin/env bash\necho 'simulated gemini failure' >&2\nexit 42\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();
    }

    let config = GeminiAssessConfig {
        program: script.display().to_string(),
        model: "gemini-test".into(),
        source_home: Some(source.path().to_path_buf()),
        // The full all-features suite deliberately saturates CPU and SQLite
        // workers. Give this ordering assertion enough scheduling headroom so
        // it tests stderr-vs-stdin precedence, not host load.
        timeout_secs: 30,
    };
    let large_prompt = "x".repeat(2 * 1024 * 1024);
    let err = run_gemini_assessment(&large_prompt, &config, |_| Ok(()))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Gemini headless exited"));
    assert!(err.contains("simulated gemini failure"));
}

#[test]
#[serial]
fn env_config_uses_syslog_specific_knobs() {
    let _cmd = EnvGuard::set("CORTEX_HEADLESS_GEMINI_CMD", "custom-gemini");
    let _model = EnvGuard::set("CORTEX_HEADLESS_GEMINI_MODEL", "gemini-custom");
    let config = GeminiAssessConfig::from_env(None, 42);
    assert_eq!(config.program, "custom-gemini");
    assert_eq!(config.model, "gemini-custom");
    assert_eq!(config.timeout_secs, 42);
}

// Eng review fix (Fix 1 — architecture + performance reviewers): the
// caller-supplied timeout is now the SINGLE source of truth end to end —
// `GeminiAssessConfig::from_env` must not re-read
// `CORTEX_LLM_COMPLETION_TIMEOUT_SECS`, or the outer `LlmRunner::run`
// timeout ([llm].timeout_secs) and the inner Gemini-subprocess timeout
// could silently disagree (effective timeout becomes min(both)).
#[test]
#[serial]
fn from_env_uses_the_passed_timeout_not_the_legacy_env_var() {
    let _timeout = EnvGuard::set("CORTEX_LLM_COMPLETION_TIMEOUT_SECS", "5");
    let cfg = GeminiAssessConfig::from_env(None, 77);
    assert_eq!(
        cfg.timeout_secs, 77,
        "GeminiAssessConfig must use the passed-in resolved timeout, \
         NOT re-read CORTEX_LLM_COMPLETION_TIMEOUT_SECS, so it can never \
         silently disagree with LlmRunner's own outer timeout"
    );
}
