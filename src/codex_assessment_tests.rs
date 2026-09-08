use super::*;

#[tokio::test]
async fn protocol_refuses_approval_requests_errors_disconnect_and_oversized_frames() {
    for bytes in [
        b"{\"id\":4,\"method\":\"item/commandExecution/requestApproval\"}\n".to_vec(),
        b"{\"id\":1,\"error\":{\"message\":\"private content\"}}\n".to_vec(),
        Vec::new(),
        vec![b'x'; MAX_FRAME as usize + 1],
    ] {
        let error = receive(&mut bytes.as_slice()).await.unwrap_err();
        assert!(!error.to_string().contains("private content"));
    }
}

#[tokio::test]
#[ignore = "requires an authenticated Codex installation and consumes a model request"]
async fn live_codex_app_server_returns_a_completed_assessment() {
    let config = CodexAssessConfig::from_env(None);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        run(
            "Return exactly CORTEX_ASSESSMENT_READY as text. Do not use tools.",
            &config,
            |_| Ok(()),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(output.contains("CORTEX_ASSESSMENT_READY"));
}

#[test]
fn assessment_thread_is_ephemeral_read_only_and_noninteractive() {
    let params = thread_params(std::path::Path::new("/tmp/assessment"), &None);
    assert_eq!(params["ephemeral"], true);
    assert_eq!(params["sandbox"], "read-only");
    assert_eq!(params["approvalPolicy"], "never");
    assert_eq!(params["config"]["features.shell_tool"], false);
    assert_eq!(params["config"]["web_search"], "disabled");
    assert_eq!(params["model"], Value::Null);
}

#[test]
fn output_cap_rejects_overflow_without_emitting_partial_delta() {
    let mut output = "x".repeat(MAX_OUTPUT - 1);
    assert!(append_delta(&mut output, "é").is_err());
    assert_eq!(output.len(), MAX_OUTPUT - 1);
    append_delta(&mut output, "y").unwrap();
    assert_eq!(output.len(), MAX_OUTPUT);
}
