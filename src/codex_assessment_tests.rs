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
    assert_eq!(params["environments"], json!([]));
}

#[cfg(unix)]
fn mock_worker() -> (tempfile::TempDir, CodexAssessConfig) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("auth.json"), "0").unwrap();
    let program = root.path().join("mock-codex");
    std::fs::write(
        &program,
        r#"#!/usr/bin/env python3
import json, os, sys, time
def send(value):
    print(json.dumps(value), flush=True)
for line in sys.stdin:
    request = json.loads(line)
    method = request['method']
    if method == 'initialize':
        send({'id': 1, 'result': {}})
    elif method == 'thread/start':
        if request['params'].get('environments') != []:
            send({'id': 2, 'error': {'message': 'local environment exposed'}})
            continue
        send({'id': 2, 'result': {'thread': {'id': 'thread'}}})
    elif method == 'turn/start':
        auth = os.path.join(os.environ['CODEX_HOME'], 'auth.json')
        with open(auth) as f: previous = int(f.read())
        with open(auth, 'w') as f: f.write(str(previous + 1))
        mode = request['params']['input'][0]['text']
        if mode == 'cancel':
            time.sleep(30)
        elif mode == 'error':
            send({'id': 3, 'error': {'message': 'redacted'}})
        else:
            if mode == 'tool':
                send({'method': 'item/started', 'params': {'item': {'type': 'imageView'}}})
            send({'method': 'item/agentMessage/delta', 'params': {'delta': str(previous)}})
            send({'method': 'turn/completed', 'params': {'turn': {'status': 'completed'}}})
"#,
    )
    .unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = CodexAssessConfig {
        program: program.to_string_lossy().into_owned(),
        model: None,
        source_home: root.path().to_owned(),
    };
    (root, config)
}

#[cfg(unix)]
#[tokio::test]
async fn auth_rotation_survives_success_and_failure() {
    let (_root, config) = mock_worker();
    assert_eq!(run("success", &config, |_| Ok(())).await.unwrap(), "0");
    assert!(run("error", &config, |_| Ok(())).await.is_err());
    assert_eq!(run("success", &config, |_| Ok(())).await.unwrap(), "2");
}

#[cfg(unix)]
#[tokio::test]
async fn auth_rotation_survives_cancellation_and_releases_worker_lock() {
    let (root, config) = mock_worker();
    let owned = config.clone();
    let task = tokio::spawn(async move { run("cancel", &owned, |_| Ok(())).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while std::fs::read_to_string(root.path().join("auth.json")).unwrap() != "1" {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let second_config = config.clone();
    let mut second = tokio::spawn(async move { run("success", &second_config, |_| Ok(())).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut second)
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("auth.json")).unwrap(),
        "1"
    );
    task.abort();
    let _ = task.await;
    let next = tokio::time::timeout(std::time::Duration::from_secs(5), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(next, "1");
}

#[cfg(unix)]
#[tokio::test]
async fn unexpected_tool_execution_cannot_complete_assessment() {
    let (_root, config) = mock_worker();
    assert!(run("tool", &config, |_| Ok(())).await.is_err());
}

#[test]
fn output_cap_rejects_overflow_without_emitting_partial_delta() {
    let mut output = "x".repeat(MAX_OUTPUT - 1);
    assert!(append_delta(&mut output, "é").is_err());
    assert_eq!(output.len(), MAX_OUTPUT - 1);
    append_delta(&mut output, "y").unwrap();
    assert_eq!(output.len(), MAX_OUTPUT);
}
