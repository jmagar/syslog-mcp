//! Authentication fixtures use fake credentials only; no live login or inference.
use super::*;

#[test]
fn isolated_auth_alias_shares_refreshes_and_never_copies_over_newer_logins() {
    let source = tempfile::tempdir().unwrap();
    let auth = source.path().join("auth.json");
    std::fs::write(&auth, "initial-fake-token").unwrap();
    let first = tempfile::tempdir().unwrap();
    link_auth_file(source.path(), first.path()).unwrap();
    std::fs::write(first.path().join("auth.json"), "rotated-fake-token").unwrap();
    assert_eq!(
        std::fs::read_to_string(&auth).unwrap(),
        "rotated-fake-token"
    );

    // The official Codex file store writes through the alias to its authority.
    // A subsequent operator login is visible immediately; dropping the isolated
    // home has no stale copy-back step that could overwrite it.
    std::fs::write(&auth, "newer-operator-login").unwrap();
    assert_eq!(
        std::fs::read_to_string(first.path().join("auth.json")).unwrap(),
        "newer-operator-login"
    );
    drop(first);
    let second = tempfile::tempdir().unwrap();
    link_auth_file(source.path(), second.path()).unwrap();
    assert_eq!(
        std::fs::read_to_string(second.path().join("auth.json")).unwrap(),
        "newer-operator-login"
    );
}

#[cfg(unix)]
fn rotating_provider(source: &std::path::Path, outcome: &str) -> CodexAssessConfig {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(source.join("auth.json"), "initial").unwrap();
    let script = source.join("fake-codex");
    let ending = match outcome {
        "success" => {
            "printf '%s\\n' '{\"method\":\"item/agentMessage/delta\",\"params\":{\"delta\":\"ok\"}}' '{\"method\":\"turn/completed\",\"params\":{\"turn\":{\"status\":\"completed\"}}}'\nread -r ignored\n"
        }
        "tool" => {
            "printf '%s\\n' '{\"method\":\"item/started\",\"params\":{\"item\":{\"type\":\"viewImage\"}}}'\nread -r ignored\n"
        }
        "cancel" => "read -r ignored\n",
        _ => unreachable!(),
    };
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
read -r initialize
printf '%s\n' '{{"id":1,"result":{{}}}}'
read -r initialized
read -r thread
case "$thread" in *'"environments":[]'*) ;; *) exit 4 ;; esac
printf '%s\n' '{{"id":2,"result":{{"thread":{{"id":"test"}}}}}}'
read -r turn
printf 'rotated' > "$CODEX_HOME/auth.json"
{ending}"#
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    CodexAssessConfig {
        program: script.to_str().unwrap().into(),
        model: None,
        source_home: source.into(),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn authentication_rotation_survives_success_and_protocol_failure() {
    for outcome in ["success", "tool"] {
        let source = tempfile::tempdir().unwrap();
        let config = rotating_provider(source.path(), outcome);
        let result = run("passive evidence", &config, 100, |_| Ok(())).await;
        if outcome == "success" {
            assert_eq!(result.unwrap(), "ok");
        } else {
            assert!(result.unwrap_err().to_string().contains("tool activity"));
        }
        assert_eq!(
            std::fs::read_to_string(source.path().join("auth.json")).unwrap(),
            "rotated"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn authentication_rotation_survives_cancellation() {
    let source = tempfile::tempdir().unwrap();
    let config = rotating_provider(source.path(), "cancel");
    let task = tokio::spawn(async move { run("passive evidence", &config, 100, |_| Ok(())).await });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while std::fs::read_to_string(source.path().join("auth.json")).unwrap() != "rotated" {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        std::fs::read_to_string(source.path().join("auth.json")).unwrap(),
        "rotated"
    );
}
