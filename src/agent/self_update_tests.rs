use super::*;

#[test]
fn update_needed_false_for_matching_version() {
    let directive = AgentUpdateDirective {
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        path: "/v1/agent/binary?os=linux&arch=x86_64".to_string(),
        sha256: Some("deadbeef".to_string()),
        checksum_path: None,
        format: "binary".to_string(),
    };
    assert!(!update_needed(&directive));
}

#[test]
fn update_needed_true_for_different_version() {
    let directive = AgentUpdateDirective {
        version: "999.0.0".to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        path: "/v1/agent/binary".to_string(),
        sha256: Some("deadbeef".to_string()),
        checksum_path: None,
        format: "binary".to_string(),
    };
    assert!(update_needed(&directive));
}

#[test]
fn update_needed_rejects_semver_downgrade() {
    let directive = AgentUpdateDirective {
        version: "0.0.0".to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        path: "/binary".to_string(),
        sha256: Some("deadbeef".to_string()),
        checksum_path: None,
        format: "binary".to_string(),
    };
    assert!(!update_needed(&directive));
}

#[test]
fn directive_platform_binding_is_exact() {
    let matching = AgentUpdateDirective {
        version: "999.0.0".to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        path: "/binary".to_string(),
        sha256: Some("deadbeef".to_string()),
        checksum_path: None,
        format: "binary".to_string(),
    };
    assert!(directive_matches_platform(&matching));
    let mut wrong = matching;
    wrong.os = "not-this-os".to_string();
    assert!(!directive_matches_platform(&wrong));
}

#[test]
fn sha256_hex_matches_known_vector() {
    // SHA-256 of the empty input.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // SHA-256 of "abc".
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn join_url_normalizes_slashes() {
    assert_eq!(
        join_url("http://127.0.0.1:3100", "/v1/agent/binary").unwrap(),
        "http://127.0.0.1:3100/v1/agent/binary"
    );
    assert_eq!(
        join_url("http://127.0.0.1:3100/", "v1/agent/binary").unwrap(),
        "http://127.0.0.1:3100/v1/agent/binary"
    );
    assert_eq!(
        join_url(
            "https://cortex.example.invalid",
            "/v1/agent/binary?os=linux&arch=x86_64"
        )
        .unwrap(),
        "https://cortex.example.invalid/v1/agent/binary?os=linux&arch=x86_64"
    );
}

#[test]
fn join_url_rejects_cross_origin_directives() {
    assert!(join_url("https://cortex.example", "https://evil.example/binary").is_err());
    assert!(join_url("https://cortex.example", "//evil.example/binary").is_err());
}

#[test]
fn windows_swap_script_preserves_literal_paths_and_process_arguments() {
    let script = windows_swap_script(
        42,
        Path::new("C:\\Cortex User's\\.cortex-update.tmp.exe"),
        Path::new("C:\\Cortex User's\\cortex.exe"),
        Some(Path::new("C:\\Cortex User's\\cortex.bak")),
        &["heartbeat".into(), "agent".into(), "--label=a b".into()],
    );
    assert!(script.contains("WaitForExit()"));
    assert!(script.contains("C:\\Cortex User''s\\.cortex-update.tmp.exe"));
    assert!(script.contains("C:\\Cortex User''s\\cortex.exe"));
    assert!(script.contains("$psi.Arguments='heartbeat agent \"--label=a b\"'"));
    assert!(!script.contains("ArgumentList"));
    assert!(script.contains("catch{"));
    assert!(script.contains("cortex.bak"));
    assert!(script.contains(".handoff.log"));
    assert!(script.contains("Get-ScheduledTask -TaskName 'CortexHeartbeatAgent'"));
    assert!(script.contains("Start-ScheduledTask -TaskName 'CortexHeartbeatAgent'"));
    assert!(script.contains("task did not become restartable"));
    assert!(script.contains("task did not enter Running state"));
    assert!(script.contains("$task.State -ne 'Running'"));
}

#[test]
fn windows_command_line_quotes_backslashes_before_quotes_and_at_end() {
    let args = [
        "plain".into(),
        "two words".into(),
        r#"say \"hello\""#.into(),
        "trailing slash\\".into(),
        "".into(),
    ];
    assert_eq!(
        windows_command_line(&args),
        "plain \"two words\" \"say \\\\\\\"hello\\\\\\\"\" \"trailing slash\\\\\" \"\""
    );
}

#[test]
fn marker_roundtrips_through_disk() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("cortex");
    std::fs::write(&exe, b"fake").unwrap();

    let marker = UpdateMarker {
        target: "1.2.3".to_string(),
        bak: dir.path().join("cortex.bak-1.1.0"),
        attempts: 2,
    };
    write_marker(&exe, &marker).unwrap();

    let read = read_marker(&marker_path(&exe)).expect("marker present");
    assert_eq!(read.target, "1.2.3");
    assert_eq!(read.attempts, 2);
    assert_eq!(read.bak, marker.bak);
}

#[test]
fn read_marker_absent_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read_marker(&dir.path().join("nope.json")).is_none());
}

#[test]
fn backup_current_binary_uses_unique_backup_paths() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("cortex");
    std::fs::write(&exe, b"current").unwrap();
    std::fs::write(dir.path().join("cortex.bak-3.1.0"), b"stale").unwrap();

    let first = backup_current_binary(&exe, dir.path(), "3.1.0").unwrap();
    let second = backup_current_binary(&exe, dir.path(), "3.1.0").unwrap();

    assert_ne!(first, dir.path().join("cortex.bak-3.1.0"));
    assert_ne!(second, dir.path().join("cortex.bak-3.1.0"));
    assert_ne!(first, second);
    assert_eq!(std::fs::read(first).unwrap(), b"current");
    assert_eq!(std::fs::read(second).unwrap(), b"current");
    assert_eq!(
        std::fs::read(dir.path().join("cortex.bak-3.1.0")).unwrap(),
        b"stale"
    );
}

#[test]
fn ensure_binary_still_present_errors_with_clear_diagnosis_when_exe_vanished() {
    // Regression: devhost's agent logged a bare, unhelpful ENOENT ("back up
    // current binary to ...") for hours because a concurrent `cargo build
    // --release` replaced the exact path the running agent was exec'd from
    // (~/.local/bin/cortex was a dev-only symlink into the build output).
    // current_exe() then resolves to "<path> (deleted)", which never exists.
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("cortex (deleted)");

    let err = ensure_binary_still_present(&exe).unwrap_err();
    let message = format!("{err:#}");
    assert!(
        message.contains("no longer exists") && message.contains("concurrent rebuild"),
        "expected a clear diagnosis, got: {message}"
    );
}

#[test]
fn ensure_binary_still_present_ok_when_exe_exists() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("cortex");
    std::fs::write(&exe, b"current").unwrap();
    assert!(ensure_binary_still_present(&exe).is_ok());
}

#[test]
fn staged_binary_creation_is_exclusive_and_synced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stage.tmp");
    write_staged_exclusive(&path, b"first").unwrap();
    assert!(write_staged_exclusive(&path, b"second").is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"first");
}

#[test]
fn pruning_bounds_backups_and_removes_stale_staging() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["cortex.bak-1", "cortex.bak-2", "cortex.bak-3"] {
        std::fs::write(dir.path().join(name), name).unwrap();
    }
    std::fs::write(dir.path().join(".cortex-update-old.tmp"), b"old").unwrap();
    prune_update_artifacts(dir.path()).unwrap();
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names
            .iter()
            .filter(|name| name.starts_with("cortex.bak-"))
            .count(),
        RETAIN_BACKUPS
    );
    assert!(!names.iter().any(|name| name == ".cortex-update-old.tmp"));
}

#[tokio::test]
async fn download_binary_accepts_authenticated_body() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/binary"))
        .and(header("authorization", "Bearer secret"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"cortex".to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let client = build_update_client().unwrap();
    let bytes = download_binary(
        &client,
        &format!("{}/binary", server.uri()),
        Some("secret"),
        64,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(bytes, b"cortex");
}

#[tokio::test]
async fn maybe_update_resolves_server_checksum_before_validating_binary() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let bytes = b"not-an-executable";
    let checksum = format!("{}  cortex-windows-x86_64.exe\n", sha256_hex(bytes));
    Mock::given(method("GET"))
        .and(path("/checksum"))
        .and(header("authorization", "Bearer secret"))
        .respond_with(ResponseTemplate::new(200).set_body_string(checksum))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/binary"))
        .and(header("authorization", "Bearer secret"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let directive = AgentUpdateDirective {
        version: "999.0.0".to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        path: "/binary".to_string(),
        sha256: None,
        checksum_path: Some("/checksum".to_string()),
        format: "binary".to_string(),
    };
    let error = maybe_update(
        &build_update_client().unwrap(),
        &server.uri(),
        Some("secret"),
        &directive,
    )
    .await
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("staged agent binary failed validation"),
        "checksum should be resolved before executable validation: {error:#}"
    );
}

#[tokio::test]
async fn download_binary_rejects_oversized_content_length() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/binary"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0_u8; 16]))
        .mount(&server)
        .await;

    let client = build_update_client().unwrap();
    let error = download_binary(
        &client,
        &format!("{}/binary", server.uri()),
        None,
        8,
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("content length 16 exceeds 8-byte limit"));
}

#[tokio::test]
async fn download_binary_times_out_waiting_for_first_byte() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = socket.read(&mut request).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
            .await
            .unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = socket.write_all(b"x").await;
    });

    let client = build_update_client().unwrap();
    let error = download_binary(
        &client,
        &format!("http://{address}/binary"),
        None,
        8,
        Duration::from_millis(20),
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("first byte exceeded"));
}

#[tokio::test]
async fn download_binary_times_out_when_stream_stalls() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = socket.read(&mut request).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .await
            .unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = socket.write_all(b"y").await;
    });

    let client = build_update_client().unwrap();
    let error = download_binary(
        &client,
        &format!("http://{address}/binary"),
        None,
        8,
        Duration::from_secs(1),
        Duration::from_millis(20),
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("download stalled"));
}

#[cfg(unix)]
#[test]
fn validate_binary_accepts_matching_version_and_rejects_mismatch() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let fake = dir.path().join("fake-cortex");
    std::fs::write(&fake, "#!/bin/sh\necho \"cortex 9.9.9\"\n").unwrap();
    let mut perms = std::fs::metadata(&fake).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&fake, perms).unwrap();

    assert!(validate_binary(&fake, "9.9.9").is_ok());
    assert!(validate_binary(&fake, "1.2.3").is_err());
}
