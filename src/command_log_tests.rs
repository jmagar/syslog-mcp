use std::io::Write;

use crate::config::StorageConfig;
use crate::db::{SearchParams, init_pool, search_logs};
use serial_test::serial;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

/// Pins the actual fix rather than the delegation: the old implementation read
/// `$HOSTNAME` directly, so setting it to a sentinel must not change what
/// `hostname()` reports. Comparing against `local_hostname()` alone would pass
/// against a full revert in Docker and most CI runners, where `$HOSTNAME` is
/// already the OS hostname.
#[cfg(unix)]
#[test]
#[serial]
fn command_log_hostname_ignores_the_hostname_env_var() {
    const SENTINEL: &str = "cortex-hostname-sentinel.invalid";

    let previous = crate::env::var("HOSTNAME").ok();
    // The test overlay avoids mutating libc's process environment. `#[serial]`
    // still prevents same-key semantic interference with neighboring tests.
    crate::env::remove_test_var("HOSTNAME");
    let without_env = hostname();
    crate::env::set_test_var("HOSTNAME", SENTINEL);
    let with_env = hostname();

    match previous {
        Some(value) => crate::env::set_test_var("HOSTNAME", value),
        None => crate::env::remove_test_var("HOSTNAME"),
    }

    if without_env == crate::hostname::UNRESOLVED_HOSTNAME {
        // Neither gethostname() nor a platform source answers on this host, so
        // `$HOSTNAME` is the documented fallback and there is nothing to assert.
        return;
    }
    assert_eq!(
        with_env, without_env,
        "hostname() must resolve via gethostname(), not $HOSTNAME"
    );
    assert_ne!(with_env, SENTINEL);
    assert_eq!(with_env, crate::hostname::local_hostname());
}

#[test]
fn parses_zsh_extended_history_line() {
    let parsed = parse_zsh_extended_history_line(": 1716500000:3;cargo test").unwrap();

    assert_eq!(parsed.duration_secs, 3);
    assert_eq!(parsed.command, "cargo test");
    assert_eq!(parsed.started_at.timestamp(), 1_716_500_000);
}

#[test]
fn skips_plain_zsh_history_line_without_timestamp() {
    assert!(parse_zsh_extended_history_line("cargo test").is_none());
}

#[test]
fn command_scrubber_redacts_shell_specific_secret_forms() {
    let command = "env OPENAI_API_KEY=sk-proj-123 gh auth token --token abc curl -u user:pass https://user:pass@example.test";
    let scrubbed = scrub_command(command);

    assert!(!scrubbed.contains("sk-proj-123"));
    assert!(!scrubbed.contains("abc"));
    assert!(!scrubbed.contains("user:pass"));
    assert!(scrubbed.contains("[REDACTED]"));
}

#[test]
fn command_args_to_shell_command_quotes_multi_arg_invocations() {
    let args = vec![
        "sh".to_string(),
        "-lc".to_string(),
        "printf wrappedok >/dev/null".to_string(),
    ];

    assert_eq!(
        command_args_to_shell_command(&args),
        "sh -lc 'printf wrappedok >/dev/null'"
    );
    assert_eq!(
        command_args_to_shell_command(&["printf wrappedok >/dev/null".to_string()]),
        "printf wrappedok >/dev/null"
    );
}

#[test]
fn agent_command_ingest_spool_guard_is_argv_scoped() {
    // Canonical grammar: `cortex ingest shell agent index`.
    assert!(is_agent_command_ingest_spool_invocation(&[
        "cortex".to_string(),
        "ingest".to_string(),
        "shell".to_string(),
        "agent".to_string(),
        "index".to_string(),
    ]));
    assert!(is_agent_command_ingest_spool_invocation(&[
        "/usr/local/bin/cortex".to_string(),
        "ingest".to_string(),
        "shell".to_string(),
        "agent".to_string(),
        "index".to_string(),
        "--path".to_string(),
        "/tmp/x.jsonl".to_string(),
    ]));
    // Grouped grammar predating this rename: `cortex ingest agent-command
    // ingest-spool`. This is the one already deployed on live hosts (e.g.
    // devhost) and the only legacy shape worth tolerating here — the even
    // older bare `cortex agent-command ingest-spool` (no `ingest` prefix) is
    // unreachable: the CLI's top-level parser rejects it outright (see
    // `src/surfaces.rs`'s `MovedIntoGroupedDomain` entry), so no process can
    // ever actually invoke it for this guard to need to catch.
    assert!(is_agent_command_ingest_spool_invocation(&[
        "cortex".to_string(),
        "ingest".to_string(),
        "agent-command".to_string(),
        "ingest-spool".to_string(),
    ]));
    assert!(!is_agent_command_ingest_spool_invocation(&[
        "sh".to_string(),
        "-c".to_string(),
        "cortex ingest shell agent index".to_string(),
    ]));
    assert!(!is_agent_command_ingest_spool_invocation(&[
        "bash".to_string(),
        "-c".to_string(),
        "agent-command ingest-spool".to_string(),
    ]));
}

#[test]
fn sanitize_uri_segment_percent_encodes_losslessly() {
    assert_eq!(sanitize_uri_segment("a/b"), "a%2Fb");
    assert_eq!(sanitize_uri_segment("a b"), "a%20b");
    assert_eq!(sanitize_uri_segment("a-b"), "a-b");
    assert_eq!(sanitize_uri_segment("lambda-λ"), "lambda-%CE%BB");
}

#[cfg(unix)]
#[test]
#[serial]
fn wrapper_executes_multi_arg_commands_without_shell_reparse() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let fake_shell = dir.path().join("fake-shell");
    let arg_out = dir.path().join("args.txt");
    let spool_dir = dir.path().join("state");
    std::fs::create_dir(&spool_dir).unwrap();
    std::fs::set_permissions(&spool_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let spool = spool_dir.join("agent-command.jsonl");
    std::fs::write(
        &fake_shell,
        "#!/bin/sh\nprintf shell-used >\"$CORTEX_TEST_ARG_OUT\"\nexit 97\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake_shell, std::fs::Permissions::from_mode(0o755)).unwrap();
    let previous_shell = crate::env::var_os("SHELL");
    let previous_out = crate::env::var_os("CORTEX_TEST_ARG_OUT");
    crate::env::set_test_var("SHELL", &fake_shell);
    crate::env::set_test_var("CORTEX_TEST_ARG_OUT", &arg_out);

    let exit_code = run_agent_command_wrapper(
        &spool,
        &[
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf '%s\\n%s\\n%s\\n' \"$#\" \"$1\" \"$2\" >\"$CORTEX_TEST_ARG_OUT\"".to_string(),
            "sh".to_string(),
            "two words".to_string(),
            "literal;not-shell".to_string(),
        ],
    )
    .unwrap();

    match previous_shell {
        Some(value) => crate::env::set_test_var("SHELL", value),
        None => crate::env::remove_test_var("SHELL"),
    }
    match previous_out {
        Some(value) => crate::env::set_test_var("CORTEX_TEST_ARG_OUT", value),
        None => crate::env::remove_test_var("CORTEX_TEST_ARG_OUT"),
    }
    assert_eq!(exit_code, 0);
    assert_eq!(
        std::fs::read_to_string(arg_out).unwrap(),
        "2\ntwo words\nliteral;not-shell\n"
    );
}

#[test]
fn imports_zsh_history_as_shell_history_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let history = dir.path().join(".zsh_history");
    std::fs::write(
        &history,
        ": 1716500000:3;export API_KEY=abc123\nplain command\n",
    )
    .unwrap();

    let result = import_zsh_history(&pool, &history, "zsh").unwrap();

    assert_eq!(result.scanned, 2);
    assert_eq!(result.imported, 1);
    assert_eq!(result.skipped, 1);
    let rows = search_logs(
        &pool,
        &SearchParams {
            query: Some("export".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].facility.as_deref(), Some("shell"));
    assert_eq!(rows[0].app_name.as_deref(), Some("zsh"));
    assert!(
        rows[0]
            .metadata_json
            .as_deref()
            .unwrap()
            .contains("shell-history")
    );
    assert!(
        rows[0]
            .metadata_json
            .as_deref()
            .unwrap()
            .contains("\"shell\"")
    );
    assert!(rows[0].message.contains("[REDACTED]"));
}

#[test]
fn imports_zsh_history_from_saved_offset() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let history = dir.path().join(".zsh_history");
    let state = dir.path().join("shell-state.json");
    std::fs::write(&history, ": 1716500000:3;cargo test\n").unwrap();

    let first = import_zsh_history_with_state(&pool, &history, "zsh", &state).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&history)
        .unwrap()
        .write_all(b": 1716500010:1;cargo fmt\n")
        .unwrap();
    let second = import_zsh_history_with_state(&pool, &history, "zsh", &state).unwrap();
    let third = import_zsh_history_with_state(&pool, &history, "zsh", &state).unwrap();

    assert_eq!(first.scanned, 1);
    assert_eq!(first.imported, 1);
    assert_eq!(second.scanned, 1);
    assert_eq!(second.imported, 1);
    assert_eq!(third.scanned, 0);
    assert_eq!(third.imported, 0);
    let rows = search_logs(
        &pool,
        &SearchParams {
            query: Some("cargo".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(rows.len(), 2);
}

#[test]
fn imports_atuin_history_as_shell_history_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let atuin = dir.path().join("history.db");
    let conn = rusqlite::Connection::open(&atuin).unwrap();
    conn.execute_batch(
        "CREATE TABLE history (
            id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            duration INTEGER NOT NULL,
            exit INTEGER NOT NULL,
            command TEXT NOT NULL,
            cwd TEXT NOT NULL,
            session TEXT NOT NULL,
            hostname TEXT NOT NULL,
            deleted_at INTEGER,
            author TEXT,
            intent TEXT
        );",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO history (id, timestamp, duration, exit, command, cwd, session, hostname)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            "hist-1",
            1_716_500_000_123_000_000_i64,
            3_000_000_000_i64,
            2_i64,
            "export API_KEY=abc123",
            "/tmp/project",
            "session-1",
            "devhost"
        ],
    )
    .unwrap();

    let result = import_atuin_history_with_state(
        &pool,
        &atuin,
        dir.path().join("atuin-state.json").as_path(),
    )
    .unwrap();

    assert_eq!(result.scanned, 1);
    assert_eq!(result.imported, 1);
    let rows = search_logs(
        &pool,
        &SearchParams {
            query: Some("export".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].hostname, "devhost");
    assert_eq!(rows[0].facility.as_deref(), Some("shell"));
    assert_eq!(rows[0].app_name.as_deref(), Some("atuin"));
    assert_eq!(rows[0].severity, "warning");
    assert!(rows[0].message.contains("[REDACTED]"));
    let metadata = rows[0].metadata_json.as_deref().unwrap();
    assert!(metadata.contains("\"source_kind\":\"shell-history\""));
    assert!(metadata.contains("\"session\":\"session-1\""));
    assert!(metadata.contains("\"cwd\":\"/tmp/project\""));
}

#[test]
fn imports_atuin_history_from_saved_timestamp_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let atuin = dir.path().join("history.db");
    let state = dir.path().join("atuin-state.json");
    let conn = rusqlite::Connection::open(&atuin).unwrap();
    conn.execute_batch(
        "CREATE TABLE history (
            id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            duration INTEGER NOT NULL,
            exit INTEGER NOT NULL,
            command TEXT NOT NULL,
            cwd TEXT NOT NULL,
            session TEXT NOT NULL,
            hostname TEXT NOT NULL,
            deleted_at INTEGER,
            author TEXT,
            intent TEXT
        );",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO history (id, timestamp, duration, exit, command, cwd, session, hostname)
         VALUES ('hist-1', 1716500000000000000, 1000, 0, 'cargo test', '/tmp/project', 's1', 'devhost')",
        [],
    )
    .unwrap();

    let first = import_atuin_history_with_state(&pool, &atuin, &state).unwrap();
    conn.execute(
        "INSERT INTO history (id, timestamp, duration, exit, command, cwd, session, hostname)
         VALUES ('hist-2', 1716500001000000000, 1000, 0, 'cargo fmt', '/tmp/project', 's1', 'devhost')",
        [],
    )
    .unwrap();
    let second = import_atuin_history_with_state(&pool, &atuin, &state).unwrap();
    let third = import_atuin_history_with_state(&pool, &atuin, &state).unwrap();

    assert_eq!(first.scanned, 1);
    assert_eq!(first.imported, 1);
    assert_eq!(second.scanned, 1);
    assert_eq!(second.imported, 1);
    assert_eq!(third.scanned, 0);
    assert_eq!(third.imported, 0);
}

#[test]
fn imports_agent_spool_as_agent_command_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let spool_dir = dir.path().join("private-state");
    std::fs::create_dir(&spool_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&spool_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let spool = spool_dir.join("claude-commands.jsonl");
    let auth_header = format!("{} {}", "Authorization:", "Bearer test-token");
    let record = AgentCommandSpoolRecord {
        started_at: "2026-05-24T05:00:00.000Z".into(),
        finished_at: "2026-05-24T05:00:01.000Z".into(),
        duration_ms: 1000,
        exit_status: Some(2),
        command: format!("curl -H '{auth_header}' http://example.test"),
        cwd: Some("/tmp/project".into()),
        agent: "claude-code".into(),
        command_surface: Some("bash_tool".into()),
        hostname: "devhost".into(),
        user: Some("jmagar".into()),
        pid: 42,
        session_id: Some("session-1".into()),
        schema_version: 1,
        content_scrubbed: false,
    };
    let mut file = std::fs::File::create(&spool).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    serde_json::to_writer(&mut file, &record).unwrap();
    writeln!(file).unwrap();

    let result = import_agent_command_spool(&pool, &spool).unwrap();

    assert_eq!(result.imported, 1);
    let rows = search_logs(
        &pool,
        &SearchParams {
            query: Some("curl".into()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].facility.as_deref(), Some("agent"));
    assert_eq!(rows[0].severity, "warning");
    assert_eq!(rows[0].ai_tool.as_deref(), Some("claude-code"));
    assert!(rows[0].message.contains("[REDACTED]"));
    assert!(
        rows[0]
            .metadata_json
            .as_deref()
            .unwrap()
            .contains("agent-command")
    );
    assert!(
        rows[0]
            .metadata_json
            .as_deref()
            .unwrap()
            .contains("agent_command")
    );
    assert_eq!(std::fs::read_to_string(&spool).unwrap(), "");
    let second = import_agent_command_spool(&pool, &spool).unwrap();
    assert_eq!(second.scanned, 0);
    assert_eq!(second.imported, 0);
}

fn sample_agent_command_record(command: &str) -> AgentCommandSpoolRecord {
    AgentCommandSpoolRecord {
        started_at: "2026-07-06T00:00:00Z".to_string(),
        finished_at: "2026-07-06T00:00:01Z".to_string(),
        duration_ms: 1000,
        exit_status: Some(0),
        command: command.to_string(),
        cwd: None,
        agent: "claude-code".to_string(),
        command_surface: None,
        hostname: "testhost".to_string(),
        user: None,
        pid: 1234,
        session_id: None,
        schema_version: 1,
        content_scrubbed: true,
    }
}

#[test]
fn import_agent_command_records_dedupes_against_existing_rows() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let record = sample_agent_command_record("echo hi");

    let first = import_agent_command_records(&pool, std::slice::from_ref(&record), None).unwrap();
    assert_eq!(first.imported, 1);
    assert_eq!(first.skipped_duplicates, 0);

    let second = import_agent_command_records(&pool, &[record], None).unwrap();
    assert_eq!(second.imported, 0);
    assert_eq!(second.skipped_duplicates, 1);
}

#[test]
fn import_agent_command_records_dedupes_within_same_batch() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let record = sample_agent_command_record("echo hi");

    // Two identical records in the SAME call: a per-record check-then-insert
    // loop would let both pass a "not already present" check before either
    // is inserted. The batch-level `existing_entry_keys` query alone doesn't
    // catch this either, since neither record is in the DB yet — dedup must
    // also happen against keys already accepted earlier in this same batch.
    let result = import_agent_command_records(&pool, &[record.clone(), record], None).unwrap();
    assert_eq!(result.imported, 1);
    assert_eq!(result.skipped_duplicates, 1);
}

#[test]
fn import_agent_command_records_annotates_forwarded_peer_when_present() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let record = sample_agent_command_record("echo hi");

    let result = import_agent_command_records(&pool, &[record], Some("203.0.113.7")).unwrap();
    assert_eq!(result.imported, 1);

    // Query the inserted row directly to prove the peer IP actually landed
    // in metadata_json, rather than just asserting the call didn't panic.
    // Acquire and drop a pool connection per query rather than holding one
    // across the second `import_agent_command_records` call below, which
    // also needs a connection from the same (small, test-sized) pool.
    let metadata_json: String = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT metadata_json FROM logs WHERE message = ?1",
            ["echo hi"],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        metadata_json.contains("203.0.113.7"),
        "expected forwarded_from_peer_ip in metadata_json, got: {metadata_json}"
    );

    // A second record with no forwarding peer must NOT gain the field.
    let local_record = sample_agent_command_record("echo local");
    import_agent_command_records(&pool, &[local_record], None).unwrap();
    let local_metadata_json: String = pool
        .get()
        .unwrap()
        .query_row(
            "SELECT metadata_json FROM logs WHERE message = ?1",
            ["echo local"],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!local_metadata_json.contains("forwarded_from_peer_ip"));
}

#[tokio::test]
async fn forward_agent_command_spool_posts_and_truncates_on_success() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("agent-command.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&spool_path)
        .unwrap();
    writeln!(
        file,
        r#"{{"started_at":"2026-07-06T00:00:00Z","finished_at":"2026-07-06T00:00:01Z","duration_ms":1000,"exit_status":0,"command":"echo hi","cwd":null,"agent":"claude-code","command_surface":null,"hostname":"testhost","user":null,"pid":1234,"session_id":null,"schema_version":1,"content_scrubbed":true}}"#
    )
    .unwrap();
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&spool_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent-commands"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"scanned":0,"imported":1,"skipped":0,"skipped_duplicates":0,"errors":0}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let result = forward_agent_command_spool(&spool_path, &server.uri(), Some("secret"))
        .await
        .unwrap();

    assert_eq!(result.imported, 1);
    let remaining = std::fs::metadata(&spool_path).unwrap();
    assert_eq!(
        remaining.len(),
        0,
        "spool must be truncated after a successful forward"
    );
}

#[tokio::test]
async fn run_agent_command_forward_loop_drains_spool_on_first_tick() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("agent-command.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&spool_path)
        .unwrap();
    writeln!(
        file,
        r#"{{"started_at":"2026-07-06T00:00:00Z","finished_at":"2026-07-06T00:00:01Z","duration_ms":1000,"exit_status":0,"command":"echo hi","cwd":null,"agent":"claude-code","command_surface":null,"hostname":"testhost","user":null,"pid":1234,"session_id":null,"schema_version":1,"content_scrubbed":true}}"#
    )
    .unwrap();
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&spool_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent-commands"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"scanned":0,"imported":1,"skipped":0,"skipped_duplicates":0,"errors":0}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let handle = tokio::spawn(run_agent_command_forward_loop(
        spool_path.clone(),
        server.uri(),
        Some("secret".to_string()),
        std::time::Duration::from_millis(10),
    ));
    // The loop never returns on its own; poll for the side effect (spool
    // truncated by the first successful forward) instead of a fixed sleep,
    // since a loaded CI box can make one 200ms window flaky.
    let mut truncated = false;
    for _ in 0..100 {
        if std::fs::metadata(&spool_path).unwrap().len() == 0 {
            truncated = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    handle.abort();

    assert!(
        truncated,
        "spool must be truncated after the loop's first successful forward"
    );
}

#[tokio::test]
async fn forward_agent_command_spool_preserves_records_appended_during_slow_post() {
    // Engineering-review regression test: the exclusive spool lock must be
    // released before the network POST, not held across it — otherwise a
    // concurrent `ingest shell agent wrap` invocation appending a new record
    // while a slow forward is in flight would stall behind the lock, and if
    // the lock-release/truncate logic were wrong, that concurrently
    // appended record could be silently lost.
    //
    // Test-review fix: the appender below now goes through the crate's real
    // `append_spool_record` (which takes the same `flock(LOCK_EX)` as
    // `forward_agent_command_spool`), not a bare `OpenOptions` write — an
    // earlier version of this test bypassed the lock entirely, so it could
    // never have detected the bug it claimed to guard against (it would
    // have passed identically even with the old "hold the lock across the
    // whole POST" behavior, since nothing on the append side ever contended
    // for that lock). This version proves both: an append using the real
    // locking path completes promptly (not stalled behind an
    // already-released lock) while the POST is in flight, and its content
    // survives the post-POST truncate.
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("agent-command.jsonl");
    let first_record = AgentCommandSpoolRecord {
        started_at: "2026-07-06T00:00:00Z".to_string(),
        finished_at: "2026-07-06T00:00:01Z".to_string(),
        duration_ms: 1000,
        exit_status: Some(0),
        command: "echo first".to_string(),
        cwd: None,
        agent: "claude-code".to_string(),
        command_surface: None,
        hostname: "testhost".to_string(),
        user: None,
        pid: 1234,
        session_id: None,
        schema_version: 1,
        content_scrubbed: true,
    };
    append_spool_record(&spool_path, &first_record).unwrap();

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent-commands"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    r#"{"scanned":0,"imported":1,"skipped":0,"skipped_duplicates":0,"errors":0}"#,
                )
                .set_delay(std::time::Duration::from_secs(1)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let forward_path = spool_path.clone();
    let server_uri = server.uri();
    let forward = tokio::spawn(async move {
        forward_agent_command_spool(&forward_path, &server_uri, Some("secret")).await
    });

    // Do not guess when the forward future has reached the network with an
    // arbitrary sleep. Wait until Wiremock has actually observed the POST,
    // then verify the delayed response is still in flight before appending.
    // This makes the lock regression deterministic even under a heavily loaded
    // parallel test runner.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let requests = server.received_requests().await.expect("received requests");
            if !requests.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("forward POST should reach the mock server");
    assert!(
        !forward.is_finished(),
        "request observation must happen while the delayed response is still in flight"
    );

    // Append a second record through the same locking helper a concurrent
    // `ingest shell agent wrap` invocation would use. If the fix regressed
    // (lock held across the POST), this `flock(LOCK_EX)` would block until the
    // delayed response completes; with the fix it returns promptly.
    let append_path = spool_path.clone();
    let second_record = AgentCommandSpoolRecord {
        started_at: "2026-07-06T00:00:02Z".to_string(),
        finished_at: "2026-07-06T00:00:03Z".to_string(),
        duration_ms: 500,
        exit_status: Some(0),
        command: "echo second".to_string(),
        cwd: None,
        agent: "claude-code".to_string(),
        command_surface: None,
        hostname: "testhost".to_string(),
        user: None,
        pid: 5678,
        session_id: None,
        schema_version: 1,
        content_scrubbed: true,
    };
    let appended = tokio::task::spawn_blocking(move || {
        let start = std::time::Instant::now();
        append_spool_record(&append_path, &second_record).unwrap();
        start.elapsed()
    });

    let append_elapsed = appended.await.unwrap();
    let result = forward.await.unwrap().unwrap();

    assert_eq!(result.imported, 1, "the first record was forwarded");
    assert!(
        append_elapsed < std::time::Duration::from_millis(500),
        "a real flock(LOCK_EX)-taking append while the POST is in flight must not block on \
         the (already-released) forwarding lock, took {append_elapsed:?}"
    );

    let remaining = std::fs::read_to_string(&spool_path).unwrap();
    assert!(
        remaining.contains("echo second"),
        "record appended during the in-flight POST must survive the post-forward truncate, got: {remaining:?}"
    );
    assert!(
        !remaining.contains("echo first"),
        "the already-forwarded record must be consumed, got: {remaining:?}"
    );
}

#[tokio::test]
async fn forward_agent_command_spool_keeps_file_on_http_failure() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("agent-command.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&spool_path)
        .unwrap();
    writeln!(
        file,
        r#"{{"started_at":"2026-07-06T00:00:00Z","finished_at":"2026-07-06T00:00:01Z","duration_ms":1000,"exit_status":0,"command":"echo hi","cwd":null,"agent":"claude-code","command_surface":null,"hostname":"testhost","user":null,"pid":1234,"session_id":null,"schema_version":1,"content_scrubbed":true}}"#
    )
    .unwrap();
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&spool_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent-commands"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    let error = forward_agent_command_spool(&spool_path, &server.uri(), None)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("503"), "got: {error}");
    let remaining = std::fs::metadata(&spool_path).unwrap();
    assert!(remaining.len() > 0, "spool must survive a failed forward");
}

#[tokio::test]
async fn forward_agent_command_spool_drains_backlog_larger_than_one_chunk() {
    // Regression: a spool that's accumulated more than one
    // FORWARD_CHUNK_MAX_BYTES worth of backlog (e.g. the forwarder was never
    // running) must drain across multiple internal chunks in one call
    // instead of failing outright on an oversized single POST.
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("agent-command.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&spool_path)
        .unwrap();
    // Each record line is a little over 300 bytes; 5,000 of them exceeds
    // FORWARD_CHUNK_MAX_BYTES (512 KiB), forcing at least 3 chunks.
    for i in 0..5_000 {
        writeln!(
            file,
            r#"{{"started_at":"2026-07-06T00:00:00Z","finished_at":"2026-07-06T00:00:01Z","duration_ms":1000,"exit_status":0,"command":"echo command number {i}","cwd":null,"agent":"claude-code","command_surface":null,"hostname":"testhost","user":null,"pid":1234,"session_id":null,"schema_version":1,"content_scrubbed":true}}"#
        )
        .unwrap();
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&spool_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/agent-commands"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"scanned":0,"imported":1,"skipped":0,"skipped_duplicates":0,"errors":0}"#,
        ))
        .mount(&server)
        .await;

    let result = forward_agent_command_spool(&spool_path, &server.uri(), None)
        .await
        .unwrap();

    assert_eq!(result.scanned, 5_000);
    let remaining = std::fs::metadata(&spool_path).unwrap();
    assert_eq!(
        remaining.len(),
        0,
        "the whole backlog must drain across chunks in one call"
    );
}

#[test]
fn agent_spool_malformed_line_with_multibyte_at_preview_boundary_no_panic() {
    // Regression (bead syslog-mcp-8ouq): the JSON-parse error branch logs an
    // 80-byte preview of the offending line. The original code byte-sliced at
    // index 80, panicking when a multi-byte UTF-8 character straddled that
    // boundary. Sweep pad lengths so the 4-byte emoji covers every alignment
    // around byte 80, including mid-character offsets.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cortex.db");
    let pool = init_pool(&StorageConfig::for_test(db_path)).unwrap();
    let spool_dir = dir.path().join("private-state");
    std::fs::create_dir(&spool_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&spool_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let spool = spool_dir.join("claude-commands.jsonl");
    let mut file = std::fs::File::create(&spool).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut expected_errors = 0;
    for pad in 60..=80 {
        // Not valid JSON, longer than 80 bytes, multibyte char near byte 80.
        writeln!(file, "{}\u{1F600}tail-not-json", "a".repeat(pad)).unwrap();
        expected_errors += 1;
    }
    drop(file);

    let result = import_agent_command_spool(&pool, &spool).unwrap();

    assert_eq!(result.errors, expected_errors);
    assert_eq!(result.imported, 0);
}

#[test]
#[serial]
fn wrapper_preserves_command_exit_when_spool_append_fails() {
    use std::os::unix::fs::PermissionsExt;

    // `["true"]` is a single token, so the wrapper runs it via `$SHELL -c true`
    // (see `command_status`). The fake shell rejects login-shell invocation:
    // loading a persistent runner's profile made this test inherit stale
    // absolute paths from unrelated repositories. This must be `#[serial]` to exclude
    // `wrapper_executes_multi_arg_commands_without_shell_reparse`, which mutates
    // the global `SHELL`/`CORTEX_TEST_ARG_OUT` env — overlapping would exec that
    // test's fake shell here and corrupt its output buffer (both tests fail).
    let dir = tempfile::tempdir().unwrap();
    let fake_shell = dir.path().join("fake-shell");
    std::fs::write(
        &fake_shell,
        "#!/bin/sh\n[ \"$1\" = \"-c\" ] || exit 98\nexec /bin/sh \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake_shell, std::fs::Permissions::from_mode(0o755)).unwrap();
    let previous_shell = crate::env::var_os("SHELL");
    crate::env::set_test_var("SHELL", &fake_shell);

    let exit_code =
        run_agent_command_wrapper(dir.path(), &["true".to_string()]).expect("wrapper runs command");

    match previous_shell {
        Some(value) => crate::env::set_test_var("SHELL", value),
        None => crate::env::remove_test_var("SHELL"),
    }
    assert_eq!(exit_code, 0);
}

#[cfg(unix)]
#[test]
fn existing_spool_parent_permissions_are_not_mutated() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("existing-parent");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

    ensure_private_parent(&parent.join("agent-command.jsonl")).unwrap();

    let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);
}

#[cfg(unix)]
#[test]
fn newly_created_spool_parent_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("new-parent");

    ensure_private_parent(&parent.join("agent-command.jsonl")).unwrap();

    let mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}
