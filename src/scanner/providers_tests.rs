use super::*;
use crate::config::StorageConfig;
use crate::db::init_pool;
use serial_test::serial;

struct EnvOverride {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvOverride {
    fn set(key: &'static str, value: &Path) -> Self {
        let previous = crate::env::var_os(key);
        crate::env::set_test_var(key, value);
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = crate::env::var_os(key);
        crate::env::remove_test_var(key);
        Self { key, previous }
    }
}

impl Drop for EnvOverride {
    fn drop(&mut self) {
        if let Some(value) = &self.previous {
            crate::env::set_test_var(self.key, value);
        } else {
            crate::env::remove_test_var(self.key);
        }
    }
}

#[test]
fn aliases_and_antigravity_lane_coverage_are_explicit() {
    assert_eq!(Provider::from_alias("openai-codex"), Some(Provider::Codex));
    assert_eq!(Provider::from_alias("agy"), Some(Provider::Antigravity));
    assert_eq!(Provider::from_alias("unknown"), None);

    let antigravity = definition(Provider::Antigravity);
    for lane in [
        ProviderLane::SessionMetadata,
        ProviderLane::Transcript,
        ProviderLane::ToolCalls,
    ] {
        assert_eq!(antigravity.support(lane), AdapterSupport::Supported);
    }
    assert_eq!(
        antigravity.support(ProviderLane::McpEvents),
        AdapterSupport::Partial
    );
    for lane in [ProviderLane::Skills, ProviderLane::Hooks] {
        assert_eq!(antigravity.support(lane), AdapterSupport::Unsupported);
    }
    assert_eq!(Coverage::NotObserved.as_str(), "not_observed");
    assert_eq!(AdapterSupport::Supported.as_str(), "supported");
    assert_eq!(AdapterSupport::Unsupported.as_str(), "unsupported");
}

#[test]
fn registry_is_the_single_source_for_source_kinds_and_forwarding_lanes() {
    for (provider, source_kind) in [
        (Provider::Claude, "claude_project"),
        (Provider::Codex, "codex_session"),
        (Provider::Gemini, "gemini_session"),
    ] {
        assert_eq!(source_kind_for_provider(provider), Some(source_kind));
        assert_eq!(provider_for_source_kind(source_kind), Some(provider));
        assert_eq!(
            definition(provider).forwarding_coverage(ProviderLane::Transcript),
            Coverage::Observed
        );
    }

    assert_eq!(
        source_kind_for_provider(Provider::Antigravity),
        Some("antigravity_desktop")
    );
    assert_eq!(
        provider_for_source_kind("antigravity_cli"),
        Some(Provider::Antigravity)
    );
    assert_eq!(provider_for_source_kind("explicit_file"), None);
    assert_eq!(
        definition(Provider::Codex).forwarding_coverage(ProviderLane::Hooks),
        Coverage::NotObserved,
        "an unsupported lane cannot become evidence merely through forwarding"
    );
}

#[test]
fn mounted_transcript_layouts_resolve_through_registry() {
    for (path, expected) in [
        (
            "/mounted/.claude/projects/project/session.jsonl",
            Provider::Claude,
        ),
        (
            "/mounted/.codex/archived_sessions/2026/session.jsonl",
            Provider::Codex,
        ),
        (
            "/mounted/.gemini/tmp/run/chats/session.json",
            Provider::Gemini,
        ),
    ] {
        let provider = provider_for_transcript_layout(Path::new(path));
        assert_eq!(provider, Some(expected));
        assert_eq!(
            provider.and_then(source_kind_for_provider),
            definition(expected).source_kind
        );
    }
}

#[test]
#[serial]
fn codex_active_archive_and_alternate_roots_are_safe_and_classified() {
    let home = tempfile::tempdir().unwrap();
    let alternate = tempfile::tempdir().unwrap();
    let _home = EnvOverride::set("HOME", home.path());
    let _codex_home = EnvOverride::set("CODEX_HOME", alternate.path());

    let roots = transcript_roots();
    for expected in [
        home.path().join(".codex/sessions"),
        home.path().join(".codex/archived_sessions"),
        home.path().join(".codex/worktrees"),
        alternate.path().join("sessions"),
        alternate.path().join("archived_sessions"),
        alternate.path().join("worktrees"),
    ] {
        assert!(
            roots.contains(&expected),
            "missing root: {}",
            expected.display()
        );
        assert!(is_known_transcript_root(&expected));
        assert_eq!(
            provider_for_path(&expected.join("session.jsonl")),
            Some(Provider::Codex)
        );
    }
}

#[test]
#[serial]
fn antigravity_transcript_projections_have_narrow_roots() {
    let home = tempfile::tempdir().unwrap();
    let _home = EnvOverride::set("HOME", home.path());
    let database = home
        .path()
        .join(".gemini/antigravity/conversations/example.db");
    let root = home.path().join(".gemini/antigravity/brain");
    let transcript = root.join("session/.system_generated/logs/transcript.jsonl");

    assert_eq!(provider_for_path(&database), Some(Provider::Antigravity));
    assert!(transcript_roots().contains(&root));
    assert_eq!(
        provider_for_transcript_layout(&transcript),
        Some(Provider::Antigravity)
    );
}

#[test]
fn empty_install_runtime_json_does_not_promote_static_adapter_support() {
    let db = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(db.path().join("test.db"))).unwrap();

    let health = runtime_health(&pool).unwrap();
    assert!(
        health
            .iter()
            .flat_map(|provider| provider.lanes.iter())
            .all(|lane| lane.coverage == "not_observed")
    );

    let json = serde_json::to_value(&health).unwrap();
    let codex_transcript = json
        .as_array()
        .unwrap()
        .iter()
        .find(|provider| provider["provider"] == "codex")
        .unwrap()["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|lane| lane["lane"] == "transcript")
        .unwrap();
    assert_eq!(codex_transcript["declared_support"], "supported");
    assert_eq!(codex_transcript["coverage"], "not_observed");
    assert_ne!(codex_transcript["declared_support"], "observed");
    assert_ne!(codex_transcript["declared_support"], "failed");
}

#[test]
fn runtime_health_aggregates_provider_source_kinds_without_reading_paths() {
    use rusqlite::{
        hooks::{AuthAction, Authorization},
        params,
    };

    let db = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(db.path().join("test.db"))).unwrap();
    let conn = pool.get().unwrap();

    for (path, source_kind, last_error) in [
        (
            "/private/transcripts/claude-success.jsonl",
            "claude_project",
            None,
        ),
        (
            "/private/transcripts/claude-failed.jsonl",
            "claude_project",
            Some("bad json"),
        ),
        (
            "/private/transcripts/codex-quiet.jsonl",
            "codex_session",
            None,
        ),
        (
            "/private/transcripts/gemini-success.json",
            "gemini_session",
            None,
        ),
        (
            "/private/transcripts/antigravity-success.jsonl",
            "antigravity_desktop",
            None,
        ),
        (
            "/private/transcripts/antigravity-failed.jsonl",
            "antigravity_cli",
            Some("bad json"),
        ),
    ] {
        conn.execute(
            "INSERT INTO transcript_sources (canonical_path, source_kind, last_error)
             VALUES (?1, ?2, ?3)",
            params![path, source_kind, last_error],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO transcript_import_records (source_id, record_key)
         SELECT id, 'claude-receipt' FROM transcript_sources
         WHERE source_kind = 'claude_project' AND last_error IS NULL",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO transcript_import_records (source_id, record_key)
         SELECT id, 'antigravity-receipt' FROM transcript_sources
         WHERE source_kind = 'antigravity_desktop'",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO transcript_import_records (source_id, record_key)
         SELECT id, 'gemini-receipt' FROM transcript_sources
         WHERE source_kind = 'gemini_session'",
        [],
    )
    .unwrap();

    // Reject any status-query attempt to access canonical_path. The health
    // projection must derive its fixed provider counters from source kind and
    // receipts alone, even when those paths cannot be read.
    conn.authorizer(Some(
        |context: rusqlite::hooks::AuthContext<'_>| match context.action {
            AuthAction::Read {
                table_name: "transcript_sources",
                column_name: "canonical_path",
            } => Authorization::Deny,
            _ => Authorization::Allow,
        },
    ))
    .unwrap();
    let health = runtime_health_conn(&conn).unwrap();
    conn.authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> Authorization>)
        .unwrap();

    let claude = health
        .iter()
        .find(|entry| entry.provider == "claude")
        .unwrap();
    assert_eq!(
        (
            claude.source_count,
            claude.successful_sources,
            claude.failed_sources
        ),
        (2, 1, 1)
    );
    assert_eq!(
        claude
            .lanes
            .iter()
            .find(|lane| lane.lane == "transcript")
            .unwrap()
            .coverage,
        "partial"
    );
    let codex = health
        .iter()
        .find(|entry| entry.provider == "codex")
        .unwrap();
    assert_eq!(
        (
            codex.source_count,
            codex.successful_sources,
            codex.failed_sources
        ),
        (1, 0, 0)
    );
    assert_eq!(
        codex
            .lanes
            .iter()
            .find(|lane| lane.lane == "transcript")
            .unwrap()
            .coverage,
        "not_observed"
    );
    let gemini = health
        .iter()
        .find(|entry| entry.provider == "gemini")
        .unwrap();
    assert_eq!(
        (
            gemini.source_count,
            gemini.successful_sources,
            gemini.failed_sources
        ),
        (1, 1, 0)
    );
    assert_eq!(
        gemini
            .lanes
            .iter()
            .find(|lane| lane.lane == "mcp_events")
            .unwrap()
            .coverage,
        "not_observed"
    );
    let antigravity = health
        .iter()
        .find(|entry| entry.provider == "antigravity")
        .unwrap();
    assert_eq!(
        (
            antigravity.source_count,
            antigravity.successful_sources,
            antigravity.failed_sources
        ),
        (2, 1, 1)
    );
}

#[test]
#[serial]
fn runtime_health_uses_real_scanner_outcomes_and_isolates_a_bad_provider_source() {
    let home = tempfile::tempdir().unwrap();
    let _home = EnvOverride::set("HOME", home.path());
    let _codex_home = EnvOverride::remove("CODEX_HOME");
    let db = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(db.path().join("test.db"))).unwrap();

    let bad_claude = home.path().join(".claude/projects/demo/broken.jsonl");
    std::fs::create_dir_all(bad_claude.parent().unwrap()).unwrap();
    std::fs::write(&bad_claude, "not-json\n").unwrap();

    let codex_archive = home
        .path()
        .join(".codex/archived_sessions/2026-09/session.jsonl");
    std::fs::create_dir_all(codex_archive.parent().unwrap()).unwrap();
    std::fs::write(
        &codex_archive,
        concat!(
            r#"{"type":"session_meta","payload":{"id":"archived-codex"}}"#,
            "\n",
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":"archive survives bad source"}}"#,
            "\n"
        ),
    )
    .unwrap();
    let bad_codex = home
        .path()
        .join(".codex/archived_sessions/2026-09/broken.jsonl");
    std::fs::write(&bad_codex, "not-json\n").unwrap();
    let quiet_codex = home.path().join(".codex/sessions/2026/quiet.jsonl");
    std::fs::create_dir_all(quiet_codex.parent().unwrap()).unwrap();
    std::fs::write(
        &quiet_codex,
        concat!(
            r#"{"type":"session_meta","payload":{"id":"quiet-codex"}}"#,
            "\n"
        ),
    )
    .unwrap();

    let result = crate::scanner::index_roots(&pool, None).unwrap();
    assert_eq!(
        result.ingested, 1,
        "a malformed Claude source must not block Codex"
    );
    // The malformed Claude and Codex fixtures each fail once. The
    // metadata-only Codex session has no transcript record to ingest, but it
    // is not malformed and therefore must not fabricate a parse error.
    assert_eq!(result.parse_errors, 2);

    let health = runtime_health(&pool).unwrap();
    assert!(
        health
            .iter()
            .flat_map(|provider| provider.lanes.iter())
            .all(|lane| {
                matches!(
                    lane.declared_support.as_str(),
                    "supported" | "partial" | "unsupported"
                )
            })
    );
    let codex = health
        .iter()
        .find(|entry| entry.provider == "codex")
        .unwrap();
    // The fixture contains one valid archive, one malformed archive, and one
    // metadata-only active session. It remains a distinct scanned source but
    // has no durable import receipt, so it must not upgrade transcript
    // coverage beyond the one successfully imported archive.
    assert_eq!(codex.source_count, 3);
    assert_eq!(codex.successful_sources, 1);
    assert_eq!(codex.failed_sources, 1);
    assert_eq!(
        codex
            .lanes
            .iter()
            .find(|lane| lane.lane == "transcript")
            .unwrap()
            .coverage,
        "partial"
    );
    assert_eq!(
        codex
            .lanes
            .iter()
            .find(|lane| lane.lane == "mcp_events")
            .unwrap()
            .coverage,
        "not_observed",
        "provider format support must not upgrade a quiet lane"
    );
    let claude = health
        .iter()
        .find(|entry| entry.provider == "claude")
        .unwrap();
    assert_eq!(claude.failed_sources, 1);
    assert_eq!(
        claude
            .lanes
            .iter()
            .find(|lane| lane.lane == "transcript")
            .unwrap()
            .coverage,
        "failed"
    );

    let antigravity = health
        .iter()
        .find(|entry| entry.provider == "antigravity")
        .unwrap();
    assert_eq!(antigravity.source_count, 0);
    assert!(
        antigravity
            .lanes
            .iter()
            .all(|lane| lane.coverage == "not_observed")
    );

    let source_id = crate::scanner::CheckpointStore::new(&pool)
        .ensure_source(
            &home
                .path()
                .join(".gemini/antigravity/conversations/failed.db")
                .display()
                .to_string(),
            "explicit_file",
        )
        .unwrap();
    crate::scanner::CheckpointStore::new(&pool)
        .mark_error(source_id, "locked sqlite source")
        .unwrap();
    let failed_antigravity = runtime_health(&pool)
        .unwrap()
        .into_iter()
        .find(|entry| entry.provider == "antigravity")
        .unwrap();
    // Antigravity has no transcript source kind or receipt-backed transcript
    // adapter yet. A manually-created generic checkpoint must not promote its
    // SQLite metadata descriptor into observed scanner evidence.
    assert_eq!(failed_antigravity.source_count, 0);
    assert_eq!(failed_antigravity.failed_sources, 0);
    assert!(
        failed_antigravity
            .lanes
            .iter()
            .all(|lane| lane.coverage == "not_observed")
    );
}
use std::path::Path;
