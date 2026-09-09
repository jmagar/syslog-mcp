use super::{
    AgentActorUpsert, AgentProjectionOutboxInput, AgentProjectionWriteFault,
    AgentProjectionWriteInput, AgentRunEventUpsert, AgentRunUpsert, AgentWorktreeEvidenceUpsert,
    write_agent_projection, write_agent_projection_with_cursor,
    write_agent_projection_with_cursor_and_fault, write_agent_projection_with_fault,
};
use crate::agent_observatory::identity::{actor_key, event_key, run_key};
use crate::config::StorageConfig;
use crate::db::agent_observatory::{
    AgentEventKind, EvidenceTrustLevel, GitCommitUpsert, RepositoryObservationInput,
    RepositoryObservationKind, RepositoryUpsert, RepositoryWorktreeUpsert, RunStatus,
    StreamEventName, get_repository_by_key, projection_cursor,
    reconcile_git_repository_snapshot_with, reconcile_repository,
};
use crate::db::init_pool;
use rusqlite::Connection;

const STARTED_AT: &str = "2026-08-05T12:00:00.000Z";
const EVENT_AT: &str = "2026-08-05T12:00:01.000Z";
const EXPIRES_AT: &str = "2026-08-06T12:00:01.000Z";
const HEAD_SHA: &str = "0123456789012345678901234567890123456789";

fn repository() -> RepositoryUpsert {
    RepositoryUpsert {
        repository_key: "repo-key".to_string(),
        hostname: "devhost".to_string(),
        common_git_dir: "/workspace/cortex/.git".to_string(),
        primary_path: "/workspace/cortex".to_string(),
        display_name: "cortex".to_string(),
        remote_url_hash: None,
        metadata_json: "{}".to_string(),
    }
}

fn worktree() -> RepositoryWorktreeUpsert {
    RepositoryWorktreeUpsert {
        worktree_key: "worktree-key".to_string(),
        hostname: "devhost".to_string(),
        path: "/workspace/cortex".to_string(),
        git_dir: "/workspace/cortex/.git".to_string(),
        branch_ref: Some("refs/heads/main".to_string()),
        branch_name: Some("main".to_string()),
        head_sha: Some(HEAD_SHA.to_string()),
        upstream_ref: None,
        detached: false,
        bare: false,
        locked: false,
        lock_reason: None,
        prunable: false,
        prune_reason: None,
        dirty: false,
        staged_count: 0,
        unstaged_count: 0,
        untracked_count: 0,
        ahead: None,
        behind: None,
        status_hash: Some("clean".to_string()),
    }
}

fn input() -> AgentProjectionWriteInput {
    AgentProjectionWriteInput {
        run: AgentRunUpsert {
            native_session_id: "session-one".to_string(),
            tool: "Claude".to_string(),
            provider_tool: Some("claude-code".to_string()),
            hostname: "devhost".to_string(),
            parent_run_key: None,
            previous_run_key: None,
            primary_worktree_key: Some("worktree-key".to_string()),
            transcript_path: Some("/workspace/cortex/session.jsonl".to_string()),
            process_id: Some("4242".to_string()),
            status: RunStatus::Active,
            status_reason: "provider activity".to_string(),
            status_observed_at: EVENT_AT.to_string(),
            started_at: STARTED_AT.to_string(),
            last_activity_at: EVENT_AT.to_string(),
            ended_at: None,
            primary_branch: Some("main".to_string()),
            start_head_sha: Some(HEAD_SHA.to_string()),
            current_head_sha: Some(HEAD_SHA.to_string()),
            projection_version: 1,
            freshness_json: r#"{"transcript":"fresh"}"#.to_string(),
            metadata_json: r#"{"provider":"claude"}"#.to_string(),
        },
        actor: Some(AgentActorUpsert {
            native_actor_id: "main".to_string(),
            actor_type: Some("primary".to_string()),
            display_name: Some("Main agent".to_string()),
            started_at: Some(STARTED_AT.to_string()),
            last_activity_at: Some(EVENT_AT.to_string()),
            ended_at: None,
            metadata_json: "{}".to_string(),
        }),
        worktree_evidence: Some(AgentWorktreeEvidenceUpsert {
            worktree_key: "worktree-key".to_string(),
            evidence_kind: "cwd".to_string(),
            evidence_source: "ai_logs:42".to_string(),
            trust_level: EvidenceTrustLevel::Verified,
            confidence: 1.0,
            is_primary: true,
            first_seen_at: EVENT_AT.to_string(),
            last_seen_at: EVENT_AT.to_string(),
            metadata_json: "{}".to_string(),
        }),
        trace_relation: None,
        event: AgentRunEventUpsert {
            source_kind: "ai_logs".to_string(),
            source_id: "42".to_string(),
            projection_variant: "transcript".to_string(),
            worktree_key: Some("worktree-key".to_string()),
            observed_at: EVENT_AT.to_string(),
            ingested_at: EVENT_AT.to_string(),
            event_kind: AgentEventKind::Transcript,
            source_log_id: Some(42),
            provider_sequence: Some(7),
            trace_id: None,
            span_id: None,
            severity: "info".to_string(),
            title: "Assistant response".to_string(),
            summary: "Projected transcript event".to_string(),
            payload_json: r#"{"role":"assistant"}"#.to_string(),
            content_scrubbed: true,
        },
        outbox: AgentProjectionOutboxInput {
            event_name: StreamEventName::RunEvent,
            expires_at: EXPIRES_AT.to_string(),
            payload_json: r#"{"changed":["event_count","last_activity_at"]}"#.to_string(),
        },
    }
}

fn setup() -> (tempfile::TempDir, crate::db::DbPool) {
    let dir = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(dir.path().join("projection.db"))).unwrap();
    reconcile_repository(&pool, &repository(), &[worktree()], STARTED_AT).unwrap();
    (dir, pool)
}

fn table_count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn assert_projection_counts(pool: &crate::db::DbPool, expected: [i64; 5]) {
    let connection = pool.get().unwrap();
    let actual = [
        table_count(&connection, "agent_runs"),
        table_count(&connection, "agent_run_actors"),
        table_count(&connection, "agent_run_worktrees"),
        table_count(&connection, "agent_run_events"),
        table_count(&connection, "agent_stream_outbox"),
    ];
    assert_eq!(actual, expected);
}

#[test]
fn injected_failure_after_event_insert_rolls_back_everything_and_retry_is_idempotent() {
    let (_dir, pool) = setup();
    let input = input();

    let error =
        write_agent_projection_with_fault(&pool, &input, AgentProjectionWriteFault::EventInsert)
            .unwrap_err();
    assert!(error.to_string().contains("after event insert"));
    assert_projection_counts(&pool, [0, 0, 0, 0, 0]);

    let written = write_agent_projection(&pool, &input).unwrap();
    assert!(written.materialized_state_changed);
    assert!(written.event_inserted);
    assert_eq!(written.run.event_count, 1);
    assert_eq!(written.run.error_count, 0);
    assert_eq!(written.run.first_source_log_id, Some(42));
    assert_eq!(written.run.last_source_log_id, Some(42));
    assert_eq!(written.run.last_event_id, Some(written.event.id));
    assert_eq!(
        written.run.run_key,
        run_key("devhost", "claude", "session-one").unwrap()
    );
    let actor = written.actor.as_ref().unwrap();
    assert_eq!(
        actor.actor_key,
        actor_key(&written.run.run_key, "main").unwrap()
    );
    assert_eq!(written.event.actor_id, Some(actor.id));
    assert_eq!(
        written.event.worktree_id,
        Some(written.worktree_evidence.as_ref().unwrap().worktree_id)
    );
    assert_eq!(
        written.event.event_key,
        event_key("ai_logs", "42", "transcript").unwrap()
    );
    let outbox = written.outbox.as_ref().unwrap();
    assert_eq!(outbox.run_id, written.run.id);
    assert_eq!(outbox.event_name, StreamEventName::RunEvent);
    assert!(outbox.outbox_key.starts_with("v1:projection_outbox:"));
    assert_projection_counts(&pool, [1, 1, 1, 1, 1]);

    let replay = write_agent_projection(&pool, &input).unwrap();
    assert!(!replay.materialized_state_changed);
    assert!(!replay.event_inserted);
    assert_eq!(replay.run.id, written.run.id);
    assert_eq!(replay.actor.as_ref().unwrap().id, actor.id);
    assert_eq!(
        replay.worktree_evidence.as_ref().unwrap().id,
        written.worktree_evidence.as_ref().unwrap().id
    );
    assert_eq!(replay.event.id, written.event.id);
    assert!(replay.outbox.is_none());
    assert_projection_counts(&pool, [1, 1, 1, 1, 1]);
}

#[test]
fn existing_projection_cursor_read_does_not_require_sqlite_write_lock() {
    let (dir, pool) = setup();
    assert_eq!(projection_cursor(&pool, "logs").unwrap(), "");

    let blocker = Connection::open(dir.path().join("projection.db")).unwrap();
    blocker.busy_timeout(std::time::Duration::ZERO).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();

    assert_eq!(projection_cursor(&pool, "logs").unwrap(), "");

    blocker.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn projection_and_source_cursor_commit_atomically_and_replay_without_duplicates() {
    let (_dir, pool) = setup();
    let input = input();
    assert_eq!(projection_cursor(&pool, "logs").unwrap(), "");

    let error = write_agent_projection_with_cursor_and_fault(
        &pool,
        &input,
        "logs",
        "42",
        AgentProjectionWriteFault::CursorAdvance,
    )
    .unwrap_err();
    assert!(error.to_string().contains("after cursor advance"));
    assert_eq!(projection_cursor(&pool, "logs").unwrap(), "");
    assert_projection_counts(&pool, [0, 0, 0, 0, 0]);

    let error = write_agent_projection_with_cursor_and_fault(
        &pool,
        &input,
        "logs",
        "42",
        AgentProjectionWriteFault::Commit,
    )
    .unwrap_err();
    assert!(error.to_string().contains("after commit"));
    assert_eq!(projection_cursor(&pool, "logs").unwrap(), "42");
    assert_projection_counts(&pool, [1, 1, 1, 1, 1]);

    let replay = write_agent_projection_with_cursor(&pool, &input, "logs", "42").unwrap();
    assert!(!replay.materialized_state_changed);
    assert!(!replay.event_inserted);
    assert_eq!(projection_cursor(&pool, "logs").unwrap(), "42");
    assert_projection_counts(&pool, [1, 1, 1, 1, 1]);
}

#[test]
fn material_run_update_emits_one_outbox_without_double_counting_the_event() {
    let (_dir, pool) = setup();
    let initial_input = input();
    let initial = write_agent_projection(&pool, &initial_input).unwrap();
    let initial_outbox_key = initial.outbox.as_ref().unwrap().outbox_key.clone();

    let mut updated_input = initial_input.clone();
    updated_input.run.status = RunStatus::Waiting;
    updated_input.run.status_reason = "awaiting user input".to_string();
    updated_input.run.status_observed_at = "2026-08-05T12:00:10.000Z".to_string();
    updated_input.run.last_activity_at = "2026-08-05T12:00:10.000Z".to_string();
    updated_input.outbox.event_name = StreamEventName::RunStatus;
    updated_input.outbox.payload_json = r#"{"status":"waiting"}"#.to_string();

    let updated = write_agent_projection(&pool, &updated_input).unwrap();
    assert!(updated.materialized_state_changed);
    assert!(!updated.event_inserted);
    assert_eq!(updated.run.status, RunStatus::Waiting);
    assert_eq!(updated.run.event_count, 1);
    assert_eq!(updated.run.error_count, 0);
    let updated_outbox = updated.outbox.as_ref().unwrap();
    assert_eq!(updated_outbox.event_name, StreamEventName::RunStatus);
    assert_ne!(updated_outbox.outbox_key, initial_outbox_key);
    assert_projection_counts(&pool, [1, 1, 1, 1, 2]);

    let replay = write_agent_projection(&pool, &updated_input).unwrap();
    assert!(!replay.materialized_state_changed);
    assert!(!replay.event_inserted);
    assert!(replay.outbox.is_none());
    assert_eq!(replay.run.event_count, 1);
    assert_projection_counts(&pool, [1, 1, 1, 1, 2]);
}

#[test]
fn missing_worktree_reference_rolls_back_run_actor_and_event() {
    let (_dir, pool) = setup();
    let mut invalid = input();
    invalid.run.primary_worktree_key = Some("missing-worktree".to_string());

    let error = write_agent_projection(&pool, &invalid).unwrap_err();
    assert!(error.to_string().contains("missing-worktree"));
    assert_projection_counts(&pool, [0, 0, 0, 0, 0]);
}

#[test]
fn reverse_replay_cannot_regress_actor_or_worktree_evidence() {
    let (_dir, pool) = setup();
    let mut newest = input();
    newest.actor.as_mut().unwrap().display_name = Some("Newest actor".to_string());
    newest.actor.as_mut().unwrap().last_activity_at = Some("2026-08-05T12:05:00.000Z".to_string());
    newest.worktree_evidence.as_mut().unwrap().last_seen_at =
        "2026-08-05T12:05:00.000Z".to_string();
    newest.worktree_evidence.as_mut().unwrap().trust_level = EvidenceTrustLevel::Verified;
    write_agent_projection(&pool, &newest).unwrap();

    let mut older = input();
    older.event.source_id = "43".to_string();
    older.event.source_log_id = Some(43);
    older.actor.as_mut().unwrap().display_name = Some("Stale actor".to_string());
    older.actor.as_mut().unwrap().last_activity_at = Some(STARTED_AT.to_string());
    older.worktree_evidence.as_mut().unwrap().last_seen_at = STARTED_AT.to_string();
    older.worktree_evidence.as_mut().unwrap().trust_level = EvidenceTrustLevel::Inferred;
    let replay = write_agent_projection(&pool, &older).unwrap();
    assert_eq!(
        replay.actor.unwrap().display_name.as_deref(),
        Some("Newest actor")
    );
    let evidence = replay.worktree_evidence.unwrap();
    assert_eq!(evidence.last_seen_at, "2026-08-05T12:05:00.000Z");
    assert_eq!(evidence.trust_level, EvidenceTrustLevel::Verified);
}

#[test]
fn event_key_collision_rejects_any_fingerprint_mismatch() {
    let (_dir, pool) = setup();
    let original = input();
    write_agent_projection(&pool, &original).unwrap();
    let mut collision = original;
    collision.event.trace_id = Some("0123456789abcdef0123456789abcdef".to_string());
    let error = write_agent_projection(&pool, &collision).unwrap_err();
    assert!(error.to_string().contains("event identity conflict"));
    assert_projection_counts(&pool, [1, 1, 1, 1, 1]);
}

#[test]
fn git_snapshot_failure_after_topology_and_commits_rolls_back_all_stages() {
    let directory = tempfile::tempdir().unwrap();
    let pool = init_pool(&StorageConfig::for_test(
        directory.path().join("atomic-git.db"),
    ))
    .unwrap();
    let commit = GitCommitUpsert {
        sha: HEAD_SHA.to_string(),
        parent_shas_json: "[]".to_string(),
        author_name: None,
        author_email_hash: None,
        authored_at: Some(STARTED_AT.to_string()),
        committed_at: Some(STARTED_AT.to_string()),
        subject: "atomic snapshot".to_string(),
        changed_files: Some(1),
        insertions: Some(1),
        deletions: Some(0),
        changed_paths_json: "[]".to_string(),
        reachable: true,
        metadata_json: "{}".to_string(),
    };
    let error = reconcile_git_repository_snapshot_with(
        &pool,
        &repository(),
        &[worktree()],
        &[commit],
        &[],
        STARTED_AT,
        |_| {
            Ok(vec![RepositoryObservationInput {
                worktree_key: Some("missing-worktree".to_string()),
                observation_kind: RepositoryObservationKind::Status,
                new_head_sha: None,
                summary: "injected failure".to_string(),
                payload_json: "{}".to_string(),
            }])
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("missing-worktree"));
    assert!(get_repository_by_key(&pool, "repo-key").unwrap().is_none());
    let connection = pool.get().unwrap();
    assert_eq!(table_count(&connection, "git_commits"), 0);
    assert_eq!(table_count(&connection, "repository_observations"), 0);
}

#[test]
fn equal_timestamp_a_b_a_replay_converges_for_all_materialized_state() {
    for variant in ["run", "actor", "evidence"] {
        let (_dir, pool) = setup();
        let original = input();
        write_agent_projection(&pool, &original).unwrap();
        let mut conflicting = original.clone();
        match variant {
            "run" => conflicting.run.metadata_json = r#"{"provider":"other"}"#.to_string(),
            "actor" => {
                conflicting.actor.as_mut().unwrap().display_name = Some("Other actor".to_string());
            }
            "evidence" => conflicting.worktree_evidence.as_mut().unwrap().confidence = 0.5,
            _ => unreachable!(),
        }
        write_agent_projection(&pool, &conflicting).unwrap();
        let outbox_before = table_count(&pool.get().unwrap(), "agent_stream_outbox");
        let replay = write_agent_projection(&pool, &original).unwrap();
        assert!(!replay.materialized_state_changed, "{variant}");
        assert!(!replay.event_inserted, "{variant}");
        assert!(replay.outbox.is_none(), "{variant}");
        assert_eq!(
            table_count(&pool.get().unwrap(), "agent_stream_outbox"),
            outbox_before,
            "{variant}"
        );
        assert_eq!(table_count(&pool.get().unwrap(), "agent_run_events"), 1);
    }
}

#[test]
fn older_different_replay_is_a_true_noop_without_outbox() {
    let (_dir, pool) = setup();
    let original = input();
    write_agent_projection(&pool, &original).unwrap();
    let mut older = original.clone();
    older.run.last_activity_at = STARTED_AT.to_string();
    older.run.status_observed_at = STARTED_AT.to_string();
    older.run.status = RunStatus::Waiting;
    older.run.status_reason = "stale".to_string();
    older.run.metadata_json = r#"{"provider":"stale"}"#.to_string();
    older.actor.as_mut().unwrap().last_activity_at = Some(STARTED_AT.to_string());
    older.actor.as_mut().unwrap().display_name = Some("Stale actor".to_string());
    older.actor.as_mut().unwrap().metadata_json = r#"{"stale":true}"#.to_string();
    older.worktree_evidence.as_mut().unwrap().last_seen_at = STARTED_AT.to_string();
    older.worktree_evidence.as_mut().unwrap().confidence = 0.25;
    older.worktree_evidence.as_mut().unwrap().metadata_json = r#"{"stale":true}"#.to_string();
    let replay = write_agent_projection(&pool, &older).unwrap();
    assert!(!replay.materialized_state_changed);
    assert!(!replay.event_inserted);
    assert!(replay.outbox.is_none());
    assert_eq!(replay.run.event_count, 1);
    assert_projection_counts(&pool, [1, 1, 1, 1, 1]);
}
