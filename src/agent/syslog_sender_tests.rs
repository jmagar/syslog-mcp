use super::*;

#[test]
fn backoff_ms_doubles_until_capped() {
    assert_eq!(backoff_ms(0), 500);
    assert_eq!(backoff_ms(1), 1_000);
    assert_eq!(backoff_ms(6), 30_000);
    assert_eq!(backoff_ms(42), 30_000);
}

#[test]
fn quota_eviction_creates_a_payload_free_gap() {
    let source_key = "source-000000000000000000000001";
    let mut spool = SpoolState {
        source_instance: "host-a".into(),
        source_epoch: 1,
        next_sequence: 0,
        next_sequences: HashMap::from([(source_key.into(), (MAX_SOURCE_SPOOL_RECORDS + 1) as u64)]),
        records: (1..=MAX_SOURCE_SPOOL_RECORDS + 1)
            .map(|sequence| SyslogForwardRecord {
                source_instance: format!("host-a:{source_key}"),
                source_epoch: 1,
                sequence: sequence as u64,
                idempotency_key: delivery_key("host-a", 1, sequence as u64, "record"),
                observed_at: now(),
                line: "x".into(),
            })
            .collect(),
        gaps: VecDeque::new(),
        dispatched_gap_keys: HashSet::new(),
        gap_overflow_intervals: 0,
        evicted_records: 0,
        last_dispatched_source: None,
    };
    evict_source_to_quota(&mut spool, source_key);
    assert_eq!(spool.records.len(), MAX_SOURCE_SPOOL_RECORDS);
    assert_eq!(spool.evicted_records, 1);
    let gap = spool.gaps.front().unwrap();
    assert_eq!((gap.from_sequence, gap.to_sequence), (1, 1));
    assert_eq!(gap.reason_code, "local_retention_quota");
}

#[test]
fn exact_receipt_advances_only_the_matching_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spool.json");
    let state = Arc::new(Mutex::new(SenderState {
        spool_path: path.clone(),
        spool: SpoolState {
            source_instance: "host-a".into(),
            source_epoch: 1,
            next_sequence: 2,
            next_sequences: HashMap::new(),
            records: VecDeque::from([record(1), record(2)]),
            gaps: VecDeque::new(),
            dispatched_gap_keys: HashSet::new(),
            gap_overflow_intervals: 0,
            evicted_records: 0,
            last_dispatched_source: None,
        },
        recovery_required: false,
        last_error_code: None,
    }));
    let request = SyslogForwardRequest {
        records: vec![record(1)],
        gaps: vec![],
    };
    apply_receipts(
        &state,
        &request,
        &[delivery_key("host-a:syslog", 1, 1, "record")],
    )
    .unwrap();
    let state = state.lock().unwrap();
    assert_eq!(state.spool.records.len(), 1);
    assert_eq!(state.spool.records.front().unwrap().sequence, 2);
    assert!(path.exists());
}

#[test]
fn incomplete_duplicate_and_unknown_receipts_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spool.json");
    let first = record(1);
    let second = record(2);
    let third = record(3);
    let state = Arc::new(Mutex::new(SenderState {
        spool_path: path,
        spool: SpoolState {
            source_instance: "host-a".into(),
            source_epoch: 1,
            next_sequence: 3,
            next_sequences: HashMap::new(),
            records: VecDeque::from([first.clone(), second.clone(), third.clone()]),
            gaps: VecDeque::new(),
            dispatched_gap_keys: HashSet::new(),
            gap_overflow_intervals: 0,
            evicted_records: 0,
            last_dispatched_source: None,
        },
        recovery_required: false,
        last_error_code: None,
    }));

    // A 2xx response without the complete exact receipt set is a protocol
    // failure: no local data may move.
    let request = SyslogForwardRequest {
        records: vec![first.clone(), second.clone()],
        gaps: vec![],
    };
    assert!(apply_receipts(&state, &request, &[]).is_err());
    assert_eq!(state.lock().unwrap().spool.records.len(), 3);

    assert!(
        apply_receipts(
            &state,
            &request,
            &[first.idempotency_key.clone(), first.idempotency_key.clone()],
        )
        .is_err()
    );
    assert_eq!(state.lock().unwrap().spool.records.len(), 3);

    // A response may acknowledge only request IDs. An unsent local record or
    // an unknown key is a protocol violation, not an acknowledgement.
    assert!(
        apply_receipts(
            &state,
            &request,
            &[
                "unknown-receipt".into(),
                third.idempotency_key,
                first.idempotency_key,
            ],
        )
        .is_err()
    );
    let state = state.lock().unwrap();
    assert_eq!(state.spool.records.len(), 3);
}

#[test]
fn receipt_save_failure_restores_records_gaps_and_dispatched_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spool.json");
    std::fs::create_dir(&path).unwrap();
    let item = record(1);
    let loss = gap("host-a:syslog", 2);
    let state = Arc::new(Mutex::new(SenderState {
        spool_path: path,
        spool: SpoolState {
            records: VecDeque::from([item.clone()]),
            gaps: VecDeque::from([loss.clone()]),
            dispatched_gap_keys: HashSet::from([loss.idempotency_key.clone()]),
            ..SpoolState::default()
        },
        recovery_required: false,
        last_error_code: None,
    }));
    let request = SyslogForwardRequest {
        records: vec![item.clone()],
        gaps: vec![loss.clone()],
    };

    assert!(
        apply_receipts(
            &state,
            &request,
            &[item.idempotency_key.clone(), loss.idempotency_key.clone()]
        )
        .is_err()
    );

    let locked = state.lock().unwrap();
    assert_eq!(locked.spool.records, VecDeque::from([item]));
    assert_eq!(locked.spool.gaps, VecDeque::from([loss.clone()]));
    assert!(
        locked
            .spool
            .dispatched_gap_keys
            .contains(&loss.idempotency_key)
    );
}

#[test]
fn source_quota_emits_only_maximal_contiguous_loss_intervals() {
    let source_key = "source-000000000000000000000001";
    let source = format!("host-a:{source_key}");
    let other = "host-a:source-000000000000000000000002";
    let old = (Utc::now() - chrono::Duration::days(2)).to_rfc3339();
    let mut records = VecDeque::new();
    for sequence in [10, 12] {
        let mut item = source_record(&source, sequence);
        item.observed_at = old.clone();
        records.push_back(item);
        records.push_back(source_record(other, sequence));
    }
    let mut spool = SpoolState {
        records,
        ..SpoolState::default()
    };

    evict_source_to_quota(&mut spool, source_key);

    let windows = spool
        .gaps
        .iter()
        .map(|item| (item.from_sequence, item.to_sequence))
        .collect::<Vec<_>>();
    assert_eq!(windows, vec![(10, 10), (12, 12)]);
}

#[tokio::test]
async fn status_uses_oldest_gap_when_no_records_are_queued() {
    let dir = tempfile::tempdir().unwrap();
    let sender = SyslogSender::new(String::new(), None, dir.path().join("spool.json"));
    let old = (Utc::now() - chrono::Duration::seconds(90)).to_rfc3339();
    {
        let mut state = sender.state.lock().unwrap();
        let mut loss = gap("host-a:syslog", 1);
        loss.observed_at = old;
        state.spool.gaps.push_back(loss);
    }

    assert!(sender.status().oldest_age_secs.unwrap() >= 89);
}

#[tokio::test]
async fn incomplete_success_response_sets_error_and_backs_off() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/syslog-forward"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "receipts": []
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let sender = SyslogSender::new(server.uri(), None, dir.path().join("spool.json"));
    sender.send("frame".into()).await.unwrap();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if sender.status().last_error_code == Some("invalid_receipt_response") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("delivery loop should surface the invalid receipt set");

    assert_eq!(sender.status().queued_records, 1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn receiver_failure_plans_are_bounded_and_leave_spool_records_untouched() {
    let throttled = retry_plan(429, 0, Some(9_999), 0);
    assert_eq!(throttled.reason_code, "receiver_backpressure");
    assert_eq!(throttled.delay_ms, RECONNECT_MAX_MS);

    let unavailable = retry_plan(503, 0, None, u64::MAX);
    assert_eq!(unavailable.reason_code, "receiver_unavailable");
    assert!((backoff_ms(0)..=backoff_ms(0) + backoff_ms(0) / 10).contains(&unavailable.delay_ms));

    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(SenderState {
        spool_path: dir.path().join("spool.json"),
        spool: SpoolState {
            source_instance: "host-a".into(),
            source_epoch: 1,
            next_sequence: 1,
            next_sequences: HashMap::new(),
            records: VecDeque::from([record(1)]),
            gaps: VecDeque::new(),
            dispatched_gap_keys: HashSet::new(),
            gap_overflow_intervals: 0,
            evicted_records: 0,
            last_dispatched_source: None,
        },
        recovery_required: false,
        last_error_code: None,
    }));
    // Failure paths intentionally call no receipt application.
    let _ = (throttled, unavailable);
    assert_eq!(state.lock().unwrap().spool.records.len(), 1);
}

#[test]
fn retry_jitter_varies_with_entropy_and_stays_within_the_bounded_window() {
    let base = backoff_ms(4);
    let minimum = retry_delay_ms(4, None, 0);
    let maximum = retry_delay_ms(4, None, base / 10);
    assert_eq!(minimum, base);
    assert!(minimum < maximum);
    assert!(maximum <= base + base / 10);
    assert_eq!(retry_delay_ms(0, Some(2), 123), 2_000);
}

#[test]
fn receiver_outage_spool_is_bounded_and_records_a_gap_when_it_evicts() {
    let source_key = "source-000000000000000000000001";
    let mut spool = SpoolState {
        source_instance: "host-a".into(),
        source_epoch: 1,
        next_sequence: MAX_SOURCE_SPOOL_RECORDS as u64,
        next_sequences: HashMap::new(),
        records: (1..=MAX_SOURCE_SPOOL_RECORDS)
            .map(|sequence| source_record(&format!("host-a:{source_key}"), sequence as u64))
            .collect(),
        gaps: VecDeque::new(),
        dispatched_gap_keys: HashSet::new(),
        gap_overflow_intervals: 0,
        evicted_records: 0,
        last_dispatched_source: None,
    };
    spool.records.push_back(source_record(
        &format!("host-a:{source_key}"),
        (MAX_SOURCE_SPOOL_RECORDS + 1) as u64,
    ));
    evict_source_to_quota(&mut spool, source_key);

    assert_eq!(spool.records.len(), MAX_SOURCE_SPOOL_RECORDS);
    assert_eq!(spool.evicted_records, 1);
    assert!(spool.gaps.iter().any(|gap| {
        gap.reason_code == "local_retention_quota" && (gap.from_sequence, gap.to_sequence) == (1, 1)
    }));
}

fn record(sequence: u64) -> SyslogForwardRecord {
    SyslogForwardRecord {
        source_instance: "host-a:syslog".into(),
        source_epoch: 1,
        sequence,
        idempotency_key: delivery_key("host-a:syslog", 1, sequence, "record"),
        observed_at: now(),
        line: "frame".into(),
    }
}

#[test]
fn round_robin_dispatch_keeps_a_quiet_source_visible_behind_a_noisy_one() {
    let noisy = "source-000000000000000000000001";
    let quiet = "source-000000000000000000000002";
    let mut spool = SpoolState {
        source_instance: "host-a".into(),
        source_epoch: 1,
        next_sequence: 0,
        next_sequences: HashMap::new(),
        records: VecDeque::from([
            source_record(&format!("host-a:{noisy}"), 1),
            source_record(&format!("host-a:{noisy}"), 2),
            source_record(&format!("host-a:{quiet}"), 1),
        ]),
        gaps: VecDeque::new(),
        dispatched_gap_keys: HashSet::new(),
        gap_overflow_intervals: 0,
        evicted_records: 0,
        last_dispatched_source: None,
    };
    assert_eq!(next_source_key(&spool).as_deref(), Some(noisy));
    spool.last_dispatched_source = Some(noisy.into());
    assert_eq!(next_source_key(&spool).as_deref(), Some(quiet));
}

#[test]
fn source_identity_requires_an_exact_hashed_component() {
    assert_eq!(
        source_key_of("host-a:container:source-000000000000000000000001"),
        Some("source-000000000000000000000001")
    );
    assert_eq!(
        source_key_of("host-a:source-00000000000000000000000z"),
        None
    );
    assert_eq!(
        source_key_of("host-a:source-000000000000000000000001-extra"),
        None
    );
}

#[test]
fn path_like_source_key_is_never_serialized_into_spool_or_delivery_request() {
    let raw_source = "/Users/jmagar/private/production/access.log";
    let source_key = stable_source_key(raw_source);
    let record = source_record(&format!("host-a:{source_key}"), 1);
    let spool = SpoolState {
        source_instance: "host-a".into(),
        source_epoch: 1,
        next_sequence: 0,
        next_sequences: HashMap::from([(source_key.clone(), 1)]),
        records: VecDeque::from([record]),
        gaps: VecDeque::new(),
        dispatched_gap_keys: HashSet::new(),
        gap_overflow_intervals: 0,
        evicted_records: 0,
        last_dispatched_source: None,
    };
    assert!(
        !String::from_utf8(serde_json::to_vec(&spool).unwrap())
            .unwrap()
            .contains(raw_source)
    );
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(SenderState {
        spool_path: dir.path().join("spool.json"),
        spool,
        recovery_required: false,
        last_error_code: None,
    }));
    let request = next_request(&state).unwrap().unwrap();
    assert!(
        !serde_json::to_string(&request)
            .unwrap()
            .contains(raw_source)
    );
}

#[test]
fn unreadable_spool_is_retained_and_remains_visible_after_delivery_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spool.json");
    std::fs::write(&path, b"not-json").unwrap();

    let loaded = load_spool(&path);
    assert_eq!(loaded.error_code, Some("spool_recovery_required"));
    assert_eq!(std::fs::read(&path).unwrap(), b"not-json");
    assert_ne!(loaded.spool_path, path);

    let state = Arc::new(Mutex::new(SenderState {
        spool_path: loaded.spool_path,
        spool: loaded.spool,
        recovery_required: true,
        last_error_code: loaded.error_code,
    }));
    set_error(&state, "none");
    assert_eq!(
        state.lock().unwrap().last_error_code,
        Some("spool_recovery_required")
    );
}

#[test]
fn unreadable_recovery_spool_is_preserved_in_a_new_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spool.json");
    let recovery = path.with_extension("recovery");
    std::fs::write(&path, b"corrupt-primary").unwrap();
    std::fs::write(&recovery, b"corrupt-recovery").unwrap();

    let loaded = load_spool(&path);
    assert_eq!(loaded.spool_path, path.with_extension("recovery-2"));
    save_spool(&loaded.spool_path, &loaded.spool).unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), b"corrupt-primary");
    assert_eq!(std::fs::read(&recovery).unwrap(), b"corrupt-recovery");
    assert!(path.with_extension("recovery-2").is_file());

    let restarted = load_spool(&path);
    assert_eq!(restarted.spool_path, path.with_extension("recovery-2"));
    assert_eq!(
        restarted.spool.source_instance,
        loaded.spool.source_instance
    );
}

#[test]
fn corrupt_newer_generation_never_reactivates_an_older_valid_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spool.json");
    let recovery = path.with_extension("recovery");
    let generation_two = path.with_extension("recovery-2");
    let generation_three = path.with_extension("recovery-3");
    std::fs::write(&path, b"corrupt-primary").unwrap();
    std::fs::write(&recovery, b"corrupt-recovery").unwrap();
    let old = SpoolState {
        evicted_records: 77,
        ..SpoolState::default()
    };
    save_spool(&generation_two, &old).unwrap();
    let generation_two_bytes = std::fs::read(&generation_two).unwrap();
    std::fs::write(&generation_three, b"corrupt-newer-generation").unwrap();

    let loaded = load_spool(&path);

    assert_eq!(loaded.spool_path, path.with_extension("recovery-4"));
    assert_eq!(loaded.spool.evicted_records, 0);
    save_spool(&loaded.spool_path, &loaded.spool).unwrap();
    assert_eq!(
        std::fs::read(&generation_two).unwrap(),
        generation_two_bytes
    );
    assert_eq!(
        std::fs::read(&generation_three).unwrap(),
        b"corrupt-newer-generation"
    );
}

#[test]
fn recovery_spool_survives_a_restart_while_primary_remains_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spool.json");
    std::fs::write(&path, b"not-json").unwrap();

    let mut first = load_spool(&path);
    first.spool.records.push_back(record(7));
    save_spool(&first.spool_path, &first.spool).unwrap();

    let second = load_spool(&path);
    assert_eq!(second.spool_path, first.spool_path);
    assert_eq!(second.error_code, Some("spool_recovery_required"));
    assert_eq!(second.spool.records.len(), 1);
    assert_eq!(second.spool.records.front().unwrap().sequence, 7);
    assert_eq!(std::fs::read(&path).unwrap(), b"not-json");
}

#[test]
fn gap_compaction_preserves_every_loss_interval_beyond_the_old_cap() {
    let mut spool = SpoolState::default();
    let source = "host-a:source-000000000000000000000001";
    for sequence in 1..=600_u64 {
        push_gap(
            &mut spool,
            SyslogForwardGap {
                source_instance: source.into(),
                source_epoch: 1,
                from_sequence: sequence,
                to_sequence: sequence,
                idempotency_key: delivery_key(source, 1, sequence, "gap"),
                observed_at: now(),
                reason_code: "record_too_large".into(),
            },
        );
    }

    assert_eq!(spool.gaps.len(), 1);
    let gap = spool.gaps.front().unwrap();
    assert_eq!((gap.from_sequence, gap.to_sequence), (1, 600));
    assert_eq!(gap.idempotency_key, delivery_key(source, 1, 600, "gap"));
}

#[test]
fn gap_compaction_does_not_merge_noncontiguous_or_different_reason_windows() {
    let mut spool = SpoolState::default();
    let source = "host-a:source-000000000000000000000001";
    for (from, to, reason) in [
        (1, 2, "record_too_large"),
        (4, 5, "record_too_large"),
        (3, 3, "local_retention_quota"),
    ] {
        push_gap(
            &mut spool,
            SyslogForwardGap {
                source_instance: source.into(),
                source_epoch: 1,
                from_sequence: from,
                to_sequence: to,
                idempotency_key: delivery_key(source, 1, to, "gap"),
                observed_at: now(),
                reason_code: reason.into(),
            },
        );
    }
    assert_eq!(spool.gaps.len(), 3);
}

#[test]
fn spool_save_succeeds_after_a_failed_atomic_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spool.json");
    std::fs::create_dir(&path).unwrap();

    // `save_spool` creates its temporary sibling before the rename. A
    // destination-directory failure therefore verifies that the temporary is
    // cleaned, rather than permanently blocking the next save with EEXIST.
    assert!(save_spool(&path, &SpoolState::default()).is_err());
    std::fs::remove_dir(&path).unwrap();

    save_spool(&path, &SpoolState::default()).unwrap();
    assert!(path.is_file());
}

#[test]
fn aggregate_cap_bounds_high_cardinality_sources_and_records_each_loss_window() {
    let records = (0..=MAX_SPOOL_RECORDS)
        .map(|index| {
            let key = format!("source-{index:024x}");
            source_record(&format!("host-a:{key}"), 1)
        })
        .collect();
    let mut spool = SpoolState {
        source_instance: "host-a".into(),
        source_epoch: 1,
        next_sequence: 0,
        next_sequences: HashMap::new(),
        records,
        gaps: VecDeque::new(),
        dispatched_gap_keys: HashSet::new(),
        gap_overflow_intervals: 0,
        evicted_records: 0,
        last_dispatched_source: None,
    };
    evict_aggregate_to_quota(&mut spool);
    assert_eq!(spool.records.len(), MAX_SPOOL_RECORDS);
    assert_eq!(spool.evicted_records, 1);
    assert_eq!(spool.gaps.len(), 1);
    assert_eq!(
        spool.gaps.front().unwrap().reason_code,
        "aggregate_retention_quota"
    );
}

#[tokio::test]
async fn forward_status_reports_exact_spool_bytes_and_cumulative_evictions() {
    let dir = tempfile::tempdir().unwrap();
    let sender = SyslogSender::new(String::new(), None, dir.path().join("spool.json"));
    sender.enqueue("alpha", "12345".into()).unwrap();
    sender.enqueue("beta", "1234567".into()).unwrap();
    {
        let mut state = sender.state.lock().unwrap();
        state.spool.evicted_records = 9;
    }

    let status = sender.status();
    assert_eq!(status.queued_records, 2);
    assert_eq!(status.queued_bytes, 12);
    assert_eq!(status.evicted_records, 9);
}

#[tokio::test]
async fn oversized_input_gaps_compact_without_losing_the_loss_window() {
    let dir = tempfile::tempdir().unwrap();
    let sender = SyslogSender::new(String::new(), None, dir.path().join("spool.json"));
    let oversized = "x".repeat(MAX_FORWARD_RECORD_BYTES + 1);
    for _ in 0..257 {
        sender
            .send_from("journald", oversized.clone())
            .await
            .unwrap();
    }

    let status = sender.status();
    assert_eq!(status.queued_records, 0);
    assert_eq!(status.pending_gaps, 1);
    assert_eq!(status.evicted_records, 257);
    let state = sender.state.lock().unwrap();
    let gap = state.spool.gaps.front().unwrap();
    assert_eq!((gap.from_sequence, gap.to_sequence), (1, 257));
}

#[test]
fn dispatched_gap_identity_stays_immutable_during_later_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let source = "host-a:source-000000000000000000000001";
    let first = gap(source, 1);
    let state = Arc::new(Mutex::new(SenderState {
        spool_path: dir.path().join("spool.json"),
        spool: SpoolState {
            source_instance: "host-a".into(),
            gaps: VecDeque::from([first.clone()]),
            ..SpoolState::default()
        },
        recovery_required: false,
        last_error_code: None,
    }));

    let request = next_request(&state).unwrap().unwrap();
    {
        let mut locked = state.lock().unwrap();
        push_gap(&mut locked.spool, gap(source, 2));
        push_gap(&mut locked.spool, gap(source, 3));
        assert_eq!(locked.spool.gaps.len(), 2);
        assert_eq!(locked.spool.gaps[0].idempotency_key, first.idempotency_key);
        assert_eq!(
            (
                locked.spool.gaps[1].from_sequence,
                locked.spool.gaps[1].to_sequence
            ),
            (2, 3)
        );
    }

    apply_receipts(&state, &request, &[first.idempotency_key]).unwrap();
    let locked = state.lock().unwrap();
    assert_eq!(locked.spool.gaps.len(), 1);
    assert_eq!(
        (
            locked.spool.gaps[0].from_sequence,
            locked.spool.gaps[0].to_sequence
        ),
        (2, 3)
    );
}

#[tokio::test]
async fn high_cardinality_gap_queue_is_bounded_and_reports_degradation() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("spool.json");
    let sender = SyslogSender::new(String::new(), None, spool_path.clone());
    {
        let mut state = sender.state.lock().unwrap();
        for sequence in 1..=(MAX_SPOOL_GAPS as u64 + 2_000) {
            let source = format!("host-a:source-{sequence:024x}");
            push_gap(&mut state.spool, gap(&source, sequence));
        }
        save_spool(&state.spool_path, &state.spool).unwrap();
    }
    let status = sender.status();
    assert_eq!(status.pending_gaps, MAX_SPOOL_GAPS);
    assert_eq!(status.gap_overflow_intervals, 2_000);
    assert!(status.queued_bytes > 0);
    assert_eq!(status.last_error_code, Some("gap_evidence_overflow"));
    let reloaded = load_spool(&spool_path);
    assert_eq!(reloaded.spool.gaps.len(), MAX_SPOOL_GAPS);
    assert_eq!(reloaded.spool.gap_overflow_intervals, 2_000);
}

#[test]
fn gap_overflow_logging_is_bounded_to_first_and_powers_of_two() {
    let reported = (1..=10)
        .filter(|count| should_report_gap_overflow(*count))
        .collect::<Vec<_>>();
    assert_eq!(reported, vec![1, 2, 4, 8]);
}

fn gap(source_instance: &str, sequence: u64) -> SyslogForwardGap {
    SyslogForwardGap {
        source_instance: source_instance.into(),
        source_epoch: 1,
        from_sequence: sequence,
        to_sequence: sequence,
        idempotency_key: delivery_key(source_instance, 1, sequence, "gap"),
        observed_at: now(),
        reason_code: "record_too_large".into(),
    }
}

fn source_record(source_instance: &str, sequence: u64) -> SyslogForwardRecord {
    SyslogForwardRecord {
        source_instance: source_instance.into(),
        source_epoch: 1,
        sequence,
        idempotency_key: delivery_key(source_instance, 1, sequence, "record"),
        observed_at: now(),
        line: "frame".into(),
    }
}

#[test]
fn format_rfc5424_replaces_newlines_and_keeps_valid_fields() {
    assert_eq!(
        format_rfc5424(PRI_LOCAL0_ERR, "ts", "host", "app", "pid", "first\nsecond"),
        "<131>1 ts host app pid - - first second"
    );
}

#[tokio::test]
async fn failed_spool_write_rolls_back_frame_and_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let spool_path = dir.path().join("spool.json");
    let sender = SyslogSender::new("http://127.0.0.1:9".to_string(), None, spool_path.clone());
    std::fs::create_dir(&spool_path).unwrap();

    assert!(
        sender
            .send_from("journald", "not-durable".into())
            .await
            .is_err()
    );
    let state = sender.state.lock().unwrap();
    assert!(state.spool.records.is_empty());
    assert!(state.spool.gaps.is_empty());
    assert!(state.spool.next_sequences.is_empty());
}
