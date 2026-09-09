//! Dedicated durable-spool owner and transactional mutations.

use super::*;

pub(super) fn enqueue(
    state: &Arc<Mutex<SenderState>>,
    source_key: &str,
    line: String,
) -> Result<()> {
    let mut state = state.lock().expect("syslog sender state poisoned");
    // Persistence is the durability boundary. Keep an exact snapshot so a
    // failed atomic write cannot consume a sequence, retain a memory-only
    // frame, or apply quota eviction that was never committed to disk.
    let previous_spool = state.spool.clone();
    let source_key = stable_source_key(source_key);
    let sequence = {
        let legacy_next = state.spool.next_sequence;
        let next = state
            .spool
            .next_sequences
            .entry(source_key.clone())
            .or_insert(legacy_next);
        *next = next.saturating_add(1);
        *next
    };
    let source_instance = format!("{}:{source_key}", state.spool.source_instance);
    let epoch = state.spool.source_epoch;
    if line.len() > MAX_FORWARD_RECORD_BYTES {
        push_gap(
            &mut state.spool,
            SyslogForwardGap {
                source_instance: source_instance.clone(),
                source_epoch: epoch,
                from_sequence: sequence,
                to_sequence: sequence,
                idempotency_key: delivery_key(&source_instance, epoch, sequence, "gap"),
                observed_at: now(),
                reason_code: "record_too_large".into(),
            },
        );
        state.spool.evicted_records = state.spool.evicted_records.saturating_add(1);
    } else {
        state.spool.records.push_back(SyslogForwardRecord {
            source_instance: source_instance.clone(),
            source_epoch: epoch,
            sequence,
            idempotency_key: delivery_key(&source_instance, epoch, sequence, "record"),
            observed_at: now(),
            line,
        });
    }
    evict_source_to_quota(&mut state.spool, &source_key);
    evict_aggregate_to_quota(&mut state.spool);
    if let Err(error) = save_spool(&state.spool_path, &state.spool) {
        state.spool = previous_spool;
        return Err(error);
    }
    drop(state);
    Ok(())
}

pub(super) fn persistence_owner(
    state: Arc<Mutex<SenderState>>,
    notify: Arc<Notify>,
    mut commands: mpsc::Receiver<PersistCommand>,
) {
    while let Some(command) = commands.blocking_recv() {
        match command {
            PersistCommand::Enqueue {
                source_key,
                line,
                reply,
            } => {
                let result = enqueue(&state, &source_key, line);
                if result.is_ok() {
                    notify.notify_one();
                }
                if reply.is_closed()
                    && let Err(error) = &result
                {
                    tracing::error!(
                        reason_code = "local_spool_persist_failed",
                        source_key = %stable_source_key(&source_key),
                        error = format!("{error:#}"),
                        "syslog frame could not be retained"
                    );
                }
                let _ = reply.send(result);
            }
            PersistCommand::NextRequest { reply } => {
                let _ = reply.send(next_request(&state));
            }
            PersistCommand::ApplyReceipts {
                request,
                receipts,
                reply,
            } => {
                let _ = reply.send(apply_receipts(&state, &request, &receipts));
            }
        }
    }
}
pub(super) fn next_request(
    state: &Arc<Mutex<SenderState>>,
) -> Result<Option<SyslogForwardRequest>> {
    let mut state = state.lock().expect("syslog sender state poisoned");
    let Some(source_key) = next_source_key(&state.spool) else {
        return Ok(None);
    };
    let mut bytes = 0usize;
    let records = state
        .spool
        .records
        .iter()
        .filter(|record| {
            source_key_of(&record.source_instance).is_some_and(|key| key == source_key)
        })
        .take_while(|record| {
            let include = bytes == 0 || bytes.saturating_add(record.line.len()) <= MAX_BATCH_BYTES;
            if include {
                bytes = bytes.saturating_add(record.line.len());
            }
            include
        })
        .take(MAX_BATCH_RECORDS)
        .cloned()
        .collect();
    let gaps: Vec<SyslogForwardGap> = state
        .spool
        .gaps
        .iter()
        .filter(|gap| source_key_of(&gap.source_instance).is_some_and(|key| key == source_key))
        .take(50)
        .cloned()
        .collect();
    let previous_spool = state.spool.clone();
    state.spool.last_dispatched_source = Some(source_key);
    state
        .spool
        .dispatched_gap_keys
        .extend(gaps.iter().map(|gap| gap.idempotency_key.clone()));
    if let Err(error) = save_spool(&state.spool_path, &state.spool) {
        state.spool = previous_spool;
        return Err(error);
    }
    Ok(Some(SyslogForwardRequest { records, gaps }))
}

pub(super) fn apply_receipts(
    state: &Arc<Mutex<SenderState>>,
    request: &SyslogForwardRequest,
    receipts: &[String],
) -> Result<()> {
    let outbound_keys: HashSet<&str> = request
        .records
        .iter()
        .map(|record| record.idempotency_key.as_str())
        .chain(request.gaps.iter().map(|gap| gap.idempotency_key.as_str()))
        .collect();
    let keys: HashSet<&str> = receipts.iter().map(String::as_str).collect();
    if receipts.len() != outbound_keys.len()
        || keys.len() != receipts.len()
        || keys != outbound_keys
    {
        return Err(anyhow::Error::new(InvalidReceiptSet));
    }
    let mut state = state.lock().expect("syslog sender state poisoned");
    let previous_spool = state.spool.clone();
    state
        .spool
        .records
        .retain(|record| !keys.contains(record.idempotency_key.as_str()));
    state
        .spool
        .gaps
        .retain(|gap| !keys.contains(gap.idempotency_key.as_str()));
    state
        .spool
        .dispatched_gap_keys
        .retain(|key| !keys.contains(key.as_str()));
    if let Err(error) = save_spool(&state.spool_path, &state.spool) {
        state.spool = previous_spool;
        return Err(error);
    }
    Ok(())
}
