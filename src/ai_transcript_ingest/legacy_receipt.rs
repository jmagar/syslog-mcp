//! Replay identity validation for transcript receipt ledgers.

use super::*;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(super) struct IdempotencyConflict;

impl std::fmt::Display for IdempotencyConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("source_record_id was reused for different transcript evidence")
    }
}

impl std::error::Error for IdempotencyConflict {}

fn envelope_fingerprint(envelope: &EvidenceEnvelope) -> anyhow::Result<String> {
    // Supplemental display metadata can change without a transcript revision.
    let mut evidence = envelope.clone();
    evidence.source.title = None;
    evidence.source.title_provenance = None;
    let encoded = serde_json::to_vec(&evidence)?;
    Ok(format!("evidence-v2:sha256:{:x}", Sha256::digest(encoded)))
}

fn receipt_key(forwarder_identity: &str, source_record_id: &str, shared_bearer: bool) -> String {
    if shared_bearer {
        source_record_id.to_owned()
    } else {
        format!(
            "principal:sha256:{:x}",
            Sha256::digest(format!("{forwarder_identity}\0{source_record_id}").as_bytes())
        )
    }
}

/// Reconstruct only mutable titles from the stored row, then check the old
/// full-envelope hash. This also preserves timestamp-less exact replays: the
/// hash, unlike a canonical log timestamp, retains their original `None`.
fn old_fingerprint_matches(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    envelope: &EvidenceEnvelope,
    previous: &str,
) -> anyhow::Result<bool> {
    // An exact old hash is sufficient even if bounded log metadata omitted
    // its source fields. Canonical metadata is needed only for a title change.
    if previous == format!("sha256:{:x}", Sha256::digest(serde_json::to_vec(envelope)?)) {
        return Ok(true);
    }
    let metadata: Option<String> = tx.query_row(
        "SELECT l.metadata_json FROM ai_transcript_forward_receipts r
         JOIN logs l ON l.id = r.log_id WHERE r.source_record_id = ?1",
        [key],
        |row| row.get(0),
    )?;
    let Some(metadata) = metadata else {
        return Ok(false);
    };
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    let Some(source) = metadata.get("source") else {
        return Ok(false);
    };
    let source: EvidenceSource = serde_json::from_value(source.clone())?;
    let mut original = envelope.clone();
    original.source.title = source.title;
    original.source.title_provenance = source.title_provenance;
    Ok(previous
        == format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&original)?)
        ))
}

/// Migration-53 receipts have no request fingerprint. Validate an incoming
/// replay against the canonical log and metadata that receipt committed before
/// binding its fingerprint. This prevents the first post-upgrade request from
/// silently claiming a legacy ID with different evidence.
fn legacy_receipt_matches(
    tx: &rusqlite::Transaction<'_>,
    stored_receipt_key: &str,
    envelope: &EvidenceEnvelope,
) -> anyhow::Result<bool> {
    let stored = tx
        .query_row(
            "SELECT r.envelope_version, r.provider, r.source_identity,
                    r.source_epoch, r.source_revision,
                    l.timestamp, l.message, l.ai_project, l.ai_session_id,
                    l.ai_transcript_path, l.metadata_json
             FROM ai_transcript_forward_receipts r
             JOIN logs l ON l.id = r.log_id
             WHERE r.source_record_id = ?1",
            [stored_receipt_key],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .optional()?;
    let Some((
        version,
        provider,
        source_identity,
        source_epoch,
        source_revision,
        timestamp,
        message,
        ai_project,
        ai_session_id,
        locator,
        metadata_json,
    )) = stored
    else {
        return Ok(false);
    };
    let Some(metadata_json) = metadata_json else {
        return Ok(false);
    };
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json)?;
    let mut stored_source = metadata
        .get("source")
        .cloned()
        .map(serde_json::from_value::<EvidenceSource>)
        .transpose()?;
    let mut incoming_source = envelope.source.clone();
    incoming_source.title = None;
    incoming_source.title_provenance = None;
    if let Some(source) = &mut stored_source {
        source.title = None;
        source.title_provenance = None;
    }
    let stored_capabilities = metadata
        .get("capabilities")
        .cloned()
        .map(serde_json::from_value::<EvidenceCapabilityCoverage>)
        .transpose()?;
    let stored_diagnostics = metadata
        .get("diagnostics")
        .cloned()
        .map(serde_json::from_value::<Vec<EvidenceDiagnostic>>)
        .transpose()?;
    let stored_event_kind = metadata
        .get("event_kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let stored_hostname = metadata
        .pointer("/provenance/hostname_claim")
        .and_then(serde_json::Value::as_str);

    Ok(version == i64::from(envelope.version)
        && provider == envelope.source.provider
        && source_identity == envelope.source.source_identity
        && source_epoch == envelope.source.source_epoch
        && source_revision == envelope.source.source_revision
        && stored_source.as_ref() == Some(&incoming_source)
        && stored_capabilities.as_ref() == Some(&envelope.capabilities)
        && stored_diagnostics.as_deref() == Some(envelope.diagnostics.as_slice())
        && stored_event_kind == envelope.event_kind.as_deref().unwrap_or("unknown")
        && stored_hostname == Some(envelope.hostname.as_str())
        && message == envelope.message
        && ai_project == envelope.ai_project
        && ai_session_id == envelope.ai_session_id
        && locator.as_deref() == Some(envelope.source.locator.as_str())
        // A legacy canonical row does not record whether its timestamp came
        // from the source envelope or the receiver clock. Requiring the replay
        // to supply the stored value avoids silently binding an ambiguous
        // timestamp-less request to an old receipt.
        && envelope.timestamp.as_ref() == Some(&timestamp))
}

/// Commit each canonical log insert and its source-record receipt in one
/// SQLite transaction.  A retry after a lost HTTP response returns a
/// `duplicate` receipt instead of materializing another log row.
#[cfg(test)]
pub(super) fn insert_envelopes_with_receipts(
    pool: &DbPool,
    records: Vec<AiTranscriptRecord>,
    forwarder_identity: String,
    peer: SocketAddr,
) -> anyhow::Result<Vec<AiTranscriptReceipt>> {
    let shared_bearer = forwarder_identity == "shared_bearer";
    insert_envelopes_with_identity(
        pool,
        records,
        &forwarder_identity,
        &forwarder_identity,
        shared_bearer,
        peer,
    )
}

pub(super) fn insert_envelopes_with_principal(
    pool: &DbPool,
    records: Vec<AiTranscriptRecord>,
    principal: ForwardingPrincipal,
    peer: SocketAddr,
) -> anyhow::Result<Vec<AiTranscriptReceipt>> {
    insert_envelopes_with_identity(
        pool,
        records,
        &principal.receipt_namespace(),
        principal.label(),
        principal.is_shared(),
        peer,
    )
}

fn insert_envelopes_with_identity(
    pool: &DbPool,
    records: Vec<AiTranscriptRecord>,
    receipt_namespace: &str,
    display_identity: &str,
    shared_bearer: bool,
    peer: SocketAddr,
) -> anyhow::Result<Vec<AiTranscriptReceipt>> {
    let mut conn = db::write_conn(pool)?;
    let tx = conn.transaction()?;
    let mut receipts = Vec::with_capacity(records.len());

    for record in records {
        let envelope = scrub_envelope(record.envelope)
            .map_err(|reason| anyhow::anyhow!("invalid transcript evidence envelope: {reason}"))?;
        let request_fingerprint = envelope_fingerprint(&envelope)?;
        let stored_receipt_key =
            receipt_key(receipt_namespace, &envelope.source_record_id, shared_bearer);
        // Retention can remove canonical evidence on a connection where
        // foreign-key enforcement was unavailable. A receipt without its log
        // cannot prove a replay, so remove it in this transaction and let the
        // request create fresh canonical evidence.
        tx.execute(
            "DELETE FROM ai_transcript_forward_receipts
             WHERE source_record_id = ?1
               AND NOT EXISTS (SELECT 1 FROM logs WHERE id = log_id)",
            [&stored_receipt_key],
        )?;
        let already_accepted = tx
            .query_row(
                "SELECT request_fingerprint FROM ai_transcript_forward_receipts WHERE source_record_id = ?1",
                [&stored_receipt_key],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;
        if let Some(previous_fingerprint) = already_accepted {
            if previous_fingerprint.as_deref() != Some(request_fingerprint.as_str()) {
                // Old hashes included titles. Rebind only after comparing all
                // immutable evidence against the canonical row, never merely
                // because the caller reused an existing source-record ID.
                let matches = match previous_fingerprint.as_deref() {
                    Some(previous) if previous.starts_with("sha256:") => {
                        old_fingerprint_matches(&tx, &stored_receipt_key, &envelope, previous)?
                    }
                    Some(_) => false,
                    None => legacy_receipt_matches(&tx, &stored_receipt_key, &envelope)?,
                };
                if !matches {
                    return Err(IdempotencyConflict.into());
                }
                tx.execute(
                    "UPDATE ai_transcript_forward_receipts
                     SET request_fingerprint = ?2
                     WHERE source_record_id = ?1",
                    rusqlite::params![stored_receipt_key, request_fingerprint],
                )?;
            }
            receipts.push(AiTranscriptReceipt {
                source_record_id: envelope.source_record_id,
                disposition: ReceiptDisposition::Duplicate,
            });
            continue;
        }

        let entries = [to_log_batch_entry(
            envelope.clone(),
            display_identity,
            &peer,
        )];
        let ids = db::insert_logs_batch_in_tx(&tx, &entries)?;
        let log_id = ids
            .into_iter()
            .next()
            .expect("one transcript envelope must insert one log row");
        let entry = &entries[0];
        if entry.ai_tool.as_deref() == Some("codex") {
            let events = crate::scanner::skill_events::extract_codex_skill_events_with_kind(
                &entry.message,
                envelope.event_kind.as_deref(),
            )
            .into_iter()
            .map(|event| db::SkillEventInsert {
                log_id,
                ai_tool: "codex".to_string(),
                ai_project: entry.ai_project.clone(),
                ai_session_id: entry.ai_session_id.clone(),
                hostname: entry.hostname.clone(),
                timestamp: entry.timestamp.clone(),
                event,
            })
            .collect::<Vec<_>>();
            db::insert_skill_events_in_tx(&tx, &events)?;
        }
        tx.execute(
            "INSERT INTO ai_transcript_forward_receipts
                (source_record_id, envelope_version, log_id, provider,
                source_identity, source_epoch, source_revision,
                request_fingerprint, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            rusqlite::params![
                stored_receipt_key,
                i64::from(envelope.version),
                log_id,
                envelope.source.provider,
                envelope.source.source_identity,
                envelope.source.source_epoch,
                envelope.source.source_revision,
                request_fingerprint,
            ],
        )?;
        receipts.push(AiTranscriptReceipt {
            source_record_id: envelope.source_record_id,
            disposition: ReceiptDisposition::Accepted,
        });
    }
    tx.commit()?;
    if !receipts.is_empty() {
        crate::db::agent_observatory::notify_projection_work();
    }
    Ok(receipts)
}
