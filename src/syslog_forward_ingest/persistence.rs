//! Transactional syslog-forward receipt and evidence persistence.

use super::*;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::db;
use crate::enrich::{SourceKind, stamp_source_kind};
use crate::receiver::parser::parse_syslog;

#[cfg(test)]
pub(super) fn persist_request(
    pool: &DbPool,
    request: SyslogForwardRequest,
    peer_ip: &str,
    forwarder_identity: &str,
) -> anyhow::Result<Vec<String>> {
    persist_request_with_identity(
        pool,
        request,
        peer_ip,
        forwarder_identity,
        forwarder_identity,
        forwarder_identity == "shared_bearer",
    )
}

fn persist_request_with_identity(
    pool: &DbPool,
    request: SyslogForwardRequest,
    peer_ip: &str,
    receipt_namespace: &str,
    display_identity: &str,
    shared_bearer: bool,
) -> anyhow::Result<Vec<String>> {
    let mut conn = db::write_conn(pool)?;
    let tx = conn.transaction()?;
    let mut receipts = Vec::with_capacity(request.records.len() + request.gaps.len());
    for record in request.records {
        let receipt_key =
            namespaced_receipt_key(receipt_namespace, &record.idempotency_key, shared_bearer);
        let source_identity =
            opaque_receipt_value(&format!("{receipt_namespace}:{}", record.source_instance));
        let fingerprint = request_fingerprint(receipt_namespace, &record)?;
        if receipt_replay(
            &tx,
            &receipt_key,
            ReceiptIdentity {
                source: &source_identity,
                epoch: record.source_epoch,
                sequence: record.sequence,
                kind: "record",
            },
            &fingerprint,
            LegacyReplay::Record(&record.line),
        )? {
            receipts.push(record.idempotency_key);
            continue;
        }
        let mut entry = parse_syslog(&record.line, format!("agent-syslog://{peer_ip}"));
        let claimed_hostname = entry.hostname.clone();
        entry.hostname = format!("agent-{display_identity}");
        entry.metadata_json = Some(forwarded_metadata(
            entry.metadata_json.as_deref(),
            display_identity,
            peer_ip,
            claimed_hostname,
        )?);
        stamp_source_kind(&mut entry, SourceKind::SyslogTcp);
        let ids = db::insert_logs_batch_in_tx(&tx, &[entry])?;
        insert_receipt(
            &tx,
            &receipt_key,
            &source_identity,
            record.source_epoch,
            record.sequence,
            ids[0],
            "record",
            &fingerprint,
        )?;
        receipts.push(record.idempotency_key);
    }
    for gap in request.gaps {
        let receipt_key =
            namespaced_receipt_key(receipt_namespace, &gap.idempotency_key, shared_bearer);
        let source_identity =
            opaque_receipt_value(&format!("{receipt_namespace}:{}", gap.source_instance));
        let fingerprint = request_fingerprint(receipt_namespace, &gap)?;
        if receipt_replay(
            &tx,
            &receipt_key,
            ReceiptIdentity {
                source: &source_identity,
                epoch: gap.source_epoch,
                sequence: gap.to_sequence,
                kind: "gap",
            },
            &fingerprint,
            LegacyReplay::Gap { gap: &gap, peer_ip },
        )? {
            receipts.push(gap.idempotency_key);
            continue;
        }
        // This is deliberately payload-free: it makes the exact loss window
        // queryable without leaking a dropped record into status/diagnostics.
        let entry = crate::db::LogBatchEntry {
            timestamp: gap.observed_at.clone(),
            hostname: source_identity.clone(),
            facility: Some("local0".into()),
            severity: "warning".into(),
            app_name: Some("cortex-agent-forward".into()),
            process_id: None,
            message: format!(
                "syslog forwarding retention gap: sequence {} through {} ({})",
                gap.from_sequence, gap.to_sequence, gap.reason_code
            ),
            raw: String::new(),
            source_ip: format!("agent-syslog://{peer_ip}"),
            docker_checkpoint: None,
            ai_tool: None,
            ai_project: None,
            ai_session_id: None,
            ai_transcript_path: None,
            metadata_json: Some(crate::ingest_metadata::bounded_metadata_json(
                json!({"source_kind":"syslog-forward-gap", "reason_code": gap.reason_code, "from_sequence": gap.from_sequence, "to_sequence": gap.to_sequence}),
            )),
            http_status: None,
            auth_outcome: None,
            dns_blocked: None,
            event_action: None,
            parse_error: None,
        };
        let ids = db::insert_logs_batch_in_tx(&tx, &[entry])?;
        insert_receipt(
            &tx,
            &receipt_key,
            &source_identity,
            gap.source_epoch,
            gap.to_sequence,
            ids[0],
            "gap",
            &fingerprint,
        )?;
        receipts.push(gap.idempotency_key);
    }
    tx.commit()?;
    crate::db::agent_observatory::notify_projection_work();
    Ok(receipts)
}

pub(super) fn persist_authenticated_request(
    pool: &DbPool,
    request: SyslogForwardRequest,
    peer_ip: &str,
    principal: &ForwardingPrincipal,
) -> anyhow::Result<Vec<String>> {
    persist_request_with_identity(
        pool,
        request,
        peer_ip,
        &principal.receipt_namespace(),
        principal.label(),
        principal.is_shared(),
    )
}

pub(super) fn forwarded_metadata(
    existing: Option<&str>,
    forwarder_identity: &str,
    peer_ip: &str,
    hostname_claim: String,
) -> anyhow::Result<String> {
    let mut metadata = match existing {
        Some(encoded) => serde_json::from_str::<Value>(encoded)?
            .as_object()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("parsed syslog metadata is not a JSON object"))?,
        None => serde_json::Map::new(),
    };
    metadata.insert(
        "forwarded_provenance".into(),
        json!({
            "authenticated_forwarder": forwarder_identity,
            "transport_peer": peer_ip,
            "hostname_claim": hostname_claim,
            "trust": if forwarder_identity == "shared_bearer" { "claimed" } else { "verified_forwarder_claimed_host" },
        }),
    );
    Ok(crate::ingest_metadata::bounded_metadata_json(
        Value::Object(metadata),
    ))
}

fn opaque_receipt_value(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..16])
}

/// Keep caller supplied idempotency IDs inside the authenticated principal's
/// namespace. Shared-bearer deployments retain their historical key encoding
/// so pre-migration receipts remain replayable.
fn namespaced_receipt_key(identity: &str, value: &str, shared_bearer: bool) -> String {
    if shared_bearer {
        opaque_receipt_value(value)
    } else {
        opaque_receipt_value(&format!("{identity}\0{value}"))
    }
}

fn request_fingerprint<T: Serialize>(identity: &str, value: &T) -> anyhow::Result<String> {
    Ok(opaque_receipt_value(&format!(
        "{identity}:{}",
        serde_json::to_string(value)?
    )))
}

enum LegacyReplay<'a> {
    Record(&'a str),
    Gap {
        gap: &'a SyslogForwardGap,
        peer_ip: &'a str,
    },
}

struct ReceiptIdentity<'a> {
    source: &'a str,
    epoch: u64,
    sequence: u64,
    kind: &'a str,
}

fn receipt_replay(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    identity: ReceiptIdentity<'_>,
    fingerprint: &str,
    legacy_replay: LegacyReplay<'_>,
) -> anyhow::Result<bool> {
    // A receipt can outlive its evidence when storage cleanup ran on a
    // connection that did not enforce foreign keys. Remove it atomically so
    // this request can create fresh evidence under the same key.
    tx.execute(
        "DELETE FROM syslog_forward_receipts
         WHERE idempotency_key = ?1
           AND NOT EXISTS (SELECT 1 FROM logs WHERE id = canonical_log_id)",
        [key],
    )?;
    let stored = tx
        .query_row(
            "SELECT r.source_instance, r.source_epoch, r.sequence, r.receipt_kind,
                    r.request_fingerprint, l.timestamp, l.hostname, l.facility,
                    l.severity, l.app_name, l.message, l.raw, l.source_ip,
                    l.metadata_json
             FROM syslog_forward_receipts r
             JOIN logs l ON l.id = r.canonical_log_id
             WHERE r.idempotency_key = ?1",
            [key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                ))
            },
        )
        .optional()?;
    match stored {
        None => Ok(false),
        Some((
            stored_source,
            stored_epoch,
            stored_sequence,
            stored_kind,
            stored_fingerprint,
            timestamp,
            hostname,
            facility,
            severity,
            app_name,
            message,
            raw,
            source_ip,
            metadata_json,
        )) if stored_source == identity.source
            && stored_epoch == identity.epoch as i64
            && stored_sequence == identity.sequence as i64
            && stored_kind == identity.kind
            && (stored_fingerprint == fingerprint
                || (stored_fingerprint.is_empty()
                    && legacy_canonical_evidence_matches(
                        &legacy_replay,
                        identity.source,
                        &timestamp,
                        &hostname,
                        facility.as_deref(),
                        &severity,
                        app_name.as_deref(),
                        &message,
                        &raw,
                        &source_ip,
                        metadata_json.as_deref(),
                    )?)) =>
        {
            if stored_fingerprint.is_empty() {
                tx.execute(
                    "UPDATE syslog_forward_receipts SET request_fingerprint = ?2
                     WHERE idempotency_key = ?1 AND request_fingerprint = ''",
                    params![key, fingerprint],
                )?;
            }
            Ok(true)
        }
        Some(_) => Err(anyhow::Error::new(IdempotencyConflict)),
    }
}

#[allow(clippy::too_many_arguments)]
fn legacy_canonical_evidence_matches(
    replay: &LegacyReplay<'_>,
    source: &str,
    timestamp: &str,
    hostname: &str,
    facility: Option<&str>,
    severity: &str,
    app_name: Option<&str>,
    message: &str,
    raw: &str,
    source_ip: &str,
    metadata_json: Option<&str>,
) -> anyhow::Result<bool> {
    match replay {
        LegacyReplay::Record(line) => Ok(*line == raw),
        LegacyReplay::Gap { gap, peer_ip } => {
            let expected_metadata = json!({
                "source_kind": "syslog-forward-gap",
                "reason_code": gap.reason_code,
                "from_sequence": gap.from_sequence,
                "to_sequence": gap.to_sequence,
            });
            let stored_metadata = metadata_json
                .map(serde_json::from_str::<Value>)
                .transpose()?;
            Ok(timestamp == gap.observed_at
                && hostname == source
                && facility == Some("local0")
                && severity == "warning"
                && app_name == Some("cortex-agent-forward")
                && message
                    == format!(
                        "syslog forwarding retention gap: sequence {} through {} ({})",
                        gap.from_sequence, gap.to_sequence, gap.reason_code
                    )
                && raw.is_empty()
                && source_ip == format!("agent-syslog://{peer_ip}")
                && stored_metadata.as_ref() == Some(&expected_metadata))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_receipt(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    source: &str,
    epoch: u64,
    sequence: u64,
    log_id: i64,
    kind: &str,
    fingerprint: &str,
) -> anyhow::Result<()> {
    tx.execute("INSERT INTO syslog_forward_receipts (idempotency_key, source_instance, source_epoch, sequence, canonical_log_id, receipt_kind, request_fingerprint) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)", params![key, source, epoch as i64, sequence as i64, log_id, kind, fingerprint])?;
    Ok(())
}
