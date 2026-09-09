//! Forwards local AI transcript changes (Claude/Codex/Gemini/Antigravity) to the central
//! cortex server via `POST /v1/ai-transcripts`, mirroring the local-only
//! `cortex sessions watch` path but over the network — one more supervised
//! stream inside `cortex agent`, alongside docker/journald/file-tail.
//!
//! Claude, Codex, and Antigravity projections are append-only JSONL — tailed
//! with seekable line/byte checkpoints. Gemini sessions are a single whole-file JSON object
//! (new messages appended, not a growing log file), so they're handled
//! separately in `scan_and_forward`: re-parsed in full each cycle via
//! `scanner::gemini::parse_file`, with the checkpoint tracking a *record
//! index* instead of a byte offset.
//!
//! Unlike the local watcher (`ai_watch.rs`, notify-based, debounced), this
//! forwarder polls on a fixed interval and tracks a simple per-file
//! "already forwarded" checkpoint (lines for JSONL providers, records for
//! Gemini) in a local JSON state file. Polling (rather than filesystem
//! notify) keeps the agent's dependency footprint small and matches the
//! reliability bar of the other agent streams, which all tolerate
//! multi-second latency already.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ai_project::normalize_local_ai_project_path;
use crate::ai_transcript_ingest::{
    AI_TRANSCRIPT_BODY_LIMIT_BYTES, AiTranscriptIngestRequest, AiTranscriptIngestResponse,
    AiTranscriptRecord, EVIDENCE_ENVELOPE_VERSION, EvidenceCapabilityCoverage, EvidenceCoverage,
    EvidenceDiagnostic, EvidenceEnvelope, EvidenceSource,
};
use crate::scanner;

/// Cap on the *aggregate* batch per scan cycle, across every transcript file
/// combined — stays comfortably under the server's `MAX_RECORDS_PER_BATCH`
/// (2,000) and any fronting proxy's request-size limit. A backlog larger
/// than this drains over several poll cycles instead of one oversized POST.
const MAX_BATCH_RECORDS: usize = 500;
/// Local transcript input is hostile filesystem data. Bound both discovery
/// and individual reads before parsing so one malformed session cannot wedge
/// the agent's recurring forwarder.
const MAX_FORWARD_FILES: usize = 1_024;
const MAX_TRANSCRIPT_FILE_BYTES: u64 = 1024 * 1024;
// Claude and Codex embed tool results (and occasionally encoded media) in a
// single JSONL record. Real sessions routinely exceed 64 KiB; keep the read
// finite while leaving enough room for those provider-native records. The
// forwarded message is independently reduced to MAX_FORWARDED_MESSAGE_BYTES.
const MAX_JSONL_LINE_BYTES: usize = 8 * 1024 * 1024;
const OVERSIZED_JSONL_GAP_RECORD: &str =
    r#"{"type":"status","message":"[Cortex skipped an oversized transcript record]"}"#;
// At 500 records, a 3 KiB message can at worst double while JSON escaping.
// Together with the explicitly bounded scalar fields below, that remains
// under the receiver's 4 MiB request budget without an unbounded retry loop.
const MAX_FORWARDED_MESSAGE_BYTES: usize = 3_000;
const MAX_FORWARDED_IDENTIFIER_BYTES: usize = 512;
const MAX_FORWARDED_TIMESTAMP_BYTES: usize = 128;
const MAX_FORWARD_BODY_BYTES: usize = AI_TRANSCRIPT_BODY_LIMIT_BYTES - 128 * 1024;
const CODEX_PREFIX_METADATA_SCAN_LINES: usize = 200;
const TRANSCRIPT_FORWARDER_ADAPTER_VERSION: &str = "cortex-ai-forwarder-v1";

#[derive(Debug, Clone)]
pub struct AiTranscriptForwardConfig {
    pub roots: Vec<PathBuf>,
    /// Central server base URL, e.g. `http://nashost:3100`.
    pub target: String,
    pub token: Option<String>,
    pub hostname: String,
    pub checkpoint_path: PathBuf,
    pub poll_interval: Duration,
}

impl AiTranscriptForwardConfig {
    pub fn new(target: String, token: Option<String>, checkpoint_path: PathBuf) -> Self {
        Self {
            roots: scanner::default_transcript_roots(),
            target,
            token,
            hostname: scanner::local_hostname(),
            checkpoint_path,
            poll_interval: Duration::from_secs(15),
        }
    }
}

#[path = "ai_transcript_helpers.rs"]
mod helpers;
use helpers::*;

async fn scan_and_forward(
    config: &AiTranscriptForwardConfig,
    client: &reqwest::Client,
    checkpoint: &mut Checkpoint,
) -> Result<usize> {
    let mut files = Vec::new();
    let mut discovery_updates = HashMap::new();
    for root in &config.roots {
        // Bound each configured root independently and rotate that window on
        // subsequent scans. One busy provider must not hide later roots (or
        // its own later sessions) forever.
        let root_key = root.to_string_lossy().to_string();
        let cursor = checkpoint
            .discovery_cursors
            .get(&root_key)
            .map(PathBuf::from);
        let mut root_files = Vec::new();
        if let Err(error) = collect_files_after(root, &mut root_files, cursor.as_deref()) {
            tracing::warn!(
                root = %root.display(),
                error = format!("{error:#}"),
                reason_code = "transcript_discovery_failed",
                "AI transcript root could not be scanned"
            );
            continue;
        }
        if root_files.is_empty() && cursor.is_some() {
            // Reached the end of this stable traversal: wrap so ongoing
            // sessions near the beginning remain observable.
            if let Err(error) = collect_files(root, &mut root_files) {
                tracing::warn!(
                    root = %root.display(),
                    error = format!("{error:#}"),
                    reason_code = "transcript_discovery_failed",
                    "AI transcript root could not be scanned after cursor wrap"
                );
                continue;
            }
        }
        root_files.sort();
        if let Some(last) = root_files.last() {
            discovery_updates.insert(root_key, last.to_string_lossy().to_string());
        }
        files.extend(root_files);
    }
    // Surface active work before draining historical backlogs. A path-sorted
    // archive can contain enough records to consume every bounded batch and
    // otherwise keep a newly-written session invisible for many poll cycles.
    // Path remains the deterministic tie-breaker when mtimes match.
    files.sort_by(|left, right| {
        let modified = |path: &Path| fs::metadata(path).and_then(|meta| meta.modified()).ok();
        modified(right)
            .cmp(&modified(left))
            .then_with(|| left.cmp(right))
    });
    files.dedup();
    evict_missing_gemini_failures(
        checkpoint,
        &files
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect(),
    );

    let mut records = Vec::new();
    let mut new_totals: HashMap<String, usize> = HashMap::new();
    let mut new_fingerprints: HashMap<String, String> = HashMap::new();
    let mut new_jsonl_positions: HashMap<String, JsonlPosition> = HashMap::new();
    for path in &files {
        // Cap the aggregate batch across ALL files, not just per-file — a
        // host with a large never-forwarded backlog (many past sessions)
        // can otherwise blow well past the server's/proxy's request-size
        // limit even with a per-file cap, since MAX_BATCH_RECORDS applied
        // per file still multiplies by however many files have new lines.
        // Files not fully drained this cycle keep their unmodified
        // checkpoint and get picked up on the next poll.
        if records.len() >= MAX_BATCH_RECORDS {
            break;
        }
        let source_kind = forward_source_kind(path);
        let key = path.to_string_lossy().to_string();

        if matches!(source_kind, scanner::SourceKind::GeminiSession) {
            // Gemini sessions are a single whole-file JSON object rewritten
            // (with new messages appended) each turn, not an append-only
            // JSONL stream — there's no byte/line offset to tail. The
            // checkpoint here is a *record index* into `parse_file`'s output
            // instead: re-parse the whole file each cycle and only forward
            // records past however many were already sent. The fingerprint is
            // of that acknowledged logical record prefix, rather than raw
            // bytes: every normal Gemini append rewrites the whole JSON file.
            let mut from_record = checkpoint.files.get(&key).copied().unwrap_or(0);
            let raw = match fs::read_to_string(path) {
                Ok(raw) => raw,
                Err(error) => {
                    tracing::warn!(path = %path.display(), error = format!("{error:#}"), "ai transcript forwarder failed to read gemini file");
                    continue;
                }
            };
            let parsed = match scanner::gemini::parse_file(&raw, path) {
                Ok(parsed) => {
                    checkpoint.gemini_parse_failures.remove(&key);
                    parsed
                }
                Err(error) => {
                    if should_warn_gemini_parse_failure(checkpoint, &key, &raw, Instant::now()) {
                        tracing::warn!(
                            path = %path.display(),
                            error = format!("{error:#}"),
                            unparseable_transcripts = checkpoint.gemini_parse_failures.len(),
                            "ai transcript forwarder failed to parse gemini file — its data is not being forwarded"
                        );
                    }
                    continue;
                }
            };
            if parsed.records.len() < from_record
                || (from_record > 0
                    && checkpoint.fingerprints.get(&key).is_some_and(|previous| {
                        previous != &gemini_prefix_fingerprint(&parsed.records, from_record)
                    }))
            {
                // A shrink or a changed logical prefix means this is a source
                // rewrite/rotation. Replay from zero; exact server receipts
                // suppress unchanged records.
                from_record = 0;
            }
            if parsed.missing_messages || parsed.records.len() <= from_record {
                continue;
            }
            let remaining_budget = MAX_BATCH_RECORDS - records.len();
            let forwarded_through = (from_record + remaining_budget).min(parsed.records.len());
            let fingerprint = gemini_prefix_fingerprint(&parsed.records, forwarded_through);
            let new_records: Vec<_> = parsed
                .records
                .into_iter()
                .skip(from_record)
                .take(remaining_budget)
                .collect();
            // Only advance the checkpoint to how far this cycle actually
            // forwarded — if the global batch cap cut the read short, the
            // remaining tail is picked up next cycle, same as the
            // line-based sources below.
            for (record_index, parsed_record) in new_records.into_iter().enumerate() {
                let revision = format!(
                    "gemini:{}:{}:{}",
                    from_record + record_index,
                    parsed_record.event_kind,
                    parsed_record.message
                );
                records.push(transcript_record(
                    config,
                    path,
                    source_kind,
                    TranscriptRecordDetails {
                        revision,
                        timestamp: parsed_record.timestamp,
                        ai_project: parsed_record.ai_project,
                        ai_session_id: parsed_record.session_id,
                        event_kind: Some(parsed_record.event_kind),
                        message: parsed_record.message,
                        title: parsed_record.session_metadata.title,
                        title_provenance: parsed_record.session_metadata.title_provenance,
                        diagnostics: Vec::new(),
                    },
                ));
            }
            new_totals.insert(key, forwarded_through);
            new_fingerprints.insert(path.to_string_lossy().to_string(), fingerprint);
            continue;
        }

        let mut from_line = checkpoint.files.get(&key).copied().unwrap_or(0);
        let mut byte_offset = 0;
        if let Some(position) = checkpoint.jsonl_positions.get(&key) {
            if jsonl_position_is_current(path, position) {
                from_line = position.line;
                byte_offset = position.byte_offset;
            } else {
                from_line = 0;
            }
        } else {
            // One-time migration for checkpoints written before seekable JSONL
            // positions existed. Preserve the exact historical rewrite check.
            let fingerprint = match file_prefix_fingerprint(path, from_line) {
                Ok(fingerprint) => fingerprint,
                Err(error) => {
                    tracing::warn!(path = %path.display(), error = %error, "ai transcript forwarder failed to fingerprint file");
                    continue;
                }
            };
            if checkpoint
                .fingerprints
                .get(&key)
                .is_some_and(|previous| previous != &fingerprint)
            {
                from_line = 0;
            }
            byte_offset = match jsonl_offset_after_lines(path, from_line) {
                Ok(offset) => offset,
                Err(error) => {
                    tracing::warn!(path = %path.display(), error = %error, "ai transcript forwarder failed to migrate JSONL cursor");
                    continue;
                }
            };
        }
        let mut fallback_project = scanner::project_for_file(source_kind, path);
        let mut fallback_session_id = codex_fallback_session_id(path, source_kind);
        if let Err(error) = seed_codex_prefix_fallbacks(
            path,
            source_kind,
            from_line,
            &mut fallback_project,
            &mut fallback_session_id,
        ) {
            tracing::warn!(
                path = %path.display(),
                error = format!("{error:#}"),
                reason_code = "codex_prefix_recovery_failed",
                "ai transcript forwarder could not recover Codex prefix metadata"
            );
        }
        let codex_home = (source_kind == scanner::SourceKind::CodexSession)
            .then(|| {
                path.ancestors().find(|ancestor| {
                    ancestor.file_name().and_then(|name| name.to_str()) == Some(".codex")
                })
            })
            .flatten();
        let mut supplemental_lookup_session_id = None;
        let mut supplemental_title = None;
        let remaining_budget = MAX_BATCH_RECORDS - records.len();
        let (new_lines, total_lines, acknowledged_offset) = match read_new_lines_from_offset(
            path,
            from_line,
            byte_offset,
            remaining_budget,
        ) {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(path = %path.display(), error = format!("{error:#}"), "ai transcript forwarder failed to read file");
                continue;
            }
        };
        for (line_no, line) in &new_lines {
            scanner::update_codex_fallbacks(
                source_kind,
                line,
                &mut fallback_project,
                &mut fallback_session_id,
            );
            match scanner::parse_line_for_source(source_kind, line, path, *line_no) {
                Ok(Some(parsed)) => {
                    let ai_project = parsed
                        .ai_project
                        .as_deref()
                        .or(fallback_project.as_deref())
                        .map(normalize_local_ai_project_path);
                    let ai_session_id = parsed
                        .session_id
                        .clone()
                        .or_else(|| fallback_session_id.as_deref().map(ToString::to_string));
                    if supplemental_lookup_session_id.as_deref() != ai_session_id.as_deref() {
                        supplemental_title = codex_home.zip(ai_session_id.as_deref()).and_then(
                            |(home, session_id)| {
                                scanner::codex::lookup_supplemental_session_title(home, session_id)
                            },
                        );
                        supplemental_lookup_session_id = ai_session_id.clone();
                    }
                    let title = parsed.session_metadata.title.or_else(|| {
                        supplemental_title
                            .as_ref()
                            .map(|metadata| metadata.title.clone())
                    });
                    let title_provenance = parsed.session_metadata.title_provenance.or_else(|| {
                        supplemental_title
                            .as_ref()
                            .map(|metadata| metadata.provenance.clone())
                    });
                    records.push(transcript_record(
                        config,
                        path,
                        source_kind,
                        TranscriptRecordDetails {
                            revision: format!("line:{line_no}:{line}"),
                            timestamp: parsed.timestamp,
                            ai_project,
                            ai_session_id,
                            event_kind: Some(parsed.event_kind),
                            message: parsed.message,
                            title,
                            title_provenance,
                            diagnostics: Vec::new(),
                        },
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        line = line_no,
                        error = %error,
                        reason_code = "transcript_record_parse_failed",
                        "ai transcript forwarder replaced an unparseable record with a diagnostic"
                    );
                    records.push(transcript_record(
                        config,
                        path,
                        source_kind,
                        TranscriptRecordDetails {
                            revision: format!("parse-gap:{line_no}:{line}"),
                            timestamp: None,
                            ai_project: fallback_project.clone(),
                            ai_session_id: fallback_session_id.clone(),
                            event_kind: Some("parse_gap".to_string()),
                            message: "[Cortex skipped an unparseable transcript record]"
                                .to_string(),
                            title: None,
                            title_provenance: None,
                            diagnostics: vec![EvidenceDiagnostic {
                                code: "malformed_transcript_record".to_string(),
                                detail: Some(format!("line {line_no}")),
                            }],
                        },
                    ));
                }
            }
        }
        let prefix_guard = match jsonl_prefix_guard(path, acknowledged_offset) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(path = %path.display(), error = %error, "ai transcript forwarder failed to guard acknowledged prefix");
                continue;
            }
        };
        let prefix_digest = match jsonl_prefix_digest(path, acknowledged_offset) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(path = %path.display(), error = %error, "ai transcript forwarder failed to digest acknowledged prefix");
                continue;
            }
        };
        new_totals.insert(key.clone(), total_lines);
        let (observed_len, modified_ns) = path
            .metadata()
            .map(|metadata| (metadata.len(), file_modified_ns(&metadata)))
            .unwrap_or((0, None));
        new_jsonl_positions.insert(
            key,
            JsonlPosition {
                line: total_lines,
                byte_offset: acknowledged_offset,
                source_epoch: source_epoch(path),
                prefix_guard,
                prefix_digest: Some(prefix_digest),
                observed_len,
                modified_ns,
            },
        );
        if new_lines.is_empty() {
            continue;
        }
    }

    if records.is_empty() {
        // Advancing an all-quiet window is still essential: otherwise a
        // checkpointed first 1,024 files would starve every later file.
        save_checkpoint_updates(
            &config.checkpoint_path,
            checkpoint,
            new_totals,
            new_fingerprints,
            new_jsonl_positions,
            discovery_updates,
        )?;
        return Ok(0);
    }

    let sent = records.len();
    let expected_receipts: HashSet<String> = records
        .iter()
        .map(|record| record.envelope.source_record_id.clone())
        .collect();
    anyhow::ensure!(
        expected_receipts.len() == sent,
        "ai transcript forward constructed duplicate source-record identities"
    );
    let payload = serde_json::to_vec(&AiTranscriptIngestRequest { records })?;
    anyhow::ensure!(
        payload.len() <= MAX_FORWARD_BODY_BYTES,
        "ai transcript forward payload exceeded bounded request budget"
    );
    let mut url = config.target.trim_end_matches('/').to_string();
    url.push_str("/v1/ai-transcripts");
    let mut request = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(payload);
    if let Some(token) = &config.token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.context("ai transcript POST failed")?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response
            .text()
            .await
            .map(|body| {
                crate::receiver::enrichment::scrub_ai_message(
                    &truncate_utf8(body.trim(), 1_024),
                    None,
                )
            })
            .unwrap_or_else(|error| format!("response_body_read_failed: {error}"));
        anyhow::bail!("ai transcript forward rejected: {} {}", status, detail);
    }
    let receipt: AiTranscriptIngestResponse = response
        .json()
        .await
        .context("ai transcript forward response was not a receipt")?;
    let returned_receipts: HashSet<String> = receipt
        .receipts
        .iter()
        .map(|receipt| receipt.source_record_id.clone())
        .collect();
    if receipt.accepted != sent
        || receipt.receipts.len() != sent
        || returned_receipts != expected_receipts
    {
        anyhow::bail!(
            "ai transcript forward returned incomplete receipt set: expected {sent}, accepted {}, receipts {}",
            receipt.accepted,
            receipt.receipts.len()
        );
    }

    // Only advance after the server supplied an exact receipt for every
    // submitted source-record ID. A lost/malformed response leaves the local
    // cursor untouched; a retry is deduplicated by the server receipt table.
    save_checkpoint_updates(
        &config.checkpoint_path,
        checkpoint,
        new_totals,
        new_fingerprints,
        new_jsonl_positions,
        discovery_updates,
    )?;
    Ok(sent)
}

/// Run the AI-transcript forward loop forever, polling every
/// `config.poll_interval`. Errors from a single scan are logged and do not
/// stop the loop — matches the retry-by-continuing behavior the other agent
/// streams get from `run_agent_streams`'s outer supervision wrapper.
pub async fn run(config: AiTranscriptForwardConfig) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build ai transcript forwarder http client")?;
    let mut checkpoint = load_checkpoint(&config.checkpoint_path)?;
    loop {
        match scan_and_forward(&config, &client, &mut checkpoint).await {
            Ok(0) => {}
            Ok(sent) => tracing::info!(sent, "ai transcript forwarder: batch sent"),
            Err(error) => tracing::warn!(
                error = format!("{error:#}"),
                "ai transcript forward scan failed"
            ),
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

#[cfg(test)]
#[path = "ai_transcript_tests.rs"]
mod tests;
