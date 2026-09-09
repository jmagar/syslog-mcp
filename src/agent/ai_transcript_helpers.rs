//! Checkpoint, discovery, and record-normalization helpers.

use super::*;
use std::io::{Read, Seek, SeekFrom};

#[path = "ai_transcript_helpers_checkpoint.rs"]
mod checkpoint;
pub(super) use checkpoint::*;

pub(super) type JsonlReadWindow = (Vec<(usize, String)>, usize, u64);

/// Recursively collect supported transcript files under `root` (mirrors
/// `scanner`'s discovery rules via the public `is_supported_transcript_file`
/// predicate, without pulling in the local-indexing `IndexResult` coupling
/// that `scanner::collect_supported_files` carries).
pub(super) fn collect_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    collect_files_after(root, out, None)
}

/// Collect one stable discovery window after `after`. Directories are always
/// traversed, because a directory whose own path precedes the cursor can
/// contain later files. File paths are sorted at every level so a persisted
/// cursor rotates predictably across a large transcript tree.
pub(super) fn collect_files_after(
    root: &Path,
    out: &mut Vec<PathBuf>,
    after: Option<&Path>,
) -> Result<()> {
    if out.len() >= MAX_FORWARD_FILES {
        return Ok(());
    }
    if !root
        .try_exists()
        .with_context(|| format!("check transcript path {}", root.display()))?
    {
        return Ok(());
    }
    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect transcript path {}", root.display()))?;
    if root_metadata.file_type().is_symlink() {
        // Forwarder roots are local operator configuration, but their
        // descendants are still hostile filesystem input. Never traverse a
        // symlink into an unrelated home/cache tree or forward its locator.
        return Ok(());
    }
    if root_metadata.file_type().is_file() {
        if scanner::is_supported_transcript_file(root)
            && after.is_none_or(|cursor| root > cursor)
            && transcript_file_within_limit(root)?
        {
            out.push(root.to_path_buf());
        }
        return Ok(());
    }
    if !scanner::should_descend_transcript_dir(root) {
        return Ok(());
    }
    let mut paths = fs::read_dir(root)
        .with_context(|| format!("read transcript directory {}", root.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .with_context(|| format!("read entry in transcript directory {}", root.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect transcript path {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.file_type().is_dir() {
            collect_files_after(&path, out, after)?;
        } else if scanner::is_supported_transcript_file(&path)
            && after.is_none_or(|cursor| path > cursor)
            && transcript_file_within_limit(&path)?
        {
            out.push(path);
        }
    }
    Ok(())
}

fn transcript_file_within_limit(path: &Path) -> Result<bool> {
    if !scanner::gemini::is_chat_file(path) {
        return Ok(true);
    }
    let size = path
        .metadata()
        .with_context(|| format!("read transcript metadata {}", path.display()))?
        .len();
    if size > MAX_TRANSCRIPT_FILE_BYTES {
        tracing::warn!(
            path = %path.display(),
            size,
            limit = MAX_TRANSCRIPT_FILE_BYTES,
            reason_code = "transcript_file_too_large",
            "AI transcript file skipped"
        );
        return Ok(false);
    }
    Ok(true)
}

/// The scanner's provider registry intentionally recognizes only configured
/// `$HOME` roots. An agent may be explicitly configured with a mounted or
/// test root outside that home, though, so preserve provider classification
/// from the safe, structural transcript layout as a fallback. This never
/// broadens file discovery: [`collect_files`] already admits only supported
/// filename shapes.
pub(super) fn forward_source_kind(path: &Path) -> scanner::SourceKind {
    match scanner::detect_source_kind(path) {
        scanner::SourceKind::ExplicitFile if scanner::gemini::is_chat_file(path) => {
            scanner::SourceKind::GeminiSession
        }
        scanner::SourceKind::ExplicitFile => {
            scanner::providers::provider_for_transcript_layout(path)
                .and_then(scanner::providers::source_kind_for_provider)
                .and_then(scanner::SourceKind::from_persisted_kind)
                .unwrap_or(scanner::SourceKind::ExplicitFile)
        }
        source_kind => source_kind,
    }
}

/// Return up to `limit` complete newline-terminated records starting at `from_line` (0-indexed), plus
/// the checkpoint value to resume from next time.
///
/// The returned line count is deliberately NOT the file's true EOF line
/// count when `limit` cuts the read short — it's the index of the first
/// line not yet read. Advancing the checkpoint to true EOF regardless of
/// how much was actually read would silently skip every line past `limit`
/// forever (a real bug this signature previously had: it read at most
/// `limit` lines into the batch but always reported the file's full line
/// count as the new checkpoint).
#[cfg(test)]
pub(super) fn read_new_lines(
    path: &Path,
    from_line: usize,
    limit: usize,
) -> Result<(Vec<(usize, String)>, usize)> {
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    let mut line_no = 0usize;
    while let Some(line) = read_bounded_jsonl_line(&mut reader)? {
        if line_no < from_line {
            line_no += 1;
            continue;
        }
        if out.len() >= limit {
            break;
        }
        out.push((line_no, line));
        line_no += 1;
    }
    Ok((out, line_no))
}

pub(super) fn read_new_lines_from_offset(
    path: &Path,
    from_line: usize,
    byte_offset: u64,
    limit: usize,
) -> Result<JsonlReadWindow> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    file.seek(SeekFrom::Start(byte_offset))?;
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    let mut line_no = from_line;
    while out.len() < limit {
        let before = reader.stream_position()?;
        let Some(line) = read_bounded_jsonl_line(&mut reader)? else {
            // Preserve the last complete-record boundary when the writer has
            // only appended part of its next JSONL record.
            reader.seek(SeekFrom::Start(before))?;
            break;
        };
        out.push((line_no, line));
        line_no += 1;
    }
    Ok((out, line_no, reader.stream_position()?))
}

pub(super) fn read_bounded_jsonl_line(reader: &mut BufReader<fs::File>) -> Result<Option<String>> {
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            // A writer may have appended only part of its final JSONL record.
            // It is not a record until the terminating newline arrives: handing
            // it to the caller would let a successful earlier batch advance the
            // line checkpoint past evidence that will be completed next poll.
            return Ok(None);
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if !oversized && line.len().saturating_add(take) > MAX_JSONL_LINE_BYTES {
            oversized = true;
            line.clear();
        }
        if oversized {
            let terminated = available[..take].ends_with(b"\n");
            reader.consume(take);
            if terminated {
                return Ok(Some(OVERSIZED_JSONL_GAP_RECORD.to_string()));
            }
            continue;
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.ends_with(b"\n") {
            line.pop();
            if line.ends_with(b"\r") {
                line.pop();
            }
            return String::from_utf8(line)
                .context("transcript line is not UTF-8")
                .map(Some);
        }
    }
}

pub(super) fn codex_fallback_session_id(
    path: &Path,
    source_kind: scanner::SourceKind,
) -> Option<String> {
    (source_kind == scanner::SourceKind::CodexSession)
        .then(|| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(ToString::to_string)
        })
        .flatten()
}

pub(super) fn seed_codex_prefix_fallbacks(
    path: &Path,
    source_kind: scanner::SourceKind,
    from_line: usize,
    fallback_project: &mut Option<String>,
    fallback_session_id: &mut Option<String>,
) -> Result<()> {
    if source_kind != scanner::SourceKind::CodexSession
        || from_line == 0
        || (fallback_project.is_some() && fallback_session_id.is_some())
    {
        return Ok(());
    }

    let file = fs::File::open(path)
        .with_context(|| format!("open Codex prefix metadata {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let scan_limit = from_line.min(CODEX_PREFIX_METADATA_SCAN_LINES);
    for _ in 0..scan_limit {
        let Some(line) = read_bounded_jsonl_line(&mut reader)
            .with_context(|| format!("read Codex prefix metadata {}", path.display()))?
        else {
            break;
        };
        scanner::update_codex_fallbacks(source_kind, &line, fallback_project, fallback_session_id);
        if fallback_project.is_some() && fallback_session_id.is_some() {
            break;
        }
    }
    Ok(())
}

pub(super) fn sha256_id(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_ref());
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub(super) fn source_epoch(path: &Path) -> String {
    let mut parts = Vec::new();
    if let Ok(metadata) = fs::metadata(path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            parts.push(metadata.dev().to_le_bytes().to_vec());
            parts.push(metadata.ino().to_le_bytes().to_vec());
        }
        parts.push(
            metadata
                .created()
                .ok()
                .and_then(|created| created.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos().to_le_bytes().to_vec())
                .unwrap_or_default(),
        );
    } else {
        // A disappeared source cannot be forwarded, but retain a deterministic
        // fallback for callers constructing an envelope during a race.
        parts.push(path.as_os_str().as_encoded_bytes().to_vec());
    }
    sha256_id(parts)
}

pub(super) fn file_prefix_fingerprint(path: &Path, acknowledged_lines: usize) -> Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    for _ in 0..acknowledged_lines {
        let Some(line) = read_bounded_jsonl_line(&mut reader)? else {
            break;
        };
        hasher.update(line.as_bytes());
        hasher.update([0]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub(super) fn jsonl_offset_after_lines(path: &Path, acknowledged_lines: usize) -> Result<u64> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    for _ in 0..acknowledged_lines {
        if read_bounded_jsonl_line(&mut reader)?.is_none() {
            break;
        }
    }
    reader.stream_position().map_err(Into::into)
}

const PREFIX_GUARD_WINDOW_BYTES: u64 = 4 * 1024;

/// A bounded identity for an acknowledged append-only prefix. The source
/// epoch detects replacement; sampling both ends detects truncation and the
/// common in-place rewrite cases without rereading the historical body.
pub(super) fn jsonl_prefix_guard(path: &Path, byte_offset: u64) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    hasher.update(byte_offset.to_le_bytes());
    let first_len = byte_offset.min(PREFIX_GUARD_WINDOW_BYTES) as usize;
    let mut buffer = vec![0; first_len];
    file.read_exact(&mut buffer)?;
    hasher.update(&buffer);
    if byte_offset > PREFIX_GUARD_WINDOW_BYTES {
        let tail_len = byte_offset.min(PREFIX_GUARD_WINDOW_BYTES);
        file.seek(SeekFrom::Start(byte_offset - tail_len))?;
        buffer.resize(tail_len as usize, 0);
        file.read_exact(&mut buffer)?;
        hasher.update(&buffer);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub(super) fn jsonl_prefix_digest(path: &Path, byte_offset: u64) -> Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = file.take(byte_offset);
    let mut hasher = Sha256::new();
    let copied = std::io::copy(&mut reader, &mut hasher)?;
    anyhow::ensure!(
        copied == byte_offset,
        "transcript became shorter while hashing acknowledged prefix"
    );
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

pub(super) fn file_modified_ns(metadata: &fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos()
        .try_into()
        .ok()
}

pub(super) fn jsonl_position_is_current(path: &Path, position: &JsonlPosition) -> bool {
    path.metadata().is_ok_and(|metadata| {
        let len = metadata.len();
        len >= position.byte_offset
            && len >= position.observed_len
            && position.observed_len != 0
            && position.prefix_digest.is_some()
            && if len > position.observed_len {
                position.prefix_digest.as_ref().is_some_and(|expected| {
                    jsonl_prefix_digest(path, position.byte_offset)
                        .is_ok_and(|actual| actual == *expected)
                })
            } else {
                position.modified_ns.is_some()
                    && file_modified_ns(&metadata) == position.modified_ns
            }
    }) && source_epoch(path) == position.source_epoch
        && jsonl_prefix_guard(path, position.byte_offset)
            .is_ok_and(|guard| guard == position.prefix_guard)
}

/// Returns a fingerprint for the acknowledged logical prefix of a Gemini
/// transcript. Gemini persists an entire JSON snapshot on every turn, so a
/// byte prefix changes even when the already-forwarded messages have not.
/// Fingerprinting the parsed records instead lets an append retain its record
/// cursor while still detecting a rewrite, reordering, or truncation of the
/// acknowledged prefix.
pub(super) fn gemini_prefix_fingerprint(
    records: &[scanner::ParsedTranscriptRecord],
    count: usize,
) -> String {
    let mut hasher = Sha256::new();
    for record in records.iter().take(count) {
        for field in [
            record.record_key.as_bytes(),
            record.timestamp.as_deref().unwrap_or_default().as_bytes(),
            record.event_kind.as_bytes(),
            record.message.as_bytes(),
            record.session_id.as_deref().unwrap_or_default().as_bytes(),
        ] {
            hasher.update(field);
            hasher.update([0]);
        }
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub(super) fn capability_coverage(source_kind: scanner::SourceKind) -> EvidenceCapabilityCoverage {
    let provider = scanner::providers::provider_for_source_kind(source_kind.as_str());
    let coverage = |lane| {
        provider
            .map(|provider| scanner::providers::definition(provider).forwarding_coverage(lane))
            // An explicitly configured generic file remains a bounded,
            // parseable transcript input, but never inherits provider events.
            .unwrap_or_else(|| match lane {
                scanner::providers::ProviderLane::Transcript => {
                    scanner::providers::Coverage::Partial
                }
                _ => scanner::providers::Coverage::NotObserved,
            })
    };

    EvidenceCapabilityCoverage {
        transcript: evidence_coverage(coverage(scanner::providers::ProviderLane::Transcript)),
        mcp_events: evidence_coverage(coverage(scanner::providers::ProviderLane::McpEvents)),
        skill_events: evidence_coverage(coverage(scanner::providers::ProviderLane::Skills)),
        hook_events: evidence_coverage(coverage(scanner::providers::ProviderLane::Hooks)),
    }
}

pub(super) fn evidence_coverage(coverage: scanner::providers::Coverage) -> EvidenceCoverage {
    match coverage {
        scanner::providers::Coverage::Observed => EvidenceCoverage::Observed,
        scanner::providers::Coverage::Partial => EvidenceCoverage::Partial,
        scanner::providers::Coverage::NotObserved => EvidenceCoverage::NotObserved,
        scanner::providers::Coverage::Failed => EvidenceCoverage::Failed,
    }
}

pub(super) fn safe_provenance_id(prefix: &str, value: Option<String>) -> Option<String> {
    value.map(|value| format!("{prefix}:{}", sha256_id([value.as_bytes()])))
}

pub(super) struct TranscriptRecordDetails {
    pub(super) revision: String,
    pub(super) timestamp: Option<String>,
    pub(super) ai_project: Option<String>,
    pub(super) ai_session_id: Option<String>,
    pub(super) event_kind: Option<String>,
    pub(super) message: String,
    pub(super) title: Option<String>,
    pub(super) title_provenance: Option<String>,
    pub(super) diagnostics: Vec<EvidenceDiagnostic>,
}

pub(super) fn transcript_record(
    config: &AiTranscriptForwardConfig,
    path: &Path,
    source_kind: scanner::SourceKind,
    details: TranscriptRecordDetails,
) -> AiTranscriptRecord {
    let provider = source_kind.tool_name().to_string();
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let canonical_bytes = canonical.as_os_str().as_encoded_bytes();
    let source_identity = match details.ai_session_id.as_deref() {
        // A native provider session identifier survives an archive move. It is
        // hashed before forwarding, so the canonical receipt contains no raw
        // session text or local path.
        Some(session_id) => sha256_id([
            b"ai-transcript-native-session",
            provider.as_bytes(),
            config.hostname.as_bytes(),
            session_id.as_bytes(),
        ]),
        None => sha256_id([provider.as_bytes(), canonical_bytes]),
    };
    let epoch = source_epoch(&canonical);
    let source_revision = sha256_id([details.revision.as_bytes()]);
    let locator = sha256_id([
        b"ai-transcript-locator",
        provider.as_bytes(),
        canonical_bytes,
    ]);
    let source_record_id = sha256_id([
        b"ai-transcript-record-v1",
        provider.as_bytes(),
        source_identity.as_bytes(),
        epoch.as_bytes(),
        source_revision.as_bytes(),
    ]);
    AiTranscriptRecord {
        envelope: EvidenceEnvelope {
            version: EVIDENCE_ENVELOPE_VERSION,
            source_record_id,
            source: EvidenceSource {
                provider,
                adapter_version: TRANSCRIPT_FORWARDER_ADAPTER_VERSION.to_string(),
                source_identity,
                source_epoch: epoch,
                source_revision,
                locator,
                native_session_id: safe_provenance_id("session", details.ai_session_id.clone()),
                title: details.title.map(|title| {
                    crate::receiver::enrichment::scrub_ai_message(
                        &truncate_utf8(&title, MAX_FORWARDED_IDENTIFIER_BYTES),
                        None,
                    )
                }),
                title_provenance: details
                    .title_provenance
                    .map(|provenance| truncate_utf8(&provenance, MAX_FORWARDED_IDENTIFIER_BYTES)),
            },
            timestamp: details
                .timestamp
                .map(|timestamp| truncate_utf8(&timestamp, MAX_FORWARDED_TIMESTAMP_BYTES)),
            hostname: truncate_utf8(&config.hostname, MAX_FORWARDED_IDENTIFIER_BYTES),
            ai_project: safe_provenance_id("project", details.ai_project),
            ai_session_id: safe_provenance_id("session", details.ai_session_id),
            event_kind: details
                .event_kind
                .map(|event_kind| truncate_utf8(&event_kind, MAX_FORWARDED_IDENTIFIER_BYTES)),
            message: crate::receiver::enrichment::scrub_ai_message(
                &truncate_utf8(&details.message, MAX_FORWARDED_MESSAGE_BYTES),
                None,
            ),
            capabilities: capability_coverage(source_kind),
            diagnostics: details.diagnostics,
        },
    }
}

pub(super) fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}
