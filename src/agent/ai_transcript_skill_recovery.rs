//! Explicit source-host recovery of completed Codex skill reads.

use super::*;

/// Recover only completed Codex skill reads that older scanners dropped.
/// This does not rewind or modify the live transcript checkpoint. Original
/// source identities/revisions and the normal receipt protocol make retries
/// idempotent. Run explicitly from the source host, not from copied files.
pub async fn backfill_codex_skill_reads(config: AiTranscriptForwardConfig) -> Result<usize> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut files = Vec::new();
    for root in &config.roots {
        let mut cursor = None;
        loop {
            let mut window = Vec::new();
            collect_files_after(root, &mut window, cursor.as_deref())?;
            if window.is_empty() {
                break;
            }
            cursor = window.last().cloned();
            files.extend(window);
        }
    }
    files.sort();
    files.dedup();
    let mut records = Vec::new();
    let mut sent = 0;
    for path in files {
        let source_kind = forward_source_kind(&path);
        if source_kind != scanner::SourceKind::CodexSession {
            continue;
        }
        let mut project = scanner::project_for_file(source_kind, &path);
        let mut session = codex_fallback_session_id(&path, source_kind);
        let mut reader = BufReader::new(fs::File::open(&path)?);
        let mut line_no = 0;
        while let Some(line) = read_bounded_jsonl_line(&mut reader)? {
            scanner::update_codex_fallbacks(source_kind, &line, &mut project, &mut session);
            if let Ok(Some(parsed)) =
                scanner::parse_line_for_source(source_kind, &line, &path, line_no)
                && parsed.message.starts_with("{\"cortex_skill_read\":")
            {
                let ai_session_id = parsed.session_id.or_else(|| session.clone());
                let title = path
                    .ancestors()
                    .find(|ancestor| {
                        ancestor.file_name().and_then(|name| name.to_str()) == Some(".codex")
                    })
                    .zip(ai_session_id.as_deref())
                    .and_then(|(home, id)| {
                        scanner::codex::lookup_supplemental_session_title(home, id)
                    });
                records.push(transcript_record(
                    &config,
                    &path,
                    source_kind,
                    TranscriptRecordDetails {
                        revision: format!("line:{line_no}:{line}"),
                        timestamp: parsed.timestamp,
                        ai_project: parsed
                            .ai_project
                            .or_else(|| project.clone())
                            .map(|path| normalize_local_ai_project_path(&path)),
                        ai_session_id,
                        event_kind: Some(parsed.event_kind),
                        message: parsed.message,
                        title: title.as_ref().map(|value| value.title.clone()),
                        title_provenance: title.map(|value| value.provenance),
                        diagnostics: Vec::new(),
                    },
                ));
                if records.len() == MAX_BATCH_RECORDS {
                    sent += send_records(&config, &client, std::mem::take(&mut records)).await?;
                    tracing::info!(sent, "Codex skill-read recovery receipts acknowledged");
                }
            }
            line_no += 1;
        }
    }
    if !records.is_empty() {
        sent += send_records(&config, &client, records).await?;
    }
    Ok(sent)
}
