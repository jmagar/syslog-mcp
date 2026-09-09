use crate::db::LogBatchEntry;
use crate::enrich::{SourceKind, stamp_source_kind};
use crate::ingest_metadata::bounded_metadata_json;

use super::super::models::FileTailSource;

pub(crate) fn file_tail_line_to_entry(
    source: &FileTailSource,
    line: &str,
    now: &str,
) -> LogBatchEntry {
    let hostname = source
        .hostname
        .clone()
        .unwrap_or_else(|| super::super::models::derived_source_hostname(&source.id));
    let source_hostname = source_identity_component(&hostname);
    let path_basename = std::path::Path::new(&source.path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");
    let metadata_json = bounded_metadata_json(serde_json::json!({
        "source_type": "file_tail",
        "source_kind": SourceKind::FileTail.as_str(),
        "file_tail_id": source.id,
        "tag": source.tag,
        "path_basename": path_basename,
    }));
    let mut entry = LogBatchEntry {
        timestamp: now.to_string(),
        hostname: hostname.clone(),
        facility: source.facility.clone(),
        severity: source.severity.clone(),
        app_name: Some(source.tag.clone()),
        process_id: None,
        message: line.to_string(),
        raw: line.to_string(),
        source_ip: format!("file-tail://{source_hostname}/{}", source.id),
        docker_checkpoint: None,
        ai_tool: None,
        ai_project: None,
        ai_session_id: None,
        ai_transcript_path: None,
        metadata_json: Some(metadata_json),
        http_status: None,
        auth_outcome: None,
        dns_blocked: None,
        event_action: None,
        parse_error: None,
    };
    stamp_source_kind(&mut entry, SourceKind::FileTail);
    entry
}

#[cfg(test)]
pub(crate) async fn tail_file_once_for_test(
    source: FileTailSource,
    ingest: crate::ingest::IngestTx,
) -> anyhow::Result<()> {
    use tokio::io::AsyncBufReadExt;

    let file = tokio::fs::File::open(&source.path).await?;
    let mut reader = tokio::io::BufReader::new(file);
    let mut line = String::new();
    while reader.read_line(&mut line).await? > 0 {
        let msg = line.trim_end_matches(['\r', '\n']);
        if !msg.is_empty() {
            ingest
                .send(file_tail_line_to_entry(
                    &source,
                    msg,
                    "2026-06-11T20:01:00Z",
                ))
                .await?;
        }
        line.clear();
    }
    Ok(())
}

fn source_identity_component(hostname: &str) -> String {
    let normalized = hostname
        .trim()
        .to_ascii_lowercase()
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
                byte as char
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches(['.', '-', '_'])
        .to_string()
        .chars()
        .take(255)
        .collect::<String>();
    if normalized.is_empty() {
        "localhost".to_string()
    } else {
        normalized
    }
}
