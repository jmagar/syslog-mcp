use super::*;
use crate::app::models::{
    RENDERED_SESSION_PAGE_MAX_BYTES, RENDERED_SESSION_PAGE_MAX_ITEMS,
    RENDERED_SESSION_POLL_AFTER_MS, RenderedSessionEvent, RenderedSessionEventKind,
    RenderedSessionPageRequest, RenderedSessionPageResponse,
};

const CURSOR_PREFIX: &str = "cortex-session-v1:";
const MAX_EVENT_TEXT_BYTES: usize = 240 * 1024;

impl CortexService {
    pub async fn rendered_session_page(
        &self,
        req: RenderedSessionPageRequest,
    ) -> ServiceResult<RenderedSessionPageResponse> {
        validate_identity(&req)?;
        let after_id = decode_cursor(req.cursor.as_deref())?;
        let requested_limit = req.limit.unwrap_or(RENDERED_SESSION_PAGE_MAX_ITEMS);
        let limit = requested_limit.clamp(1, RENDERED_SESSION_PAGE_MAX_ITEMS);
        let limit_clamped_to = (requested_limit > limit).then_some(limit);
        let params = db::RenderedSessionPageParams {
            ai_project: req.project,
            ai_tool: req.tool,
            ai_session_id: req.session_id,
            host: req.host,
            after_id,
            limit: limit + 1,
        };
        let rows = self
            .run_db("rendered_session_page", move |pool| {
                db::rendered_session_page(pool, &params)
            })
            .await?;

        let count_truncated = rows.len() > limit as usize;
        let mut events = Vec::with_capacity(limit as usize);
        let mut retained_bytes = 0usize;
        let mut byte_truncated = false;
        for row in rows.into_iter().take(limit as usize) {
            let event = project_event(row);
            let event_bytes = serde_json::to_vec(&event)
                .map_err(|error| ServiceError::Internal(error.into()))?
                .len();
            if !events.is_empty()
                && retained_bytes.saturating_add(event_bytes) > RENDERED_SESSION_PAGE_MAX_BYTES
            {
                byte_truncated = true;
                break;
            }
            retained_bytes = retained_bytes.saturating_add(event_bytes);
            events.push(event);
        }
        let high_watermark = events.last().map_or(after_id, |event| event.position);
        let mut response = RenderedSessionPageResponse {
            contract_version: "1.0.0",
            delivery: "polling",
            events,
            next_cursor: encode_cursor(high_watermark),
            high_watermark,
            has_more: count_truncated || byte_truncated,
            truncated_by_bytes: byte_truncated,
            limit_clamped_to,
            poll_after_ms: RENDERED_SESSION_POLL_AFTER_MS,
            max_page_items: RENDERED_SESSION_PAGE_MAX_ITEMS,
            max_page_bytes: RENDERED_SESSION_PAGE_MAX_BYTES,
        };
        while serde_json::to_vec(&response)
            .map_err(|error| ServiceError::Internal(error.into()))?
            .len()
            > RENDERED_SESSION_PAGE_MAX_BYTES
        {
            if response.events.pop().is_none() {
                break;
            }
            response.has_more = true;
            response.truncated_by_bytes = true;
            response.high_watermark = response
                .events
                .last()
                .map_or(after_id, |event| event.position);
            response.next_cursor = encode_cursor(response.high_watermark);
        }
        Ok(response)
    }
}

fn validate_identity(req: &RenderedSessionPageRequest) -> ServiceResult<()> {
    for (name, value) in [
        ("project", req.project.as_str()),
        ("tool", req.tool.as_str()),
        ("session_id", req.session_id.as_str()),
        ("host", req.host.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(ServiceError::InvalidInput(format!(
                "{name} must not be empty"
            )));
        }
    }
    Ok(())
}

fn decode_cursor(cursor: Option<&str>) -> ServiceResult<i64> {
    let Some(cursor) = cursor else { return Ok(0) };
    let value = cursor
        .strip_prefix(CURSOR_PREFIX)
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 0)
        .ok_or_else(|| ServiceError::InvalidInput("invalid session cursor".to_string()))?;
    Ok(value)
}

fn encode_cursor(position: i64) -> String {
    format!("{CURSOR_PREFIX}{position}")
}

fn project_event(row: db::RenderedSessionEventRow) -> RenderedSessionEvent {
    let mut metadata = row
        .metadata_json
        .as_deref()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
    let kind = metadata
        .as_ref()
        .and_then(event_kind_from_metadata)
        .unwrap_or_else(|| event_kind_from_text(&row.message));
    let mut metadata_was_redacted = false;
    if let Some(value) = &mut metadata {
        let before = value.clone();
        crate::assessment::redact_json_value_strings(value);
        metadata_was_redacted = *value != before;
    }
    let pattern_scrubbed = crate::receiver::enrichment::scrub_ai_message(&row.message, None);
    let scrubbed = crate::assessment::redact_secrets(&pattern_scrubbed);
    let mut redacted = pattern_scrubbed != row.message
        || scrubbed != pattern_scrubbed
        || metadata_was_redacted
        || metadata
            .as_ref()
            .and_then(|value| value.get("content_scrubbed"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        || scrubbed.contains("[REDACTED]");
    let (text, text_truncated) = truncate_utf8(scrubbed, MAX_EVENT_TEXT_BYTES);
    let parse_error_before = row.parse_error.clone();
    let parse_error = row
        .parse_error
        .map(|warning| crate::assessment::redact_secrets(&warning));
    redacted |= parse_error.as_deref() != parse_error_before.as_deref();
    let parse_warning = match (parse_error, text_truncated) {
        (Some(warning), true) => Some(format!("{warning}; rendered text truncated")),
        (None, true) => Some("rendered text truncated".to_string()),
        (warning, false) => warning,
    };
    RenderedSessionEvent {
        position: row.id,
        timestamp: row.timestamp,
        kind,
        text,
        redacted,
        parse_warning,
    }
}

fn truncate_utf8(value: String, max_bytes: usize) -> (String, bool) {
    if value.len() <= max_bytes {
        return (value, false);
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    (format!("{}...[truncated]", &value[..boundary]), true)
}

fn event_kind_from_metadata(value: &serde_json::Value) -> Option<RenderedSessionEventKind> {
    let kind = value
        .get("event_kind")
        .or_else(|| value.get("role"))
        .or_else(|| value.get("type"))?
        .as_str()?;
    Some(match kind {
        "user" => RenderedSessionEventKind::User,
        "assistant" => RenderedSessionEventKind::Assistant,
        "tool" | "tool_use" | "tool_result" | "function_call" | "function_call_output" => {
            RenderedSessionEventKind::Tool
        }
        "hook" => RenderedSessionEventKind::Hook,
        "reasoning" => RenderedSessionEventKind::Reasoning,
        "status" | "event_msg" | "turn_context" => RenderedSessionEventKind::Status,
        "error" => RenderedSessionEventKind::Error,
        _ => RenderedSessionEventKind::Unknown,
    })
}

fn event_kind_from_text(text: &str) -> RenderedSessionEventKind {
    if text.starts_with("[tool_use ")
        || text.starts_with("[function_call ")
        || text.starts_with("[function_call_output ")
    {
        RenderedSessionEventKind::Tool
    } else {
        RenderedSessionEventKind::Unknown
    }
}

#[cfg(test)]
#[path = "session_pages_tests.rs"]
mod tests;
