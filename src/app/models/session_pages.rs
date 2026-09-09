use super::*;

pub const RENDERED_SESSION_PAGE_MAX_ITEMS: u32 = 200;
pub const RENDERED_SESSION_PAGE_MAX_BYTES: usize = 256 * 1024;
pub const RENDERED_SESSION_POLL_AFTER_MS: u32 = 2_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedSessionPageRequest {
    pub project: String,
    pub tool: String,
    pub session_id: String,
    pub host: String,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderedSessionEventKind {
    User,
    Assistant,
    Tool,
    Hook,
    Reasoning,
    Status,
    Error,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedSessionEvent {
    pub position: i64,
    pub timestamp: String,
    pub kind: RenderedSessionEventKind,
    pub text: String,
    pub redacted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedSessionPageResponse {
    pub contract_version: &'static str,
    pub delivery: &'static str,
    pub events: Vec<RenderedSessionEvent>,
    pub next_cursor: String,
    pub high_watermark: i64,
    pub has_more: bool,
    pub truncated_by_bytes: bool,
    pub limit_clamped_to: Option<u32>,
    pub poll_after_ms: u32,
    pub max_page_items: u32,
    pub max_page_bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CortexCapabilities {
    pub contract_version: &'static str,
    pub generation: u32,
    pub sessions: SessionCapabilities,
    pub logs: LogCapabilities,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionCapabilities {
    pub rendered_pages: bool,
    pub polling: PollingCapability,
    pub native_stream: bool,
    pub stream: Option<StreamCapability>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogCapabilities {
    pub polling: bool,
    pub native_stream: bool,
    pub stream: Option<StreamCapability>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PollingCapability {
    pub cursor: &'static str,
    pub ordering: &'static str,
    pub max_page_items: u32,
    pub max_page_bytes: usize,
    pub poll_after_ms: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamCapability {
    pub cursor: &'static str,
    pub ordering: &'static str,
    pub max_batch_items: u32,
    pub max_batch_bytes: usize,
    pub reconnect_budget_ms: u32,
}

pub fn capabilities() -> CortexCapabilities {
    CortexCapabilities {
        contract_version: "1.0.0",
        generation: 1,
        sessions: SessionCapabilities {
            rendered_pages: true,
            polling: PollingCapability {
                cursor: "durable_log_row_id",
                ordering: "position_ascending",
                max_page_items: RENDERED_SESSION_PAGE_MAX_ITEMS,
                max_page_bytes: RENDERED_SESSION_PAGE_MAX_BYTES,
                poll_after_ms: RENDERED_SESSION_POLL_AFTER_MS,
            },
            native_stream: true,
            stream: Some(stream_capability()),
        },
        logs: LogCapabilities {
            polling: true,
            native_stream: true,
            stream: Some(stream_capability()),
        },
    }
}

fn stream_capability() -> StreamCapability {
    StreamCapability {
        cursor: "principal_and_filter_bound_durable_log_row_id",
        ordering: "position_ascending",
        max_batch_items: 100,
        max_batch_bytes: 128 * 1024,
        reconnect_budget_ms: 5_000,
    }
}
