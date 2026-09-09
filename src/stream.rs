use std::{collections::VecDeque, convert::Infallible, sync::OnceLock, time::Duration};

use axum::response::sse::{Event, KeepAlive, Sse};
use chrono::Utc;
use lab_auth::AuthContext;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{app::CortexService, db};

mod cursor;
#[cfg(test)]
use cursor::{StreamCursor, decode_cursor, encode_cursor, test_cursor_keys};
use cursor::{decode_cursor_with_keys, fingerprint, principal_key};
pub(crate) use cursor::{
    decode_session_handoff, encode_cursor_with_keys, principal, session_filter_fingerprint,
};

pub const MAX_BATCH_ITEMS: u32 = 100;
pub const MAX_BATCH_BYTES: usize = 128 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const CURSOR_TTL_SECS: i64 = 900;
const CURSOR_CLOCK_SKEW_SECS: i64 = 30;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_CLIENTS: usize = 64;
const MAX_CONNECTION_DURATION: Duration = Duration::from_secs(15 * 60);
static CLIENTS: OnceLock<std::sync::Arc<Semaphore>> = OnceLock::new();

pub(crate) fn shared_client_permits() -> std::sync::Arc<Semaphore> {
    CLIENTS
        .get_or_init(|| std::sync::Arc::new(Semaphore::new(MAX_CLIENTS)))
        .clone()
}

fn acquire_client_permit(
    clients: std::sync::Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, StreamError> {
    clients
        .try_acquire_owned()
        .map_err(|_| StreamError::Overloaded)
}

#[derive(Clone)]
pub struct CursorKeys {
    current: std::sync::Arc<[u8]>,
    previous: std::sync::Arc<Vec<Vec<u8>>>,
}

impl CursorKeys {
    pub fn resolved(
        current: Option<&str>,
        previous: &[String],
        loopback: bool,
    ) -> Result<Self, StreamError> {
        let current = match current.map(str::trim).filter(|key| !key.is_empty()) {
            Some(key) => key.as_bytes().to_vec(),
            None if loopback => {
                let mut key = vec![0_u8; 32];
                getrandom::fill(&mut key)
                    .map_err(|_| StreamError::Invalid("cursor key generation failed"))?;
                key
            }
            None => {
                return Err(StreamError::Invalid(
                    "non-loopback streams require a cursor signing key",
                ));
            }
        };
        let previous = previous
            .iter()
            .map(|key| key.trim())
            .filter(|key| !key.is_empty())
            .map(|key| key.as_bytes().to_vec())
            .collect();
        Ok(Self {
            current: current.into(),
            previous: std::sync::Arc::new(previous),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogStreamRequest {
    pub cursor: Option<String>,
    pub host: Option<String>,
    pub app: Option<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStreamRequest {
    pub project: String,
    pub tool: String,
    pub session_id: String,
    pub host: String,
    pub cursor: Option<String>,
}

struct StreamState {
    service: CortexService,
    params: db::DurableStreamParams,
    principal: String,
    filters: String,
    position: i64,
    snapshot_high: i64,
    pending: VecDeque<db::DurableStreamRow>,
    pending_bytes: usize,
    issued_at: i64,
    deadline: tokio::time::Instant,
    cursor_keys: CursorKeys,
    _client_lease: ClientLease,
}

struct StreamContract {
    event_name: &'static str,
    cursor_keys: CursorKeys,
    connection_duration: Duration,
    clients: std::sync::Arc<Semaphore>,
}

#[derive(Clone)]
struct ClientLease(std::sync::Arc<std::sync::Mutex<Option<OwnedSemaphorePermit>>>);

fn client_lease(permit: OwnedSemaphorePermit, duration: Duration) -> ClientLease {
    let lease = ClientLease(std::sync::Arc::new(std::sync::Mutex::new(Some(permit))));
    let expiry = std::sync::Arc::downgrade(&lease.0);
    tokio::spawn(async move {
        tokio::time::sleep(duration).await;
        if let Some(expiry) = expiry.upgrade() {
            let _ = expiry.lock().expect("client lease mutex poisoned").take();
        }
    });
    lease
}

pub async fn log_stream(
    service: CortexService,
    auth: AuthContext,
    request: LogStreamRequest,
    cursor_keys: CursorKeys,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, StreamError> {
    log_stream_with_clients(service, auth, request, cursor_keys, shared_client_permits()).await
}

pub(crate) async fn log_stream_with_clients(
    service: CortexService,
    auth: AuthContext,
    request: LogStreamRequest,
    cursor_keys: CursorKeys,
    clients: std::sync::Arc<Semaphore>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, StreamError> {
    let mut filter_request = request.clone();
    filter_request.cursor = None;
    let filters = fingerprint(&filter_request)?;
    let params = db::DurableStreamParams {
        hostname: request.host,
        app_name: request.app,
        severity: request.severity,
        limit: MAX_BATCH_ITEMS + 1,
        include_bounds: true,
        ..Default::default()
    };
    build_stream(
        service,
        auth,
        request.cursor,
        filters,
        params,
        StreamContract {
            event_name: "log",
            cursor_keys,
            connection_duration: MAX_CONNECTION_DURATION,
            clients,
        },
    )
    .await
}

pub async fn session_stream(
    service: CortexService,
    auth: AuthContext,
    request: SessionStreamRequest,
    cursor_keys: CursorKeys,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, StreamError> {
    for value in [
        &request.project,
        &request.tool,
        &request.session_id,
        &request.host,
    ] {
        if value.trim().is_empty() {
            return Err(StreamError::Invalid("session identity must not be empty"));
        }
    }
    let mut filter_request = request.clone();
    filter_request.cursor = None;
    let filters = fingerprint(&filter_request)?;
    let params = db::DurableStreamParams {
        hostname: Some(request.host),
        ai_project: Some(request.project),
        ai_tool: Some(request.tool),
        ai_session_id: Some(request.session_id),
        limit: MAX_BATCH_ITEMS + 1,
        include_bounds: true,
        ..Default::default()
    };
    build_stream(
        service,
        auth,
        request.cursor,
        filters,
        params,
        StreamContract {
            event_name: "session",
            cursor_keys,
            connection_duration: MAX_CONNECTION_DURATION,
            clients: shared_client_permits(),
        },
    )
    .await
}

async fn build_stream(
    service: CortexService,
    auth: AuthContext,
    cursor: Option<String>,
    filters: String,
    mut params: db::DurableStreamParams,
    contract: StreamContract,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, StreamError> {
    require_read_scope(&auth)?;
    let client_permit = acquire_client_permit(contract.clients.clone())?;
    let principal = principal_key(&auth);
    let decoded = cursor
        .as_deref()
        .map(|value| decode_cursor_with_keys(value, &contract.cursor_keys))
        .transpose()?;
    if let Some(cursor) = &decoded {
        if cursor.principal != principal {
            return Err(StreamError::Forbidden(
                "cursor belongs to another principal",
            ));
        }
        if cursor.filters != filters {
            return Err(StreamError::Invalid("cursor does not match stream filters"));
        }
        let age = Utc::now().timestamp() - cursor.issued_at;
        if !(-CURSOR_CLOCK_SKEW_SECS..=CURSOR_TTL_SECS).contains(&age) {
            return Err(StreamError::Expired);
        }
    }
    params.after_id = decoded.as_ref().map_or(0, |cursor| cursor.position);
    let initial = service
        .durable_stream_page(params.clone())
        .await
        .map_err(StreamError::Service)?;
    if decoded.is_some()
        && initial
            .minimum_watermark
            .is_some_and(|minimum| params.after_id < minimum.saturating_sub(1))
    {
        return Err(StreamError::Gap {
            minimum: initial.minimum_watermark.unwrap(),
            requested: params.after_id,
        });
    }
    let position = decoded
        .as_ref()
        .map_or(initial.high_watermark, |cursor| cursor.position);
    let issued_at = decoded
        .as_ref()
        .map_or_else(|| Utc::now().timestamp(), |cursor| cursor.issued_at);
    let state = StreamState {
        service,
        params,
        principal,
        filters,
        position,
        snapshot_high: initial.high_watermark,
        pending: VecDeque::new(),
        pending_bytes: 0,
        issued_at,
        deadline: tokio::time::Instant::now() + contract.connection_duration,
        cursor_keys: contract.cursor_keys,
        _client_lease: client_lease(client_permit, contract.connection_duration),
    };
    let stream = async_stream::stream! {
        let mut state = state;
        let snapshot = serde_json::json!({"kind":"snapshot","highWatermark":state.snapshot_high,
            "cursor": encode_cursor_with_keys(state.position, &state.principal, &state.filters, state.issued_at, &state.cursor_keys)});
        yield Ok(Event::default().event("snapshot").data(snapshot.to_string()));
        loop {
            if tokio::time::Instant::now() >= state.deadline { break; }
            if Utc::now().timestamp() - state.issued_at > CURSOR_TTL_SECS {
                yield Ok(control_event("token_expired", serde_json::json!({"resync":true})));
                break;
            }
            if let Some(row) = state.pending.pop_front() {
                let data = row_json(&row, contract.event_name);
                let size = data.len();
                state.pending_bytes = state.pending_bytes.saturating_sub(size);
                state.position = row.id;
                let cursor = encode_cursor_with_keys(state.position, &state.principal, &state.filters, state.issued_at, &state.cursor_keys);
                yield Ok(Event::default().event(contract.event_name).id(cursor).data(data));
                continue;
            }
            state.params.after_id = state.position;
            state.params.high_watermark = None;
            state.params.include_bounds = false;
            match state.service.durable_stream_page(state.params.clone()).await {
                Ok(page) => {
                    let mut bytes = 0usize;
                    for row in page.rows.into_iter().take(MAX_BATCH_ITEMS as usize) {
                        let data = row_json(&row, contract.event_name);
                        let cursor = encode_cursor_with_keys(row.id, &state.principal, &state.filters, state.issued_at, &state.cursor_keys);
                        let size = data.len() + cursor.len() + contract.event_name.len() + 24;
                        if !state.pending.is_empty() && bytes.saturating_add(size) > MAX_BATCH_BYTES { break; }
                        bytes = bytes.saturating_add(size);
                        state.pending.push_back(row);
                    }
                    state.pending_bytes = bytes;
                    if state.pending.is_empty() {
                        tokio::select! { _ = tokio::time::sleep(POLL_INTERVAL) => {}, _ = tokio::time::sleep_until(state.deadline) => break }
                    }
                }
                Err(_) => {
                    yield Ok(control_event("overload", serde_json::json!({"retryAfterMs":1000,"resync":false})));
                    break;
                }
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keepalive"),
    ))
}

fn row_json(row: &db::DurableStreamRow, kind: &str) -> String {
    let pattern_scrubbed = crate::receiver::enrichment::scrub_ai_message(&row.message, None);
    let scrubbed = crate::assessment::redact_secrets(&pattern_scrubbed);
    let mut was_redacted = pattern_scrubbed != row.message || scrubbed != pattern_scrubbed;
    let mut metadata: Option<serde_json::Value> = row
        .metadata_json
        .as_deref()
        .and_then(|v| serde_json::from_str(v).ok());
    if let Some(value) = &mut metadata {
        let before = value.clone();
        crate::assessment::redact_json_value_strings(value);
        was_redacted |= *value != before;
    }
    let mut warning = row
        .parse_error
        .as_deref()
        .map(crate::assessment::redact_secrets);
    was_redacted |= warning.as_deref() != row.parse_error.as_deref();
    let mut budget = MAX_EVENT_BYTES;
    loop {
        let (message, truncated) = truncate_utf8(&scrubbed, budget);
        let value = serde_json::json!({"contractVersion":"1.0.0","kind":kind,"position":row.id,
        "timestamp":row.timestamp,"host":row.hostname,"severity":row.severity,
        "app":row.app_name,"message":message,"metadata":metadata,
        "parseWarning":warning,"redacted":was_redacted,"truncated":truncated});
        let serialized = value.to_string();
        if serialized.len() <= MAX_EVENT_BYTES {
            return serialized;
        }
        if budget == 0 {
            warning = Some("event fields exceeded serialized byte bound".into());
            return serde_json::json!({"contractVersion":"1.0.0","kind":kind,"position":row.id,"message":"","parseWarning":warning,"redacted":was_redacted,"truncated":true}).to_string();
        }
        budget = budget.saturating_sub(serialized.len() - MAX_EVENT_BYTES + 32);
    }
}

fn control_event(kind: &'static str, data: serde_json::Value) -> Event {
    Event::default().event(kind).data(data.to_string())
}

fn require_read_scope(auth: &AuthContext) -> Result<(), StreamError> {
    if auth
        .scopes
        .iter()
        .any(|scope| scope == "cortex:read" || scope == "cortex:admin")
    {
        Ok(())
    } else {
        Err(StreamError::Forbidden("cortex:read scope required"))
    }
}

fn truncate_utf8(value: &str, max: usize) -> (String, bool) {
    if value.len() <= max {
        return (value.to_owned(), false);
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}...[truncated]", &value[..end]), true)
}

#[derive(Debug)]
pub enum StreamError {
    Invalid(&'static str),
    Forbidden(&'static str),
    Expired,
    Overloaded,
    Gap { minimum: i64, requested: i64 },
    Service(crate::app::ServiceError),
}

impl axum::response::IntoResponse for StreamError {
    fn into_response(self) -> axum::response::Response {
        use axum::{Json, http::StatusCode};
        let (status, body) = match self {
            Self::Invalid(message) => (
                StatusCode::BAD_REQUEST,
                serde_json::json!({"error":"invalid_cursor","message":message}),
            ),
            Self::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                serde_json::json!({"error":"forbidden","message":message}),
            ),
            Self::Expired => (
                StatusCode::GONE,
                serde_json::json!({"error":"cursor_expired","resync":true}),
            ),
            Self::Overloaded => (
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({"error":"stream_capacity_exhausted","retryAfterMs":1000}),
            ),
            Self::Gap { minimum, requested } => (
                StatusCode::GONE,
                serde_json::json!({"error":"retention_gap","minimumWatermark":minimum,"requestedWatermark":requested,"resync":true}),
            ),
            Self::Service(error) => (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"error":"stream_unavailable","message":error.to_string()}),
            ),
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
