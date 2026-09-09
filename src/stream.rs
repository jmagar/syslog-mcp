use std::{collections::VecDeque, convert::Infallible, sync::OnceLock, time::Duration};

use axum::response::sse::{Event, KeepAlive, Sse};
use chrono::Utc;
use hmac::{Hmac, Mac};
use lab_auth::AuthContext;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{app::CortexService, db};

pub const MAX_BATCH_ITEMS: u32 = 100;
pub const MAX_BATCH_BYTES: usize = 128 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const CURSOR_TTL_SECS: i64 = 900;
const CURSOR_CLOCK_SKEW_SECS: i64 = 30;
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_CLIENTS: usize = 64;
const MAX_CONNECTION_DURATION: Duration = Duration::from_secs(15 * 60);
static CLIENTS: OnceLock<std::sync::Arc<Semaphore>> = OnceLock::new();

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

/// A resumable historical + live evidence stream scoped to a Git branch or
/// absolute worktree path projected by Agent Observatory.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStreamRequest {
    pub branch: Option<String>,
    pub worktree: Option<String>,
    #[serde(default)]
    pub kinds: Vec<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    #[serde(default)]
    pub include_payload: bool,
    pub history_limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StreamCursor {
    version: u8,
    position: i64,
    principal: String,
    filters: String,
    issued_at: i64,
    signature: String,
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

fn history_is_truncated(returned: usize, limit: usize, position: i64, high: i64) -> bool {
    returned >= limit && position < high
}

pub async fn log_stream(
    service: CortexService,
    auth: AuthContext,
    request: LogStreamRequest,
    cursor_keys: CursorKeys,
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
        },
    )
    .await
}

pub async fn evidence_stream(
    service: CortexService,
    auth: AuthContext,
    request: EvidenceStreamRequest,
    cursor_keys: CursorKeys,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, StreamError> {
    require_read_scope(&auth)?;
    if request.branch.as_deref().is_none_or(str::is_empty)
        && request.worktree.as_deref().is_none_or(str::is_empty)
    {
        return Err(StreamError::Invalid("branch or worktree is required"));
    }
    if request.branch.as_ref().is_some_and(|v| v.len() > 512)
        || request.worktree.as_ref().is_some_and(|v| v.len() > 4096)
        || request.kinds.len() > 32
    {
        return Err(StreamError::Invalid(
            "evidence stream filters exceed bounds",
        ));
    }
    let mut bound = request.clone();
    bound.cursor = None;
    let filters = fingerprint(&bound)?;
    let principal = principal_key(&auth);
    let decoded = request
        .cursor
        .as_deref()
        .map(|value| decode_cursor_with_keys(value, &cursor_keys))
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
    let permit = CLIENTS
        .get_or_init(|| std::sync::Arc::new(Semaphore::new(MAX_CLIENTS)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| StreamError::Overloaded)?;
    let issued_at = decoded
        .as_ref()
        .map_or_else(|| Utc::now().timestamp(), |c| c.issued_at);
    let start = decoded.as_ref().map_or(0, |c| c.position);
    let history_limit = request.history_limit.unwrap_or(500).clamp(1, 500);
    let query = crate::db::agent_observatory::EvidenceScopeQuery {
        branch: request.branch,
        worktree: request.worktree,
        kinds: request.kinds,
        since: request.since,
        until: request.until,
        include_payload: request.include_payload,
    };
    let initial = service
        .scoped_evidence(query.clone(), start, history_limit)
        .await
        .map_err(StreamError::Service)?;
    if decoded.is_some()
        && initial
            .minimum_watermark
            .is_some_and(|minimum| start < minimum.saturating_sub(1))
    {
        return Err(StreamError::Gap {
            minimum: initial.minimum_watermark.unwrap(),
            requested: start,
        });
    }
    let deadline = tokio::time::Instant::now() + MAX_CONNECTION_DURATION;
    let lease = client_lease(permit, MAX_CONNECTION_DURATION);
    let stream = async_stream::stream! {
        let _lease = lease;
        let mut position = start;
        let snapshot_high = initial.high_watermark;
        let cursor = encode_cursor_with_keys(position, &principal, &filters, issued_at, &cursor_keys);
        yield Ok(Event::default().event("snapshot").data(serde_json::json!({
            "kind":"snapshot","scope":{"branch":query.branch,"worktree":query.worktree},
            "highWatermark":snapshot_high,"historicalCount":initial.items.len(),"cursor":cursor
        }).to_string()));
        let initial_count = initial.items.len();
        for row in initial.items {
            position = row.id;
            let cursor = encode_cursor_with_keys(position, &principal, &filters, issued_at, &cursor_keys);
            yield Ok(Event::default().event("evidence").id(cursor).data(scoped_event_json(&row)));
        }
        if history_is_truncated(initial_count, history_limit, position, snapshot_high) {
            yield Ok(control_event("history_truncated", serde_json::json!({
                "resync":true,"returnedThrough":position,"snapshotHigh":snapshot_high,
                "instruction":"request bounded historical pages before following live events"
            })));
            position = snapshot_high;
        }
        loop {
            if tokio::time::Instant::now() >= deadline { break; }
            if Utc::now().timestamp() - issued_at > CURSOR_TTL_SECS {
                yield Ok(control_event("token_expired", serde_json::json!({"resync":true}))); break;
            }
            match service.scoped_evidence(query.clone(), position, 100).await {
                Ok(page) => {
                    if page.items.is_empty() {
                        tokio::select! { _ = tokio::time::sleep(POLL_INTERVAL) => {}, _ = tokio::time::sleep_until(deadline) => break }
                    } else {
                        for row in page.items {
                            position = row.id;
                            let cursor = encode_cursor_with_keys(position, &principal, &filters, issued_at, &cursor_keys);
                            yield Ok(Event::default().event("evidence").id(cursor).data(scoped_event_json(&row)));
                        }
                    }
                }
                Err(_) => { yield Ok(control_event("overload", serde_json::json!({"retryAfterMs":1000,"resync":false}))); break; }
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keepalive"),
    ))
}

fn scoped_event_json(row: &crate::db::agent_observatory::ObservatoryEventRow) -> String {
    let mut value = serde_json::to_value(row).unwrap_or_else(|_| serde_json::json!({"id":row.id}));
    // `payload_json` is JSON encoded inside a string. Redact its leaf values
    // before the outer tree walk so quoting cannot hide secret prefixes.
    if let Some(payload) = value.get_mut("payload_json")
        && let Some(encoded) = payload.as_str()
        && let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(encoded)
    {
        crate::assessment::redact_json_value_strings(&mut parsed);
        *payload = serde_json::Value::String(parsed.to_string());
    }
    crate::assessment::redact_json_value_strings(&mut value);
    serde_json::json!({"contractVersion":"1.0.0","kind":"evidence","event":value}).to_string()
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
    let client_permit = CLIENTS
        .get_or_init(|| std::sync::Arc::new(Semaphore::new(MAX_CLIENTS)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| StreamError::Overloaded)?;
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

fn principal_key(auth: &AuthContext) -> String {
    format!("{}:{}", auth.issuer, auth.sub)
}
fn fingerprint<T: Serialize>(value: &T) -> Result<String, StreamError> {
    let bytes = serde_json::to_vec(value).map_err(|_| StreamError::Invalid("invalid filters"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn cursor_mac(
    position: i64,
    principal: &str,
    filters: &str,
    issued_at: i64,
    key: &[u8],
) -> Hmac<Sha256> {
    let body = format!("1\0{position}\0{principal}\0{filters}\0{issued_at}");
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(body.as_bytes());
    mac
}
fn cursor_signature(
    position: i64,
    principal: &str,
    filters: &str,
    issued_at: i64,
    key: &[u8],
) -> String {
    hex::encode(
        cursor_mac(position, principal, filters, issued_at, key)
            .finalize()
            .into_bytes(),
    )
}
pub(crate) fn encode_cursor_with_keys(
    position: i64,
    principal: &str,
    filters: &str,
    issued_at: i64,
    keys: &CursorKeys,
) -> String {
    let cursor = StreamCursor {
        version: 1,
        position,
        principal: principal.into(),
        filters: filters.into(),
        issued_at,
        signature: cursor_signature(position, principal, filters, issued_at, &keys.current),
    };
    hex::encode(serde_json::to_vec(&cursor).expect("cursor is serializable"))
}
fn decode_cursor_with_keys(value: &str, keys: &CursorKeys) -> Result<StreamCursor, StreamError> {
    if value.len() > 2048 {
        return Err(StreamError::Invalid("invalid cursor"));
    }
    let bytes = hex::decode(value).map_err(|_| StreamError::Invalid("invalid cursor"))?;
    let cursor: StreamCursor =
        serde_json::from_slice(&bytes).map_err(|_| StreamError::Invalid("invalid cursor"))?;
    if cursor.version != 1 || cursor.position < 0 {
        return Err(StreamError::Invalid("invalid cursor"));
    }
    let tag = hex::decode(&cursor.signature)
        .map_err(|_| StreamError::Invalid("cursor signature is invalid"))?;
    if tag.len() != 32 {
        return Err(StreamError::Invalid("cursor signature is invalid"));
    }
    let mut signature_ok = cursor_mac(
        cursor.position,
        &cursor.principal,
        &cursor.filters,
        cursor.issued_at,
        &keys.current,
    )
    .verify_slice(&tag)
    .is_ok();
    for key in keys.previous.iter() {
        signature_ok |= cursor_mac(
            cursor.position,
            &cursor.principal,
            &cursor.filters,
            cursor.issued_at,
            key,
        )
        .verify_slice(&tag)
        .is_ok();
    }
    if !signature_ok {
        return Err(StreamError::Invalid("cursor signature is invalid"));
    }
    Ok(cursor)
}

#[cfg(test)]
fn test_cursor_keys() -> CursorKeys {
    CursorKeys::resolved(Some("test-only-cursor-key"), &[], true).unwrap()
}

#[cfg(test)]
fn encode_cursor(position: i64, principal: &str, filters: &str, issued_at: i64) -> String {
    encode_cursor_with_keys(position, principal, filters, issued_at, &test_cursor_keys())
}

#[cfg(test)]
fn decode_cursor(value: &str) -> Result<StreamCursor, StreamError> {
    decode_cursor_with_keys(value, &test_cursor_keys())
}

pub(crate) fn session_filter_fingerprint(
    project: &str,
    tool: &str,
    session_id: &str,
    host: &str,
) -> Result<String, StreamError> {
    fingerprint(&SessionStreamRequest {
        project: project.into(),
        tool: tool.into(),
        session_id: session_id.into(),
        host: host.into(),
        cursor: None,
    })
}

pub(crate) fn principal(auth: &AuthContext) -> String {
    principal_key(auth)
}
pub(crate) fn decode_session_handoff(
    value: &str,
    auth: &AuthContext,
    project: &str,
    tool: &str,
    session_id: &str,
    host: &str,
    keys: &CursorKeys,
) -> Result<i64, StreamError> {
    let cursor = decode_cursor_with_keys(value, keys)?;
    if cursor.principal != principal_key(auth) {
        return Err(StreamError::Forbidden(
            "cursor belongs to another principal",
        ));
    }
    if cursor.filters != session_filter_fingerprint(project, tool, session_id, host)? {
        return Err(StreamError::Invalid(
            "cursor does not match session filters",
        ));
    }
    let age = Utc::now().timestamp() - cursor.issued_at;
    if !(-CURSOR_CLOCK_SKEW_SECS..=CURSOR_TTL_SECS).contains(&age) {
        return Err(StreamError::Expired);
    }
    Ok(cursor.position)
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
