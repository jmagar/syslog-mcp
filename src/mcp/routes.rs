use std::time::Instant;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware,
    response::{
        sse::{Event, Sse},
        IntoResponse, Json,
    },
    routing::{get, post},
    Router,
};
use futures_core::Stream;
use serde_json::json;
use subtle::ConstantTimeEq;
use tower_http::cors::{Any, CorsLayer};

use super::protocol::{dispatch, DispatchResult, JsonRpcRequest};
use super::AppState;

/// Build the MCP router
pub fn router(state: AppState) -> Router {
    // Authenticated routes: /mcp and /sse require Bearer token when api_token is set
    let authenticated = Router::new()
        .route("/mcp", post(handle_mcp_post))
        .route("/sse", get(handle_sse))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Unauthenticated routes: /health must be accessible without credentials
    // so Docker HEALTHCHECK, docker-compose health probes, and SWAG can reach it
    let unauthenticated = Router::new().route("/health", get(health));

    Router::new()
        .merge(authenticated)
        .merge(unauthenticated)
        .fallback(|| async { (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))) })
        .layer(DefaultBodyLimit::max(65_536))
        .layer(cors_layer(state.config.port))
        .with_state(state)
}

/// Bearer-token authentication middleware.
///
/// When `config.api_token` is `Some(token)`, every request must carry:
///   `Authorization: Bearer <token>`
/// Requests with a missing or incorrect token receive HTTP 401.
/// When `api_token` is `None` (the default), all requests pass through unchanged.
async fn require_auth(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    if let Some(ref expected) = state.config.api_token {
        let auth = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let authorized = auth
            .and_then(bearer_token)
            .map(|token| token_matches(token, expected))
            .unwrap_or(false);
        if !authorized {
            tracing::warn!(
                method = %method,
                path = %path,
                has_auth_header = auth.is_some(),
                "Unauthorized MCP request rejected"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {"code": -32001, "message": "unauthorized"}
                })),
            )
                .into_response();
        }
    }
    next.run(req).await
}

fn cors_layer(port: u16) -> CorsLayer {
    CorsLayer::new()
        .allow_origin([
            format!("http://localhost:{port}")
                .parse::<axum::http::HeaderValue>()
                .expect("valid localhost origin"),
            format!("http://127.0.0.1:{port}")
                .parse::<axum::http::HeaderValue>()
                .expect("valid 127.0.0.1 origin"),
        ])
        .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
        .allow_headers(Any)
}

fn bearer_token(auth: &str) -> Option<&str> {
    let mut parts = auth.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    if parts.next().is_some() || !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    Some(token)
}

fn token_matches(provided: &str, expected: &str) -> bool {
    const MAX_TOKEN_LEN: usize = 4096;
    if provided.len() > MAX_TOKEN_LEN || expected.len() > MAX_TOKEN_LEN {
        return false;
    }

    let mut provided_buf = [0_u8; MAX_TOKEN_LEN];
    let mut expected_buf = [0_u8; MAX_TOKEN_LEN];
    provided_buf[..provided.len()].copy_from_slice(provided.as_bytes());
    expected_buf[..expected.len()].copy_from_slice(expected.as_bytes());

    let bytes_match = provided_buf.ct_eq(&expected_buf).unwrap_u8() == 1;
    let lengths_match = (provided.len() as u64)
        .ct_eq(&(expected.len() as u64))
        .unwrap_u8()
        == 1;
    bytes_match && lengths_match
}

/// Health check — lightweight probe that verifies DB connectivity without
/// running COUNT(*) over the entire logs table.
async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let started = Instant::now();
    match state.service.health_check().await {
        Ok(()) => {
            tracing::debug!(
                elapsed_ms = started.elapsed().as_millis(),
                "Health check passed"
            );
            Json(json!({ "status": "ok" })).into_response()
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                elapsed_ms = started.elapsed().as_millis(),
                "Health check failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "status": "error", "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// Streamable HTTP transport (POST /mcp)
pub(super) async fn handle_mcp_post(
    State(state): State<AppState>,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    match dispatch(&state, &req).await {
        DispatchResult::Response(response) => Json(response).into_response(),
        // JSON-RPC notifications must not produce a response body.
        DispatchResult::Notification => StatusCode::ACCEPTED.into_response(),
    }
}

/// SSE endpoint for MCP (legacy transport support)
async fn handle_sse(
    State(_state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = tokio_stream::once(Ok(Event::default().event("endpoint").data("/mcp")));
    Sse::new(stream)
}

#[cfg(test)]
#[path = "routes_tests.rs"]
mod tests;
