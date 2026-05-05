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
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "http://localhost:3100"
                        .parse::<axum::http::HeaderValue>()
                        .expect("valid localhost origin"),
                    "http://127.0.0.1:3100"
                        .parse::<axum::http::HeaderValue>()
                        .expect("valid 127.0.0.1 origin"),
                ])
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers(Any),
        )
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
        let provided = auth.and_then(|v| v.strip_prefix("Bearer "));
        let authorized = match provided {
            Some(token) => token.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1,
            None => false,
        };
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
