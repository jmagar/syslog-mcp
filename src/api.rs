use axum::{
    extract::{Query, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::app::{
    CorrelateEventsRequest, GetErrorsRequest, LogService, SearchLogsRequest, TailLogsRequest,
};
use crate::config::ApiConfig;

#[derive(Clone)]
pub struct ApiState {
    pub service: LogService,
    pub config: ApiConfig,
}

pub fn router(state: ApiState) -> anyhow::Result<Router> {
    if state.config.enabled && state.config.api_token.is_none() {
        anyhow::bail!("non-MCP API requires SYSLOG_API_TOKEN when enabled");
    }
    let routes = Router::new()
        .route("/api/search", get(search))
        .route("/api/tail", get(tail))
        .route("/api/errors", get(errors))
        .route("/api/hosts", get(hosts))
        .route("/api/correlate", get(correlate))
        .route("/api/stats", get(stats))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state);
    Ok(routes)
}

async fn require_auth(
    State(state): State<ApiState>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let Some(expected) = state.config.api_token.as_deref() else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "api_token_required"})),
        )
            .into_response();
    };
    let auth = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let provided = auth.and_then(|v| v.strip_prefix("Bearer "));
    let authorized = provided
        .map(|token| token.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1)
        .unwrap_or(false);
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    next.run(req).await
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    query: Option<String>,
    hostname: Option<String>,
    source_ip: Option<String>,
    severity: Option<String>,
    app_name: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<u32>,
}

async fn search(
    State(state): State<ApiState>,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .search_logs(SearchLogsRequest {
                query: query.query,
                hostname: query.hostname,
                source_ip: query.source_ip,
                severity: query.severity,
                app_name: query.app_name,
                from: query.from,
                to: query.to,
                limit: query.limit,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
struct TailQuery {
    hostname: Option<String>,
    source_ip: Option<String>,
    app_name: Option<String>,
    n: Option<u32>,
}

async fn tail(State(state): State<ApiState>, Query(query): Query<TailQuery>) -> impl IntoResponse {
    respond(
        state
            .service
            .tail_logs(TailLogsRequest {
                hostname: query.hostname,
                source_ip: query.source_ip,
                app_name: query.app_name,
                n: query.n,
            })
            .await,
    )
}

#[derive(Debug, Deserialize)]
struct ErrorQuery {
    from: Option<String>,
    to: Option<String>,
}

async fn errors(
    State(state): State<ApiState>,
    Query(query): Query<ErrorQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .get_errors(GetErrorsRequest {
                from: query.from,
                to: query.to,
            })
            .await,
    )
}

async fn hosts(State(state): State<ApiState>) -> impl IntoResponse {
    respond(state.service.list_hosts().await)
}

#[derive(Debug, Deserialize)]
struct CorrelateQuery {
    reference_time: String,
    window_minutes: Option<u32>,
    severity_min: Option<String>,
    hostname: Option<String>,
    source_ip: Option<String>,
    query: Option<String>,
    limit: Option<u32>,
}

async fn correlate(
    State(state): State<ApiState>,
    Query(query): Query<CorrelateQuery>,
) -> impl IntoResponse {
    respond(
        state
            .service
            .correlate_events(CorrelateEventsRequest {
                reference_time: query.reference_time,
                window_minutes: query.window_minutes,
                severity_min: query.severity_min,
                hostname: query.hostname,
                source_ip: query.source_ip,
                query: query.query,
                limit: query.limit,
            })
            .await,
    )
}

async fn stats(State(state): State<ApiState>) -> impl IntoResponse {
    respond(state.service.get_stats().await)
}

fn respond<T: serde::Serialize>(result: crate::app::ServiceResult<T>) -> axum::response::Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(crate::app::ServiceError::InvalidInput(msg)) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
        Err(crate::app::ServiceError::Busy(msg)) => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": msg}))).into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
