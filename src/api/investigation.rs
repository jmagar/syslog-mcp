use crate::surfaces::{get, post};
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderValue, header::CACHE_CONTROL},
    response::IntoResponse,
};

use super::{ApiState, CRATE_VERSION, respond};
use crate::app::{
    AppGraphEntityResponse, AppGraphEvidenceResponse, AskInvestigationRequest, GraphAroundRequest,
    GraphEntityLookupRequest, GraphEvidenceLookupRequest, GraphExplainRequest,
    GraphResponseMetadata, INVESTIGATION_UI_VERSION, InvestigationBudget, InvestigationBudgetUsed,
    InvestigationEnvelope, InvestigationMetadata, InvestigationVersionResponse, app_entity_summary,
    app_evidence_summary, app_graph_from_around_response, app_graph_from_explain_response,
    app_log_summary, app_relationship_summary,
};

pub fn routes() -> Router<ApiState> {
    use crate::surfaces::ContractRouterExt as _;
    Router::new()
        .contract_route("GET /api/v1/investigation/version", get(version))
        .contract_route("POST /api/v1/investigations/ask", post(ask))
        .contract_route("GET /api/v1/graph/entity", get(graph_entity))
        .contract_route("GET /api/v1/graph/around", get(graph_around))
        .contract_route("GET /api/v1/graph/explain", get(graph_explain))
        .contract_route("GET /api/v1/graph/evidence", get(graph_evidence))
}

pub async fn version() -> impl IntoResponse {
    no_store_json(Ok(InvestigationVersionResponse {
        ui_version: INVESTIGATION_UI_VERSION,
        schema_version: INVESTIGATION_UI_VERSION,
    }))
}

pub async fn ask(
    State(state): State<ApiState>,
    Json(req): Json<AskInvestigationRequest>,
) -> impl IntoResponse {
    no_store_json(state.service.investigation_ask(req).await)
}

pub async fn graph_entity(
    State(state): State<ApiState>,
    Query(q): Query<GraphEntityLookupRequest>,
) -> impl IntoResponse {
    let result = match state.service.graph_entity_lookup(q).await {
        Ok(response) => Ok(InvestigationEnvelope {
            metadata: metadata_from_graph(&response.metadata),
            result: AppGraphEntityResponse {
                resolved_entity: response.resolved_entity.as_ref().map(app_entity_summary),
                candidates: response
                    .candidates
                    .iter()
                    .map(|candidate| app_entity_summary(&candidate.entity))
                    .collect(),
            },
        }),
        Err(error) => Err(error),
    };
    no_store_json(result)
}

pub async fn graph_around(
    State(state): State<ApiState>,
    Query(q): Query<GraphAroundRequest>,
) -> impl IntoResponse {
    let result = match state.service.graph_around(q).await {
        Ok(response) => Ok(InvestigationEnvelope {
            metadata: metadata_from_graph(&response.metadata),
            result: app_graph_from_around_response(&response),
        }),
        Err(error) => Err(error),
    };
    no_store_json(result)
}

pub async fn graph_explain(
    State(state): State<ApiState>,
    Query(q): Query<GraphExplainRequest>,
) -> impl IntoResponse {
    let result = match state.service.graph_explain(q).await {
        Ok(response) => Ok(InvestigationEnvelope {
            metadata: metadata_from_graph(&response.metadata),
            result: app_graph_from_explain_response(&response),
        }),
        Err(error) => Err(error),
    };
    no_store_json(result)
}

pub async fn graph_evidence(
    State(state): State<ApiState>,
    Query(q): Query<GraphEvidenceLookupRequest>,
) -> impl IntoResponse {
    let result = match state.service.graph_evidence_lookup(q).await {
        Ok(response) => Ok(InvestigationEnvelope {
            metadata: metadata_from_graph(&response.metadata),
            result: AppGraphEvidenceResponse {
                evidence: app_evidence_summary(&response.evidence),
                relationship: app_relationship_summary(&response.relationship),
                source_log_summary: response
                    .source_log_summary
                    .as_ref()
                    .map(log_summary_from_graph_source),
                missing_source_reason: response.missing_source_reason,
            },
        }),
        Err(error) => Err(error),
    };
    no_store_json(result)
}

fn no_store_json<T: serde::Serialize>(
    result: crate::app::ServiceResult<T>,
) -> axum::response::Response {
    let mut response = respond(result);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn metadata_from_graph(metadata: &GraphResponseMetadata) -> InvestigationMetadata {
    let budget = InvestigationBudget {
        max_graph_calls: 1,
        max_log_rows: 0,
        max_evidence_rows: metadata.evidence_sample_limit,
        max_candidate_explanations: metadata.limit,
        max_wall_time_ms: 2_000,
        max_payload_bytes: metadata.payload_budget,
    };
    InvestigationMetadata {
        server_version: CRATE_VERSION.to_string(),
        schema_version: INVESTIGATION_UI_VERSION.to_string(),
        graph_projection_status: Some(metadata.projection_status.clone()),
        source_watermark: Some(metadata.source_watermark.clone()),
        degraded_reasons: metadata.last_error.clone().into_iter().collect(),
        truncated: metadata.truncated,
        truncation_reasons: metadata.truncated_reason.clone().into_iter().collect(),
        partial: metadata.truncated,
        partial_reasons: metadata
            .truncated
            .then(|| "graph_response_truncated".to_string())
            .into_iter()
            .collect(),
        auth_state: "bearer".to_string(),
        budget,
        budget_used: InvestigationBudgetUsed {
            graph_calls: 1,
            evidence_rows: metadata.evidence_sample_limit,
            candidate_explanations: metadata.limit,
            payload_bytes: metadata.payload_budget,
            ..Default::default()
        },
        payload_limit_bytes: metadata.payload_budget,
        version_skew: None,
    }
}

fn log_summary_from_graph_source(
    log: &crate::app::GraphSourceLogSummary,
) -> crate::app::AppLogSummary {
    app_log_summary(
        &crate::app::LogEntry {
            id: log.id,
            timestamp: log.timestamp.clone(),
            hostname: log.hostname.clone(),
            facility: None,
            severity: log.severity.clone(),
            app_name: log.app_name.clone(),
            process_id: log.process_id.clone(),
            message: log.message.clone(),
            received_at: log.received_at.clone(),
            source_ip: log.source_ip.clone(),
            ai_tool: None,
            ai_project: None,
            ai_session_id: None,
            ai_transcript_path: None,
            metadata_json: None,
        },
        500,
    )
}
