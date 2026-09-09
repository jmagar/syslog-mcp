use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "request", rename_all = "snake_case")]
pub enum AnalysisRequest {
    Errors(GetErrorsRequest),
    Incident(IncidentRequest),
    SimilarIncidents(SimilarIncidentsRequest),
    RecurringErrorComparison(RecurringErrorComparisonRequest),
    IncidentContext(IncidentContextRequest),
    Patterns(PatternsRequest),
    Anomalies(AnomaliesRequest),
    Compare(CompareRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "response", rename_all = "snake_case")]
pub enum AnalysisResponse {
    Errors(GetErrorsResponse),
    Incident(IncidentResponse),
    SimilarIncidents(SimilarIncidentsResponse),
    RecurringErrorComparison(RecurringErrorComparisonResponse),
    IncidentContext(IncidentContextResponse),
    Patterns(PatternsResponse),
    Anomalies(AnomaliesResponse),
    Compare(CompareResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "request", rename_all = "snake_case")]
pub enum CorrelateRequest {
    Events(CorrelateEventsRequest),
    State(CorrelateStateRequest),
    Topic(TopicCorrelateRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "response", rename_all = "snake_case")]
pub enum CorrelateResponse {
    Events(CorrelateEventsResponse),
    State(CorrelateStateResponse),
    Topic(TopicCorrelateResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "request", rename_all = "snake_case")]
pub enum StateRequest {
    Host(HostStateRequest),
    Fleet(FleetStateRequest),
    ClockSkew(ClockSkewRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "response", rename_all = "snake_case")]
pub enum StateResponse {
    Host(Box<HostStateResponse>),
    Fleet(FleetStateResponse),
    ClockSkew(ClockSkewResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "request", rename_all = "snake_case")]
pub enum StatsRequest {
    Summary,
    IngestRate(IngestRateRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "response", rename_all = "snake_case")]
pub enum StatsResponse {
    Summary(DbStats),
    IngestRate(IngestRateResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "request", rename_all = "snake_case")]
pub enum IngestRequest {
    FileTails(FileTailRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "response", rename_all = "snake_case")]
pub enum IngestResponse {
    FileTails(FileTailResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "request", rename_all = "snake_case")]
pub enum AlertsRequest {
    UnaddressedErrors(UnaddressedErrorsRequest),
    AckError {
        request: AckErrorRequest,
        actor: RequestActor,
    },
    UnackError {
        request: UnackErrorRequest,
        actor: RequestActor,
    },
    NotificationsRecent(NotificationsRecentRequest),
    NotificationsTest {
        body: String,
        actor: RequestActor,
        config: crate::config::NotificationsConfig,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", content = "response", rename_all = "snake_case")]
pub enum AlertsResponse {
    UnaddressedErrors(UnaddressedErrorsResponse),
    AckError(AckErrorResponse),
    UnackError(UnackErrorResponse),
    NotificationsRecent(Vec<crate::db::notifications::FiringRow>),
    NotificationsTest(String),
}
