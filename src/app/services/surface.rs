use crate::app::models::{
    AlertsRequest, AlertsResponse, AnalysisRequest, AnalysisResponse, CorrelateRequest,
    CorrelateResponse, IngestRequest, IngestResponse, StateRequest, StateResponse, StatsRequest,
    StatsResponse,
};

use super::*;

impl CortexService {
    pub async fn analysis(&self, req: AnalysisRequest) -> ServiceResult<AnalysisResponse> {
        match req {
            AnalysisRequest::Errors(req) => {
                self.get_errors(req).await.map(AnalysisResponse::Errors)
            }
            AnalysisRequest::Incident(req) => {
                self.incident(req).await.map(AnalysisResponse::Incident)
            }
            AnalysisRequest::SimilarIncidents(req) => self
                .similar_incidents(req)
                .await
                .map(AnalysisResponse::SimilarIncidents),
            AnalysisRequest::RecurringErrorComparison(req) => self
                .compare_recurring_errors(req)
                .await
                .map(AnalysisResponse::RecurringErrorComparison),
            AnalysisRequest::IncidentContext(req) => self
                .incident_context(req)
                .await
                .map(AnalysisResponse::IncidentContext),
            AnalysisRequest::Patterns(req) => {
                self.patterns(req).await.map(AnalysisResponse::Patterns)
            }
            AnalysisRequest::Anomalies(req) => {
                self.anomalies(req).await.map(AnalysisResponse::Anomalies)
            }
            AnalysisRequest::Compare(req) => self.compare(req).await.map(AnalysisResponse::Compare),
        }
    }

    pub async fn correlate_domain(
        &self,
        req: CorrelateRequest,
    ) -> ServiceResult<CorrelateResponse> {
        match req {
            CorrelateRequest::Events(req) => self
                .correlate_events(req)
                .await
                .map(CorrelateResponse::Events),
            CorrelateRequest::State(req) => self
                .correlate_state(req)
                .await
                .map(CorrelateResponse::State),
            CorrelateRequest::Topic(req) => self
                .topic_correlate(req)
                .await
                .map(CorrelateResponse::Topic),
        }
    }

    pub async fn state(&self, req: StateRequest) -> ServiceResult<StateResponse> {
        match req {
            StateRequest::Host(req) => self
                .host_state(req)
                .await
                .map(Box::new)
                .map(StateResponse::Host),
            StateRequest::Fleet(req) => self.fleet_state(req).await.map(StateResponse::Fleet),
            StateRequest::ClockSkew(req) => {
                self.clock_skew(req).await.map(StateResponse::ClockSkew)
            }
        }
    }

    pub async fn stats_domain(&self, req: StatsRequest) -> ServiceResult<StatsResponse> {
        match req {
            StatsRequest::Summary => self.get_stats().await.map(StatsResponse::Summary),
            StatsRequest::IngestRate(req) => {
                self.ingest_rate(req).await.map(StatsResponse::IngestRate)
            }
        }
    }

    pub async fn ingest(&self, req: IngestRequest) -> ServiceResult<IngestResponse> {
        match req {
            IngestRequest::FileTails(req) => {
                self.file_tails(req).await.map(IngestResponse::FileTails)
            }
        }
    }

    pub async fn alerts(&self, req: AlertsRequest) -> ServiceResult<AlertsResponse> {
        match req {
            AlertsRequest::UnaddressedErrors(req) => self
                .unaddressed_errors(req)
                .await
                .map(AlertsResponse::UnaddressedErrors),
            AlertsRequest::AckError { request, actor } => self
                .ack_error(request, actor)
                .await
                .map(AlertsResponse::AckError),
            AlertsRequest::UnackError { request, actor } => self
                .unack_error(request, actor)
                .await
                .map(AlertsResponse::UnackError),
            AlertsRequest::NotificationsRecent(req) => self
                .notifications_recent_checked(req)
                .await
                .map(AlertsResponse::NotificationsRecent),
            AlertsRequest::NotificationsTest {
                body,
                actor,
                config,
            } => self
                .notifications_test_checked(body, actor, &config)
                .await
                .map(AlertsResponse::NotificationsTest),
        }
    }
}

#[cfg(test)]
#[path = "surface_tests.rs"]
mod tests;
