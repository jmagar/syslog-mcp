use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiBinding {
    pub path: &'static str,
    pub method: HttpMethod,
    pub access: SurfaceAccess,
    pub mutation: MutationClass,
}

/// Executable REST method/path bindings derived from the catalog. Routes with
/// more than one method are expanded here, so `/api/artifact-evidence` cannot
/// accidentally count GET coverage as POST coverage.
pub fn api_bindings() -> impl Iterator<Item = ApiBinding> {
    API_SURFACE_SPECS
        .iter()
        .filter(|spec| !matches!(spec.disposition, SurfaceDisposition::RemovedCleanBreak))
        .flat_map(|spec| {
            let default = ApiBinding {
                path: spec.spelling,
                method: if matches!(
                    spec.spelling,
                    "/api/v1/investigations/ask"
                        | "/api/topic-correlate"
                        | "/api/errors/ack"
                        | "/api/errors/unack"
                        | "/api/notifications/test"
                        | "/api/file-tails"
                        | "/api/sessions/prune-checkpoints"
                        | "/api/db/integrity/background"
                        | "/api/db/checkpoint"
                        | "/api/db/vacuum"
                        | "/api/db/backup"
                ) {
                    HttpMethod::Post
                } else {
                    HttpMethod::Get
                },
                access: spec.access,
                mutation: match spec.spelling {
                    "/api/errors/ack" | "/api/errors/unack" | "/api/file-tails" => {
                        MutationClass::Reversible
                    }
                    "/api/notifications/test" | "/api/db/checkpoint" => MutationClass::Operational,
                    "/api/sessions/prune-checkpoints" | "/api/db/vacuum" => {
                        MutationClass::Destructive
                    }
                    "/api/db/integrity/background" | "/api/db/backup" => MutationClass::AppendOnly,
                    _ => MutationClass::None,
                },
            };
            let second = (spec.spelling == "/api/artifact-evidence").then_some(ApiBinding {
                path: spec.spelling,
                method: HttpMethod::Post,
                access: SurfaceAccess::Admin,
                mutation: MutationClass::AppendOnly,
            });
            std::iter::once(default).chain(second)
        })
}

pub(super) const API_SURFACE_SPECS: &[SurfaceSpec] = &[
    api!("/api/search", Search, Canonical, Read),
    api!("/api/filter", Search, Canonical, Read),
    api!("/api/feed", Search, Canonical, Read),
    api!("/api/tail", Search, Canonical, Read),
    api!("/api/errors", Analysis, RetainedProtocolCompatibility, Read),
    api!("/api/hosts", Hosts, Canonical, Read),
    api!(
        "/api/correlate",
        Correlate,
        RetainedProtocolCompatibility,
        Read
    ),
    api!("/api/stats", Stats, Canonical, Read),
    api!("/api/version", Runtime, Canonical, Read),
    api!("/api/integration-profile", Runtime, Canonical, Read),
    api!("/v1/integration/identity", Runtime, Canonical, Read),
    api!("/api/capabilities", Runtime, Canonical, Read),
    // Agent Observatory is a first-class, authenticated read surface. Keep
    // every mounted spelling here so router construction and qualification
    // cannot drift apart.
    api!(
        "/api/agent-observatory/repositories",
        Sessions,
        Canonical,
        Read
    ),
    api!(
        "/api/repositories",
        Sessions,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/agent-observatory/worktrees",
        Sessions,
        Canonical,
        Read
    ),
    api!(
        "/api/repositories/{repository_id}/worktrees",
        Sessions,
        RetainedProtocolCompatibility,
        Read
    ),
    api!("/api/agent-observatory/runs", Sessions, Canonical, Read),
    api!(
        "/api/agent-runs",
        Sessions,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/agent-observatory/runs/{run_key}/events",
        Sessions,
        Canonical,
        Read
    ),
    api!(
        "/api/agent-runs/{run_key}/events",
        Sessions,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/agent-observatory/runs/{run_key}/telemetry",
        Sessions,
        Canonical,
        Read
    ),
    api!(
        "/api/agent-runs/{run_key}/telemetry",
        Sessions,
        RetainedProtocolCompatibility,
        Read
    ),
    api!("/api/streams/logs", Search, Canonical, Read),
    api!("/api/streams/sessions", Sessions, Canonical, Read),
    api!("/api/v1/investigation/version", Runtime, Canonical, Read),
    api!("/api/v1/investigations/ask", Analysis, Canonical, Read),
    api!("/api/v1/graph/entity", Graph, Canonical, Read),
    api!("/api/v1/graph/around", Graph, Canonical, Read),
    api!("/api/v1/graph/explain", Graph, Canonical, Read),
    api!("/api/v1/graph/evidence", Graph, Canonical, Read),
    api!(
        "/api/source-ips",
        Hosts,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/timeline",
        Analysis,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/patterns",
        Analysis,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/ingest-rate",
        Stats,
        RetainedProtocolCompatibility,
        Read
    ),
    api!("/api/get", Search, Canonical, Read),
    api!(
        "/api/host-state",
        State,
        RetainedProtocolCompatibility,
        Read
    ),
    api!("/api/context", Search, Canonical, Read),
    api!(
        "/api/fleet-state",
        State,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/correlate-state",
        Correlate,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/topic-correlate",
        Correlate,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/errors/unaddressed",
        Alerts,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/errors/ack",
        Alerts,
        RetainedProtocolCompatibility,
        Admin
    ),
    api!(
        "/api/errors/unack",
        Alerts,
        RetainedProtocolCompatibility,
        Admin
    ),
    api!(
        "/api/notifications/recent",
        Alerts,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/notifications/test",
        Alerts,
        RetainedProtocolCompatibility,
        Admin
    ),
    api!(
        "/api/file-tails",
        Ingest,
        RetainedProtocolCompatibility,
        Admin
    ),
    api!(
        "/api/silent-hosts",
        Hosts,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/clock-skew",
        State,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/anomalies",
        Analysis,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/compare",
        Analysis,
        RetainedProtocolCompatibility,
        Read
    ),
    api!("/api/apps", Search, Canonical, Read),
    // GET is the canonical read surface. POST on the same route requires the
    // existing explicit admin-token guard in api.rs.
    api!("/api/artifact-evidence", Evidence, Canonical, Read),
    api!(
        "/api/similar-incidents",
        Analysis,
        RetainedProtocolCompatibility,
        Read
    ),
    api!("/api/recurring-error-comparison", Analysis, Canonical, Read),
    api!(
        "/api/incident-context",
        Analysis,
        RetainedProtocolCompatibility,
        Read
    ),
    api!("/api/graph/entity", Graph, Canonical, Read),
    api!("/api/graph/around", Graph, Canonical, Read),
    api!("/api/graph/explain", Graph, Canonical, Read),
    api!("/api/graph/evidence", Graph, Canonical, Read),
    api!("/api/sessions/incidents", Sessions, Canonical, Read),
    api!("/api/sessions/investigate", Sessions, Canonical, Read),
    api!("/api/sessions/llm-invocations", Sessions, Canonical, Admin),
    api!("/api/sessions/skills", Sessions, Canonical, Read),
    api!("/api/sessions/skill-incidents", Sessions, Canonical, Read),
    api!("/api/sessions/skill-investigate", Sessions, Canonical, Read),
    api!("/api/sessions/mcp-events", Sessions, Canonical, Read),
    api!("/api/sessions/mcp-incidents", Sessions, Canonical, Read),
    api!("/api/sessions/mcp-investigate", Sessions, Canonical, Read),
    api!("/api/sessions/hooks", Sessions, Canonical, Read),
    api!("/api/sessions/hook-incidents", Sessions, Canonical, Read),
    api!("/api/sessions/hook-investigate", Sessions, Canonical, Read),
    api!(
        "/api/compose/status",
        Compose,
        RetainedProtocolCompatibility,
        Read
    ),
    api!(
        "/api/compose/doctor",
        Compose,
        RetainedProtocolCompatibility,
        Read
    ),
    api!("/api/sessions", Sessions, Canonical, Read),
    api!("/api/sessions/rendered", Sessions, Canonical, Read),
    api!("/api/sessions/search", Sessions, Canonical, Read),
    api!("/api/sessions/abuse", Sessions, Canonical, Read),
    api!("/api/sessions/correlate", Sessions, Canonical, Read),
    api!("/api/sessions/blocks", Sessions, Canonical, Read),
    api!("/api/sessions/context", Sessions, Canonical, Read),
    api!("/api/sessions/tools", Sessions, Canonical, Read),
    api!("/api/sessions/projects", Sessions, Canonical, Read),
    api!("/api/sessions/checkpoints", Sessions, Canonical, Read),
    api!("/api/sessions/errors", Sessions, Canonical, Read),
    api!(
        "/api/sessions/prune-checkpoints",
        Sessions,
        Canonical,
        Admin
    ),
    api!("/api/db/status", Db, RetainedTopLevelOperational, Read),
    api!("/api/db/integrity", Db, RetainedTopLevelOperational, Read),
    api!(
        "/api/db/integrity/background",
        Db,
        RetainedTopLevelOperational,
        Admin
    ),
    api!(
        "/api/db/integrity/jobs/{id}",
        Db,
        RetainedTopLevelOperational,
        Read
    ),
    api!("/api/db/checkpoint", Db, RetainedTopLevelOperational, Admin),
    api!("/api/db/vacuum", Db, RetainedTopLevelOperational, Admin),
    api!("/api/db/backup", Db, RetainedTopLevelOperational, Admin),
    api!("/api/ai", Sessions, RemovedCleanBreak, Read, replace: "/api/sessions", reason: "AI session REST routes moved to /api/sessions with no compatibility shim"),
    api!("/api/ai/search", Sessions, RemovedCleanBreak, Read, replace: "/api/sessions/search", reason: "AI session REST routes moved to /api/sessions with no compatibility shim"),
    api!("/api/ai/abuse", Sessions, RemovedCleanBreak, Read, replace: "/api/sessions/abuse", reason: "AI session REST routes moved to /api/sessions with no compatibility shim"),
    api!("/api/ai/correlate", Sessions, RemovedCleanBreak, Read, replace: "/api/sessions/correlate", reason: "AI session REST routes moved to /api/sessions with no compatibility shim"),
    api!("/api/ai/blocks", Sessions, RemovedCleanBreak, Read, replace: "/api/sessions/blocks", reason: "AI session REST routes moved to /api/sessions with no compatibility shim"),
    api!("/api/ai/context", Sessions, RemovedCleanBreak, Read, replace: "/api/sessions/context", reason: "AI session REST routes moved to /api/sessions with no compatibility shim"),
    api!("/api/ai/tools", Sessions, RemovedCleanBreak, Read, replace: "/api/sessions/tools", reason: "AI session REST routes moved to /api/sessions with no compatibility shim"),
    api!("/api/ai/projects", Sessions, RemovedCleanBreak, Read, replace: "/api/sessions/projects", reason: "AI session REST routes moved to /api/sessions with no compatibility shim"),
];
