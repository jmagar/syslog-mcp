//! Shared command/API/action surfaces catalog and qualification contract.

use serde::Serialize;

/// Version of the exported qualification contract. Bump this when consumers
/// must change how they interpret an entry (adding entries does not require a
/// bump).
pub const SURFACE_CONTRACT_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceKind {
    Cli,
    McpAction,
    ApiRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationClass {
    None,
    AppendOnly,
    Reversible,
    Destructive,
    Operational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequiredCaseKind {
    SemanticPositive,
    ExecutedRefusalSemantic,
    ValidationNegative,
    Authorization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileDisposition {
    ExecutedSemantic,
    ExecutedRefusalSemantic,
    PlatformQualified,
    ArtifactQualified,
    ContractApprovedNotApplicable,
    PendingScenario,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    Any,
    Unix,
    Linux,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceContractEntry {
    pub id: String,
    pub kind: &'static str,
    pub spelling: String,
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<HttpMethod>,
    pub auth: &'static str,
    pub mutation: MutationClass,
    pub profiles: &'static [&'static str],
    pub platforms: &'static [Platform],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parity_group: Option<String>,
    pub required_cases: Vec<RequiredCaseKind>,
    pub allowed_dispositions: &'static [ProfileDisposition],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SurfaceContractExport {
    pub version: u32,
    pub entries: Vec<SurfaceContractEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceDisposition {
    Canonical,
    MovedIntoGroupedDomain,
    RetainedTopLevelOperational,
    RetainedProtocolCompatibility,
    RemovedCleanBreak,
    OutOfScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceDomain {
    Search,
    Hosts,
    Sessions,
    Graph,
    Evidence,
    Analysis,
    Correlate,
    State,
    Stats,
    Ingest,
    Alerts,
    Compose,
    Setup,
    Db,
    Config,
    Runtime,
    Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceAccess {
    Read,
    Admin,
    Info,
    LocalOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceTransport(u8);

impl SurfaceTransport {
    pub const LOCAL_CLI: Self = Self(1 << 0);
    pub const HTTP_CLI: Self = Self(1 << 1);
    pub const MCP: Self = Self(1 << 2);
    pub const REST: Self = Self(1 << 3);
    pub const LOCAL_ONLY: Self = Self(1 << 4);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Debug)]
pub struct SurfaceSpec {
    pub kind: SurfaceKind,
    pub spelling: &'static str,
    pub domain: SurfaceDomain,
    pub disposition: SurfaceDisposition,
    pub access: SurfaceAccess,
    pub transports: SurfaceTransport,
    pub replacement: Option<&'static str>,
    pub reason: Option<&'static str>,
}

macro_rules! cli {
    ($spelling:literal, $domain:ident, $disposition:ident, $access:ident) => {
        SurfaceSpec {
            kind: SurfaceKind::Cli,
            spelling: $spelling,
            domain: SurfaceDomain::$domain,
            disposition: SurfaceDisposition::$disposition,
            access: SurfaceAccess::$access,
            transports: SurfaceTransport::LOCAL_CLI.union(SurfaceTransport::HTTP_CLI),
            replacement: None,
            reason: None,
        }
    };
    ($spelling:literal, $domain:ident, $disposition:ident, $access:ident, replace: $replacement:literal, reason: $reason:literal) => {
        SurfaceSpec {
            kind: SurfaceKind::Cli,
            spelling: $spelling,
            domain: SurfaceDomain::$domain,
            disposition: SurfaceDisposition::$disposition,
            access: SurfaceAccess::$access,
            transports: SurfaceTransport::LOCAL_CLI.union(SurfaceTransport::HTTP_CLI),
            replacement: Some($replacement),
            reason: Some($reason),
        }
    };
}

macro_rules! local_cli {
    ($spelling:literal, $domain:ident, $disposition:ident) => {
        SurfaceSpec {
            kind: SurfaceKind::Cli,
            spelling: $spelling,
            domain: SurfaceDomain::$domain,
            disposition: SurfaceDisposition::$disposition,
            access: SurfaceAccess::LocalOnly,
            transports: SurfaceTransport::LOCAL_CLI.union(SurfaceTransport::LOCAL_ONLY),
            replacement: None,
            reason: None,
        }
    };
    ($spelling:literal, $domain:ident, $disposition:ident, replace: $replacement:literal, reason: $reason:literal) => {
        SurfaceSpec {
            kind: SurfaceKind::Cli,
            spelling: $spelling,
            domain: SurfaceDomain::$domain,
            disposition: SurfaceDisposition::$disposition,
            access: SurfaceAccess::LocalOnly,
            transports: SurfaceTransport::LOCAL_CLI.union(SurfaceTransport::LOCAL_ONLY),
            replacement: Some($replacement),
            reason: Some($reason),
        }
    };
}

macro_rules! mcp {
    ($spelling:literal, $domain:ident, $disposition:ident, $access:ident) => {
        SurfaceSpec {
            kind: SurfaceKind::McpAction,
            spelling: $spelling,
            domain: SurfaceDomain::$domain,
            disposition: SurfaceDisposition::$disposition,
            access: SurfaceAccess::$access,
            transports: SurfaceTransport::MCP,
            replacement: None,
            reason: None,
        }
    };
}

macro_rules! api {
    ($spelling:literal, $domain:ident, $disposition:ident, $access:ident) => {
        SurfaceSpec {
            kind: SurfaceKind::ApiRoute,
            spelling: $spelling,
            domain: SurfaceDomain::$domain,
            disposition: SurfaceDisposition::$disposition,
            access: SurfaceAccess::$access,
            transports: SurfaceTransport::REST.union(SurfaceTransport::HTTP_CLI),
            replacement: None,
            reason: None,
        }
    };
    ($spelling:literal, $domain:ident, $disposition:ident, $access:ident, replace: $replacement:literal, reason: $reason:literal) => {
        SurfaceSpec {
            kind: SurfaceKind::ApiRoute,
            spelling: $spelling,
            domain: SurfaceDomain::$domain,
            disposition: SurfaceDisposition::$disposition,
            access: SurfaceAccess::$access,
            transports: SurfaceTransport::REST.union(SurfaceTransport::HTTP_CLI),
            replacement: Some($replacement),
            reason: Some($reason),
        }
    };
}

pub const SURFACE_SPECS: &[SurfaceSpec] = &[
    cli!("search", Search, Canonical, Read),
    cli!("filter", Search, Canonical, Read),
    cli!("tail", Search, Canonical, Read),
    cli!("hosts", Hosts, Canonical, Read),
    cli!("apps", Search, Canonical, Read),
    cli!("artifactevents", Evidence, Canonical, Read),
    cli!("sessions", Sessions, Canonical, Read),
    // LLM assessment spawns Gemini CLI on the local host via LlmRunner —
    // local-only by design (see PR 4 of GH #94's safety invariants).
    local_cli!("assess", Sessions, Canonical),
    cli!("analysis", Analysis, Canonical, Read),
    cli!("state", State, Canonical, Read),
    cli!("ingest", Ingest, Canonical, Admin),
    cli!("alerts", Alerts, Canonical, Admin),
    cli!("entity", Graph, Canonical, Read),
    cli!("graph", Graph, Canonical, Read),
    cli!("errors", Analysis, MovedIntoGroupedDomain, Read, replace: "analysis errors", reason: "analysis owns error, incident, pattern, and anomaly views"),
    cli!("incident", Analysis, MovedIntoGroupedDomain, Read, replace: "analysis incident", reason: "incident context belongs to analysis"),
    cli!("timeline", Analysis, Canonical, Read),
    cli!("patterns", Analysis, MovedIntoGroupedDomain, Read, replace: "analysis patterns", reason: "recurring patterns are analysis output"),
    cli!("anomalies", Analysis, MovedIntoGroupedDomain, Read, replace: "analysis anomalies", reason: "volume anomalies are analysis output"),
    cli!("compare", Analysis, MovedIntoGroupedDomain, Read, replace: "analysis compare", reason: "window comparisons are analysis output"),
    cli!("correlate", Correlate, Canonical, Read),
    cli!("correlate-state", Correlate, MovedIntoGroupedDomain, Read, replace: "correlate state", reason: "state correlation is a correlate mode"),
    cli!("topic-correlate", Correlate, MovedIntoGroupedDomain, Read, replace: "correlate topic", reason: "topic correlation is a correlate mode"),
    cli!("host-state", State, MovedIntoGroupedDomain, Read, replace: "state host", reason: "host state belongs under state"),
    cli!("fleet-state", State, MovedIntoGroupedDomain, Read, replace: "state fleet", reason: "fleet state belongs under state"),
    cli!("clock-skew", State, MovedIntoGroupedDomain, Read, replace: "state clockskew", reason: "clock skew is a host-state health view"),
    cli!("stats", Stats, Canonical, Read),
    cli!("ingest-rate", Stats, MovedIntoGroupedDomain, Read, replace: "stats ingestrate", reason: "ingest throughput is a stats mode"),
    cli!("shell", Ingest, MovedIntoGroupedDomain, Admin, replace: "ingest shell", reason: "manual ingestion commands live under ingest"),
    cli!("agent-command", Ingest, MovedIntoGroupedDomain, Admin, replace: "ingest shell agent", reason: "agent command ingestion lives under ingest shell agent"),
    local_cli!("heartbeat", Ingest, RetainedTopLevelOperational),
    cli!("inventory", Ingest, MovedIntoGroupedDomain, Read, replace: "ingest inventory", reason: "inventory refresh/status is an ingest-adjacent cache operation"),
    cli!("file-tail", Ingest, MovedIntoGroupedDomain, Admin, replace: "ingest filetail", reason: "file-tail management lives under ingest"),
    cli!("sig", Alerts, MovedIntoGroupedDomain, Admin, replace: "alerts signatures", reason: "signatures are alert inputs"),
    cli!("notify", Alerts, MovedIntoGroupedDomain, Admin, replace: "alerts notifications", reason: "notification firings and test sends live under alerts"),
    local_cli!("serve", Runtime, RetainedTopLevelOperational),
    local_cli!("mcp", Runtime, RetainedTopLevelOperational),
    local_cli!("doctor", Runtime, RetainedTopLevelOperational),
    local_cli!("status", Runtime, RetainedTopLevelOperational),
    local_cli!("db", Db, RetainedTopLevelOperational),
    local_cli!("compose", Compose, RetainedTopLevelOperational),
    local_cli!("setup", Setup, RetainedTopLevelOperational),
    local_cli!("update", Setup, RetainedTopLevelOperational),
    local_cli!("config", Config, RetainedTopLevelOperational),
    local_cli!("completions", Runtime, RetainedTopLevelOperational),
    cli!("ai", Sessions, RemovedCleanBreak, Read, replace: "sessions", reason: "AI transcript operations were moved under sessions"),
    cli!("source-ips", Hosts, RemovedCleanBreak, Read, replace: "hosts sources", reason: "source identities are a hosts mode"),
    cli!("silent-hosts", Hosts, RemovedCleanBreak, Read, replace: "hosts silent", reason: "host silence is a hosts mode"),
    cli!("service", Compose, RemovedCleanBreak, Read, replace: "compose logs SERVICE", reason: "service log inspection is a compose mode"),
    cli!("deploy", Setup, RemovedCleanBreak, Admin, replace: "setup deploy", reason: "deployment workflows are setup operations"),
    mcp!("search", Search, Canonical, Read),
    mcp!("filter", Search, Canonical, Read),
    mcp!("tail", Search, Canonical, Read),
    mcp!("errors", Analysis, RetainedProtocolCompatibility, Read),
    mcp!("hosts", Hosts, Canonical, Read),
    mcp!("map", Graph, Canonical, Read),
    mcp!("host_state", State, RetainedProtocolCompatibility, Read),
    mcp!("fleet_state", State, RetainedProtocolCompatibility, Read),
    mcp!("correlate", Correlate, RetainedProtocolCompatibility, Read),
    mcp!(
        "correlate_state",
        Correlate,
        RetainedProtocolCompatibility,
        Read
    ),
    mcp!("stats", Stats, Canonical, Read),
    mcp!("status", Runtime, Canonical, Read),
    mcp!("apps", Search, Canonical, Read),
    mcp!("sessions", Sessions, Canonical, Read),
    mcp!("search_sessions", Sessions, Canonical, Read),
    mcp!("abuse", Sessions, Canonical, Read),
    mcp!("abuse_incidents", Sessions, Canonical, Read),
    mcp!("abuse_investigate", Sessions, Canonical, Read),
    mcp!("ai_correlate", Sessions, Canonical, Read),
    mcp!(
        "topic_correlate",
        Correlate,
        RetainedProtocolCompatibility,
        Read
    ),
    mcp!("usage_blocks", Sessions, Canonical, Read),
    mcp!("project_context", Sessions, Canonical, Read),
    mcp!("list_ai_tools", Sessions, Canonical, Read),
    mcp!("list_ai_projects", Sessions, Canonical, Read),
    mcp!("source_ips", Hosts, RetainedProtocolCompatibility, Read),
    mcp!("timeline", Analysis, RetainedProtocolCompatibility, Read),
    mcp!("patterns", Analysis, RetainedProtocolCompatibility, Read),
    mcp!("context", Search, Canonical, Read),
    mcp!("get", Search, Canonical, Read),
    mcp!("ingest_rate", Stats, RetainedProtocolCompatibility, Read),
    mcp!("silent_hosts", Hosts, RetainedProtocolCompatibility, Read),
    mcp!("clock_skew", State, RetainedProtocolCompatibility, Read),
    mcp!("anomalies", Analysis, RetainedProtocolCompatibility, Read),
    mcp!("compare", Analysis, RetainedProtocolCompatibility, Read),
    mcp!(
        "compose_status",
        Compose,
        RetainedProtocolCompatibility,
        Read
    ),
    mcp!(
        "compose_doctor",
        Compose,
        RetainedProtocolCompatibility,
        Read
    ),
    mcp!(
        "unaddressed_errors",
        Alerts,
        RetainedProtocolCompatibility,
        Read
    ),
    mcp!("ack_error", Alerts, RetainedProtocolCompatibility, Admin),
    mcp!("unack_error", Alerts, RetainedProtocolCompatibility, Admin),
    mcp!(
        "notifications_recent",
        Alerts,
        RetainedProtocolCompatibility,
        Read
    ),
    mcp!("file_tails", Ingest, RetainedProtocolCompatibility, Admin),
    mcp!(
        "notifications_test",
        Alerts,
        RetainedProtocolCompatibility,
        Admin
    ),
    mcp!("llm_invocations", Sessions, Canonical, Admin),
    mcp!(
        "similar_incidents",
        Analysis,
        RetainedProtocolCompatibility,
        Read
    ),
    mcp!("recurring_error_comparison", Analysis, Canonical, Read),
    mcp!(
        "incident_context",
        Analysis,
        RetainedProtocolCompatibility,
        Read
    ),
    mcp!("graph", Graph, Canonical, Read),
    mcp!("artifact_evidence", Evidence, Canonical, Read),
    mcp!("artifact_evidence_record", Evidence, Canonical, Admin),
    mcp!("skill_events", Sessions, Canonical, Read),
    mcp!("skill_incidents", Sessions, Canonical, Read),
    mcp!("skill_investigate", Sessions, Canonical, Read),
    mcp!("mcp_events", Sessions, Canonical, Read),
    mcp!("mcp_incidents", Sessions, Canonical, Read),
    mcp!("mcp_investigate", Sessions, Canonical, Read),
    mcp!("hook_events", Sessions, Canonical, Read),
    mcp!("hook_incidents", Sessions, Canonical, Read),
    mcp!("hook_investigate", Sessions, Canonical, Read),
    mcp!("help", Protocol, Canonical, Info),
];

mod api;

pub use api::{ApiBinding, api_bindings};

mod contract;
pub use contract::*;
mod catalog;
pub use catalog::*;

pub fn specs_for(kind: SurfaceKind) -> impl Iterator<Item = &'static SurfaceSpec> {
    SURFACE_SPECS
        .iter()
        .chain(api::API_SURFACE_SPECS.iter())
        .filter(move |spec| spec.kind == kind)
}

pub fn find(kind: SurfaceKind, spelling: &str) -> Option<&'static SurfaceSpec> {
    specs_for(kind).find(|spec| spec.spelling == spelling)
}

pub fn canonical_cli_roots() -> impl Iterator<Item = &'static SurfaceSpec> {
    specs_for(SurfaceKind::Cli).filter(|spec| {
        matches!(
            spec.disposition,
            SurfaceDisposition::Canonical | SurfaceDisposition::RetainedTopLevelOperational
        )
    })
}

pub fn is_cli_mode_command(name: &str) -> bool {
    matches!(
        name,
        "__complete"
            | "search"
            | "filter"
            | "tail"
            | "hosts"
            | "sessions"
            | "assess"
            | "analysis"
            | "state"
            | "status"
            | "ingest"
            | "alerts"
            | "heartbeat"
            | "correlate"
            | "stats"
            | "compose"
            | "setup"
            | "db"
            | "config"
            | "timeline"
            | "apps"
            | "artifactevents"
            | "entity"
            | "graph"
            | "completions"
    )
}

pub fn removed_cli_surface(name: &str) -> Option<&'static SurfaceSpec> {
    specs_for(SurfaceKind::Cli).find(|spec| {
        spec.spelling == name
            && matches!(
                spec.disposition,
                SurfaceDisposition::MovedIntoGroupedDomain | SurfaceDisposition::RemovedCleanBreak
            )
    })
}

#[cfg(test)]
#[path = "surfaces_tests.rs"]
mod tests;
