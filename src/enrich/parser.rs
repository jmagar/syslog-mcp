use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// SourceKind — where the record entered the system
// ---------------------------------------------------------------------------

/// The transport the row arrived on. Parsers use this to decide whether to
/// run (e.g. the kernel parser only applies to `SyslogUdp`/`SyslogTcp` sources,
/// the docker-event parser only to `DockerEvent`).
///
/// **Casing convention:** kebab-case on the wire, per
/// `docs/contracts/source-kinds.md`. Locked so the same string appears in
/// `metadata_json.source_kind`, in spec B's dispatch matrix, in
/// `agent-protocol.md`, and in the URI scheme used by `log-row-shape.md` §4
/// (`syslog-udp://`, `docker-stream://`, etc.).
///
/// String forms:
///
/// - `SyslogUdp` → `"syslog-udp"` (RFC 3164/5424 on UDP :1514)
/// - `SyslogTcp` → `"syslog-tcp"` (RFC 3164/5424 on TCP :1514)
/// - `DockerStream` → `"docker-stream"` (per-container stdout/stderr)
/// - `DockerEvent` → `"docker-event"` (Docker lifecycle events)
/// - `Otlp` → `"otlp"`
/// - `AdguardApi` → `"adguard-api"`
/// - `UnifiApi` → `"unifi-api"`
/// - `Agent` → `"agent"` (per-host agent WebSocket)
/// - `ShellHistory` → `"shell-history"` (local shell history backfill)
/// - `AgentCommand` → `"agent-command"` (AI agent-launched shell command spool)
/// - `FileTail` → `"file-tail"` (Cortex-managed local file-tail ingest)
/// - `AgentFileTail` → `"agent-file-tail"` (authenticated fleet-agent file tail)
///
/// **History:** prior versions of this contract used `snake_case` with a
/// bare `Syslog` variant. Both were corrected during the cross-cutting audit
/// (bead `cortex-s6et`); kebab-case matches the existing production data
/// that already carries kebab forms in `source_ip` schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    SyslogUdp,
    SyslogTcp,
    DockerStream,
    DockerEvent,
    Otlp,
    AdguardApi,
    UnifiApi,
    Agent,
    ShellHistory,
    AgentCommand,
    FileTail,
    AgentFileTail,
}

impl SourceKind {
    /// Every variant in canonical wire order. Single source of truth for
    /// iteration, [`SourceKind::from_wire`], and MCP schema `enum` generation —
    /// keeps the kebab-case list from drifting between the enum, the JSON
    /// schema, and validation code.
    pub const ALL: [SourceKind; 12] = [
        SourceKind::SyslogUdp,
        SourceKind::SyslogTcp,
        SourceKind::DockerStream,
        SourceKind::DockerEvent,
        SourceKind::Otlp,
        SourceKind::AdguardApi,
        SourceKind::UnifiApi,
        SourceKind::Agent,
        SourceKind::ShellHistory,
        SourceKind::AgentCommand,
        SourceKind::FileTail,
        SourceKind::AgentFileTail,
    ];

    /// Canonical kebab-case wire names for every variant, in [`SourceKind::ALL`]
    /// order. Used to generate the MCP `source_kinds` schema `enum` so it can
    /// never drift from this enum.
    pub fn all_wire_names() -> Vec<&'static str> {
        Self::ALL.iter().map(|kind| kind.as_str()).collect()
    }

    /// Stable string form (kebab-case). Use this when comparing against
    /// values read from `metadata_json.source_kind` or written by the
    /// dispatcher.
    pub const fn as_str(self) -> &'static str {
        match self {
            SourceKind::SyslogUdp => "syslog-udp",
            SourceKind::SyslogTcp => "syslog-tcp",
            SourceKind::DockerStream => "docker-stream",
            SourceKind::DockerEvent => "docker-event",
            SourceKind::Otlp => "otlp",
            SourceKind::AdguardApi => "adguard-api",
            SourceKind::UnifiApi => "unifi-api",
            SourceKind::Agent => "agent",
            SourceKind::ShellHistory => "shell-history",
            SourceKind::AgentCommand => "agent-command",
            SourceKind::FileTail => "file-tail",
            SourceKind::AgentFileTail => "agent-file-tail",
        }
    }

    /// Parse the stable kebab-case wire form back into a `SourceKind`.
    /// Returns `None` for unrecognised values (e.g. a caller-supplied
    /// `--source-kinds` typo), letting callers skip rather than fail.
    pub fn from_wire(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == trimmed)
    }

    /// True when the source is one of the two syslog listeners — convenient
    /// for parsers like `kernel` that gate on syslog ingest regardless of
    /// transport.
    pub const fn is_syslog(self) -> bool {
        matches!(self, SourceKind::SyslogUdp | SourceKind::SyslogTcp)
    }
}

// ---------------------------------------------------------------------------
// ParserInput — read-only view handed to every parser
// ---------------------------------------------------------------------------

/// The view a parser sees. Borrowed so parsers cannot mutate the envelope
/// directly; they emit a [`ParserOutput`] and the dispatcher merges it onto
/// the row.
///
/// All string fields are post-normalisation: `app_name` is lowercased and
/// trimmed, `message` is post-scrub (AI redaction has already run).
#[derive(Debug, Clone, Copy)]
pub struct ParserInput<'a> {
    /// Normalised application name (lowercased, trimmed). For Docker rows
    /// this is the value of `ContainerMeta::app_name`; for syslog this is
    /// the syslog APP-NAME field; for OTLP this is `service.name`.
    pub app_name: Option<&'a str>,

    /// Container name when the source is Docker, otherwise `None`.
    /// Operators rename containers; the dispatcher uses
    /// `container_to_canonical` to fold operator names onto canonical
    /// parser names (e.g. `authelia-main` → `authelia`).
    pub container_name: Option<&'a str>,

    /// Free-form message body. For Docker stream rows this is the
    /// post-timestamp portion; for syslog rows it is whatever
    /// `syslog_loose` produced; for OTLP it is the log body.
    pub message: &'a str,

    /// Raw line as received. Provided for parsers that need to recover
    /// information stripped during normalisation (e.g. the multi-segment
    /// SWAG access line that uses escaped quotes).
    pub raw: &'a str,

    /// Transport the record arrived on. See [`SourceKind`].
    pub source_kind: SourceKind,

    /// Existing severity. Parsers MAY overwrite via [`ParserOutput::severity`]
    /// (Authelia is the canonical example — JSON `level` overrides whatever
    /// the syslog header claimed).
    pub severity: &'a str,
}

// ---------------------------------------------------------------------------
// ParserOutput — what a parser emits
// ---------------------------------------------------------------------------

/// Closed enum of `auth_outcome` values. Indexed column; new values require
/// a code change AND a SQL migration to widen any CHECK constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthOutcome {
    Success,
    Failure,
    Denied,
    Challenge,
}

impl AuthOutcome {
    /// Stable string form written to the `auth_outcome` column.
    pub const fn as_str(self) -> &'static str {
        match self {
            AuthOutcome::Success => "success",
            AuthOutcome::Failure => "failure",
            AuthOutcome::Denied => "denied",
            AuthOutcome::Challenge => "challenge",
        }
    }
}

/// What a parser produces. Every column-bound field is `Option<…>` — the
/// dispatcher merges only non-`None` values onto the row. `metadata` is
/// shallow-merged into the existing `metadata_json` blob under the namespace
/// the parser declares via [`Parser::namespace`].
#[derive(Debug, Default, Clone)]
pub struct ParserOutput {
    /// HTTP status code (3 digits). Indexed column.
    pub http_status: Option<i32>,

    /// Authentication outcome. Indexed column.
    pub auth_outcome: Option<AuthOutcome>,

    /// DNS block decision. `Some(true)` = filtered/blocked, `Some(false)` =
    /// explicit allow, `None` = N/A (rewrites and non-DNS rows). Indexed
    /// column stored as `INTEGER` (0/1) with `NULL` for N/A.
    pub dns_blocked: Option<bool>,

    /// Normalised event verb. Indexed column. See per-parser specs for
    /// allowed values (e.g. kernel: `oom_kill`/`link_up`/…; docker_event:
    /// `start`/`die`/`oom`/…).
    pub event_action: Option<String>,

    /// Overwrites the row's `severity` if `Some` (Authelia uses this to
    /// promote JSON `level` over the syslog header). Must be one of the
    /// canonical syslog severities: `emerg`, `alert`, `crit`, `err`,
    /// `warning`, `notice`, `info`, `debug`.
    pub severity: Option<&'static str>,

    /// Parser-specific free-form fields. Shallow-merged into
    /// `metadata_json` under the parser's [`Parser::namespace`] key. Avoid
    /// duplicating data already in `raw` or in dedicated columns.
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// ParserError — failure variants
// ---------------------------------------------------------------------------

/// Failure modes a parser can produce. The dispatcher records these in the
/// `parse_error` column as `"{parser_name}: {ParserError::Display}"`,
/// truncated to 512 bytes. A row is **never dropped** because parsing
/// failed; partial extractions are still applied.
#[derive(Debug, Error)]
pub enum ParserError {
    /// The input has the right shape but a required structural element is
    /// missing or malformed (e.g. an Authelia line that isn't JSON).
    #[error("structural: {0}")]
    Structural(&'static str),

    /// A field the parser needs to populate an indexed column is absent
    /// (e.g. SWAG access line without an HTTP status token).
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// JSON parsing failed. Wraps `serde_json::Error` so the upstream
    /// error message is preserved.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// The regex/tokeniser did not match. Used by parsers that gate on a
    /// shape (e.g. nginx combined format) before extracting fields.
    #[error("regex no match: {0}")]
    NoMatch(&'static str),
}

// ---------------------------------------------------------------------------
// Parser trait
// ---------------------------------------------------------------------------

/// One concrete parser implementation. Implementors are zero-state
/// singletons (compiled regexes via `LazyLock<Regex>` at module scope).
///
/// The dispatcher constructs each parser once at startup and stores
/// `&'static dyn Parser` in the dispatch table, so dispatch is an `O(1)`
/// pointer chase per row.
pub trait Parser: Send + Sync + 'static {
    /// Stable, kebab-or-snake-case name. Used as the prefix in
    /// `parse_error`, in `metadata_json.parser`, and as the dispatch key.
    /// Must match the [`ParserId`] variant string form when applicable.
    fn name(&self) -> &'static str;

    /// Namespace key under which the parser's structured fields are written
    /// into `metadata_json` (e.g. `"swag"`, `"authelia"`, `"kernel"`).
    /// Avoids cross-parser key collisions.
    fn namespace(&self) -> &'static str;

    /// Parse a single envelope. Pure function — no I/O, no shared state.
    /// Must complete in O(message length); target < 30 µs average,
    /// < 200 µs p99 (see enrichment-framework spec §10).
    fn parse(&self, input: ParserInput<'_>) -> Result<ParserOutput, ParserError>;
}

// ---------------------------------------------------------------------------
// ParserId — typed identifier for the V1 parser set
// ---------------------------------------------------------------------------

/// Closed enumeration of the V1 parser set. The dispatch table is keyed by
/// this enum so dispatch becomes a typed match rather than a string lookup
/// — adding a parser requires extending this enum *and* registering the
/// implementation. The string forms below appear in `metadata_json.parser`
/// and in the `parse_error` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserId {
    /// Linux kernel messages: OOM kills, link state, MAC collisions.
    Kernel,
    /// Docker lifecycle events (create/start/stop/die/oom/health_status).
    DockerEvent,
    /// Authelia JSON auth log.
    Authelia,
    /// SWAG / nginx access and error logs.
    Swag,
    /// AdGuard Home query log (container stdout or API poller).
    Adguard,
    /// fail2ban actions/filter log.
    Fail2ban,
}

impl ParserId {
    /// Stable string form (matches `serde` `snake_case`).
    pub const fn as_str(self) -> &'static str {
        match self {
            ParserId::Kernel => "kernel",
            ParserId::DockerEvent => "docker_event",
            ParserId::Authelia => "authelia",
            ParserId::Swag => "swag",
            ParserId::Adguard => "adguard",
            ParserId::Fail2ban => "fail2ban",
        }
    }
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod parser_tests;
