//! Canonical AI-session provider descriptors.
//!
//! Keep source format parsing in the provider-local scanner modules.  This
//! registry only owns stable provider names, safe discovery roots, and the
//! coverage a caller may honestly claim for each evidence lane.

use anyhow::Result;

#[path = "providers/paths.rs"]
mod paths;

pub use paths::provider_for_transcript_layout;
pub(crate) use paths::{is_known_transcript_root, provider_for_path, transcript_roots};

/// A provider known to the local AI-session scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Claude,
    Codex,
    Gemini,
    Antigravity,
}

impl Provider {
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Antigravity => "antigravity",
        }
    }

    pub fn from_alias(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_lowercase();
        PROVIDERS.iter().find_map(|definition| {
            (definition.canonical_name == normalized
                || definition.aliases.contains(&normalized.as_str()))
            .then_some(definition.provider)
        })
    }
}

/// A bounded evidence lane. `NotObserved` means unsupported or unavailable;
/// it is deliberately distinct from an observed lane with zero records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLane {
    SessionMetadata,
    Transcript,
    ToolCalls,
    McpEvents,
    Skills,
    Hooks,
    Usage,
}

/// Static support declared by a reviewed adapter.
///
/// This is intentionally a different vocabulary from [`Coverage`]. An
/// adapter may support a lane before this installation has received a single
/// receipt for it; serializing that fact as `observed` would be misleading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterSupport {
    Supported,
    Partial,
    Unsupported,
}

impl AdapterSupport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Receipt-backed runtime coverage, shared by health and projection consumers
/// without inventing a second session model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    Observed,
    Partial,
    NotObserved,
    Failed,
}

impl Coverage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Partial => "partial",
            Self::NotObserved => "not_observed",
            Self::Failed => "failed",
        }
    }
}

/// Checkpoint fields currently persisted for a provider source.
///
/// `canonical_path` is a mutable locator, not an immutable source identity.
/// The existing scanner combines it with a content fingerprint for safe
/// rewrites/replays. Persisting a true source epoch or immutable source ID
/// requires a migration and is intentionally not claimed by this slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointPolicy {
    pub source_locator: &'static str,
    pub revision: &'static str,
    pub content_fingerprint: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderDefinition {
    pub provider: Provider,
    pub canonical_name: &'static str,
    pub aliases: &'static [&'static str],
    /// The persisted scanner source kind for this provider, when its
    /// transcript adapter is enabled. Keeping this with the descriptor
    /// prevents health, forwarding, and projections from maintaining their
    /// own provider-to-source-kind tables.
    pub source_kind: Option<&'static str>,
    pub adapter_version: &'static str,
    pub privacy_policy: &'static str,
    pub checkpoint: CheckpointPolicy,
    lanes: &'static [ProviderLaneDefinition],
}

impl ProviderDefinition {
    pub fn support(self, lane: ProviderLane) -> AdapterSupport {
        self.lane(lane)
            .map(|definition| definition.adapter_support)
            .unwrap_or(AdapterSupport::Unsupported)
    }

    /// Conservative coverage an agent may put into a transcript evidence
    /// envelope. This is adapter-specific, but it remains distinct from
    /// receipt-backed runtime health: an envelope only describes what that
    /// forwarded record can carry, not what the server has durably observed.
    pub fn forwarding_coverage(self, lane: ProviderLane) -> Coverage {
        self.lane(lane)
            .map(|definition| definition.forwarding_coverage)
            .unwrap_or(Coverage::NotObserved)
    }

    fn lane(self, lane: ProviderLane) -> Option<&'static ProviderLaneDefinition> {
        self.lanes.iter().find(|definition| definition.lane == lane)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProviderLaneDefinition {
    pub lane: ProviderLane,
    pub adapter_support: AdapterSupport,
    /// The most the current bounded transcript forwarder can truthfully
    /// report for this lane. Static support must never silently turn into
    /// observed runtime evidence.
    pub forwarding_coverage: Coverage,
}

const fn lane(
    lane: ProviderLane,
    adapter_support: AdapterSupport,
    forwarding_coverage: Coverage,
) -> ProviderLaneDefinition {
    ProviderLaneDefinition {
        lane,
        adapter_support,
        forwarding_coverage,
    }
}

const CONTENT_FINGERPRINT_CHECKPOINT: CheckpointPolicy = CheckpointPolicy {
    source_locator: "canonical_path",
    revision: "size_and_mtime",
    content_fingerprint: "sha256",
};

const PROVIDERS: &[ProviderDefinition] = &[
    ProviderDefinition {
        provider: Provider::Claude,
        canonical_name: "claude",
        aliases: &["claude-code", "claude-transcript"],
        source_kind: Some("claude_project"),
        adapter_version: "claude-jsonl-v1",
        privacy_policy: "scrub-before-persist",
        checkpoint: CONTENT_FINGERPRINT_CHECKPOINT,
        lanes: &[
            lane(
                ProviderLane::SessionMetadata,
                AdapterSupport::Supported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Transcript,
                AdapterSupport::Supported,
                Coverage::Observed,
            ),
            lane(
                ProviderLane::ToolCalls,
                AdapterSupport::Partial,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::McpEvents,
                AdapterSupport::Supported,
                Coverage::Partial,
            ),
            lane(
                ProviderLane::Skills,
                AdapterSupport::Supported,
                Coverage::Partial,
            ),
            lane(
                ProviderLane::Hooks,
                AdapterSupport::Supported,
                Coverage::Partial,
            ),
            lane(
                ProviderLane::Usage,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
        ],
    },
    ProviderDefinition {
        provider: Provider::Codex,
        canonical_name: "codex",
        aliases: &["openai-codex", "codex-transcript"],
        source_kind: Some("codex_session"),
        adapter_version: "codex-jsonl-v1",
        privacy_policy: "scrub-before-persist",
        checkpoint: CONTENT_FINGERPRINT_CHECKPOINT,
        lanes: &[
            lane(
                ProviderLane::SessionMetadata,
                AdapterSupport::Supported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Transcript,
                AdapterSupport::Supported,
                Coverage::Observed,
            ),
            lane(
                ProviderLane::ToolCalls,
                AdapterSupport::Partial,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::McpEvents,
                AdapterSupport::Supported,
                Coverage::Partial,
            ),
            lane(
                ProviderLane::Skills,
                AdapterSupport::Supported,
                Coverage::Partial,
            ),
            lane(
                ProviderLane::Hooks,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Usage,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
        ],
    },
    ProviderDefinition {
        provider: Provider::Gemini,
        canonical_name: "gemini",
        aliases: &["gemini-cli", "gemini-transcript"],
        source_kind: Some("gemini_session"),
        adapter_version: "gemini-chat-json-v2",
        privacy_policy: "scrub-before-persist",
        checkpoint: CONTENT_FINGERPRINT_CHECKPOINT,
        lanes: &[
            lane(
                ProviderLane::SessionMetadata,
                AdapterSupport::Supported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Transcript,
                AdapterSupport::Supported,
                Coverage::Observed,
            ),
            lane(
                ProviderLane::ToolCalls,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::McpEvents,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Skills,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Hooks,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Usage,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
        ],
    },
    ProviderDefinition {
        provider: Provider::Antigravity,
        canonical_name: "antigravity",
        aliases: &["agy", "antigravity-cli"],
        source_kind: Some("antigravity_desktop"),
        adapter_version: "antigravity-transcript-jsonl-v1",
        privacy_policy: "redacted-projection-scrub-before-persist",
        checkpoint: CONTENT_FINGERPRINT_CHECKPOINT,
        lanes: &[
            lane(
                ProviderLane::SessionMetadata,
                AdapterSupport::Supported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Transcript,
                AdapterSupport::Supported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::ToolCalls,
                AdapterSupport::Supported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::McpEvents,
                AdapterSupport::Partial,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Skills,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Hooks,
                AdapterSupport::Unsupported,
                Coverage::NotObserved,
            ),
            lane(
                ProviderLane::Usage,
                AdapterSupport::Partial,
                Coverage::NotObserved,
            ),
        ],
    },
];

/// All definitions, for in-process health/forwarding/projection consumers.
pub const fn definitions() -> &'static [ProviderDefinition] {
    PROVIDERS
}

pub fn definition(provider: Provider) -> &'static ProviderDefinition {
    PROVIDERS
        .iter()
        .find(|definition| definition.provider == provider)
        .expect("every Provider has a registry definition")
}

/// Resolve the provider represented by one persisted scanner source kind.
/// Unknown and generic files intentionally do not inherit Claude support.
pub fn provider_for_source_kind(source_kind: &str) -> Option<Provider> {
    if source_kind == "antigravity_cli" {
        return Some(Provider::Antigravity);
    }
    definitions()
        .iter()
        .find(|definition| definition.source_kind == Some(source_kind))
        .map(|definition| definition.provider)
}

/// Resolve the provider's primary persisted scanner source kind.
pub fn source_kind_for_provider(provider: Provider) -> Option<&'static str> {
    definition(provider).source_kind
}

/// Normalize a provider alias only when it has an approved transcript source
/// adapter. Agent Observatory and OTLP use this at their trust boundary so
/// they cannot separately grow a list of transcript-capable providers.
pub fn canonical_transcript_provider(value: &str) -> Option<&'static str> {
    Provider::from_alias(value)
        .filter(|provider| source_kind_for_provider(*provider).is_some())
        .map(Provider::canonical_name)
}

/// Runtime scanner-only coverage for one provider. This derives coverage from
/// persisted scanner sources, so a provider descriptor alone cannot turn an
/// unavailable lane into an `observed` one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProviderRuntimeHealth {
    pub provider: String,
    pub source_count: usize,
    pub successful_sources: usize,
    pub failed_sources: usize,
    pub lanes: Vec<ProviderLaneHealth>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProviderLaneHealth {
    pub lane: String,
    /// Format support declared by the provider adapter, never runtime evidence.
    pub declared_support: String,
    pub coverage: String,
}

/// Return the bounded provider-runtime view used by scanner health callers.
///
/// Only `transcript_sources` is inspected: one source-kind aggregate query,
/// then a fixed four-provider/fourteen-lane maximum in memory. Forwarding, Observatory,
/// and OTLP consumers are deliberately not reported as wired until their
/// corresponding beads call this registry themselves.
pub fn runtime_health(pool: &crate::db::DbPool) -> Result<Vec<ProviderRuntimeHealth>> {
    let conn = pool.get()?;
    runtime_health_conn(&conn)
}

/// Same bounded projection as [`runtime_health`], using a caller-owned
/// connection so scanner health collection does not exhaust a single-slot DB
/// pool by checking out a second connection.
pub(crate) fn runtime_health_conn(
    conn: &rusqlite::Connection,
) -> Result<Vec<ProviderRuntimeHealth>> {
    // Source kinds are assigned before a source is persisted, so status need
    // not read or materialize the (potentially unbounded) canonical paths.
    // This returns at most one row for each transcript provider kind. EXISTS
    // also avoids expanding source rows by their import-record count.
    let mut stmt = conn.prepare(
        "SELECT s.source_kind,
                COUNT(*) AS source_count,
                SUM(CASE
                    WHEN s.last_error IS NULL
                     AND EXISTS (
                        SELECT 1
                        FROM transcript_import_records r
                        WHERE r.source_id = s.id
                     )
                    THEN 1 ELSE 0
                END) AS successful_sources,
                SUM(CASE WHEN s.last_error IS NOT NULL THEN 1 ELSE 0 END) AS failed_sources
         FROM transcript_sources s
         WHERE s.source_kind IN (
             'claude_project', 'codex_session', 'gemini_session',
             'antigravity_desktop', 'antigravity_cli'
         )
         GROUP BY s.source_kind",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut counts = [(0usize, 0usize, 0usize); 4];
    for (source_kind, source_count, successful_sources, failed_sources) in rows {
        let Some(provider) = provider_for_source_kind(&source_kind) else {
            continue;
        };
        let count = &mut counts[provider_index(provider)];
        count.0 += usize::try_from(source_count)?;
        count.1 += usize::try_from(successful_sources)?;
        count.2 += usize::try_from(failed_sources)?;
    }

    Ok(definitions()
        .iter()
        .map(|definition| {
            let (source_count, successful_sources, failed_sources) =
                counts[provider_index(definition.provider)];
            ProviderRuntimeHealth {
                provider: definition.canonical_name.to_string(),
                source_count,
                successful_sources,
                failed_sources,
                lanes: ALL_LANES
                    .iter()
                    .map(|lane| ProviderLaneHealth {
                        lane: lane_name(*lane).to_string(),
                        declared_support: definition.support(*lane).as_str().to_string(),
                        coverage: runtime_coverage(
                            *lane,
                            definition.support(*lane),
                            source_count,
                            successful_sources,
                            failed_sources,
                        )
                        .as_str()
                        .to_string(),
                    })
                    .collect(),
            }
        })
        .collect())
}

const ALL_LANES: &[ProviderLane] = &[
    ProviderLane::SessionMetadata,
    ProviderLane::Transcript,
    ProviderLane::ToolCalls,
    ProviderLane::McpEvents,
    ProviderLane::Skills,
    ProviderLane::Hooks,
    ProviderLane::Usage,
];

fn provider_index(provider: Provider) -> usize {
    match provider {
        Provider::Claude => 0,
        Provider::Codex => 1,
        Provider::Gemini => 2,
        Provider::Antigravity => 3,
    }
}

pub const fn lane_name(lane: ProviderLane) -> &'static str {
    match lane {
        ProviderLane::SessionMetadata => "session_metadata",
        ProviderLane::Transcript => "transcript",
        ProviderLane::ToolCalls => "tool_calls",
        ProviderLane::McpEvents => "mcp_events",
        ProviderLane::Skills => "skills",
        ProviderLane::Hooks => "hooks",
        ProviderLane::Usage => "usage",
    }
}

fn runtime_coverage(
    lane: ProviderLane,
    declared: AdapterSupport,
    source_count: usize,
    successful_sources: usize,
    failed_sources: usize,
) -> Coverage {
    // The transcript scanner persists only transcript import receipts. It has
    // no durable per-source receipts for tools, MCP, skills, hooks, usage, or
    // metadata, so those lanes remain `not_observed` even when an adapter
    // advertises format support. Later ingest/projection beads must add their
    // own receipt-backed lane logic rather than inherit this status.
    if lane != ProviderLane::Transcript || declared == AdapterSupport::Unsupported {
        return Coverage::NotObserved;
    }
    if successful_sources > 0 && failed_sources > 0 {
        Coverage::Partial
    } else if successful_sources > 0 {
        Coverage::Observed
    } else if source_count > 0 && failed_sources == source_count {
        Coverage::Failed
    } else {
        Coverage::NotObserved
    }
}

#[cfg(test)]
#[path = "providers_tests.rs"]
mod tests;
