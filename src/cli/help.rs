//! Top-level and per-command help, rendered in the Aurora-styled grouped
//! layout (modeled on `axon help`).
//!
//! Cortex is hand-rolled (no clap), so the command catalog is the single
//! source of truth here: each [`CommandDoc`] carries a one-line `summary` for
//! the grouped top-level listing and the detailed `usage` lines for
//! `cortex <command> --help`. The `catalog_covers_every_parser_token` test
//! guards against a command being added to the parser but not documented here.
//!
//! Color is built directly from the exported `*_ANSI` consts based on a `color`
//! flag the caller resolves once (via [`super::color`]) — so the render
//! functions stay pure and testable with `color = false`.

use super::color::{self, CYAN_ANSI, MUTED_ANSI, PRIMARY_ANSI};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

const TAGLINE: &str = "Syslog intelligence for homelabs";

/// One documented top-level command (or namespace root).
struct CommandDoc {
    /// Top-level token as typed, e.g. `search`, `sessions`, `db`.
    name: &'static str,
    /// One-line description for the grouped top-level listing.
    summary: &'static str,
    /// Detailed invocation/flag lines for `cortex <name> --help`.
    usage: &'static [&'static str],
}

struct NestedCommandDoc {
    /// Full path after `cortex`, e.g. `sessions search`.
    path: &'static str,
    summary: &'static str,
    usage: &'static [&'static str],
}

/// Section title → ordered command names. Drives the grouped `Commands` block;
/// every catalog entry must appear in exactly one section.
const SECTIONS: &[(&str, &[&str])] = &[
    (
        "Search & Logs",
        &[
            "search",
            "filter",
            "tail",
            "hosts",
            "apps",
            "artifactevents",
            "entity",
            "graph",
        ],
    ),
    (
        "Analytics & Correlation",
        &["analysis", "correlate", "state", "stats", "timeline"],
    ),
    ("AI Transcripts", &["sessions", "assess"]),
    ("Signals & Alerts", &["alerts"]),
    ("Ingestion", &["ingest", "heartbeat"]),
    (
        "Runtime & Setup",
        &[
            "serve",
            "mcp",
            "doctor",
            "status",
            "db",
            "compose",
            "setup",
            "update",
            "config",
            "completions",
        ],
    ),
];

const CATALOG: &[CommandDoc] = &[
    // ── Search & Logs ──────────────────────────────────────────────────────
    CommandDoc {
        name: "search",
        summary: "Full-text search across all logs",
        usage: &[
            "cortex search [query] [--grep TEXT] [--host HOST] [--source SOURCE] [--severity LEVEL] [--app APP] [--facility FACILITY] [--exclude-facility FACILITY] [--since TIME] [--until TIME] [--received-since TIME] [--received-until TIME] [--limit N] [--json]    (TIME accepts 1h, 2d, yesterday, or RFC3339)",
        ],
    },
    CommandDoc {
        name: "filter",
        summary: "Filter logs by structured fields (host, container, severity…)",
        usage: &[
            "cortex filter [--host HOST] [--source SOURCE] [--source-kind KIND] [--tool TOOL] [--project PATH] [--session-id ID] [--container NAME] [--docker-host HOST] [--stream stdout|stderr] [--event-action ACTION] [--severity LEVEL] [--app APP] [--facility FACILITY] [--exclude-facility FACILITY] [--since TIME] [--until TIME] [--received-since TIME] [--received-until TIME] [--limit N] [--json]",
        ],
    },
    CommandDoc {
        name: "tail",
        summary: "Show the most recent log lines",
        usage: &["cortex tail [-n N] [--host HOST] [--source SOURCE] [--app APP] [--json]"],
    },
    CommandDoc {
        name: "hosts",
        summary: "List hosts, source identities, and silent hosts",
        usage: &[
            "cortex hosts [--json]",
            "cortex hosts sources [--limit N] [--offset N] [--json]",
            "cortex hosts silent [--silent-minutes N] [--json]",
        ],
    },
    CommandDoc {
        name: "entity",
        summary: "Resolve a graph entity by type/key or alias",
        usage: &[
            "cortex entity <entity-type> <key> [--limit N] [--json]",
            "cortex entity <entity-type:key> [--json]",
            "cortex entity --alias-type TYPE --alias-key KEY [--limit N] [--json]",
        ],
    },
    CommandDoc {
        name: "graph",
        summary: "Explore one-hop graph neighborhoods with evidence",
        usage: &[
            "cortex graph around <entity-type> <key> [--limit N] [--depth 1] [--evidence-sample-limit N] [--payload-budget BYTES] [--json]",
            "cortex graph around <entity-type:key> [--json]",
            "cortex graph around --entity-id ID [--limit N] [--json]",
            "cortex graph explain <entity-type> <key> [--depth 2] [--beam-width N] [--max-chains N] [--json]",
            "cortex graph explain <entity-type:key> [--json]",
            "cortex graph explain --entity-id ID [--depth 2] [--json]",
            "cortex graph evidence <evidence-id> [--payload-budget BYTES] [--json]",
            "cortex graph status [--json]",
            "cortex graph rebuild [--json]",
        ],
    },
    // ── Analytics & Correlation ────────────────────────────────────────────
    CommandDoc {
        name: "stats",
        summary: "Database and ingest statistics",
        usage: &[
            "cortex stats [--json]",
            "cortex stats ingestrate [--by-host] [--json]",
        ],
    },
    CommandDoc {
        name: "timeline",
        summary: "Log volume over time, bucketed",
        usage: &[
            "cortex timeline [--bucket minute|hour|day] [--group-by FIELD] [--host HOST] [--app APP] [--severity-min LEVEL] [--since TIME] [--until TIME] [--json]",
        ],
    },
    CommandDoc {
        name: "apps",
        summary: "Top application/program names by volume",
        usage: &[
            "cortex apps [--host HOST] [--since TIME] [--until TIME] [--limit N] [--offset N] [--json]",
        ],
    },
    CommandDoc {
        name: "artifactevents",
        summary: "Query source-attributed artifact ecosystem evidence",
        usage: &[
            "cortex artifactevents [--event-kind KIND] [--artifact-id ID] [--revision-id ID] [--content-digest sha256:HEX] [--correlation-id ID] [--request-id ID] [--target-id ID] [--source-system SOURCE] [--since TIME] [--until TIME] [--limit N] [--json]",
        ],
    },
    CommandDoc {
        name: "correlate",
        summary: "Correlate events around a reference time, or a query-derived anchor",
        usage: &[
            "cortex correlate events [TIME] [--window-minutes N] [--severity-min LEVEL] [--host HOST] [--source SOURCE] [--query FTS] [--limit N] [--json]",
        ],
    },
    CommandDoc {
        name: "sessions",
        summary: "AI transcript search, correlation, and indexing",
        usage: &[
            "cortex sessions search QUERY [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--json]",
            "cortex sessions abuse [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--before N] [--after N] [--term WORD] [--json]",
            "cortex sessions incidents [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--window-minutes N] [--term WORD] [--json]",
            "cortex sessions investigate [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--window-minutes N] [--correlation-window-minutes N] [--term WORD] [--detail compact|full] [--include-transcript] [--max-bytes N] [--json]",
            "cortex sessions assess INCIDENT_ID [--model MODEL] [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--window-minutes N] [--correlation-window-minutes N] [--term WORD] [--dry-run] [--json]",
            "cortex sessions correlate [--project PATH] [--tool TOOL] [--session-id ID] [--ai-query FTS] [--log-query FTS] [--host HOST] [--source SOURCE] [--app APP] [--since TIME] [--until TIME] [--window-minutes N] [--severity-min LEVEL] [--limit N] [--events-per-anchor N] [--json]",
            "cortex sessions blocks [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--detail compact|full] [--json]",
            "cortex sessions context PROJECT [--tool TOOL] [--limit N] [--json]",
            "cortex sessions tools [--project PATH] [--since TIME] [--until TIME] [--json]",
            "cortex sessions projects [--tool TOOL] [--since TIME] [--until TIME] [--json]",
            "cortex sessions index [--path PATH] [--since TIME] [--force] [--json]",
            "cortex sessions add FILE [--force] [--json]",
            "cortex sessions watch [--path PATH] [--debounce-ms N] [--settle-ms N] [--max-retries N] [--no-initial-scan] [--json]",
            "cortex sessions checkpoints [--errors] [--missing] [--limit N] [--json]",
            "cortex sessions errors [--limit N] [--json]",
            "cortex sessions prunecheckpoints [--dry-run] [--limit N] [--json]",
            "cortex sessions doctor [--strict-permissions] [--json]",
            "cortex sessions watchstatus [--json]",
            "cortex sessions smokewatch [--json]",
            "cortex sessions hookevents [--hook NAME] [--hook-event EVENT] [--hook-source SOURCE] [--status STATUS] [--evidence-kind KIND] [--tool TOOL] [--project PATH] [--session-id ID] [--host HOST] [--since TIME] [--until TIME] [--limit N] [--json]",
            "cortex sessions hookincidents [HOOK] [--since TIME] [--limit N] [--json]",
            "cortex sessions hookinvestigate HOOK [--incident-id ID] [--limit N] [--json]",
            "cortex sessions hooksbackfill [--since TIME] [--limit N] [--dry-run] [--json]",
            "cortex sessions incidentcontext [QUERY] [--since TIME] [--until TIME] [--host HOST] [--app APP] [--limit N] [--json]",
            "cortex sessions llminvocations [--since TIME] [--action ACTION] [--status STATUS] [--limit N] [--json]",
            "cortex sessions skillincidents [SKILL] [--since TIME] [--limit N] [--json]",
            "cortex sessions skillinvestigate SKILL [--incident-id ID] [--limit N] [--json]",
            "cortex sessions skillassess SKILL [--no-llm] [--limit N] [--json]",
            "cortex sessions mcpevents [backfill] [--since TIME] [--limit N] [--dry-run] [--json]",
            "cortex sessions mcpincidents [SERVER] [--since TIME] [--limit N] [--json]",
            "cortex sessions mcpinvestigate TARGET [--incident-id ID] [--limit N] [--json]",
            "cortex sessions mcpassess TARGET [--no-llm] [--limit N] [--json]",
        ],
    },
    CommandDoc {
        name: "assess",
        summary: "LLM-guarded skill, abuse-incident, and hook assessment (LlmRunner, local-only)",
        usage: &[
            "cortex assess skill SKILL [--plugin NAME] [--model MODEL] [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--all] [--window-minutes N] [--correlation-window-minutes N] [--no-llm] [--json]",
            "cortex assess skill --plugin NAME [--model MODEL] [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--all] [--window-minutes N] [--correlation-window-minutes N] [--no-llm] [--json]",
            "cortex assess abuse [--incident-id ID] [--model MODEL] [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--window-minutes N] [--correlation-window-minutes N] [--no-llm] [--json]",
            "cortex assess hooks [--hook NAME] [--hook-event EVENT] [--hook-source SOURCE] [--model MODEL] [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--all] [--window-minutes N] [--correlation-window-minutes N] [--no-llm] [--collect-config] [--json]",
        ],
    },
    CommandDoc {
        name: "analysis",
        summary: "Error, incident, pattern, anomaly, and comparison analysis",
        usage: &[
            "cortex analysis errors [--since TIME] [--until TIME] [--limit N] [--json]",
            "cortex analysis incident [TIME] [--minutes N] [--service SERVICE] [--host HOST] [--limit N] [--json]",
            "cortex analysis patterns [--since TIME] [--until TIME] [--host HOST] [--app APP] [--severity-min LEVEL] [--limit N] [--json]",
            "cortex analysis anomalies [--recent-minutes N] [--baseline-minutes N] [--json]",
            "cortex analysis compare [--a-from TIME --a-to TIME --b-from TIME --b-to TIME] [--json]",
        ],
    },
    CommandDoc {
        name: "state",
        summary: "Host and fleet state views",
        usage: &[
            "cortex state host [HOST] [--since TIME] [--limit N] [--json]",
            "cortex state host --host-id ID [--since TIME] [--limit N] [--json]",
            "cortex state fleet [--exclude-ok] [--sort pressure|freshness|hostname] [--json]",
            "cortex state clockskew [--since TIME] [--limit N] [--json]",
        ],
    },
    CommandDoc {
        name: "ingest",
        summary: "Manual ingest and ingest-source management",
        usage: &[
            "cortex ingest shell user index PATH [--shell zsh] [--json]",
            "cortex ingest shell user atuinindex [PATH] [--json]",
            "cortex ingest shell agent index PATH [--json] [--server URL] [--token TOKEN]",
            "cortex ingest shell agent wrap SPOOL -- COMMAND...",
            "cortex ingest inventory refresh|status [--json]",
            "cortex ingest filetail list|status [--json]",
            "cortex ingest filetail add PATH [--id ID] [--tag TAG] [--host HOST] [--facility FACILITY] [--severity SEVERITY] [--from-start] [--json]",
            "cortex ingest filetail remove|enable|disable ID [--json]",
        ],
    },
    CommandDoc {
        name: "alerts",
        summary: "Error signatures and notification firings",
        usage: &[
            "cortex alerts signatures [--include-acknowledged] [--limit N] [--json]",
            "cortex alerts signatures ack HASH [--notes TEXT] [--json]",
            "cortex alerts signatures unack HASH [--reason TEXT] [--json]",
            "cortex alerts notifications [--rule-id ID] [--since TIME] [--limit N] [--json]",
            "cortex alerts notifications test [--body TEXT] [--json]   (requires --http)",
        ],
    },
    CommandDoc {
        name: "heartbeat",
        summary: "Run the host heartbeat agent",
        usage: &[
            "cortex heartbeat agent [--target URL] [--token TOKEN] [--interval-secs N] [--probe-deadline-ms N] [--collection-deadline-ms N] [--retry-buffer N] [--host-id-path PATH] [--once|--emit] [--json]",
        ],
    },
    // ── Runtime & Setup ────────────────────────────────────────────────────
    CommandDoc {
        name: "serve",
        summary: "Start the full server (ingest + HTTP MCP)",
        usage: &["cortex serve mcp     Start syslog UDP/TCP ingest plus HTTP MCP server"],
    },
    CommandDoc {
        name: "mcp",
        summary: "Start query-only MCP stdio transport",
        usage: &["cortex mcp"],
    },
    CommandDoc {
        name: "doctor",
        summary: "Run all health checks (setup, compose, binary, ingestion, heartbeats, AI)",
        usage: &[
            "cortex doctor [--json] [--fix] [--yes]",
            "cortex doctor binary [--json]",
        ],
    },
    CommandDoc {
        name: "status",
        summary: "Local-mode health snapshot (DB, maintenance, file-tails)",
        usage: &["cortex status [--json]"],
    },
    CommandDoc {
        name: "db",
        summary: "Database maintenance (status/integrity/vacuum/backup)",
        usage: &[
            "cortex db status [--check-coord] [--json]",
            "cortex db integrity [--quick] [--json]",
            "cortex db checkpoint [--mode passive|full|restart|truncate] [--json]",
            "cortex db vacuum [--pages N|--full] [--force] [--json]",
            "cortex db backup [--output PATH] [--json]",
        ],
    },
    CommandDoc {
        name: "compose",
        summary: "Manage the Docker Compose stack",
        usage: &[
            "cortex compose doctor [--json]",
            "cortex compose status [--compose-file FILE] [--project-dir DIR] [--project-name NAME] [--json]",
            "cortex compose pull|up|restart [--dry-run] [--allow-cwd-target] [--json]",
            "cortex compose down --yes [--dry-run] [--allow-cwd-target] [--json]",
            "cortex compose logs [SERVICE] [--since TIME] [--until TIME] [--tail N] [--json]",
        ],
    },
    CommandDoc {
        name: "setup",
        summary: "Initialize, check, and repair configuration",
        usage: &[
            "cortex setup check|repair [--json]",
            "cortex setup sessionstimer install|remove|check [--json]",
            "cortex setup sessionswatch install|remove|check [--json]",
            "cortex setup sessionshealth [--json]",
            "cortex setup shell agent install|remove|check [--json]",
            "cortex setup shell completions install|remove|check [--json]",
            "cortex setup heartbeatagent install|remove|check [--json]",
            "cortex setup debugwrapper install|remove|check [--json]",
            "cortex setup debugcompose install|remove|check [--json]",
            "cortex setup deploy preflight|local|remote|agent [OPTIONS]",
            "cortex setup pluginhook [--no-repair] [--json]",
            "cortex setup doctor [--json]",
        ],
    },
    CommandDoc {
        name: "update",
        summary: "Update the configured Cortex server and host-agent clients",
        usage: &["cortex update [all|server|clients|agents] [--dry-run] [--json]"],
    },
    CommandDoc {
        name: "config",
        summary: "Read and write configuration entries",
        usage: &[
            "cortex config get KEY [--env|--toml] [--toml-path PATH] [--json]",
            "cortex config set KEY VALUE [--env|--toml] [--toml-path PATH] [--json]",
            "cortex config unset KEY [--env|--toml] [--toml-path PATH] [--json]",
            "cortex config list [--env|--toml] [--toml-path PATH] [--json]",
        ],
    },
    CommandDoc {
        name: "completions",
        summary: "Print a shell completion script",
        usage: &["cortex completions zsh"],
    },
];

const NESTED_CATALOG: &[NestedCommandDoc] = &[
    NestedCommandDoc {
        path: "ingest inventory",
        summary: "Collect native homelab inventory into the private filesystem cache",
        usage: &[
            "cortex ingest inventory refresh [--json]",
            "cortex ingest inventory status [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions search",
        summary: "Full-text search over indexed AI transcript sessions",
        usage: &[
            "cortex sessions search QUERY [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions abuse",
        summary: "Find risky or failure-related transcript messages",
        usage: &[
            "cortex sessions abuse [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--before N] [--after N] [--term WORD] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions incidents",
        summary: "Cluster AI transcript abuse matches into incidents",
        usage: &[
            "cortex sessions incidents [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--window-minutes N] [--term WORD] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions investigate",
        summary: "Expand AI incidents into evidence bundles",
        usage: &[
            "cortex sessions investigate [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--window-minutes N] [--correlation-window-minutes N] [--term WORD] [--detail compact|full] [--include-transcript] [--max-bytes N] [--json]",
            "Default output is compact; use --detail full for complete evidence.",
        ],
    },
    NestedCommandDoc {
        path: "sessions assess",
        summary: "Assess one AI incident with optional model context",
        usage: &[
            "cortex sessions assess INCIDENT_ID [--model MODEL] [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--window-minutes N] [--correlation-window-minutes N] [--term WORD] [--dry-run] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions correlate",
        summary: "Correlate AI transcript anchors with non-AI logs",
        usage: &[
            "cortex sessions correlate [--project PATH] [--tool TOOL] [--session-id ID] [--ai-query FTS] [--log-query FTS] [--host HOST] [--source SOURCE] [--app APP] [--since TIME] [--until TIME] [--window-minutes N] [--severity-min LEVEL] [--limit N] [--events-per-anchor N] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions blocks",
        summary: "AI transcript activity grouped into 5-hour UTC blocks",
        usage: &[
            "cortex sessions blocks [--project PATH] [--tool TOOL] [--since TIME] [--until TIME] [--limit N] [--detail compact|full] [--json]",
            "Default output is capped for interactive use; use --detail full for every block.",
        ],
    },
    NestedCommandDoc {
        path: "sessions context",
        summary: "Recent AI transcript context for one project",
        usage: &["cortex sessions context PROJECT [--tool TOOL] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions tools",
        summary: "List AI tools present in transcript metadata",
        usage: &["cortex sessions tools [--project PATH] [--since TIME] [--until TIME] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions projects",
        summary: "List AI projects present in transcript metadata",
        usage: &["cortex sessions projects [--tool TOOL] [--since TIME] [--until TIME] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions index",
        summary: "Index local AI transcript roots",
        usage: &["cortex sessions index [--path PATH] [--since TIME] [--force] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions add",
        summary: "Index one AI transcript file",
        usage: &["cortex sessions add FILE [--force] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions watch",
        summary: "Run the local transcript watch daemon",
        usage: &[
            "cortex sessions watch [--path PATH] [--debounce-ms N] [--settle-ms N] [--max-retries N] [--no-initial-scan] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions checkpoints",
        summary: "List AI transcript indexing checkpoints",
        usage: &["cortex sessions checkpoints [--errors] [--missing] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions errors",
        summary: "List AI transcript parse errors",
        usage: &["cortex sessions errors [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions prunecheckpoints",
        summary: "Prune stale AI indexing checkpoints",
        usage: &["cortex sessions prunecheckpoints [--dry-run] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions doctor",
        summary: "Check local AI transcript indexing prerequisites",
        usage: &["cortex sessions doctor [--strict-permissions] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions watchstatus",
        summary: "Inspect the local AI transcript watch service",
        usage: &["cortex sessions watchstatus [--json]"],
    },
    NestedCommandDoc {
        path: "sessions smokewatch",
        summary: "Run a local AI transcript watch smoke test",
        usage: &["cortex sessions smokewatch [--json]"],
    },
    NestedCommandDoc {
        path: "sessions similar",
        summary: "Find incidents similar to a free-text query",
        usage: &[
            "cortex sessions similar QUERY [--host HOST] [--app APP] [--severity-min LEVEL] [--since TIME] [--until TIME] [--window-minutes N] [--limit N] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions incidentcontext",
        summary: "Build incident context from a recent or explicit time window",
        usage: &[
            "cortex sessions incidentcontext [QUERY] [--since TIME] [--until TIME] [--host HOST] [--app APP] [--severity-min LEVEL] [--limit N] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions llminvocations",
        summary: "Inspect recent LLM invocation audit records",
        usage: &[
            "cortex sessions llminvocations [--since TIME] [--action ACTION] [--status STATUS] [--limit N] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions skillincidents",
        summary: "List skill-usage incidents",
        usage: &[
            "cortex sessions skillincidents [SKILL] [--since TIME] [--until TIME] [--limit N] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions skillinvestigate",
        summary: "Investigate incidents for one skill",
        usage: &["cortex sessions skillinvestigate SKILL [--incident-id ID] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions skillassess",
        summary: "Assess one skill with deterministic evidence and optional LLM synthesis",
        usage: &["cortex sessions skillassess SKILL [--no-llm] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions mcpevents",
        summary: "List or backfill MCP tool-call events",
        usage: &[
            "cortex sessions mcpevents [--since TIME] [--limit N] [--json]",
            "cortex sessions mcpevents backfill [--since TIME] [--limit N] [--dry-run] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions mcpincidents",
        summary: "List MCP tool-usage incidents",
        usage: &["cortex sessions mcpincidents [SERVER] [--since TIME] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions mcpinvestigate",
        summary: "Investigate incidents for one MCP server or tool",
        usage: &["cortex sessions mcpinvestigate TARGET [--incident-id ID] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions mcpassess",
        summary: "Assess one MCP server or tool with optional LLM synthesis",
        usage: &["cortex sessions mcpassess TARGET [--no-llm] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions hookevents",
        summary: "List collected hook execution events",
        usage: &[
            "cortex sessions hookevents [--hook NAME] [--status STATUS] [--since TIME] [--limit N] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "sessions hookincidents",
        summary: "List hook execution incidents",
        usage: &["cortex sessions hookincidents [HOOK] [--since TIME] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions hookinvestigate",
        summary: "Investigate incidents for one hook",
        usage: &["cortex sessions hookinvestigate HOOK [--incident-id ID] [--limit N] [--json]"],
    },
    NestedCommandDoc {
        path: "sessions hooksbackfill",
        summary: "Backfill hook events from transcripts",
        usage: &["cortex sessions hooksbackfill [--since TIME] [--limit N] [--dry-run] [--json]"],
    },
    NestedCommandDoc {
        path: "db backup",
        summary: "Create a WAL-safe SQLite backup",
        usage: &["cortex db backup [PATH] [--json]"],
    },
    NestedCommandDoc {
        path: "db status",
        summary: "Inspect SQLite maintenance state",
        usage: &["cortex db status [--check-coord] [--json]"],
    },
    NestedCommandDoc {
        path: "db integrity",
        summary: "Run SQLite integrity checks",
        usage: &[
            "cortex db integrity [--quick] [--background] [--json]",
            "cortex db integrity status JOB_ID [--json]",
        ],
    },
    NestedCommandDoc {
        path: "db checkpoint",
        summary: "Run a SQLite WAL checkpoint",
        usage: &["cortex db checkpoint [passive|full|restart|truncate] [--json]"],
    },
    NestedCommandDoc {
        path: "db vacuum",
        summary: "Run SQLite incremental or full vacuum",
        usage: &["cortex db vacuum [--pages N] [--full] [--force] [--json]"],
    },
    NestedCommandDoc {
        path: "compose status",
        summary: "Inspect the resolved Docker Compose runtime",
        usage: &[
            "cortex compose status [--compose-file PATH] [--project-dir DIR] [--project-name NAME] [--service NAME] [--container NAME] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "compose doctor",
        summary: "Diagnose Docker Compose/listener ownership",
        usage: &[
            "cortex compose doctor [--compose-file PATH] [--project-dir DIR] [--project-name NAME] [--service NAME] [--container NAME] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "compose pull",
        summary: "Pull the resolved Docker Compose image",
        usage: &["cortex compose pull [--dry-run] [--allow-cwd-target] [--json]"],
    },
    NestedCommandDoc {
        path: "compose up",
        summary: "Recreate the resolved Docker Compose service",
        usage: &["cortex compose up [--dry-run] [--allow-cwd-target] [--json]"],
    },
    NestedCommandDoc {
        path: "compose restart",
        summary: "Restart the resolved Docker Compose service",
        usage: &["cortex compose restart [--dry-run] [--allow-cwd-target] [--json]"],
    },
    NestedCommandDoc {
        path: "compose down",
        summary: "Stop the resolved Docker Compose service",
        usage: &["cortex compose down --yes [--dry-run] [--allow-cwd-target] [--json]"],
    },
    NestedCommandDoc {
        path: "compose logs",
        summary: "Show bounded stack logs or one service's logs",
        usage: &[
            "cortex compose logs [--tail N] [--json]",
            "cortex compose logs SERVICE [--since TIME] [--until TIME] [--tail N] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "setup check",
        summary: "Audit plugin setup without changing files",
        usage: &["cortex setup check [--json]"],
    },
    NestedCommandDoc {
        path: "setup repair",
        summary: "Repair plugin setup idempotently",
        usage: &["cortex setup repair [--json]"],
    },
    NestedCommandDoc {
        path: "setup install",
        summary: "Install plugin setup artifacts",
        usage: &["cortex setup install [--json]"],
    },
    NestedCommandDoc {
        path: "setup pluginhook",
        summary: "Run plugin setup hook repair or audit mode",
        usage: &["cortex setup pluginhook [--no-repair] [--json]"],
    },
    NestedCommandDoc {
        path: "setup deploy",
        summary: "Provision cortex locally or on remote hosts",
        usage: &[
            "cortex setup deploy preflight [--json]",
            "cortex setup deploy local [--dry-run] [--json]",
            "cortex setup deploy remote [--home PATH] HOST [--dry-run] [--json]",
            "cortex setup deploy agent [--hosts h1,h2] [--target URL] [--heartbeat-token-file PATH] [--docker] [--journald] [--binary PATH]",
        ],
    },
    NestedCommandDoc {
        path: "update",
        summary: "Update the configured server and host-agent clients",
        usage: &[
            "cortex update [all|server|clients|agents] [--dry-run] [--json]",
            "cortex update server [--dry-run] [--json]",
            "cortex update clients [--dry-run] [--json] [--binary PATH]",
            "cortex update agents [--dry-run] [--json] [--binary PATH]",
            "cortex update config server --host HOST --home PATH [--json]",
            "cortex update config clients --hosts h1,h2 [--target URL] [--docker] [--journald] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "setup doctor",
        summary: "Run setup diagnostics across all phases",
        usage: &["cortex setup doctor [--json]"],
    },
    NestedCommandDoc {
        path: "alerts signatures",
        summary: "List error signatures",
        usage: &[
            "cortex alerts signatures [--include-acknowledged] [--limit N] [--json]",
            "cortex alerts signatures ack HASH [--notes TEXT] [--json]",
            "cortex alerts signatures unack HASH [--reason TEXT] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "alerts notifications",
        summary: "List recent notification firings",
        usage: &[
            "cortex alerts notifications [--rule-id ID] [--since TIME] [--limit N] [--json]",
            "cortex alerts notifications test [--body TEXT] [--json]   (requires --http)",
        ],
    },
    NestedCommandDoc {
        path: "ingest shell user",
        summary: "Index shell history typed by a human",
        usage: &[
            "cortex ingest shell user index PATH [--shell zsh] [--json]",
            "cortex ingest shell user atuinindex [PATH] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "ingest shell agent",
        summary: "Ingest AI-agent-issued shell commands",
        usage: &[
            "cortex ingest shell agent index PATH [--json] [--server URL] [--token TOKEN]",
            "cortex ingest shell agent wrap SPOOL -- COMMAND...",
        ],
    },
    NestedCommandDoc {
        path: "heartbeat agent",
        summary: "Run the host heartbeat agent",
        usage: &[
            "cortex heartbeat agent [--target URL] [--token TOKEN] [--interval-secs N] [--probe-deadline-ms N] [--collection-deadline-ms N] [--retry-buffer N] [--host-id-path PATH] [--once|--emit] [--json]",
        ],
    },
    NestedCommandDoc {
        path: "ingest filetail",
        summary: "List configured file-tail sources",
        usage: &[
            "cortex ingest filetail list [--json]",
            "cortex ingest filetail status [--json]",
            "cortex ingest filetail add PATH [--id ID] [--tag TAG] [--host HOST] [--facility FACILITY] [--severity SEVERITY] [--from-start] [--json]",
            "cortex ingest filetail remove ID [--json]",
            "cortex ingest filetail enable ID [--json]",
            "cortex ingest filetail disable ID [--json]",
        ],
    },
];

const GLOBAL_OPTIONS: &[(&str, &str)] = &[
    ("-h, --help", "Display help (top-level or per-command)"),
    ("--version", "Print version and exit"),
    ("--color <when>", "Colorize output: always, never, or auto"),
    (
        "--no-color",
        "Disable colored output (alias for --color=never)",
    ),
    (
        "--http",
        "Route through the container REST API instead of local SQLite (fail-closed)",
    ),
    (
        "--server <URL>",
        "API base URL (implies --http). Default: CORTEX_URL or http://127.0.0.1:3100",
    ),
    (
        "--token <TOKEN>",
        "Bearer token (implies --http). Default: CORTEX_API_TOKEN",
    ),
];

const ENVIRONMENT: &[(&str, &str)] = &[
    (
        "CORTEX_DB_PATH",
        "SQLite database path used by both transports",
    ),
    (
        "CORTEX_USE_HTTP",
        "Set 1/true to default to HTTP mode (fail-closed if discovery fails)",
    ),
    (
        "CORTEX_URL",
        "Default API base URL for --http (overridden by --server)",
    ),
    (
        "CORTEX_API_TOKEN",
        "Bearer token for --http (overridden by --token)",
    ),
    ("RUST_LOG", "Log filter; stdio logs always go to stderr"),
];

const QUICK_START: &[&str] = &[
    "cortex search \"oom killer\" --host web-01 --since 1h",
    "cortex search --grep \"smoke-test\"   # literal text, no FTS5 syntax",
    "cortex tail -n 50 --severity err",
    "cortex sessions investigate --window-minutes 30",
];

// ── Color helpers (pure: driven by the `color` flag) ────────────────────────

fn paint(color: bool, code: &str, text: &str) -> String {
    if color {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Bold cyan — section headers and category subheaders.
fn heading(color: bool, text: &str) -> String {
    if color {
        format!("{BOLD}{CYAN_ANSI}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Aligned `label  description` row. `label_code` colors the label (white for
/// command names, cyan for flags); the description is muted. Wraps to a second
/// line when the label is wider than `label_width`.
fn push_row(
    out: &mut String,
    color: bool,
    indent: usize,
    label_width: usize,
    label_code: &str,
    label: &str,
    desc: &str,
) {
    if label.chars().count() > label_width {
        out.push_str(&format!(
            "{:indent$}{}\n",
            "",
            paint(color, label_code, label),
            indent = indent
        ));
        out.push_str(&format!(
            "{:width$}{}\n",
            "",
            paint(color, MUTED_ANSI, desc),
            width = indent + label_width + 1
        ));
        return;
    }
    let padded = format!("{label:<label_width$}");
    out.push_str(&format!(
        "{:indent$}{} {}\n",
        "",
        paint(color, label_code, &padded),
        paint(color, MUTED_ANSI, desc),
        indent = indent
    ));
}

/// Render the full top-level help banner.
pub(crate) fn render_top_level(color: bool) -> String {
    let mut out = String::with_capacity(4096);

    out.push_str(&format!("  {}\n", heading(color, "CORTEX CLI")));
    out.push_str(&format!(
        "  {}\n",
        paint(color, CYAN_ANSI, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    ));
    out.push_str(&format!(
        "  Version {}  |  {}\n\n",
        env!("CARGO_PKG_VERSION"),
        paint(color, MUTED_ANSI, TAGLINE)
    ));

    out.push_str(&format!("  {}\n", heading(color, "Usage")));
    out.push_str(&format!(
        "  {}\n\n",
        paint(color, CYAN_ANSI, "cortex [options] <command> [args]")
    ));

    out.push_str(&format!("  {}\n", heading(color, "Quick Start")));
    for example in QUICK_START {
        out.push_str(&format!("  {}\n", paint(color, MUTED_ANSI, example)));
    }
    out.push('\n');

    out.push_str(&format!("  {}\n", heading(color, "Global Options")));
    for (flag, desc) in GLOBAL_OPTIONS {
        push_row(&mut out, color, 2, 28, CYAN_ANSI, flag, desc);
    }
    out.push('\n');

    out.push_str(&format!("  {}\n", heading(color, "Environment")));
    for (name, desc) in ENVIRONMENT {
        push_row(&mut out, color, 2, 28, CYAN_ANSI, name, desc);
    }
    out.push('\n');

    out.push_str(&format!("  {}\n", heading(color, "Commands")));
    for (section, names) in SECTIONS {
        out.push_str(&format!("  {}\n", paint(color, CYAN_ANSI, section)));
        for name in *names {
            if let Some(doc) = lookup(name) {
                push_row(&mut out, color, 4, 18, PRIMARY_ANSI, doc.name, doc.summary);
            }
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "  {}\n",
        paint(
            color,
            MUTED_ANSI,
            "→ Run cortex <command> --help for command-specific flags"
        )
    ));
    out
}

/// Render per-command help, or `None` if the command is unknown.
pub(crate) fn render_command(name: &str, color: bool) -> Option<String> {
    let mut out = String::with_capacity(512);
    // Header + usage differ between nested (`db status`) and top-level commands,
    // but both render the shared Examples block below.
    if let Some(doc) = nested_lookup(name) {
        out.push_str(&format!(
            "  {}  {}\n\n",
            heading(color, doc.path),
            paint(color, MUTED_ANSI, doc.summary)
        ));
        out.push_str(&format!("  {}\n", heading(color, "Usage")));
        for line in doc.usage {
            out.push_str(&format!("  {}\n", paint(color, CYAN_ANSI, line)));
        }
    } else {
        let doc = lookup(name)?;
        out.push_str(&format!(
            "  {}  {}\n\n",
            heading(color, doc.name),
            paint(color, MUTED_ANSI, doc.summary)
        ));
        out.push_str(&format!("  {}\n", heading(color, "Usage")));
        for line in doc.usage {
            out.push_str(&format!("  {}\n", paint(color, CYAN_ANSI, line)));
        }
    }
    // Copy-paste examples, sourced from the single ACTION_SPECS registry so they
    // stay in lockstep with the canonical flags. Rendered for both nested and
    // top-level help paths.
    let examples = crate::cli::registry_examples(name);
    if !examples.is_empty() {
        out.push('\n');
        out.push_str(&format!("  {}\n", heading(color, "Examples")));
        for ex in examples {
            out.push_str(&format!("  {}\n", paint(color, MUTED_ANSI, ex)));
        }
    }
    Some(out)
}

fn lookup(name: &str) -> Option<&'static CommandDoc> {
    CATALOG.iter().find(|d| d.name == name)
}

fn nested_lookup(path: &str) -> Option<&'static NestedCommandDoc> {
    NESTED_CATALOG.iter().find(|d| d.path == path)
}

fn is_known(name: &str) -> bool {
    lookup(name).is_some()
}

// ── Help-request interception ───────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HelpRequest {
    TopLevel,
    Command(String),
    None,
}

/// Classify a help request from the argv tail (program name already removed,
/// `--color`/`--no-color` already stripped). Stops at a `--` sentinel so
/// wrapped commands are untouched.
///
/// Help is recognized **positionally** (matching axon): the `--help`/`-h`
/// *flags* count anywhere (nobody queries those literals), but the bare word
/// `help` counts only in command position (`args[0]`). This keeps free-text
/// queries that contain "help" working — `cortex search help`,
/// `cortex sessions search help`, and `cortex sessions abuse --term help` all run the
/// query, not the help banner.
pub(crate) fn classify_help(args: &[String]) -> HelpRequest {
    let is_help_flag = |s: &str| matches!(s, "-h" | "--help");
    let scan: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .take_while(|a| *a != "--")
        .collect();
    if scan.is_empty() {
        return HelpRequest::None;
    }
    let has_help = scan.iter().any(|a| is_help_flag(a)) || scan.first() == Some(&"help");
    if !has_help {
        return HelpRequest::None;
    }
    // Build the command path, skipping the value consumed by a value-bearing
    // global option (`--server URL`, `--token TOK`). Otherwise
    // `cortex --server http://127.0.0.1:3100 db status --help` would treat the
    // URL as the command and fall back to the top-level banner instead of
    // resolving `db status`. (The `--flag=value` form is one `-`-prefixed token
    // and is already excluded.)
    const VALUE_FLAGS: [&str; 2] = ["--server", "--token"];
    let mut positionals = Vec::new();
    let mut skip_value = false;
    for &a in &scan {
        if skip_value {
            skip_value = false;
            continue;
        }
        if VALUE_FLAGS.contains(&a) {
            skip_value = true;
            continue;
        }
        if !a.starts_with('-') && a != "help" {
            positionals.push(a);
        }
    }
    if positionals.len() >= 2 {
        let nested = format!("{} {}", positionals[0], positionals[1]);
        if nested_lookup(&nested).is_some() {
            return HelpRequest::Command(nested);
        }
    }
    match positionals.first().copied() {
        Some(cmd) if is_known(cmd) => HelpRequest::Command(cmd.to_string()),
        _ => HelpRequest::TopLevel,
    }
}

/// Handle an explicit help request by printing to stdout and returning true
/// (caller should exit 0). Returns false when no help was requested.
pub(crate) fn maybe_handle_help(args: &[String]) -> bool {
    match classify_help(args) {
        HelpRequest::TopLevel => {
            print!("{}", render_top_level(color::color_enabled()));
            true
        }
        HelpRequest::Command(name) => {
            // Known by construction (classify only returns Command for known).
            if let Some(text) = render_command(&name, color::color_enabled()) {
                print!("{text}");
            }
            true
        }
        HelpRequest::None => false,
    }
}

/// Top-level help to stderr — used by error/misuse fallbacks (`print_usage`).
pub(crate) fn print_top_level_help_stderr() {
    eprint!("{}", render_top_level(color::color_enabled_stderr()));
}

#[cfg(test)]
#[path = "help_tests.rs"]
mod tests;
