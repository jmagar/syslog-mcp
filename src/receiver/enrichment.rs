//! Pre-insert enrichment for syslog batch entries.
//!
//! Two responsibilities:
//! 1. **Source-aware reclassification** — parse Authelia `level=` into a real
//!    syslog severity, classify AdGuard query results into
//!    `adguard-blocked` / `adguard-allowed` / `adguard-rewrite`.
//! 2. **Best-effort secret scrubbing** for AI-source records (claude/codex
//!    transcripts and OTLP records carrying their service.name) so accidental
//!    credential pastes don't end up FTS5-indexed.
//!
//! The scrubber is **defense-in-depth, not a compliance control** — regex has
//! structural bypass classes (multi-line wrapping, encoding obfuscation,
//! token formats not in the pattern list). Set `CORTEX_SCRUB_PROMPTS=false`
//! to disable.
//!
//! All regex patterns are compiled exactly once via `LazyLock` because
//! enrichment runs on the batch-writer hot path: per-record `Regex::new`
//! costs 10–50 ms each and would saturate the writer at any non-trivial
//! volume.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::{
    fs,
    path::{Path, PathBuf},
};

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::ai_project::normalize_ai_project_path;
use crate::db::LogBatchEntry;

/// Configuration for the enrichment pipeline. Built from environment variables
/// at runtime startup; cloned into the batch writer.
#[derive(Debug, Clone, Default)]
pub struct EnrichmentConfig {
    /// If `Some`, only apply Authelia enrichment when the entry's `source_ip`
    /// starts with this prefix. If `None`, apply to any entry whose
    /// `app_name` matches.
    pub authelia_source_ip: Option<String>,
    /// Same gating, for AdGuard.
    pub adguard_source_ip: Option<String>,
    /// Allowlist of sender IPs whose agent Docker metadata marker is trusted
    /// (octet-boundary semantics, see [`source_ip_matches`]). The marker rides
    /// the unauthenticated syslog message body, so without this gate any
    /// port-1514 sender can forge agent-docker identity (same trust class as
    /// the CEF `UNIFIdeviceName` gotcha).
    ///
    /// **Fail-closed:** an empty list rejects the marker from every sender.
    /// Extraction requires either a matching prefix here or an explicit
    /// [`Self::agent_docker_trust_any_source`] opt-in.
    pub agent_docker_source_prefixes: Vec<String>,
    /// Explicit opt-in to the pre-fail-closed behaviour: accept the agent
    /// Docker marker from *any* syslog sender. Only safe when every host that
    /// can reach the syslog port is trusted. Ignored when
    /// [`Self::agent_docker_source_prefixes`] already admits the sender.
    pub agent_docker_trust_any_source: bool,
    /// When `true`, redact known secret patterns from AI-source messages.
    pub scrub_prompts: bool,
    /// Optional API token value to add to the redaction set so a leaked token
    /// in tool output is scrubbed before FTS5 indexes it.
    pub api_token: Option<String>,
}

// --- compiled once at module load ----------------------------------------

/// Captures `level=...` from Authelia structured log lines.
static AUTHELIA_LEVEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\blevel=([A-Za-z]+)").expect("static regex"));

/// Common application logger prefix: optional wall-clock timestamp followed by
/// an uppercase level token. This intentionally does not match arbitrary
/// `level=...` text in a message body; source-specific formats such as Authelia
/// retain their dedicated parsers.
static STRUCTURED_LEVEL_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^\s*(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)?(?:\x1b\[[0-9;]*m\s*)?(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b",
    )
    .expect("static regex")
});

/// Capture the file="..." metadata from rsyslog imfile records.
static IMFILE_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("file=\"([^\"]+\\.(?:jsonl|json))\"").expect("static regex"));

static CLAUDE_PROJECT_INDEX_CACHE: LazyLock<Mutex<HashMap<PathBuf, Option<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Patterns scrubbed from AI-source message bodies. Each matches the entire
/// secret token; the matched text is replaced with `[REDACTED]`.
static SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    let raw = [
        // AWS access keys: AKIA, ASIA (STS), AGPA (group), AROA (role), AIDA (user)
        r"\b(?:AKIA|ASIA|AGPA|AROA|AIDA)[0-9A-Z]{16}\b",
        // GitHub tokens: gh[pousr]_<base62>
        r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        // GitHub fine-grained PATs
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        // Anthropic
        r"\bsk-ant-api03-[A-Za-z0-9_\-]{20,}\b",
        // OpenAI project keys
        r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b",
        // Standalone JWTs (3 base64url segments separated by `.`)
        r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        // Bearer tokens in Authorization headers (broad token charset incl. base64 +/=)
        r"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9._+/=\-]+",
        // Generic credential assignments. Match the key and value together so
        // delimiters cannot leave the secret behind in persisted text.
        r#"(?i)["']?\b(?:password|passphrase|api[_-]?key|token|access[_-]?token|refresh[_-]?token|id[_-]?token|secret|client[_-]?secret|credential(?:s)?|private[_-]?key)\b["']?\s*[:=]\s*["']?[^\s,;\}\]"']+["']?"#,
        // PEM private key block — match the WHOLE block including key body. (?s)
        // makes `.` cross newlines; lazy `.+?` stops at the first END marker.
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.+?-----END [A-Z ]*PRIVATE KEY-----",
    ];
    raw.into_iter()
        .map(|p| Regex::new(p).expect("static secret pattern"))
        .collect()
});

/// AI-source `app_name` values whose message bodies are eligible for scrubbing.
const AI_SOURCES: &[&str] = &[
    "claude-transcript",
    "codex-transcript",
    "gemini-transcript",
    "claude-code",
    "codex",
    "ai-transcript",
];

/// Minimal AdGuard query log row. AdGuard emits PascalCase JSON keys; the
/// container-level `rename_all` keeps Rust field names idiomatic snake_case.
/// `default` per field tolerates partial / future-incompatible payloads.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AdGuardQuery {
    #[serde(default)]
    result: AdGuardResult,
    #[serde(default)]
    upstream: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AdGuardResult {
    #[serde(default)]
    is_filtered: bool,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeSessionsIndex {
    #[serde(default)]
    original_path: Option<String>,
    #[serde(default)]
    entries: Vec<ClaudeSessionsIndexEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeSessionsIndexEntry {
    #[serde(default)]
    project_path: Option<String>,
}

// `AGENT_DOCKER_SOURCE_KIND` is the denormalised `metadata_json.source_kind`
// value written by the receiver when it extracts the agent Docker marker.
// Set from the shared constant, never from the (sender-controlled) marker
// payload.
use crate::agent::docker::{AGENT_DOCKER_META_MARKER, AGENT_DOCKER_SOURCE_KIND};

/// Apply enrichment to one entry. Pure function — never panics, never logs at
/// `error`. Parse failures fall through, leaving the entry unchanged.
pub(crate) fn enrich_entry(mut entry: LogBatchEntry, config: &EnrichmentConfig) -> LogBatchEntry {
    extract_agent_docker_metadata(&mut entry, config);
    enrich_ai_metadata(&mut entry);

    if let Some(level_severity) = extract_structured_level(&entry.message) {
        promote_severity(&mut entry.severity, level_severity);
    }

    if matches_app(&entry, "authelia")
        && source_ip_matches(&entry, config.authelia_source_ip.as_deref())
        && let Some(level_severity) = extract_authelia_level(&entry.message)
    {
        entry.severity = level_severity.to_string();
    }

    if matches_app(&entry, "adguard-query")
        && source_ip_matches(&entry, config.adguard_source_ip.as_deref())
        && let Some(new_app) = classify_adguard(&entry.message)
    {
        entry.app_name = Some(new_app.to_string());
    }

    if config.scrub_prompts && entry.app_name.as_deref().is_some_and(is_ai_source) {
        entry.message = scrub_secrets(&entry.message, config.api_token.as_deref());
    }

    entry
}

fn extract_structured_level(message: &str) -> Option<&'static str> {
    let level = STRUCTURED_LEVEL_PREFIX.captures(message)?.get(1)?.as_str();
    match level.to_ascii_lowercase().as_str() {
        "trace" | "debug" => Some("debug"),
        "info" => Some("info"),
        "warn" | "warning" => Some("warning"),
        "error" => Some("err"),
        "critical" | "fatal" => Some("crit"),
        _ => None,
    }
}

fn promote_severity(current: &mut String, candidate: &str) {
    fn rank(severity: &str) -> u8 {
        match severity {
            "emerg" => 0,
            "alert" => 1,
            "crit" => 2,
            "err" | "error" => 3,
            "warning" | "warn" => 4,
            "notice" => 5,
            "info" => 6,
            "debug" => 7,
            _ => u8::MAX,
        }
    }

    if rank(candidate) < rank(current) {
        *current = candidate.to_string();
    }
}

fn matches_app(entry: &LogBatchEntry, expected: &str) -> bool {
    entry.app_name.as_deref() == Some(expected)
}

/// Process-lifetime count of marker-bearing entries whose `source_ip` failed
/// the `agent_docker_source_prefixes` gate (see [`extract_agent_docker_metadata`]).
/// A blocked gate is otherwise only visible at `debug` log level, which is
/// off in production — this counter surfaces it via the `stats` MCP action
/// (`agent_docker_gate_blocked_count`) so operators can tell a misconfigured
/// prefix list from a quiet one.
static AGENT_DOCKER_GATE_BLOCKED_COUNT: AtomicU64 = AtomicU64::new(0);

/// Read the current value of [`AGENT_DOCKER_GATE_BLOCKED_COUNT`]. Cheap
/// (relaxed atomic load); safe to call on every `stats` request.
pub(crate) fn agent_docker_gate_blocked_count() -> u64 {
    AGENT_DOCKER_GATE_BLOCKED_COUNT.load(Ordering::Relaxed)
}

/// Whether `entry`'s transport-observed `source_ip` is trusted to assert
/// agent-docker identity.
///
/// Fail-closed: with no prefixes configured and no explicit
/// `agent_docker_trust_any_source` opt-in, this returns `false` for every
/// sender. `source_ip` is the only network-verified identity available here;
/// everything else in the record is sender-controlled.
fn agent_docker_source_trusted(entry: &LogBatchEntry, config: &EnrichmentConfig) -> bool {
    config
        .agent_docker_source_prefixes
        .iter()
        .any(|prefix| source_ip_matches(entry, Some(prefix)))
        || config.agent_docker_trust_any_source
}

/// Extract the agent Docker metadata prefix from `message` into
/// `metadata_json` and strip the marker from `message`. Malformed payloads
/// leave the entry untouched — the raw line is still stored and searchable.
///
/// **Trust boundary:** the marker rides the unauthenticated syslog body, so
/// the payload is sender-controlled. The merge is therefore scoped: only the
/// `agent_docker` object is accepted, it never overwrites a key already
/// present in `metadata_json`, and the denormalised `source_kind` is set
/// from [`AGENT_DOCKER_SOURCE_KIND`] rather than the payload.
///
/// **The source gate is fail-closed.** Extraction requires the entry's
/// `source_ip` to match an `agent_docker_source_prefixes` entry, or
/// `agent_docker_trust_any_source` to be explicitly enabled. An unconfigured
/// gate therefore rejects the marker rather than honouring it from every
/// sender — the syslog port is reachable by the whole fleet, so an empty
/// allowlist must mean "trust nobody", not "trust anybody".
fn extract_agent_docker_metadata(entry: &mut LogBatchEntry, config: &EnrichmentConfig) {
    let Some(payload_start) = entry.message.strip_prefix(AGENT_DOCKER_META_MARKER) else {
        return;
    };
    if !agent_docker_source_trusted(entry, config) {
        AGENT_DOCKER_GATE_BLOCKED_COUNT.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            source_ip = %entry.source_ip,
            hostname = %entry.hostname,
            gate_configured = !config.agent_docker_source_prefixes.is_empty(),
            "agent-docker marker present but source_ip is not trusted by the source gate; \
             marker left in message, identity not extracted"
        );
        return;
    }
    // The payload is a single JSON object; use the streaming deserializer to
    // find where it ends without guessing about braces inside strings.
    let mut stream = serde_json::Deserializer::from_str(payload_start).into_iter::<Value>();
    let Some(Ok(metadata)) = stream.next() else {
        return;
    };
    let Some(agent_docker) = metadata
        .get("agent_docker")
        .filter(|v| v.is_object())
        .cloned()
    else {
        return;
    };
    let consumed = stream.byte_offset();
    let rest = &payload_start[consumed..];
    let Some(rest) = rest.strip_prefix("] ").or_else(|| rest.strip_prefix(']')) else {
        return;
    };
    let lifecycle = agent_docker
        .get("stream")
        .and_then(Value::as_str)
        .is_some_and(|stream| stream == "event");

    // Ordering dependency: this extraction runs FIRST in `enrich_entry`, so
    // any pre-existing `metadata_json` here was set by the receiver/parser.
    // A non-object value (corrupt or non-JSON) is deliberately replaced with
    // a fresh object — later enrichment stages must keep running after this
    // one, not before, or their metadata would be discarded here.
    let mut merged = entry
        .metadata_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| Value::Object(Default::default()));
    if let Value::Object(target) = &mut merged {
        // Sender-controlled payload must never clobber parser-set keys.
        if target.contains_key("agent_docker") {
            return;
        }
        target.insert("agent_docker".to_string(), agent_docker.clone());
        target.insert(
            "source_kind".to_string(),
            Value::String(
                if lifecycle {
                    "docker-event"
                } else {
                    AGENT_DOCKER_SOURCE_KIND
                }
                .to_string(),
            ),
        );
        if lifecycle {
            let mut docker = serde_json::Map::new();
            for key in [
                "host",
                "container_id",
                "container_name",
                "compose_project",
                "compose_service",
                "image",
                "event_action",
                "exit_code",
            ] {
                if let Some(value) = agent_docker.get(key) {
                    docker.insert(key.to_string(), value.clone());
                }
            }
            target.insert("docker".to_string(), Value::Object(docker));
        }
    }
    // If the merged object would blow the metadata bound, truncation would
    // drop the `agent_docker` identity we just extracted. Back out instead:
    // the marker stays in the message, so identity is never silently lost.
    let Some(bounded) = crate::ingest_metadata::try_bounded_metadata_json(merged) else {
        return;
    };
    entry.message = rest.to_string();
    entry.metadata_json = Some(bounded);
    if lifecycle {
        // Keep transport-derived `source_ip` immutable. The asserted Docker
        // host/container/action remain queryable under metadata_json.docker.
        entry.facility = Some("docker".to_string());
    }
}

/// Match `entry.source_ip` against an operator-configured prefix at the
/// IP-octet boundary. Plain `starts_with` would let an attacker on
/// `10.0.0.10` (or `10.0.0.123`) pass a gate configured for `10.0.0.1`
/// because `"10.0.0.10:1234".starts_with("10.0.0.1")` is true. Two cases:
///
/// * **Subnet prefix** ending with `.` (e.g. `"10.0.0."`): match any IP
///   in the subnet — the byte after the prefix must be a digit (next octet).
/// * **Exact host** without trailing dot (e.g. `"10.0.0.5"`, `"2001:db8::1"`):
///   match only that IP — compare parsed addresses when both sides parse
///   (canonical-form insensitive), else compare the extracted IP string.
///
/// The source IP is parsed as a [`std::net::SocketAddr`] first, which handles
/// `"<ipv4>:<port>"` and bracketed IPv6 `"[<ipv6>]:<port>"`; a bare IP
/// without a port is parsed as [`std::net::IpAddr`]. Only if both parses fail
/// does the legacy `split(':')` string handling apply (which would truncate a
/// raw IPv6 literal — such values never reach it because they parse).
///
/// `None` or empty prefix preserves the legacy "apply to all matching
/// app_name" default.
fn source_ip_matches(entry: &LogBatchEntry, configured_prefix: Option<&str>) -> bool {
    let Some(prefix) = configured_prefix.filter(|p| !p.is_empty()) else {
        return true;
    };
    let source_ip = entry.source_ip.as_str();
    let parsed_ip: Option<std::net::IpAddr> = source_ip
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.ip())
        .or_else(|_| source_ip.parse::<std::net::IpAddr>())
        .ok();
    let ip_only = match &parsed_ip {
        Some(ip) => ip.to_string(),
        None => source_ip.split(':').next().unwrap_or("").to_string(),
    };
    if prefix.ends_with('.') {
        // Subnet match: prefix is a partial dotted-quad like "10.0.0."
        ip_only.starts_with(prefix)
    } else if let (Some(ip), Ok(prefix_ip)) = (parsed_ip, prefix.parse::<std::net::IpAddr>()) {
        // Exact-host match on parsed addresses: canonical-form insensitive
        // (e.g. `2001:0db8::1` matches `2001:db8::1`).
        ip == prefix_ip
    } else {
        // Exact-host match: prefix is a full IP literal
        ip_only == prefix
    }
}

fn extract_authelia_level(message: &str) -> Option<&'static str> {
    let cap = AUTHELIA_LEVEL.captures(message)?;
    let level = cap.get(1)?.as_str();
    Some(match level.to_ascii_lowercase().as_str() {
        "trace" | "debug" => "debug",
        "info" => "info",
        "warn" | "warning" => "warning",
        "error" => "err",
        "fatal" | "panic" => "crit",
        _ => return None,
    })
}

fn classify_adguard(message: &str) -> Option<&'static str> {
    let parsed: AdGuardQuery = serde_json::from_str(message).ok()?;
    if parsed.result.reason.contains("Rewrite") {
        return Some("adguard-rewrite");
    }
    if parsed.result.is_filtered {
        return Some("adguard-blocked");
    }
    if !parsed.upstream.is_empty() {
        return Some("adguard-allowed");
    }
    None
}

fn is_ai_source(app_name: &str) -> bool {
    AI_SOURCES.contains(&app_name)
}

fn enrich_ai_metadata(entry: &mut LogBatchEntry) {
    let Some(app_name) = entry.app_name.as_deref() else {
        return;
    };
    let Some(tool) = ai_tool_from_app(app_name) else {
        return;
    };
    entry.ai_tool = Some(tool.to_string());

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&entry.message) {
        fill_ai_metadata_from_json(entry, &value);
    }

    if let Some(path) = extract_imfile_path(&entry.raw) {
        entry.ai_transcript_path = Some(path.clone());
        if entry.ai_project.is_none() {
            entry.ai_project = project_from_transcript_path(&path);
        }
        if entry.ai_session_id.is_none() {
            entry.ai_session_id = session_id_from_path(&path);
        }
    }
}

fn ai_tool_from_app(app_name: &str) -> Option<&'static str> {
    match app_name {
        "claude-transcript" | "claude-code" => Some("claude"),
        "codex-transcript" | "codex" => Some("codex"),
        "gemini-transcript" => Some("gemini"),
        _ => None,
    }
}

fn extract_imfile_path(raw: &str) -> Option<String> {
    IMFILE_PATH
        .captures(raw)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

fn session_id_from_path(path: &str) -> Option<String> {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(str::to_string)
}

pub(crate) fn project_from_transcript_path(path: &str) -> Option<String> {
    if let Some(project) = project_from_sessions_index(path) {
        return Some(project);
    }
    if let Some(project_part) = path.split("/.claude/projects/").nth(1) {
        let encoded = project_part.split('/').next()?;
        return decode_claude_project(encoded).map(|project| normalize_ai_project_path(&project));
    }
    None
}

/// Decode a Claude project directory name back to a path.
///
/// Claude encodes project paths by replacing `/` with `-` and prefixing with `-`.
/// Example: `/home/user/code` -> `-home-user-code`.
///
/// This decoder is best-effort and lossy: it cannot distinguish between an
/// encoded `/` and a literal `-` in a directory name (e.g. `cortex` vs
/// `syslog/mcp`).
fn decode_claude_project(encoded: &str) -> Option<String> {
    let stripped = encoded.strip_prefix('-').unwrap_or(encoded);
    if stripped.is_empty() {
        return None;
    }
    Some(format!("/{}", stripped.replace('-', "/")))
}

fn project_from_sessions_index(path: &str) -> Option<String> {
    let index_path = Path::new(path).parent()?.join("sessions-index.json");
    let mut cache = CLAUDE_PROJECT_INDEX_CACHE.lock().ok()?;
    if let Some(project) = cache.get(&index_path) {
        return project.clone();
    }

    let project = fs::read_to_string(&index_path)
        .ok()
        .and_then(|body| serde_json::from_str::<ClaudeSessionsIndex>(&body).ok())
        .and_then(|index| {
            index.original_path.or_else(|| {
                index
                    .entries
                    .into_iter()
                    .find_map(|entry| entry.project_path)
            })
        })
        .map(|project| normalize_ai_project_path(&project));

    cache.insert(index_path, project.clone());
    project
}

fn fill_ai_metadata_from_json(entry: &mut LogBatchEntry, value: &serde_json::Value) {
    let payload = value.get("payload").unwrap_or(value);
    if entry.ai_session_id.is_none() {
        entry.ai_session_id = payload
            .get("id")
            .or_else(|| value.get("sessionId"))
            .or_else(|| value.get("session_id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
    }
    if entry.ai_project.is_none() {
        entry.ai_project = payload
            .get("cwd")
            .or_else(|| value.get("cwd"))
            .and_then(serde_json::Value::as_str)
            .map(normalize_ai_project_path);
    }
    if entry.ai_project.is_none() {
        entry.ai_project = payload
            .get("arguments")
            .and_then(serde_json::Value::as_str)
            .and_then(|args| serde_json::from_str::<serde_json::Value>(args).ok())
            .and_then(|args| {
                args.get("workdir")
                    .and_then(serde_json::Value::as_str)
                    .map(normalize_ai_project_path)
            });
    }
}

/// Replace any token matching the secret pattern set with `[REDACTED]`. The
/// raw API token (if configured) is appended as a literal pattern so a leaked
/// copy in tool output is scrubbed before storage.
///
/// Common case (no match) returns `Cow::Borrowed` and allocates nothing —
/// hot-path optimization for AI bursts where most messages have no secrets.
pub(crate) fn scrub_ai_message(message: &str, api_token: Option<&str>) -> String {
    let mut out: Cow<str> = Cow::Borrowed(message);
    for re in SECRET_PATTERNS.iter() {
        if let Cow::Owned(replaced) = re.replace_all(&out, "[REDACTED]") {
            out = Cow::Owned(replaced);
        }
    }
    if let Some(token) = api_token
        && !token.is_empty()
        && out.contains(token)
    {
        out = Cow::Owned(out.replace(token, "[REDACTED]"));
    }
    out.into_owned()
}

fn scrub_secrets(message: &str, api_token: Option<&str>) -> String {
    scrub_ai_message(message, api_token)
}

#[cfg(test)]
#[path = "enrichment_tests.rs"]
mod tests;
