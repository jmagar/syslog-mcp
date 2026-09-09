use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

const MAX_CLEANUP_CHUNK_SIZE: usize = 1_000_000;

thread_local! {
    /// Setup-generated .env values are a low-priority config input, not
    /// process state. Plugin-hook options are a separate high-priority layer.
    static SETUP_ENV_OVERLAY: RefCell<Option<HashMap<String, String>>> = const { RefCell::new(None) };
    static PLUGIN_ENV_OVERLAY: RefCell<Option<HashMap<String, String>>> = const { RefCell::new(None) };
}

#[cfg(not(test))]
struct SetupEnvGuard(Option<HashMap<String, String>>);

#[cfg(not(test))]
impl SetupEnvGuard {
    fn install(values: HashMap<String, String>) -> Self {
        let previous = SETUP_ENV_OVERLAY.with(|overlay| overlay.replace(Some(values)));
        Self(previous)
    }
}

#[cfg(not(test))]
impl Drop for SetupEnvGuard {
    fn drop(&mut self) {
        let previous = self.0.take();
        SETUP_ENV_OVERLAY.with(|overlay| {
            overlay.replace(previous);
        });
    }
}

#[doc(hidden)]
pub struct PluginEnvGuard(Option<HashMap<String, String>>);

impl PluginEnvGuard {
    pub fn install(values: HashMap<String, String>) -> Self {
        let previous = PLUGIN_ENV_OVERLAY.with(|overlay| overlay.replace(Some(values)));
        Self(previous)
    }
}

impl Drop for PluginEnvGuard {
    fn drop(&mut self) {
        let previous = self.0.take();
        PLUGIN_ENV_OVERLAY.with(|overlay| {
            overlay.replace(previous);
        });
    }
}

/// Resolve a config environment variable with explicit precedence:
/// plugin-hook options > real process environment > setup .env > TOML/defaults.
#[doc(hidden)]
pub fn config_env_var(key: &str) -> Option<String> {
    if let Some(value) = PLUGIN_ENV_OVERLAY.with(|overlay| {
        overlay
            .borrow()
            .as_ref()
            .and_then(|values| values.get(key).cloned())
    }) {
        return Some(value);
    }
    // Presence wins even when the process value is non-Unicode; in that case
    // preserve std::env::var's old behavior and do not fall back to setup .env.
    if crate::env::var_os(key).is_some() {
        return crate::env::var(key).ok();
    }
    SETUP_ENV_OVERLAY.with(|overlay| {
        overlay
            .borrow()
            .as_ref()
            .and_then(|values| values.get(key).cloned())
    })
}

fn config_env_present(key: &str) -> bool {
    PLUGIN_ENV_OVERLAY.with(|overlay| {
        overlay
            .borrow()
            .as_ref()
            .is_some_and(|values| values.contains_key(key))
    }) || crate::env::var_os(key).is_some()
        || SETUP_ENV_OVERLAY.with(|overlay| {
            overlay
                .borrow()
                .as_ref()
                .is_some_and(|values| values.contains_key(key))
        })
}

/// Wrapper for secret string values that prints `[REDACTED]` in Debug output
/// and is skipped during Serialize so secrets never leak into logs or JSON exports.
#[derive(Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub Option<String>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            None => write!(f, "None"),
            Some(_) => write!(f, "Some([REDACTED])"),
        }
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            None => s.serialize_none(),
            Some(_) => s.serialize_str("[REDACTED]"),
        }
    }
}

impl Secret {
    pub fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }
    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }
    pub fn as_ref(&self) -> Option<&String> {
        self.0.as_ref()
    }
}

impl From<Option<String>> for Secret {
    fn from(v: Option<String>) -> Self {
        Self(v)
    }
}

impl From<String> for Secret {
    fn from(v: String) -> Self {
        Self(Some(v))
    }
}

impl PartialEq<Option<String>> for Secret {
    fn eq(&self, other: &Option<String>) -> bool {
        &self.0 == other
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub receiver: ReceiverConfig,
    pub storage: StorageConfig,
    pub mcp: McpConfig,
    pub api: ApiConfig,
    pub docker_ingest: DockerIngestConfig,
    pub enrichment: EnrichmentConfigToml,
    pub error_detection: ErrorDetectionConfig,
    pub notifications: NotificationsConfig,
    pub llm: LlmConfig,
    pub agent_observatory: AgentObservatoryConfig,
    pub server_id: Option<String>,
    pub cursor_signing_key: Secret,
    pub cursor_previous_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentObservatoryConfig {
    pub enabled: bool,
    pub projector_poll_ms: u64,
    pub projector_page_rows: usize,
    pub projector_page_bytes: usize,
    pub active_window_secs: u64,
    pub stale_after_secs: u64,
    pub abandoned_after_secs: u64,
    pub git: AgentObservatoryGitConfig,
    pub stream: AgentObservatoryStreamConfig,
    pub privacy: AgentObservatoryPrivacyConfig,
    pub retention: AgentObservatoryRetentionConfig,
}

impl Default for AgentObservatoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            projector_poll_ms: 500,
            projector_page_rows: 500,
            projector_page_bytes: 4_194_304,
            active_window_secs: 15,
            stale_after_secs: 300,
            abandoned_after_secs: 86_400,
            git: AgentObservatoryGitConfig::default(),
            stream: AgentObservatoryStreamConfig::default(),
            privacy: AgentObservatoryPrivacyConfig::default(),
            retention: AgentObservatoryRetentionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentObservatoryGitConfig {
    pub enabled: bool,
    pub roots: Vec<String>,
    pub max_depth: usize,
    pub max_repositories: usize,
    pub reconcile_interval_secs: u64,
    pub debounce_ms: u64,
    pub command_timeout_ms: u64,
    pub max_commits_per_transition: usize,
    pub store_changed_paths: bool,
    pub store_author_name: bool,
    pub store_author_email_hash: bool,
}

impl Default for AgentObservatoryGitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            roots: vec!["~/workspace".to_string()],
            max_depth: 3,
            max_repositories: 120,
            reconcile_interval_secs: 60,
            debounce_ms: 500,
            command_timeout_ms: 5_000,
            max_commits_per_transition: 500,
            store_changed_paths: true,
            store_author_name: true,
            store_author_email_hash: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentObservatoryStreamConfig {
    pub outbox_retention_secs: u64,
    pub replay_limit: usize,
    pub client_queue: usize,
    pub max_clients: usize,
    pub keepalive_secs: u64,
    pub max_event_bytes: usize,
}

impl Default for AgentObservatoryStreamConfig {
    fn default() -> Self {
        Self {
            outbox_retention_secs: 86_400,
            replay_limit: 1_000,
            client_queue: 256,
            max_clients: 256,
            keepalive_secs: 15,
            max_event_bytes: 65_536,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentObservatoryPrivacyConfig {
    pub include_prompt_content: bool,
    pub include_tool_content: bool,
    pub include_command_content: bool,
    pub include_paths: bool,
    pub include_user_identity: bool,
    pub hash_email: bool,
}

impl Default for AgentObservatoryPrivacyConfig {
    fn default() -> Self {
        Self {
            include_prompt_content: false,
            include_tool_content: false,
            include_command_content: true,
            include_paths: true,
            include_user_identity: false,
            hash_email: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentObservatoryRetentionConfig {
    pub events_days: u64,
    pub spans_days: u64,
    pub metrics_days: u64,
    pub repository_observations_days: u64,
    pub removed_worktrees_days: u64,
}

impl Default for AgentObservatoryRetentionConfig {
    fn default() -> Self {
        Self {
            events_days: 90,
            spans_days: 30,
            metrics_days: 30,
            repository_observations_days: 90,
            removed_worktrees_days: 365,
        }
    }
}

// ---------------------------------------------------------------------------
// Notifications configuration

/// Configuration for the notifications subsystem.
/// Loaded from `[notifications]` in `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationsConfig {
    /// Enable push notifications via Apprise. Default: false.
    pub enabled: bool,
    /// Primary Apprise API base URL, e.g. "http://apprise:8000".
    pub apprise_url: String,
    /// List of Apprise notification URLs (e.g. "gotify://host/token").
    pub apprise_urls: Vec<String>,
    /// How often to run the dispatcher loop (seconds). Default: 30.
    pub dispatcher_interval_secs: u64,
    /// Dedup window in seconds — suppress duplicate firings within this
    /// window. Default: 900 (15 minutes).
    pub dedup_window_secs: u64,
    /// Local cron expression for daily digest. Default: "0 8 * * *" (8am).
    pub digest_cron_local: String,
    /// Maximum retry attempts before dead-lettering. Default: 8.
    pub max_retry_attempts: u8,
    /// Per-rule evaluator settings.
    pub evaluators: NotificationEvaluatorsConfig,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            apprise_url: String::new(),
            apprise_urls: Vec::new(),
            dispatcher_interval_secs: 30,
            dedup_window_secs: 900,
            digest_cron_local: "0 8 * * *".to_string(),
            max_retry_attempts: 8,
            evaluators: NotificationEvaluatorsConfig::default(),
        }
    }
}

/// Per-rule toggles for the notification evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationEvaluatorsConfig {
    /// Enable OOM kill detection. Default: true.
    pub oom_kill: bool,
    /// Enable container die non-zero exit detection. Default: true.
    pub container_die_nonzero: bool,
    /// Enable fail2ban ban detection. Default: true.
    pub fail2ban_ban: bool,
    /// Enable Authelia MFA failure detection. Default: true.
    pub authelia_mfa_fail: bool,
    /// Enable disk fill detection from storage guardrail. Default: true.
    pub disk_fill: bool,
    /// Enable ingest queue pressure detection. Default: true.
    pub ingest_queue_pressure: bool,
    /// Enable ingest-silence detection: fire when the DB has logs but the
    /// newest row is older than `ingest_silence_threshold_secs`. This is the
    /// push-path complement to the pull-only `silent_hosts`/`ingest_rate`
    /// actions — a dead listener or broken forwarding chain otherwise goes
    /// unnoticed until someone asks (bead syslog-mcp-7f0y). Default: true.
    pub ingest_silence: bool,
    /// Age of the newest ingested row (seconds) after which ingest is
    /// considered silent. Default: 900 (15 minutes).
    pub ingest_silence_threshold_secs: u64,
    /// Enable heartbeat-silence detection: fire when a host's latest accepted
    /// heartbeat is older than `heartbeat_silence_threshold_secs`. Fires once
    /// per outage — the host's last heartbeat timestamp rides in the dedup
    /// key, so a continuing outage does not re-page every dedup window.
    /// Default: true.
    pub heartbeat_silence: bool,
    /// Age of a host's newest accepted heartbeat (seconds) after which the
    /// host is considered silent. Default: 600 (10 minutes).
    pub heartbeat_silence_threshold_secs: u64,
    /// Enable stream-silence detection: fire when a previously-active log
    /// stream (hostname + source kind) stops producing rows for longer than
    /// `stream_silence_threshold_secs`. Expected streams are learned from
    /// observation (the `stream_last_seen` rollup), since agents do not
    /// report their collector configuration. Fires once per outage, like
    /// `heartbeat_silence`. Default: true.
    pub stream_silence: bool,
    /// Age of a stream's newest row (seconds) after which the stream is
    /// considered silent. Default: 3600 (1 hour).
    pub stream_silence_threshold_secs: u64,
    /// Source kinds eligible for stream-silence alerts. Only continuous
    /// streams belong here — sporadic, activity-driven kinds (transcripts,
    /// shell history, agent commands) would alert on every quiet afternoon.
    pub stream_silence_kinds: Vec<String>,
    /// Outages older than this (seconds) stop alerting, and stream rollup
    /// entries this stale are pruned — a decommissioned host or stream must
    /// not stay eligible for paging forever. Shared by heartbeat- and
    /// stream-silence. Default: 604800 (7 days).
    pub silence_forget_secs: u64,
    /// How often to run evaluation (seconds). Default: 300 (5 minutes).
    pub evaluator_interval_secs: u64,
}

/// Default source kinds for stream-silence alerting: the continuous streams.
pub const DEFAULT_STREAM_SILENCE_KINDS: &[&str] = &[
    "syslog-udp",
    "syslog-tcp",
    "agent-docker",
    "docker-stream",
    "docker-event",
    "file-tail",
];

impl Default for NotificationEvaluatorsConfig {
    fn default() -> Self {
        Self {
            oom_kill: true,
            container_die_nonzero: true,
            fail2ban_ban: true,
            authelia_mfa_fail: true,
            disk_fill: true,
            ingest_queue_pressure: true,
            ingest_silence: true,
            ingest_silence_threshold_secs: 900,
            heartbeat_silence: true,
            heartbeat_silence_threshold_secs: 600,
            stream_silence: true,
            stream_silence_threshold_secs: 3600,
            stream_silence_kinds: DEFAULT_STREAM_SILENCE_KINDS
                .iter()
                .map(|kind| kind.to_string())
                .collect(),
            silence_forget_secs: 604_800,
            evaluator_interval_secs: 300,
        }
    }
}

/// Configuration for the background error signature scan job.
/// Loaded from `[error_detection]` in `config.toml` or env vars.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ErrorDetectionConfig {
    /// Enable the background scan job.
    pub enabled: bool,
    /// How often to run the scan cycle (seconds). Default: 3600 (1 hour).
    pub scan_interval_secs: u64,
    /// Maximum log rows to scan per cycle. Default: 50_000.
    pub max_rows_per_cycle: u32,
    /// Minimum count of firings in a 1h window before a signature is
    /// considered "notable". Default: 30.
    pub frequency_threshold: u32,
    /// Case-insensitive message substrings whose matching log rows are skipped
    /// during scanning. Used to break notification feedback loops: cortex POSTs
    /// to Apprise's `/notify` endpoint, Apprise logs the delivery, those logs
    /// are forwarded back into cortex, and without this filter they would be
    /// re-detected as recurring errors — triggering yet more notifications.
    /// Defaults cover Apprise's own delivery log lines. Set to an empty list to
    /// disable.
    pub exclude_patterns: Vec<String>,
    /// Minimum severity that may fire a notification. Recurring signatures below
    /// this floor are still recorded (searchable, ack-able) but never notify.
    /// Default `err`: `warning`-level recurrences are extremely high volume on
    /// busy dev/service hosts and not actionable as pages. One of
    /// `emerg`/`alert`/`crit`/`err`/`warning`/`notice`/`info`/`debug`.
    pub notify_min_severity: String,
}

impl Default for ErrorDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scan_interval_secs: 3600,
            max_rows_per_cycle: 50_000,
            frequency_threshold: 30,
            exclude_patterns: vec![
                "Delivered Stateless Notification".to_string(),
                "Sent Gotify notification".to_string(),
                "POST /notify".to_string(),
            ],
            notify_min_severity: "err".to_string(),
        }
    }
}

/// Enrichment + scrubbing knobs. Loaded from `[enrichment]` in `config.toml`
/// or from `CORTEX_*` env vars at runtime startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EnrichmentConfigToml {
    /// If set, only apply Authelia severity reclassification when an entry's
    /// `source_ip` starts with this prefix. Prevents non-Authelia hosts from
    /// spoofing severity by sending crafted messages with `tag=authelia`.
    pub authelia_source_ip: Option<String>,
    /// Same gating, for AdGuard JSON tag classification.
    pub adguard_source_ip: Option<String>,
    /// Allowlist of sender IPs trusted to assert the
    /// `[cortex-agent-docker-meta:…]` marker into
    /// `metadata_json.agent_docker` (same octet-boundary semantics as
    /// `authelia_source_ip`). The marker rides the unauthenticated syslog
    /// body, so without this gate any port-1514 sender can forge agent
    /// Docker identity.
    ///
    /// Fail-closed: empty (the default) rejects the marker from every
    /// sender. Set this to the agent hosts' source IPs to enable extraction,
    /// or set `agent_docker_trust_any_source` to opt back in to accepting it
    /// from anywhere.
    pub agent_docker_source_prefixes: Vec<String>,
    /// Explicit opt-in to accepting the agent Docker marker from *any*
    /// syslog sender, bypassing `agent_docker_source_prefixes`. Only safe
    /// when every host that can reach the syslog port is trusted. Default
    /// false.
    pub agent_docker_trust_any_source: bool,
    /// Best-effort credential scrubbing on AI-source records. Default true.
    /// Set to false only if downstream consumers need raw prompt text and
    /// you trust every tailnet node.
    pub scrub_prompts: bool,
    /// FTS5 incremental-merge page budget per call. Each merge processes at most
    /// this many index pages and then returns, keeping the write lock held only
    /// briefly. 0 maps to the built-in default (`DEFAULT_FTS_MERGE_PAGES`, 500)
    /// because a 0-page merge is a no-op in FTS5's `VALUES('merge', N)` API.
    /// Raise it to reclaim phantom space faster after large deletes; lower it if
    /// merges hold the write lock too long on a very large index. Range: 0..=10000.
    pub fts_merge_pages: u32,
}

impl Default for EnrichmentConfigToml {
    fn default() -> Self {
        Self {
            authelia_source_ip: None,
            adguard_source_ip: None,
            agent_docker_source_prefixes: Vec::new(),
            agent_docker_trust_any_source: false,
            scrub_prompts: true,
            fts_merge_pages: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// LLM invocation guard configuration
//
// Shared by every LLM-backed assessment feature (ai_assess today;
// skill_assess / mcp_assess / hook_assess added by later phases). See
// `src/app/llm_runner.rs` for the runtime enforcement of these limits.
// Loaded from `[llm]` in `config.toml` or `CORTEX_LLM_*` env vars.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    /// Global kill switch. When false, every `LlmRunner::run` call is
    /// denied immediately (still audited with status "disabled").
    /// Default: true. Env override: `CORTEX_LLM_ENABLED`.
    pub enabled: bool,
    /// Max invocations running concurrently across all actions.
    /// Default: 1.
    pub max_concurrent: usize,
    /// Max invocations running concurrently for a single action.
    /// Default: 1.
    pub max_per_action_concurrent: usize,
    /// Max invocations per action per rolling 60s window. Default: 3.
    pub max_invocations_per_minute: u32,
    /// Max invocations per action per rolling 3600s window. Default: 30.
    pub max_invocations_per_hour: u32,
    /// Consecutive failures/timeouts for an action before its circuit
    /// opens. Default: 3.
    pub failure_threshold: u32,
    /// How long an open circuit stays open before allowing another
    /// attempt (seconds). Default: 300.
    pub cooldown_secs: u64,
    /// Per-invocation timeout (seconds). Default: 120. Mirrors the
    /// pre-existing `CORTEX_LLM_COMPLETION_TIMEOUT_SECS` env var read by
    /// `GeminiAssessConfig::from_env` in `src/assessment.rs` — this is
    /// threaded through instead of that struct re-reading the env var
    /// independently (see the "timeout duplication" eng review fix).
    pub timeout_secs: u64,
    /// Max prompt+evidence size in bytes. Requests over this are rejected
    /// before spawning any process. Default: 1_048_576 (1 MiB).
    pub max_prompt_bytes: usize,
    /// Max captured output size in bytes; output beyond this is
    /// truncated. Default: 262_144 (256 KiB).
    pub max_output_bytes: usize,
    /// Whether ANY background (non-interactive, non-CLI/MCP/REST-request)
    /// code path may invoke an LLM. Default: false. There must be no code
    /// path that runs LLM calls in the background without this being
    /// explicitly true — `LlmRunner::run` checks this whenever
    /// `caller_surface == Background`.
    pub background_enrichment_enabled: bool,
    /// Per-action enablement, keyed by action name (e.g. "ai_assess").
    /// An action with no entry here is treated as enabled=true UNLESS
    /// its name is "background_enrich", which defaults to disabled via
    /// `background_enrichment_enabled` regardless of this map.
    pub actions: std::collections::HashMap<String, LlmActionConfig>,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_concurrent: 1,
            max_per_action_concurrent: 1,
            max_invocations_per_minute: 3,
            max_invocations_per_hour: 30,
            failure_threshold: 3,
            cooldown_secs: 300,
            timeout_secs: 120,
            max_prompt_bytes: 1_048_576,
            max_output_bytes: 262_144,
            background_enrichment_enabled: false,
            actions: std::collections::HashMap::new(),
        }
    }
}

/// Per-action `[llm.actions.<name>]` toggle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmActionConfig {
    pub enabled: bool,
}

impl Default for LlmActionConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReceiverConfig {
    /// Listen host (shared by UDP + TCP)
    #[serde(default = "default_receiver_host")]
    pub host: String,
    /// Listen port (shared by UDP + TCP)
    #[serde(default = "default_receiver_port")]
    pub port: u16,
    /// Max message size in bytes
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    /// Maximum concurrent TCP connections (semaphore cap)
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,
    /// Idle timeout in seconds for TCP connections (per-read)
    #[serde(default = "default_tcp_idle_timeout_secs")]
    pub tcp_idle_timeout_secs: u64,
    /// Batch writer: entries per flush
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Batch writer: flush interval in milliseconds
    #[serde(default = "default_flush_interval")]
    pub flush_interval: u64,
    /// Internal parsed-message channel capacity.
    #[serde(default = "default_write_channel_capacity")]
    pub write_channel_capacity: usize,
    /// Optional CIDR allowlist for syslog senders. When non-empty, UDP packets
    /// and TCP connections from addresses not matching any CIDR are silently
    /// dropped. Empty = accept all (default).
    /// Set via `CORTEX_ALLOWED_SOURCE_CIDRS=10.0.0.0/8,192.168.0.0/16`
    #[serde(default)]
    pub allowed_source_cidrs: Vec<String>,
}

impl ReceiverConfig {
    /// Returns "host:port" for binding UDP/TCP listeners.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Path to SQLite database
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,
    /// Connection pool size
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
    /// Total SQLite page-cache budget across the whole pool, in MiB.
    /// This is divided by `pool_size` before applying `PRAGMA cache_size`.
    #[serde(default = "default_sqlite_page_cache_mb")]
    pub sqlite_page_cache_mb: u64,
    /// Bounded SQLite mmap size in MiB. Resident mapped pages can still be
    /// charged to cgroup memory, so this is measured and reported rather than
    /// treated as a memory bypass.
    #[serde(default = "default_sqlite_mmap_mb")]
    pub sqlite_mmap_mb: u64,
    /// Maximum concurrent expensive read operations. Cheap/moderate reads still
    /// use the existing writer-reserving DB permit pool.
    #[serde(default = "default_heavy_read_concurrency")]
    pub heavy_read_concurrency: usize,
    /// WAL size threshold in MiB for bounded opportunistic PASSIVE checkpoints.
    #[serde(default = "default_wal_checkpoint_mb")]
    pub wal_checkpoint_mb: u64,
    /// Days to retain logs before automatic deletion (0 = keep forever).
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    /// WAL mode (recommended for concurrent reads)
    #[serde(default = "default_true")]
    pub wal_mode: bool,
    /// Soft limit for logical DB size in MB (0 = disabled)
    #[serde(default = "default_max_db_size_mb")]
    pub max_db_size_mb: u64,
    /// Recovery target for logical DB size in MB
    #[serde(default = "default_recovery_db_size_mb")]
    pub recovery_db_size_mb: u64,
    /// Minimum free disk in MB for the DB filesystem (0 = disabled)
    #[serde(default = "default_min_free_disk_mb")]
    pub min_free_disk_mb: u64,
    /// Recovery target for free disk in MB
    #[serde(default = "default_recovery_free_disk_mb")]
    pub recovery_free_disk_mb: u64,
    /// Storage budget enforcement interval in seconds
    #[serde(default = "default_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,
    /// Number of rows to delete per chunk during storage enforcement
    #[serde(default = "default_cleanup_chunk_size")]
    pub cleanup_chunk_size: usize,
    /// Time window (hours) during which high-severity (err/crit/alert/emerg) logs
    /// are protected from disk-pressure deletion. 0 = disable the err+ floor.
    #[serde(default = "default_err_floor_window_hours")]
    pub err_floor_window_hours: u64,
    /// Maximum err+ rows protected per source IP within the floor window. Bounds
    /// any single source's share of the protected set. 0 = disable the floor.
    #[serde(default = "default_err_floor_per_source_cap")]
    pub err_floor_per_source_cap: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    /// HTTP listen host
    #[serde(default = "default_mcp_host")]
    pub host: String,
    /// HTTP listen port
    #[serde(default = "default_mcp_port")]
    pub port: u16,
    /// Server name exposed via MCP
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// Explicitly disable MCP auth. Without `trusted_gateway_no_auth`, this is
    /// only legal on loopback binds.
    #[serde(default)]
    pub no_auth: bool,
    /// Permit `no_auth` on non-loopback binds only when an upstream gateway
    /// enforces authentication before requests reach cortex.
    #[serde(default)]
    pub trusted_gateway_no_auth: bool,
    /// Optional bearer token for authenticating MCP requests.
    #[serde(default)]
    pub api_token: Secret,
    /// Named bearer credentials accepted only by the evidence-forwarding
    /// endpoints. The map key is the server-authoritative agent principal;
    /// its secret value is never serialized or exposed to browsers. A generic
    /// `CORTEX_TOKEN` remains migration-compatible but is deliberately
    /// classified as shared/unverified provenance.
    #[serde(default)]
    pub forwarding_agents: BTreeMap<String, Secret>,
    /// Optional additional Host header values accepted by RMCP Host validation.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Optional browser Origin values accepted by RMCP Origin validation.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// OAuth / JWT authentication policy (consumed by lab-auth at runtime).
    #[serde(default)]
    pub auth: AuthConfig,
    /// When `true`, the static bearer token (`CORTEX_TOKEN`) is granted
    /// both `cortex:read` and `cortex:admin` scopes. Default is `false` —
    /// static tokens receive `cortex:read` only, matching OAuth read-only
    /// tokens. Set `CORTEX_STATIC_TOKEN_ADMIN=true` or the TOML field
    /// `[mcp] static_token_is_admin = true` to opt in to admin grant.
    ///
    /// # Security
    /// Admin actions (VACUUM, Apprise test, error-sig ack/unack) are
    /// high-impact. Sharing a read-only token with a collaborator should not
    /// implicitly grant those operations.
    #[serde(default)]
    pub static_token_is_admin: bool,
}

/// Authentication mode for the MCP HTTP endpoint.
///
/// `Bearer` (default) preserves the legacy single static-token flow. `OAuth`
/// activates the dual-mode middleware shipped by `lab-auth` (Google-issued
/// JWTs with optional static-token coexistence governed by
/// [`AuthConfig::disable_static_token_with_oauth`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Bearer,
    OAuth,
}

/// `[mcp.auth]` policy table. Core deployment secrets and the bootstrap admin
/// can be provided through env vars so container deployments do not have to
/// mount a TOML file with credentials or site-local identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Runtime mode toggle. Defaults to `bearer`; set to `oauth` to activate
    /// the dual-mode middleware. Overridable via `CORTEX_AUTH_MODE`.
    #[serde(default)]
    pub mode: AuthMode,
    /// Base URL the OAuth issuer + audience are derived from. Required when
    /// `mode == OAuth`. Overridable via `CORTEX_PUBLIC_URL`.
    #[serde(default)]
    pub public_url: Option<String>,
    /// Google OAuth client id. Required when `mode == OAuth`. Overridable via
    /// `CORTEX_GOOGLE_CLIENT_ID`.
    #[serde(default)]
    pub google_client_id: Option<String>,
    /// Google OAuth client secret. Required when `mode == OAuth`. Overridable
    /// via `CORTEX_GOOGLE_CLIENT_SECRET`.
    #[serde(default)]
    pub google_client_secret: Secret,
    /// Single admin email permitted to log in via Google OAuth. Overridable via
    /// `CORTEX_AUTH_ADMIN_EMAIL`.
    #[serde(default)]
    pub admin_email: String,
    /// Future multi-user email allowlist. Parsed for schema compatibility, but
    /// rejected as the only OAuth gate until lab-auth enforces it.
    #[serde(default)]
    pub allowed_emails: Vec<String>,
    /// Path to the auth SQLite store. Relative paths are resolved against the
    /// directory containing `[storage].db_path` at runtime startup.
    #[serde(default = "default_auth_sqlite_path")]
    pub sqlite_path: PathBuf,
    /// Path to the JWT signing key (PEM). Relative paths are resolved against
    /// the directory containing `[storage].db_path` at runtime startup.
    #[serde(default = "default_auth_key_path")]
    pub key_path: PathBuf,
    /// Access-token TTL in seconds (default 1h).
    #[serde(default = "default_access_token_ttl_secs")]
    pub access_token_ttl_secs: u64,
    /// Refresh-token TTL in seconds (default 8h, deliberately shorter than
    /// lab-auth's 30d for the read-only homelab profile).
    #[serde(default = "default_refresh_token_ttl_secs")]
    pub refresh_token_ttl_secs: u64,
    /// Authorization-code TTL in seconds (default 5m).
    #[serde(default = "default_auth_code_ttl_secs")]
    pub auth_code_ttl_secs: u64,
    /// Per-process rate limit on `/register`. Moot for cortex (the
    /// bearer-only router defined in lab-auth's L2 work does not mount
    /// `/register`) but kept for lab-auth signature parity.
    #[serde(default = "default_register_rpm")]
    pub register_rpm: u32,
    /// Per-process rate limit on `/authorize`.
    #[serde(default = "default_authorize_rpm")]
    pub authorize_rpm: u32,
    /// When `mode == OAuth`, also reject the static `CORTEX_TOKEN`. Set
    /// `false` to keep the static token as a break-glass path. Default `true`.
    /// Overridable via `CORTEX_AUTH_DISABLE_STATIC_TOKEN_WITH_OAUTH`.
    #[serde(default = "default_true")]
    pub disable_static_token_with_oauth: bool,
    /// Allowed redirect URIs for OAuth clients (loopback URIs are accepted
    /// implicitly by lab-auth; entries here are non-loopback URIs).
    /// Overridable via `CORTEX_AUTH_ALLOWED_REDIRECT_URIS`.
    #[serde(default)]
    pub allowed_client_redirect_uris: Vec<String>,
}

impl McpConfig {
    /// Returns "host:port" for binding the MCP HTTP server.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ApiConfig {
    /// Required bearer token for the always-on non-MCP JSON API.
    /// Provisioned by `cortex setup repair`. The server fails to start without it.
    #[serde(default)]
    pub api_token: Secret,
    /// Optional stronger token for REST file-tail management.
    /// All `/api/file-tails` operations require this token because list/status
    /// expose configured filesystem paths.
    #[serde(default)]
    pub admin_token: Secret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerIngestConfig {
    /// Enable remote Docker log ingestion through docker-socket-proxy endpoints.
    #[serde(default)]
    pub enabled: bool,
    /// Remote Docker hosts to ingest from.
    #[serde(default)]
    pub hosts: Vec<DockerHostConfig>,
    /// Container names to skip across all Docker ingest hosts.
    #[serde(default)]
    pub excluded_containers: Vec<String>,
    /// Initial reconnect backoff in milliseconds per Docker host.
    #[serde(default = "default_docker_reconnect_initial_ms")]
    pub reconnect_initial_ms: u64,
    /// Maximum reconnect backoff in milliseconds per Docker host.
    #[serde(default = "default_docker_reconnect_max_ms")]
    pub reconnect_max_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerHostConfig {
    pub name: String,
    pub base_url: String,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub excluded_containers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DockerHostsFile {
    hosts: Vec<DockerHostConfig>,
}

// --- Defaults ---

fn default_receiver_host() -> String {
    "0.0.0.0".into()
}
fn default_receiver_port() -> u16 {
    1514
}
fn default_db_path() -> PathBuf {
    PathBuf::from("/data/cortex.db")
}
fn default_mcp_host() -> String {
    // Loopback by default — operators exposing the query API to a network
    // interface set CORTEX_HOST=0.0.0.0 (or bind a reverse proxy).
    // The syslog ingest port (1514) intentionally keeps 0.0.0.0 because
    // log receivers need to accept from all sending hosts.
    "127.0.0.1".into()
}
fn default_mcp_port() -> u16 {
    3100
}
fn default_max_message_size() -> usize {
    8192
}
fn default_max_tcp_connections() -> usize {
    512
}
fn default_tcp_idle_timeout_secs() -> u64 {
    300
}
fn default_batch_size() -> usize {
    100
}
fn default_flush_interval() -> u64 {
    500
}
fn default_write_channel_capacity() -> usize {
    10_000
}
fn default_pool_size() -> u32 {
    // 8 (up from 4): the graph projection scheduler holds one pooled connection
    // for the duration of a rebuild — a full first build can run for minutes —
    // so the previous default of 4 (3 read permits) left too little headroom for
    // concurrent MCP reads + the batch writer. Incremental passes are short, but
    // the larger pool keeps a full reconcile from starving readers.
    //
    // How these 8 are divided is `PoolBudget`, not a convention: the
    // `UNPERMITTED_CONNECTION_LANES` table reserves 4 and the read semaphore
    // gets the rest. Note `sqlite_page_cache_mb` is a whole-pool budget divided
    // by this number, so raising it shrinks per-connection cache instead of
    // adding memory — retune the cache alongside any change here.
    DEFAULT_POOL_SIZE
}
fn default_sqlite_page_cache_mb() -> u64 {
    128
}
fn default_sqlite_mmap_mb() -> u64 {
    256
}
fn default_heavy_read_concurrency() -> usize {
    1
}
fn default_wal_checkpoint_mb() -> u64 {
    256
}
fn default_retention_days() -> u32 {
    90
}
fn default_max_db_size_mb() -> u64 {
    1024
}
fn default_recovery_db_size_mb() -> u64 {
    900
}
fn default_min_free_disk_mb() -> u64 {
    // 0 = disabled. Whole-filesystem free space is an EXTERNAL condition cortex
    // cannot resolve by deleting its OWN data — see syslog-mcp-w4hh. When this is
    // non-zero the enforcement path treats low free disk as a write-block signal,
    // NOT as a trigger to self-trim. Default 0 to stop the self-wipe out of the box.
    0
}
fn default_recovery_free_disk_mb() -> u64 {
    // MUST stay paired with default_min_free_disk_mb: validate_storage_config
    // requires recovery_free_disk_mb == 0 when min_free_disk_mb == 0, so a fresh
    // StorageConfig::default() would FAIL validation if this were non-zero.
    0
}
fn default_err_floor_window_hours() -> u64 {
    // err+ rows received within this window are protected from disk-pressure
    // deletion. Time-windowed (not unbounded) so an unauthenticated source cannot
    // pin the floor indefinitely with severity=err spam (syslog-mcp-w4hh W1).
    24
}
fn default_err_floor_per_source_cap() -> usize {
    // Maximum err+ rows protected per source IP within the window. Bounds how much
    // of the protected set any single (attacker-controlled) source can occupy, so
    // one hostile sender cannot monopolise the floor (syslog-mcp-w4hh W1).
    10_000
}
fn default_cleanup_interval_secs() -> u64 {
    60
}
fn default_cleanup_chunk_size() -> usize {
    2_000
}
fn default_true() -> bool {
    true
}
fn default_server_name() -> String {
    "cortex".into()
}
fn default_docker_reconnect_initial_ms() -> u64 {
    1_000
}
fn default_docker_reconnect_max_ms() -> u64 {
    30_000
}
fn default_auth_sqlite_path() -> PathBuf {
    PathBuf::from("auth.db")
}
fn default_auth_key_path() -> PathBuf {
    PathBuf::from("auth-jwt.pem")
}
fn default_access_token_ttl_secs() -> u64 {
    3_600 // 1h
}
fn default_refresh_token_ttl_secs() -> u64 {
    28_800 // 8h
}
fn default_auth_code_ttl_secs() -> u64 {
    300 // 5m
}
fn default_register_rpm() -> u32 {
    20
}
fn default_authorize_rpm() -> u32 {
    60
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            host: default_receiver_host(),
            port: default_receiver_port(),
            max_message_size: default_max_message_size(),
            max_tcp_connections: default_max_tcp_connections(),
            tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
            batch_size: default_batch_size(),
            flush_interval: default_flush_interval(),
            write_channel_capacity: default_write_channel_capacity(),
            allowed_source_cidrs: Vec::new(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            pool_size: default_pool_size(),
            sqlite_page_cache_mb: default_sqlite_page_cache_mb(),
            sqlite_mmap_mb: default_sqlite_mmap_mb(),
            heavy_read_concurrency: default_heavy_read_concurrency(),
            wal_checkpoint_mb: default_wal_checkpoint_mb(),
            retention_days: default_retention_days(),
            wal_mode: true,
            max_db_size_mb: default_max_db_size_mb(),
            recovery_db_size_mb: default_recovery_db_size_mb(),
            min_free_disk_mb: default_min_free_disk_mb(),
            recovery_free_disk_mb: default_recovery_free_disk_mb(),
            cleanup_interval_secs: default_cleanup_interval_secs(),
            cleanup_chunk_size: default_cleanup_chunk_size(),
            err_floor_window_hours: default_err_floor_window_hours(),
            err_floor_per_source_cap: default_err_floor_per_source_cap(),
        }
    }
}

/// Whether an unpermitted connection lane is always resident or only bursts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneResidency {
    /// Always-on lane whose starvation loses data or stalls the control plane,
    /// so the pool budget reserves a connection for it permanently.
    Resident,
    /// Lane that runs on a slow interval or only during a reconnect storm. It
    /// is capped by its own semaphore and can queue behind resident lanes, so
    /// it is enumerated but not reserved for.
    Burst,
}

/// A subsystem that acquires a pooled connection **without** holding a
/// `CortexService` read permit.
///
/// `connections` is not an estimate: each lane must enforce its own cap, and
/// the cap named here has to match the mechanism that enforces it (a
/// `Semaphore`, or the fact that the lane is a single supervised task).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnpermittedLane {
    pub name: &'static str,
    pub connections: u32,
    pub residency: LaneResidency,
}

/// Every connection consumer that bypasses the service read semaphore.
///
/// This table, not a doc comment, is what the pool budget is computed from:
/// `RESERVED_UNPERMITTED_CONNECTIONS` sums the `Resident` rows, `MIN_POOL_SIZE`
/// is derived from that sum, and `validate_storage_config` rejects a pool too
/// small to satisfy it. Adding a writer therefore moves the budget instead of
/// silently eating the readers' share, which is how the previous single
/// "reserved" connection came to be contended by a dozen writers.
///
/// A lane belongs here when it calls `DbPool::get()` outside
/// `CortexService::run_db`. HTTP write handlers (heartbeat, OTLP traces and
/// metrics) are deliberately absent: they are unbounded by construction, so no
/// reservation could cover them. They bound themselves the other way, by
/// answering a retryable 503 on pool exhaustion rather than queueing.
pub const UNPERMITTED_CONNECTION_LANES: &[UnpermittedLane] = &[
    // `receiver::writer` — one flush task; starving it drops rows whose
    // `durable_ack` is `None` (UDP syslog, docker ingest, OTLP logs, file tails).
    UnpermittedLane {
        name: "ingest_batch_writer",
        connections: 1,
        residency: LaneResidency::Resident,
    },
    // `Runtime::maintenance_permit` — `Semaphore::new(1)`, shared by retention,
    // storage trim, optimize, both rollups, error scan, graph refresh,
    // inventory projection, notification evaluator and digest.
    UnpermittedLane {
        name: "maintenance_permit",
        connections: 1,
        residency: LaneResidency::Resident,
    },
    // `Runtime::dispatcher_permit` — `Semaphore::new(1)`.
    UnpermittedLane {
        name: "notification_dispatcher_permit",
        connections: 1,
        residency: LaneResidency::Resident,
    },
    // `runtime::agent_observatory::spawn_projector` — a single task, but it
    // wakes on every projection notify, so it is resident in practice.
    UnpermittedLane {
        name: "agent_observatory_projector",
        connections: 1,
        residency: LaneResidency::Resident,
    },
    // `runtime::agent_observatory::spawn_git_reconcile` — single task on
    // `git.reconcile_interval_secs`; between cycles it holds nothing.
    UnpermittedLane {
        name: "agent_observatory_git_reconcile",
        connections: 1,
        residency: LaneResidency::Burst,
    },
    // `docker_ingest::supervisor::MAX_CONCURRENT_CHECKPOINT_LOADS` — bounded at
    // 2, and only contended while streams reconnect after a daemon restart.
    UnpermittedLane {
        name: "docker_checkpoint_loads",
        connections: 2,
        residency: LaneResidency::Burst,
    },
];

const fn sum_resident_lane_connections() -> u32 {
    let mut total = 0;
    let mut index = 0;
    while index < UNPERMITTED_CONNECTION_LANES.len() {
        let lane = UNPERMITTED_CONNECTION_LANES[index];
        if matches!(lane.residency, LaneResidency::Resident) {
            total += lane.connections;
        }
        index += 1;
    }
    total
}

/// Connections held out of the read semaphore for the resident lanes above.
pub const RESERVED_UNPERMITTED_CONNECTIONS: u32 = sum_resident_lane_connections();

/// Fewest read permits the service layer is willing to run with. Below this the
/// MCP/API read path serializes hard enough that the cure is worse than the
/// contention it prevents.
pub const MIN_READ_PERMITS: u32 = 2;

/// Smallest `pool_size` that satisfies the budget.
pub const MIN_POOL_SIZE: u32 = RESERVED_UNPERMITTED_CONNECTIONS + MIN_READ_PERMITS;

const DEFAULT_POOL_SIZE: u32 = 8;

// The shipped default must satisfy the budget it is measured against.
const _: () = assert!(DEFAULT_POOL_SIZE >= MIN_POOL_SIZE);

/// How `pool_size` connections are split between the service read semaphore and
/// the lanes that bypass it.
///
/// The split is total by construction — `read_permits() + reserved() ==
/// pool_size()` for every input — so a connection cannot be counted twice or
/// left unassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolBudget {
    pool_size: u32,
    reserved: u32,
    read_permits: u32,
}

impl PoolBudget {
    /// Split `pool_size` into read permits and reserved writer connections.
    ///
    /// A pool at or above `MIN_POOL_SIZE` gets the full reservation. Anything
    /// smaller is only reachable from tests and from a config that
    /// `validate_storage_config` rejects, so it falls back to the historical
    /// `pool_size - 1` split rather than starving reads to zero.
    #[must_use]
    pub const fn for_pool_size(pool_size: u32) -> Self {
        let pool_size = if pool_size == 0 { 1 } else { pool_size };
        let reserved = if pool_size >= MIN_POOL_SIZE {
            RESERVED_UNPERMITTED_CONNECTIONS
        } else if pool_size > 1 {
            1
        } else {
            0
        };
        Self {
            pool_size,
            reserved,
            read_permits: pool_size - reserved,
        }
    }

    #[must_use]
    pub const fn pool_size(&self) -> u32 {
        self.pool_size
    }

    #[must_use]
    pub const fn reserved(&self) -> u32 {
        self.reserved
    }

    #[must_use]
    pub const fn read_permits(&self) -> usize {
        self.read_permits as usize
    }
}

impl StorageConfig {
    /// The read-permit / reserved-connection split for this pool size.
    #[must_use]
    pub fn pool_budget(&self) -> PoolBudget {
        PoolBudget::for_pool_size(self.pool_size)
    }

    pub fn sqlite_page_cache_kib_per_connection(&self) -> anyhow::Result<i64> {
        let pool_size = u64::from(self.pool_size.max(1));
        let total_kib = self
            .sqlite_page_cache_mb
            .checked_mul(1024)
            .ok_or_else(|| anyhow::anyhow!("storage.sqlite_page_cache_mb is too large"))?;
        let per_conn = (total_kib / pool_size).max(1);
        let per_conn = i64::try_from(per_conn).map_err(|_| {
            anyhow::anyhow!(
                "storage.sqlite_page_cache_mb is too large; derived cache_size must fit in i64"
            )
        })?;
        Ok(-per_conn)
    }

    pub fn sqlite_mmap_bytes_i64(&self) -> anyhow::Result<i64> {
        i64::try_from(self.sqlite_mmap_bytes()).map_err(|_| {
            anyhow::anyhow!(
                "storage.sqlite_mmap_mb is too large; derived mmap_size must fit in i64"
            )
        })
    }

    pub fn sqlite_mmap_bytes(&self) -> u64 {
        self.sqlite_mmap_mb.saturating_mul(1024 * 1024)
    }

    pub fn wal_checkpoint_threshold_bytes(&self) -> u64 {
        self.wal_checkpoint_mb.saturating_mul(1024 * 1024)
    }
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            host: default_mcp_host(),
            port: default_mcp_port(),
            server_name: default_server_name(),
            no_auth: false,
            trusted_gateway_no_auth: false,
            api_token: Secret(None),
            forwarding_agents: BTreeMap::new(),
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            auth: AuthConfig::default(),
            static_token_is_admin: false,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::default(),
            public_url: None,
            google_client_id: None,
            google_client_secret: Secret(None),
            admin_email: String::new(),
            allowed_emails: Vec::new(),
            sqlite_path: default_auth_sqlite_path(),
            key_path: default_auth_key_path(),
            access_token_ttl_secs: default_access_token_ttl_secs(),
            refresh_token_ttl_secs: default_refresh_token_ttl_secs(),
            auth_code_ttl_secs: default_auth_code_ttl_secs(),
            register_rpm: default_register_rpm(),
            authorize_rpm: default_authorize_rpm(),
            disable_static_token_with_oauth: true,
            allowed_client_redirect_uris: Vec::new(),
        }
    }
}

impl Default for DockerIngestConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hosts: Vec::new(),
            excluded_containers: Vec::new(),
            reconnect_initial_ms: default_docker_reconnect_initial_ms(),
            reconnect_max_ms: default_docker_reconnect_max_ms(),
        }
    }
}

impl Config {
    /// Load config for commands that inspect settings without opening runtime
    /// resources. Values are parsed and validated normally, but an explicit
    /// database path is not required to exist on this host.
    pub fn load_for_inspection() -> anyhow::Result<Self> {
        Self::load_inner(false, false)
    }

    /// Load config for stdio / query-only mode.
    ///
    /// Identical to [`Config::load`] but skips the non-loopback bind safety
    /// gate in `validate_auth_config`. In stdio mode cortex never binds an
    /// HTTP port, so the gate is irrelevant and would falsely reject
    /// configurations like `mcp.host = "0.0.0.0"` that are valid for the HTTP
    /// server but harmless in stdio mode.
    pub fn load_for_stdio() -> anyhow::Result<Self> {
        Self::load_inner(false, true)
    }

    pub fn load() -> anyhow::Result<Self> {
        Self::load_inner(true, true)
    }

    fn load_inner(check_bind: bool, check_db_path: bool) -> anyhow::Result<Self> {
        // 1. Start with defaults
        let mut config = Config::default();

        // 2. Overlay config.toml if present (partial configs are supported — missing
        //    fields keep their defaults from step 1 via #[serde(default)] annotations)
        match std::fs::read_to_string("config.toml") {
            Ok(contents) => {
                reject_unsupported_config_blocks(&contents)?;
                config = toml::from_str(&contents)
                    .map_err(|e| anyhow::anyhow!("Failed to parse config.toml: {e}"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow::anyhow!("Failed to read config.toml: {e}")),
        }

        #[cfg(not(test))]
        let _setup_env_guard = SetupEnvGuard::install(load_setup_env_file());

        // 3. Overlay setup .env, then process environment (highest priority).
        //    config_env_var() resolves that precedence without mutating the
        //    process-global environment.
        //    CORTEX_*     → syslog listener settings
        //    CORTEX_* → MCP server + storage settings
        env_override_str("CORTEX_RECEIVER_HOST", &mut config.receiver.host);
        env_override_parse("CORTEX_RECEIVER_PORT", &mut config.receiver.port)?;
        env_override_parse(
            "CORTEX_MAX_MESSAGE_SIZE",
            &mut config.receiver.max_message_size,
        )?;
        env_override_parse(
            "CORTEX_MAX_TCP_CONNECTIONS",
            &mut config.receiver.max_tcp_connections,
        )?;
        env_override_parse(
            "CORTEX_TCP_IDLE_TIMEOUT_SECS",
            &mut config.receiver.tcp_idle_timeout_secs,
        )?;
        env_override_parse("CORTEX_BATCH_SIZE", &mut config.receiver.batch_size)?;
        env_override_parse("CORTEX_FLUSH_INTERVAL", &mut config.receiver.flush_interval)?;
        env_override_parse(
            "CORTEX_WRITE_CHANNEL_CAPACITY",
            &mut config.receiver.write_channel_capacity,
        )?;
        env_override_list(
            "CORTEX_ALLOWED_SOURCE_CIDRS",
            &mut config.receiver.allowed_source_cidrs,
        );

        env_override_str("CORTEX_HOST", &mut config.mcp.host);
        env_override_parse("CORTEX_PORT", &mut config.mcp.port)?;
        env_override_bool("NO_AUTH", &mut config.mcp.no_auth)?;
        env_override_bool("CORTEX_NO_AUTH", &mut config.mcp.no_auth)?;
        env_override_bool(
            "CORTEX_TRUSTED_GATEWAY_NO_AUTH",
            &mut config.mcp.trusted_gateway_no_auth,
        )?;
        env_override_bool(
            "CORTEX_STATIC_TOKEN_ADMIN",
            &mut config.mcp.static_token_is_admin,
        )?;
        env_override_list("CORTEX_ALLOWED_HOSTS", &mut config.mcp.allowed_hosts);
        env_override_list("CORTEX_ALLOWED_ORIGINS", &mut config.mcp.allowed_origins);
        // MCP static token. (The pre-v1 `SYSLOG_MCP_API_TOKEN` deprecated alias was
        // dropped in the cortex v1.0.0 rebrand — its post-rename name `CORTEX_API_TOKEN`
        // now belongs exclusively to the API/OTLP token, `config.api.api_token`.)
        env_override_opt_str("CORTEX_TOKEN", &mut config.mcp.api_token.0);
        env_override_path("CORTEX_DB_PATH", &mut config.storage.db_path);
        // Fail fast when CORTEX_DB_PATH is explicitly set but its parent
        // directory doesn't exist. This catches the common Docker misconfiguration
        // where the variable is set to a host filesystem path that was never
        // bind-mounted into the container, producing a cryptic "Permission denied"
        // error deep in SQLite pool initialisation.
        if check_db_path
            && config_env_present("CORTEX_DB_PATH")
            && let Some(parent) = config.storage.db_path.parent()
            && !parent.as_os_str().is_empty()
            && !parent.exists()
        {
            anyhow::bail!(
                "CORTEX_DB_PATH parent directory does not exist: {}\n\
                         In Docker: mount the data directory at /data and set\n\
                         CORTEX_DB_PATH=/data/cortex.db",
                parent.display()
            );
        }
        env_override_parse("CORTEX_POOL_SIZE", &mut config.storage.pool_size)?;
        env_override_parse(
            "CORTEX_SQLITE_PAGE_CACHE_MB",
            &mut config.storage.sqlite_page_cache_mb,
        )?;
        env_override_parse("CORTEX_SQLITE_MMAP_MB", &mut config.storage.sqlite_mmap_mb)?;
        env_override_parse(
            "CORTEX_HEAVY_READ_CONCURRENCY",
            &mut config.storage.heavy_read_concurrency,
        )?;
        env_override_parse(
            "CORTEX_WAL_CHECKPOINT_MB",
            &mut config.storage.wal_checkpoint_mb,
        )?;
        env_override_parse("CORTEX_RETENTION_DAYS", &mut config.storage.retention_days)?;
        env_override_parse("CORTEX_MAX_DB_SIZE_MB", &mut config.storage.max_db_size_mb)?;
        env_override_parse(
            "CORTEX_RECOVERY_DB_SIZE_MB",
            &mut config.storage.recovery_db_size_mb,
        )?;
        env_override_parse(
            "CORTEX_MIN_FREE_DISK_MB",
            &mut config.storage.min_free_disk_mb,
        )?;
        env_override_parse(
            "CORTEX_RECOVERY_FREE_DISK_MB",
            &mut config.storage.recovery_free_disk_mb,
        )?;
        env_override_parse(
            "CORTEX_CLEANUP_INTERVAL_SECS",
            &mut config.storage.cleanup_interval_secs,
        )?;
        env_override_parse(
            "CORTEX_CLEANUP_CHUNK_SIZE",
            &mut config.storage.cleanup_chunk_size,
        )?;
        env_override_parse(
            "CORTEX_ERR_FLOOR_WINDOW_HOURS",
            &mut config.storage.err_floor_window_hours,
        )?;
        env_override_parse(
            "CORTEX_ERR_FLOOR_PER_SOURCE_CAP",
            &mut config.storage.err_floor_per_source_cap,
        )?;
        env_override_opt_str("CORTEX_SERVER_ID", &mut config.server_id);
        env_override_opt_str(
            "CORTEX_CURSOR_SIGNING_KEY",
            &mut config.cursor_signing_key.0,
        );
        env_override_list(
            "CORTEX_CURSOR_PREVIOUS_KEYS",
            &mut config.cursor_previous_keys,
        );

        // Auto-adjust recovery_db_size_mb if max_db_size_mb is raised but recovery
        // is still at the naive default (900MB). This prevents silent data loss
        // when users set CORTEX_MAX_DB_SIZE_MB without CORTEX_RECOVERY_DB_SIZE_MB.
        // See syslog-mcp-0kjd5 for context.
        const NAIVE_RECOVERY_DEFAULT_MB: u64 = 900;
        const DEFAULT_MAX_DB_SIZE_MB: u64 = 1024;
        if config.storage.max_db_size_mb > DEFAULT_MAX_DB_SIZE_MB * 2
            && config.storage.recovery_db_size_mb == NAIVE_RECOVERY_DEFAULT_MB
        {
            config.storage.recovery_db_size_mb = config.storage.max_db_size_mb * 90 / 100;
        }

        // [llm] env overrides.
        env_override_bool("CORTEX_LLM_ENABLED", &mut config.llm.enabled)?;

        // [mcp.auth] env overrides.
        env_override_auth_mode("CORTEX_AUTH_MODE", &mut config.mcp.auth.mode)?;
        env_override_opt_str("CORTEX_PUBLIC_URL", &mut config.mcp.auth.public_url);
        env_override_opt_str(
            "CORTEX_GOOGLE_CLIENT_ID",
            &mut config.mcp.auth.google_client_id,
        );
        env_override_opt_str(
            "CORTEX_GOOGLE_CLIENT_SECRET",
            &mut config.mcp.auth.google_client_secret.0,
        );
        env_override_str("CORTEX_AUTH_ADMIN_EMAIL", &mut config.mcp.auth.admin_email);
        env_override_list(
            "CORTEX_AUTH_ALLOWED_REDIRECT_URIS",
            &mut config.mcp.auth.allowed_client_redirect_uris,
        );
        env_override_bool(
            "CORTEX_AUTH_DISABLE_STATIC_TOKEN_WITH_OAUTH",
            &mut config.mcp.auth.disable_static_token_with_oauth,
        )?;

        env_override_opt_str("CORTEX_API_TOKEN", &mut config.api.api_token.0);
        env_override_opt_str("CORTEX_API_ADMIN_TOKEN", &mut config.api.admin_token.0);

        env_override_opt_str(
            "CORTEX_AUTHELIA_SOURCE_IP",
            &mut config.enrichment.authelia_source_ip,
        );
        env_override_opt_str(
            "CORTEX_ADGUARD_SOURCE_IP",
            &mut config.enrichment.adguard_source_ip,
        );
        env_override_list(
            "CORTEX_AGENT_DOCKER_SOURCE_PREFIXES",
            &mut config.enrichment.agent_docker_source_prefixes,
        );
        env_override_bool(
            "CORTEX_AGENT_DOCKER_TRUST_ANY_SOURCE",
            &mut config.enrichment.agent_docker_trust_any_source,
        )?;
        warn_invalid_agent_docker_prefixes(&config.enrichment.agent_docker_source_prefixes);
        env_override_bool("CORTEX_SCRUB_PROMPTS", &mut config.enrichment.scrub_prompts)?;
        env_override_parse(
            "CORTEX_FTS_MERGE_PAGES",
            &mut config.enrichment.fts_merge_pages,
        )?;
        if config.enrichment.fts_merge_pages > 10_000 {
            return Err(anyhow::anyhow!(
                "CORTEX_FTS_MERGE_PAGES must be in 0..=10000, got {}",
                config.enrichment.fts_merge_pages
            ));
        }

        env_override_bool(
            "CORTEX_ERROR_DETECTION_ENABLED",
            &mut config.error_detection.enabled,
        )?;
        env_override_parse(
            "CORTEX_ERROR_DETECTION_SCAN_INTERVAL_SECS",
            &mut config.error_detection.scan_interval_secs,
        )?;
        env_override_list(
            "CORTEX_ERROR_DETECTION_EXCLUDE_PATTERNS",
            &mut config.error_detection.exclude_patterns,
        );
        env_override_str(
            "CORTEX_ERROR_DETECTION_NOTIFY_MIN_SEVERITY",
            &mut config.error_detection.notify_min_severity,
        );
        env_override_bool(
            "CORTEX_NOTIFICATIONS_ENABLED",
            &mut config.notifications.enabled,
        )?;
        env_override_str(
            "CORTEX_NOTIFICATIONS_APPRISE_URL",
            &mut config.notifications.apprise_url,
        );
        env_override_list(
            "CORTEX_NOTIFICATIONS_APPRISE_URLS",
            &mut config.notifications.apprise_urls,
        );
        env_override_bool(
            "CORTEX_NOTIFICATIONS_HEARTBEAT_SILENCE",
            &mut config.notifications.evaluators.heartbeat_silence,
        )?;
        env_override_parse(
            "CORTEX_NOTIFICATIONS_HEARTBEAT_SILENCE_SECS",
            &mut config
                .notifications
                .evaluators
                .heartbeat_silence_threshold_secs,
        )?;
        env_override_bool(
            "CORTEX_NOTIFICATIONS_STREAM_SILENCE",
            &mut config.notifications.evaluators.stream_silence,
        )?;
        env_override_parse(
            "CORTEX_NOTIFICATIONS_STREAM_SILENCE_SECS",
            &mut config
                .notifications
                .evaluators
                .stream_silence_threshold_secs,
        )?;
        env_override_list(
            "CORTEX_NOTIFICATIONS_STREAM_SILENCE_KINDS",
            &mut config.notifications.evaluators.stream_silence_kinds,
        );
        env_override_parse(
            "CORTEX_NOTIFICATIONS_SILENCE_FORGET_SECS",
            &mut config.notifications.evaluators.silence_forget_secs,
        )?;

        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_ENABLED",
            &mut config.agent_observatory.enabled,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_PROJECTOR_POLL_MS",
            &mut config.agent_observatory.projector_poll_ms,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_PROJECTOR_PAGE_ROWS",
            &mut config.agent_observatory.projector_page_rows,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_PROJECTOR_PAGE_BYTES",
            &mut config.agent_observatory.projector_page_bytes,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_ACTIVE_WINDOW_SECS",
            &mut config.agent_observatory.active_window_secs,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_STALE_AFTER_SECS",
            &mut config.agent_observatory.stale_after_secs,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_ABANDONED_AFTER_SECS",
            &mut config.agent_observatory.abandoned_after_secs,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_GIT_ENABLED",
            &mut config.agent_observatory.git.enabled,
        )?;
        env_override_list(
            "CORTEX_AGENT_OBSERVATORY_GIT_ROOTS",
            &mut config.agent_observatory.git.roots,
        );
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_GIT_MAX_DEPTH",
            &mut config.agent_observatory.git.max_depth,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_GIT_MAX_REPOSITORIES",
            &mut config.agent_observatory.git.max_repositories,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_GIT_RECONCILE_INTERVAL_SECS",
            &mut config.agent_observatory.git.reconcile_interval_secs,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_GIT_DEBOUNCE_MS",
            &mut config.agent_observatory.git.debounce_ms,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_GIT_COMMAND_TIMEOUT_MS",
            &mut config.agent_observatory.git.command_timeout_ms,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_GIT_MAX_COMMITS_PER_TRANSITION",
            &mut config.agent_observatory.git.max_commits_per_transition,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_GIT_STORE_CHANGED_PATHS",
            &mut config.agent_observatory.git.store_changed_paths,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_GIT_STORE_AUTHOR_NAME",
            &mut config.agent_observatory.git.store_author_name,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_GIT_STORE_AUTHOR_EMAIL_HASH",
            &mut config.agent_observatory.git.store_author_email_hash,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_STREAM_OUTBOX_RETENTION_SECS",
            &mut config.agent_observatory.stream.outbox_retention_secs,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_STREAM_REPLAY_LIMIT",
            &mut config.agent_observatory.stream.replay_limit,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_STREAM_CLIENT_QUEUE",
            &mut config.agent_observatory.stream.client_queue,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_STREAM_MAX_CLIENTS",
            &mut config.agent_observatory.stream.max_clients,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_STREAM_KEEPALIVE_SECS",
            &mut config.agent_observatory.stream.keepalive_secs,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_STREAM_MAX_EVENT_BYTES",
            &mut config.agent_observatory.stream.max_event_bytes,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_PROMPT_CONTENT",
            &mut config.agent_observatory.privacy.include_prompt_content,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_TOOL_CONTENT",
            &mut config.agent_observatory.privacy.include_tool_content,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_COMMAND_CONTENT",
            &mut config.agent_observatory.privacy.include_command_content,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_PATHS",
            &mut config.agent_observatory.privacy.include_paths,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_USER_IDENTITY",
            &mut config.agent_observatory.privacy.include_user_identity,
        )?;
        env_override_bool(
            "CORTEX_AGENT_OBSERVATORY_PRIVACY_HASH_EMAIL",
            &mut config.agent_observatory.privacy.hash_email,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_RETENTION_EVENTS_DAYS",
            &mut config.agent_observatory.retention.events_days,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_RETENTION_SPANS_DAYS",
            &mut config.agent_observatory.retention.spans_days,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_RETENTION_METRICS_DAYS",
            &mut config.agent_observatory.retention.metrics_days,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_RETENTION_REPOSITORY_OBSERVATIONS_DAYS",
            &mut config
                .agent_observatory
                .retention
                .repository_observations_days,
        )?;
        env_override_parse(
            "CORTEX_AGENT_OBSERVATORY_RETENTION_REMOVED_WORKTREES_DAYS",
            &mut config.agent_observatory.retention.removed_worktrees_days,
        )?;

        env_override_bool(
            "CORTEX_DOCKER_INGEST_ENABLED",
            &mut config.docker_ingest.enabled,
        )?;
        env_override_parse(
            "CORTEX_DOCKER_RECONNECT_INITIAL_MS",
            &mut config.docker_ingest.reconnect_initial_ms,
        )?;
        env_override_parse(
            "CORTEX_DOCKER_RECONNECT_MAX_MS",
            &mut config.docker_ingest.reconnect_max_ms,
        )?;
        env_override_list(
            "CORTEX_DOCKER_EXCLUDED_CONTAINERS",
            &mut config.docker_ingest.excluded_containers,
        );
        if config.docker_ingest.enabled {
            if let Some(val) = config_env_var("CORTEX_DOCKER_HOSTS") {
                if !val.is_empty() {
                    config.docker_ingest.hosts = val
                        .split(',')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(|name| DockerHostConfig {
                            name: name.to_string(),
                            base_url: format!("http://{}:2375", name),
                            allow_insecure_http: true,
                            excluded_containers: Vec::new(),
                        })
                        .collect();
                    for host in &config.docker_ingest.hosts {
                        tracing::warn!(
                            host = %host.name,
                            base_url = %host.base_url,
                            "CORTEX_DOCKER_HOSTS expands to insecure HTTP docker-socket-proxy endpoints; use only on trusted private networks or CORTEX_DOCKER_HOSTS_FILE with TLS/custom base_url"
                        );
                    }
                }
            } else if let Some(path) = config_env_var("CORTEX_DOCKER_HOSTS_FILE")
                && !path.is_empty()
            {
                match std::fs::read_to_string(&path) {
                    Ok(contents) => {
                        let parsed: DockerHostsFile = toml::from_str(&contents).map_err(|e| {
                            anyhow::anyhow!("Failed to parse CORTEX_DOCKER_HOSTS_FILE={path}: {e}")
                        })?;
                        config.docker_ingest.hosts = parsed.hosts;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        tracing::warn!(
                            path = %path,
                            "CORTEX_DOCKER_HOSTS_FILE not found — no docker hosts loaded. \
                             Create the file or use CORTEX_DOCKER_HOSTS instead."
                        );
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "Failed to read CORTEX_DOCKER_HOSTS_FILE={path}: {e}"
                        ));
                    }
                }
            }
        }

        // Validation
        if config.storage.pool_size == 0 {
            return Err(anyhow::anyhow!("CORTEX_POOL_SIZE must be > 0"));
        }
        validate_receiver_config(&config.receiver)?;
        validate_storage_config(&config.storage)?;
        validate_notifications_config(&config.notifications)?;
        validate_error_detection_config(&config.error_detection)?;
        validate_llm_config(&config.llm)?;
        validate_agent_observatory_config(&config.agent_observatory)?;
        validate_host(&config.receiver.host)?;
        validate_host(&config.mcp.host)?;
        validate_auth_config(&config, check_bind)?;
        validate_docker_ingest_config(&config.docker_ingest)?;

        Ok(config)
    }
}

#[cfg(not(test))]
fn load_setup_env_file() -> HashMap<String, String> {
    let Ok(home) = crate::setup::cortex_home_dir() else {
        tracing::trace!("load_setup_env_file: cortex home directory unavailable");
        return HashMap::new();
    };
    let path = home.join(".env");
    let Ok(metadata) = std::fs::symlink_metadata(&path) else {
        tracing::trace!(path = %path.display(), "load_setup_env_file: env file metadata unavailable");
        return HashMap::new();
    };
    if metadata.file_type().is_symlink() {
        tracing::trace!(path = %path.display(), "load_setup_env_file: refusing symlinked env file");
        eprintln!(
            "cortex: warning: refusing to load symlinked env file {}",
            path.display()
        );
        return HashMap::new();
    }
    let Ok(raw) = std::fs::read_to_string(&path) else {
        tracing::trace!(path = %path.display(), "load_setup_env_file: env file read failed");
        return HashMap::new();
    };
    let mut entries = Vec::new();
    for (line_no, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            tracing::trace!(
                line_no = line_no + 1,
                "load_setup_env_file: skipped line without delimiter"
            );
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || key.contains(['\0']) || value.contains(['\0']) {
            tracing::trace!(key, "load_setup_env_file: skipped invalid env entry");
            continue;
        }
        if !is_supported_setup_env_key(key) {
            tracing::trace!(key, "load_setup_env_file: skipped unsupported env key");
            continue;
        }
        entries.push((key.to_string(), value.to_string()));
    }

    let data_volume = entries
        .iter()
        .find(|(key, _)| key == "CORTEX_DATA_VOLUME")
        .filter(|(_, value)| !value.trim().is_empty())
        .map(|(_, value)| value.clone());
    let mut overlay = HashMap::with_capacity(entries.len());
    for (key, mut value) in entries {
        // Preserve the setup loader's historical first-definition-wins
        // behavior while leaving real process variables to config_env_var().
        if overlay.contains_key(&key) {
            continue;
        }
        if key == "CORTEX_DB_PATH"
            && let Some(suffix) = value.strip_prefix("/data/")
            && let Some(data_volume) = data_volume.as_deref()
        {
            value = PathBuf::from(data_volume)
                .join(suffix)
                .display()
                .to_string();
            tracing::trace!(value, "load_setup_env_file: rewrote CORTEX_DB_PATH");
        }
        overlay.insert(key, value);
    }
    overlay
}

#[cfg(not(test))]
fn is_supported_setup_env_key(key: &str) -> bool {
    key == "NO_AUTH" || key.starts_with("CORTEX_")
}

/// Warn about `agent_docker_source_prefixes` entries that can never match a
/// source. Valid shapes are a full IP literal (`198.51.100.7` or
/// `2001:db8::1`, exact-host match) or a dot-terminated partial IPv4 quad
/// (`100.64.0.`, subnet-prefix match). A partial quad without its trailing
/// dot (`100.64.0`) is treated by the gate as an exact-host literal that
/// matches nothing — the failure mode silently disables all agent-docker
/// extraction. IPv6 entries are exact-host only; there is no IPv6
/// subnet-prefix form.
fn warn_invalid_agent_docker_prefixes(prefixes: &[String]) {
    for prefix in prefixes {
        if !is_agent_docker_prefix_shape(prefix) {
            tracing::warn!(
                prefix = %prefix,
                "agent_docker_source_prefixes entry is neither a full IP literal \
                 nor a dot-terminated partial IPv4 quad; it will match no source_ip and \
                 silently disables agent-docker extraction for the senders it was meant \
                 to cover (use a trailing dot, e.g. \"100.64.0.\", for a subnet prefix)"
            );
        }
    }
}

/// `true` when `prefix` is a full IPv4 dotted quad, an IPv6 literal
/// (exact-host match), or a dot-terminated partial IPv4 quad (1–3 leading
/// octets), i.e. a shape [`crate::receiver`]'s agent-docker source gate can
/// actually match.
fn is_agent_docker_prefix_shape(prefix: &str) -> bool {
    if prefix.parse::<std::net::Ipv6Addr>().is_ok() {
        return true;
    }
    let (body, partial) = match prefix.strip_suffix('.') {
        Some(body) => (body, true),
        None => (prefix, false),
    };
    let octets: Vec<&str> = body.split('.').collect();
    let count_ok = if partial {
        (1..=3).contains(&octets.len())
    } else {
        octets.len() == 4
    };
    count_ok
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.chars().all(|ch| ch.is_ascii_digit())
                && octet.parse::<u8>().is_ok()
        })
}

// --- Env var helpers ---

fn reject_unsupported_config_blocks(contents: &str) -> anyhow::Result<()> {
    let value: toml::Value = toml::from_str(contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse config.toml: {e}"))?;
    let Some(notifications) = value.get("notifications") else {
        return Ok(());
    };

    for (key, surface) in [
        ("quiet_hours", "[notifications.quiet_hours]"),
        ("apprise", "[notifications.apprise]"),
        ("digest", "[notifications.digest]"),
        ("rules", "[[notifications.rules]]"),
    ] {
        if notifications.get(key).is_some() {
            anyhow::bail!(
                "config.toml {surface} is not implemented; remove it rather than relying on silently ignored notification configuration"
            );
        }
    }
    Ok(())
}

fn env_override_str(key: &str, target: &mut String) {
    if let Some(v) = config_env_var(key)
        && !v.is_empty()
    {
        *target = v;
    }
}

fn env_override_opt_str(key: &str, target: &mut Option<String>) {
    if let Some(v) = config_env_var(key)
        && !v.is_empty()
    {
        *target = Some(v);
    }
}

fn env_override_path(key: &str, target: &mut PathBuf) {
    if let Some(v) = config_env_var(key)
        && !v.is_empty()
    {
        *target = PathBuf::from(v);
    }
}

fn env_override_list(key: &str, target: &mut Vec<String>) {
    let Some(v) = config_env_var(key) else {
        return;
    };
    let values: Vec<String> = v
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    *target = values;
}

fn env_override_auth_mode(key: &str, target: &mut AuthMode) -> anyhow::Result<()> {
    let Some(v) = config_env_var(key) else {
        return Ok(());
    };
    if v.is_empty() {
        return Ok(());
    }
    *target = match v.trim().to_ascii_lowercase().as_str() {
        "bearer" => AuthMode::Bearer,
        "oauth" => AuthMode::OAuth,
        other => {
            return Err(anyhow::anyhow!(
                "Invalid value for {key}={other}: expected `bearer` or `oauth`"
            ));
        }
    };
    Ok(())
}

fn env_override_bool(key: &str, target: &mut bool) -> anyhow::Result<()> {
    let Some(v) = config_env_var(key) else {
        return Ok(());
    };
    if v.is_empty() {
        return Ok(());
    }

    *target = match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "y" | "on" => true,
        "false" | "0" | "no" | "n" | "off" => false,
        _ => {
            return Err(anyhow::anyhow!(
                "Invalid value for {key}={v}: expected true/false/1/0/yes/no/on/off"
            ));
        }
    };
    Ok(())
}

pub(crate) fn validate_agent_observatory_config(
    config: &AgentObservatoryConfig,
) -> anyhow::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    for (name, value) in [
        ("projector_poll_ms", config.projector_poll_ms),
        ("active_window_secs", config.active_window_secs),
        ("stale_after_secs", config.stale_after_secs),
        ("abandoned_after_secs", config.abandoned_after_secs),
    ] {
        if value == 0 {
            return Err(anyhow::anyhow!(
                "agent_observatory.{name} must be greater than zero"
            ));
        }
    }
    for (name, value) in [
        ("projector_page_rows", config.projector_page_rows),
        ("projector_page_bytes", config.projector_page_bytes),
    ] {
        if value == 0 {
            return Err(anyhow::anyhow!(
                "agent_observatory.{name} must be greater than zero"
            ));
        }
    }
    if config.projector_page_rows > 500 {
        return Err(anyhow::anyhow!(
            "agent_observatory.projector_page_rows must be between 1 and 500"
        ));
    }
    if config.stale_after_secs <= config.active_window_secs {
        return Err(anyhow::anyhow!(
            "agent_observatory.stale_after_secs must be greater than active_window_secs"
        ));
    }
    if config.abandoned_after_secs <= config.stale_after_secs {
        return Err(anyhow::anyhow!(
            "agent_observatory.abandoned_after_secs must be greater than stale_after_secs"
        ));
    }

    if config.git.enabled {
        if config.git.roots.is_empty() || config.git.roots.iter().any(|root| root.trim().is_empty())
        {
            return Err(anyhow::anyhow!(
                "agent_observatory.git.roots must contain at least one non-empty root"
            ));
        }
        for (name, value) in [
            ("max_depth", config.git.max_depth),
            ("max_repositories", config.git.max_repositories),
            (
                "max_commits_per_transition",
                config.git.max_commits_per_transition,
            ),
        ] {
            if value == 0 {
                return Err(anyhow::anyhow!(
                    "agent_observatory.git.{name} must be greater than zero"
                ));
            }
        }
        for (name, value) in [
            (
                "reconcile_interval_secs",
                config.git.reconcile_interval_secs,
            ),
            ("debounce_ms", config.git.debounce_ms),
            ("command_timeout_ms", config.git.command_timeout_ms),
        ] {
            if value == 0 {
                return Err(anyhow::anyhow!(
                    "agent_observatory.git.{name} must be greater than zero"
                ));
            }
        }
    }

    for (name, value) in [
        ("replay_limit", config.stream.replay_limit),
        ("client_queue", config.stream.client_queue),
        ("max_clients", config.stream.max_clients),
        ("max_event_bytes", config.stream.max_event_bytes),
    ] {
        if value == 0 {
            return Err(anyhow::anyhow!(
                "agent_observatory.stream.{name} must be greater than zero"
            ));
        }
    }
    for (name, value) in [
        ("outbox_retention_secs", config.stream.outbox_retention_secs),
        ("keepalive_secs", config.stream.keepalive_secs),
    ] {
        if value == 0 {
            return Err(anyhow::anyhow!(
                "agent_observatory.stream.{name} must be greater than zero"
            ));
        }
    }
    if config.stream.max_event_bytes > 1_048_576 {
        return Err(anyhow::anyhow!(
            "agent_observatory.stream.max_event_bytes must not exceed 1048576"
        ));
    }

    for (name, value) in [
        ("events_days", config.retention.events_days),
        ("spans_days", config.retention.spans_days),
        ("metrics_days", config.retention.metrics_days),
        (
            "repository_observations_days",
            config.retention.repository_observations_days,
        ),
        (
            "removed_worktrees_days",
            config.retention.removed_worktrees_days,
        ),
    ] {
        if value == 0 {
            return Err(anyhow::anyhow!(
                "agent_observatory.retention.{name} must be greater than zero"
            ));
        }
    }

    Ok(())
}

pub(crate) fn validate_auth_config(config: &Config, check_bind: bool) -> anyhow::Result<()> {
    if token_is_set_but_blank(&config.mcp.api_token.0) {
        return Err(anyhow::anyhow!("mcp.api_token must not be empty"));
    }
    if token_is_set_but_blank(&config.api.api_token.0) {
        return Err(anyhow::anyhow!("api.api_token must not be empty"));
    }
    if token_is_set_but_blank(&config.api.admin_token.0) {
        return Err(anyhow::anyhow!("api.admin_token must not be empty"));
    }
    let mut forwarding_secrets = std::collections::HashSet::new();
    for (principal, secret) in &config.mcp.forwarding_agents {
        if principal.is_empty()
            || principal == "shared_bearer"
            || principal == "loopback"
            || !principal
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(anyhow::anyhow!(
                "mcp.forwarding_agents contains an invalid principal label"
            ));
        }
        let Some(token) = secret.as_deref() else {
            return Err(anyhow::anyhow!(
                "mcp.forwarding_agents contains a missing bearer secret"
            ));
        };
        if token.trim() != token || token.len() < 16 {
            return Err(anyhow::anyhow!(
                "mcp.forwarding_agents contains a weak or padded bearer secret"
            ));
        }
        if config.mcp.api_token.as_deref() == Some(token)
            || config.api.api_token.as_deref() == Some(token)
            || config.api.admin_token.as_deref() == Some(token)
        {
            return Err(anyhow::anyhow!(
                "mcp.forwarding_agents bearer secrets must differ from service API tokens"
            ));
        }
        if !forwarding_secrets.insert(token) {
            return Err(anyhow::anyhow!(
                "mcp.forwarding_agents bearer secrets must be unique"
            ));
        }
    }
    // Note: CORTEX_API_TOKEN being entirely unset is enforced at
    // route-mount time by `api::router` (anyhow::bail) rather than here.
    // Failing in `Config::load()` would break stdio-mode invocations
    // (which call `load_for_stdio()` with check_bind=false but still hit
    // this function) and the broad swath of tests that build Config
    // without exporting the token. The route-mount bail still fires
    // during server startup before any request is served, so operators
    // see the same error early.

    // ---- OAuth prerequisites ----------------------------------------------
    let auth = &config.mcp.auth;
    if config.mcp.no_auth {
        let bind_is_loopback = mcp_bind_is_loopback(config);
        if check_bind && !bind_is_loopback && !config.mcp.trusted_gateway_no_auth {
            return Err(anyhow::anyhow!(
                "MCP host `{}` is not a loopback address and CORTEX_NO_AUTH=true was set \
                 without CORTEX_TRUSTED_GATEWAY_NO_AUTH=true. Bind to 127.0.0.1 / ::1, \
                 configure CORTEX_TOKEN or OAuth, or set the trusted-gateway flag only \
                 when an upstream gateway enforces authentication before cortex.",
                config.mcp.host
            ));
        }
        return Ok(());
    }

    if auth.mode == AuthMode::OAuth {
        if option_is_blank(&auth.public_url) {
            return Err(anyhow::anyhow!(
                "CORTEX_PUBLIC_URL is required when CORTEX_AUTH_MODE=oauth — \
                 set the externally reachable base URL (e.g. https://syslog.example.com)"
            ));
        }
        if option_is_blank(&auth.google_client_id) {
            return Err(anyhow::anyhow!(
                "CORTEX_GOOGLE_CLIENT_ID is required when CORTEX_AUTH_MODE=oauth"
            ));
        }
        if option_is_blank(&auth.google_client_secret.0) {
            return Err(anyhow::anyhow!(
                "CORTEX_GOOGLE_CLIENT_SECRET is required when CORTEX_AUTH_MODE=oauth"
            ));
        }
        let admin_blank = auth.admin_email.trim().is_empty();
        let allowed_emails_set = auth
            .allowed_emails
            .iter()
            .any(|entry| !entry.trim().is_empty());
        if allowed_emails_set {
            return Err(anyhow::anyhow!(
                "[mcp.auth].allowed_emails is not passed to lab-auth; remove \
                 `allowed_emails` and use `admin_email` or lab-auth-managed allowed_users until \
                 cortex can enforce the config list"
            ));
        }
        if admin_blank {
            return Err(anyhow::anyhow!(
                "[mcp.auth] requires a non-empty `admin_email` when \
                 CORTEX_AUTH_MODE=oauth — `allowed_emails` is parsed but not passed to \
                 lab-auth yet"
            ));
        }
    }
    // Note: `disable_static_token_with_oauth` defaults to `true`; in pure
    // bearer mode the flag is a no-op (no OAuth path to disable) so we do not
    // reject the default combo. The flag only takes effect at middleware
    // mount time when OAuth is active (S3's job).

    // ---- Non-loopback safety gate -----------------------------------------
    // Skip in stdio / query-only mode: no HTTP port is bound so the gate is
    // irrelevant. `check_bind` is false when called from Config::load_for_stdio.
    let bind_is_loopback = mcp_bind_is_loopback(config);
    if check_bind && !bind_is_loopback {
        let has_static_token = config
            .mcp
            .api_token
            .as_deref()
            .is_some_and(|t| !t.trim().is_empty());
        let has_oauth = auth.mode == AuthMode::OAuth;
        if has_oauth && !has_static_token {
            return Err(anyhow::anyhow!(
                "MCP host `{}` is not a loopback address and CORTEX_AUTH_MODE=oauth is \
                 configured without CORTEX_TOKEN. OTLP /v1/logs only supports the static \
                 Bearer token gate today, so this would expose unauthenticated OTLP writes. \
                 Set CORTEX_TOKEN, bind to 127.0.0.1 / ::1, or enable an upstream auth \
                 gateway with CORTEX_NO_AUTH=true and CORTEX_TRUSTED_GATEWAY_NO_AUTH=true.",
                config.mcp.host
            ));
        }
        if !has_static_token && !has_oauth {
            return Err(anyhow::anyhow!(
                "MCP host `{}` is not a loopback address but no authentication is configured — \
                 set CORTEX_TOKEN, set CORTEX_AUTH_MODE=oauth, or bind to 127.0.0.1 / ::1",
                config.mcp.host
            ));
        }
    }

    Ok(())
}

pub fn mcp_bind_is_loopback(config: &Config) -> bool {
    IpAddr::from_str(&config.mcp.host)
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Returns true when the MCP HTTP listener is bound to a non-loopback address
/// AND the operator-facing public URL is plain http:// (or absent). In that
/// case `CORTEX_API_TOKEN` traverses the wire in plaintext. SWAG TLS
/// termination is the operator's responsibility — this helper just makes the
/// trade-off observable at startup.
pub fn api_token_plaintext_exposure(config: &Config) -> bool {
    if mcp_bind_is_loopback(config) {
        return false;
    }
    !matches!(
        config.mcp.auth.public_url.as_deref(),
        Some(url) if url.trim_start().to_ascii_lowercase().starts_with("https://"),
    )
}

fn option_is_blank(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(|v| v.trim().is_empty())
}

pub(crate) fn validate_docker_ingest_config(config: &DockerIngestConfig) -> anyhow::Result<()> {
    if !config.enabled {
        return Ok(());
    }
    if config.hosts.is_empty() {
        return Err(anyhow::anyhow!(
            "docker_ingest.hosts must not be empty when docker ingest is enabled"
        ));
    }
    if config.reconnect_initial_ms == 0 {
        return Err(anyhow::anyhow!(
            "docker_ingest.reconnect_initial_ms must be > 0"
        ));
    }
    if config.reconnect_max_ms < config.reconnect_initial_ms {
        return Err(anyhow::anyhow!(
            "docker_ingest.reconnect_max_ms must be >= reconnect_initial_ms"
        ));
    }
    let mut names = HashSet::new();
    for host in &config.hosts {
        if host.name.trim().is_empty() {
            return Err(anyhow::anyhow!("docker_ingest host name must not be empty"));
        }
        if !names.insert(host.name.as_str()) {
            return Err(anyhow::anyhow!(
                "duplicate docker_ingest host name: {}",
                host.name
            ));
        }
        if !(host.base_url.starts_with("http://") || host.base_url.starts_with("https://")) {
            return Err(anyhow::anyhow!(
                "docker_ingest host {} base_url must start with http:// or https://",
                host.name
            ));
        }
        if host.base_url.starts_with("http://") && !host.allow_insecure_http {
            return Err(anyhow::anyhow!(
                "docker_ingest host {} uses insecure http://; set allow_insecure_http = true only for trusted private networks",
                host.name
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_receiver_config(config: &ReceiverConfig) -> anyhow::Result<()> {
    if config.max_message_size == 0 {
        return Err(anyhow::anyhow!("syslog.max_message_size must be > 0"));
    }
    if config.max_tcp_connections == 0 {
        return Err(anyhow::anyhow!("syslog.max_tcp_connections must be > 0"));
    }
    if config.tcp_idle_timeout_secs == 0 {
        return Err(anyhow::anyhow!("syslog.tcp_idle_timeout_secs must be > 0"));
    }
    if config.batch_size == 0 {
        return Err(anyhow::anyhow!("syslog.batch_size must be > 0"));
    }
    if config.flush_interval == 0 {
        return Err(anyhow::anyhow!("syslog.flush_interval must be > 0"));
    }
    if config.write_channel_capacity == 0 {
        return Err(anyhow::anyhow!("syslog.write_channel_capacity must be > 0"));
    }
    for cidr in &config.allowed_source_cidrs {
        cidr.parse::<ipnet::IpNet>().map_err(|error| {
            anyhow::anyhow!(
                "CORTEX_ALLOWED_SOURCE_CIDRS: invalid CIDR entry '{cidr}' — {error}; \
                 expected format is <ip>/<prefix_len> (e.g. 10.0.0.0/8)"
            )
        })?;
    }
    Ok(())
}

/// Returns `true` only when the token is `Some` but contains only whitespace.
/// Returns `false` for `None` — an absent token is not an error; callers that
/// need to enforce token presence must check for `None` separately.
fn token_is_set_but_blank(token: &Option<String>) -> bool {
    token
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
}

fn env_override_parse<T: std::str::FromStr>(key: &str, target: &mut T) -> anyhow::Result<()>
where
    T::Err: std::fmt::Display,
{
    if let Some(v) = config_env_var(key)
        && !v.is_empty()
    {
        *target = v
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid value for {key}={v}: {e}"))?;
    }
    Ok(())
}

fn validate_host(host: &str) -> anyhow::Result<()> {
    // Accept IP addresses and hostnames. A quick parse check — if it's an IP, validate it.
    // Hostnames are validated at bind time by Tokio.
    if host.contains(':') {
        return Err(anyhow::anyhow!(
            "Host '{host}' should not contain a port — use the separate port setting"
        ));
    }
    Ok(())
}

fn validate_storage_config(storage: &StorageConfig) -> anyhow::Result<()> {
    if storage.max_db_size_mb > 0 {
        if storage.recovery_db_size_mb == 0 {
            return Err(anyhow::anyhow!(
                "recovery_db_size_mb must be > 0 when max_db_size_mb is enabled"
            ));
        }
        if storage.recovery_db_size_mb >= storage.max_db_size_mb {
            return Err(anyhow::anyhow!(
                "recovery_db_size_mb must be lower than max_db_size_mb"
            ));
        }
    } else if storage.recovery_db_size_mb != 0 {
        return Err(anyhow::anyhow!(
            "recovery_db_size_mb must be 0 when max_db_size_mb is disabled"
        ));
    }

    if storage.min_free_disk_mb > 0 {
        if storage.recovery_free_disk_mb == 0 {
            return Err(anyhow::anyhow!(
                "recovery_free_disk_mb must be > 0 when min_free_disk_mb is enabled"
            ));
        }
        if storage.recovery_free_disk_mb <= storage.min_free_disk_mb {
            return Err(anyhow::anyhow!(
                "recovery_free_disk_mb must be higher than min_free_disk_mb"
            ));
        }
    } else if storage.recovery_free_disk_mb != 0 {
        return Err(anyhow::anyhow!(
            "recovery_free_disk_mb must be 0 when min_free_disk_mb is disabled"
        ));
    }

    if storage.cleanup_interval_secs < 5 {
        return Err(anyhow::anyhow!(
            "cleanup_interval_secs must be at least 5 seconds"
        ));
    }

    if storage.cleanup_chunk_size == 0 {
        return Err(anyhow::anyhow!("cleanup_chunk_size must be > 0"));
    }

    if storage.cleanup_chunk_size > MAX_CLEANUP_CHUNK_SIZE {
        return Err(anyhow::anyhow!(
            "cleanup_chunk_size must be <= {} (larger values hold the write lock too long)",
            MAX_CLEANUP_CHUNK_SIZE
        ));
    }

    if storage.pool_size < MIN_POOL_SIZE {
        let lanes = UNPERMITTED_CONNECTION_LANES
            .iter()
            .filter(|lane| matches!(lane.residency, LaneResidency::Resident))
            .map(|lane| lane.name)
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "storage.pool_size must be at least {MIN_POOL_SIZE}: {RESERVED_UNPERMITTED_CONNECTIONS} \
             connections are reserved for lanes that acquire a connection without a service read \
             permit ({lanes}), leaving {MIN_READ_PERMITS} read permits"
        );
    }

    if storage.sqlite_page_cache_mb == 0 {
        anyhow::bail!("storage.sqlite_page_cache_mb must be > 0");
    }
    storage.sqlite_page_cache_kib_per_connection()?;
    storage.sqlite_mmap_bytes_i64()?;
    if storage.heavy_read_concurrency == 0 {
        anyhow::bail!("storage.heavy_read_concurrency must be > 0");
    }
    if storage.wal_checkpoint_mb == 0 {
        anyhow::bail!("storage.wal_checkpoint_mb must be > 0");
    }

    // err+ retention floor (syslog-mcp-w4hh). The floor is dimensioned in
    // (time window × per-source row count), NOT bytes, so there is no
    // meaningful "floor < max_db_size_mb" byte comparison. The coherent
    // invariant is that the floor must not be self-contradictory: if a window
    // is configured, the per-source cap must be > 0, otherwise the floor would
    // protect a non-empty time window yet retain zero rows from it — a silent
    // footgun that re-enables the err+ self-wipe the floor exists to prevent.
    if storage.err_floor_window_hours > 0 && storage.err_floor_per_source_cap == 0 {
        return Err(anyhow::anyhow!(
            "err_floor_per_source_cap must be > 0 when err_floor_window_hours is set \
             (a window with a zero per-source cap protects no err+ rows)"
        ));
    }

    Ok(())
}

/// Validate the error detection configuration.
fn validate_error_detection_config(cfg: &ErrorDetectionConfig) -> anyhow::Result<()> {
    if cfg.scan_interval_secs == 0 {
        anyhow::bail!("[error_detection] scan_interval_secs must be > 0");
    }
    if crate::db::severity_to_num(&cfg.notify_min_severity).is_none() {
        anyhow::bail!(
            "[error_detection] notify_min_severity must be a syslog severity \
             (emerg/alert/crit/err/warning/notice/info/debug), got {:?}",
            cfg.notify_min_severity
        );
    }
    Ok(())
}

fn validate_llm_config(cfg: &LlmConfig) -> anyhow::Result<()> {
    if cfg.max_concurrent == 0 {
        anyhow::bail!("[llm] max_concurrent must be > 0");
    }
    if cfg.max_per_action_concurrent == 0 {
        anyhow::bail!("[llm] max_per_action_concurrent must be > 0");
    }
    if cfg.timeout_secs == 0 {
        anyhow::bail!("[llm] timeout_secs must be > 0");
    }
    if cfg.max_prompt_bytes == 0 {
        anyhow::bail!("[llm] max_prompt_bytes must be > 0");
    }
    if cfg.max_output_bytes == 0 {
        anyhow::bail!("[llm] max_output_bytes must be > 0");
    }
    Ok(())
}

/// Validate the notifications configuration.
///
/// Fails at startup if notifications are enabled but no Apprise URLs are
/// configured — without URLs all notifications would be silently dropped.
fn validate_notifications_config(cfg: &NotificationsConfig) -> anyhow::Result<()> {
    if cfg.dispatcher_interval_secs == 0 {
        anyhow::bail!("[notifications] dispatcher_interval_secs must be > 0");
    }
    if cfg.evaluators.evaluator_interval_secs == 0 {
        anyhow::bail!("[notifications] evaluator_interval_secs must be > 0");
    }
    if cfg.evaluators.ingest_silence && cfg.evaluators.ingest_silence_threshold_secs == 0 {
        anyhow::bail!(
            "[notifications] ingest_silence_threshold_secs must be > 0 when \
             ingest_silence is enabled"
        );
    }
    if cfg.evaluators.heartbeat_silence && cfg.evaluators.heartbeat_silence_threshold_secs == 0 {
        anyhow::bail!(
            "[notifications] heartbeat_silence_threshold_secs must be > 0 when \
             heartbeat_silence is enabled"
        );
    }
    if cfg.evaluators.stream_silence {
        if cfg.evaluators.stream_silence_threshold_secs == 0 {
            anyhow::bail!(
                "[notifications] stream_silence_threshold_secs must be > 0 when \
                 stream_silence is enabled"
            );
        }
        if cfg
            .evaluators
            .stream_silence_kinds
            .iter()
            .all(|kind| kind.trim().is_empty())
        {
            anyhow::bail!(
                "[notifications] stream_silence_kinds must not be empty when \
                 stream_silence is enabled (set stream_silence = false to disable)"
            );
        }
    }
    if cfg.evaluators.heartbeat_silence || cfg.evaluators.stream_silence {
        let max_threshold = cfg
            .evaluators
            .heartbeat_silence_threshold_secs
            .max(cfg.evaluators.stream_silence_threshold_secs);
        if cfg.evaluators.silence_forget_secs <= max_threshold {
            anyhow::bail!(
                "[notifications] silence_forget_secs must exceed the silence \
                 thresholds (forget: {}, max threshold: {max_threshold})",
                cfg.evaluators.silence_forget_secs
            );
        }
    }
    // Trim whitespace before checking emptiness to catch " " entries.
    // Delivery requires BOTH the Apprise API base URL (`apprise_url`, where the
    // dispatcher POSTs `{base}/notify/`) AND at least one target URL
    // (`apprise_urls`, sent in the request body). The base URL alone cannot
    // deliver anything in Apprise stateless mode — the dispatcher logs
    // "no apprise URLs configured" and drops every firing. Fail loud at startup
    // instead of dropping silently.
    if cfg.enabled {
        let has_apprise_url = !cfg.apprise_url.trim().is_empty();
        let has_apprise_urls = cfg.apprise_urls.iter().any(|u| !u.trim().is_empty());
        if !has_apprise_url {
            anyhow::bail!(
                "[notifications] enabled = true but apprise_url (the Apprise API \
                 base URL, e.g. http://apprise:8000) is empty. \
                 Set apprise_url / CORTEX_NOTIFICATIONS_APPRISE_URL or set enabled = false."
            );
        }
        if !has_apprise_urls {
            anyhow::bail!(
                "[notifications] enabled = true but no apprise_urls (delivery \
                 target URLs, e.g. gotify://host/token) are configured; all \
                 notifications would be silently dropped. Set apprise_urls / \
                 CORTEX_NOTIFICATIONS_APPRISE_URLS or set enabled = false."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
impl StorageConfig {
    /// Returns a minimal StorageConfig for use in unit tests.
    pub(crate) fn for_test(db_path: std::path::PathBuf) -> Self {
        Self {
            db_path,
            pool_size: 1,
            sqlite_page_cache_mb: default_sqlite_page_cache_mb(),
            sqlite_mmap_mb: default_sqlite_mmap_mb(),
            heavy_read_concurrency: default_heavy_read_concurrency(),
            wal_checkpoint_mb: default_wal_checkpoint_mb(),
            retention_days: 90,
            wal_mode: false,
            max_db_size_mb: 1024,
            recovery_db_size_mb: 900,
            min_free_disk_mb: 0,
            recovery_free_disk_mb: 0,
            cleanup_interval_secs: 60,
            cleanup_chunk_size: 1,
            err_floor_window_hours: default_err_floor_window_hours(),
            err_floor_per_source_cap: default_err_floor_per_source_cap(),
        }
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
