use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

const MAX_CLEANUP_CHUNK_SIZE: usize = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub syslog: SyslogConfig,
    pub storage: StorageConfig,
    pub mcp: McpConfig,
    pub api: ApiConfig,
    pub docker_ingest: DockerIngestConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyslogConfig {
    /// Listen host (shared by UDP + TCP)
    #[serde(default = "default_syslog_host")]
    pub host: String,
    /// Listen port (shared by UDP + TCP)
    #[serde(default = "default_syslog_port")]
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
}

impl SyslogConfig {
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
    /// Optional bearer token for authenticating MCP requests.
    #[serde(default)]
    pub api_token: Option<String>,
    /// Optional additional Host header values accepted by RMCP Host validation.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Optional browser Origin values accepted by RMCP Origin validation.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
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
    /// Enable the non-MCP JSON API. Disabled by default.
    #[serde(default)]
    pub enabled: bool,
    /// Required bearer token when the non-MCP API is enabled.
    #[serde(default)]
    pub api_token: Option<String>,
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
}

#[derive(Debug, Deserialize)]
struct DockerHostsFile {
    hosts: Vec<DockerHostConfig>,
}

// --- Defaults ---

fn default_syslog_host() -> String {
    "0.0.0.0".into()
}
fn default_syslog_port() -> u16 {
    1514
}
fn default_db_path() -> PathBuf {
    PathBuf::from("/data/syslog.db")
}
fn default_mcp_host() -> String {
    "0.0.0.0".into()
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
fn default_pool_size() -> u32 {
    4
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
    512
}
fn default_recovery_free_disk_mb() -> u64 {
    768
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
    "syslog-mcp".into()
}
fn default_docker_reconnect_initial_ms() -> u64 {
    1_000
}
fn default_docker_reconnect_max_ms() -> u64 {
    30_000
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            host: default_syslog_host(),
            port: default_syslog_port(),
            max_message_size: default_max_message_size(),
            max_tcp_connections: default_max_tcp_connections(),
            tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
            batch_size: default_batch_size(),
            flush_interval: default_flush_interval(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            pool_size: default_pool_size(),
            retention_days: default_retention_days(),
            wal_mode: true,
            max_db_size_mb: default_max_db_size_mb(),
            recovery_db_size_mb: default_recovery_db_size_mb(),
            min_free_disk_mb: default_min_free_disk_mb(),
            recovery_free_disk_mb: default_recovery_free_disk_mb(),
            cleanup_interval_secs: default_cleanup_interval_secs(),
            cleanup_chunk_size: default_cleanup_chunk_size(),
        }
    }
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            host: default_mcp_host(),
            port: default_mcp_port(),
            server_name: default_server_name(),
            api_token: None,
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
        }
    }
}

impl Default for DockerIngestConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hosts: Vec::new(),
            reconnect_initial_ms: default_docker_reconnect_initial_ms(),
            reconnect_max_ms: default_docker_reconnect_max_ms(),
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        // 1. Start with defaults
        let mut config = Config::default();

        // 2. Overlay config.toml if present (partial configs are supported — missing
        //    fields keep their defaults from step 1 via #[serde(default)] annotations)
        match std::fs::read_to_string("config.toml") {
            Ok(contents) => {
                config = toml::from_str(&contents)
                    .map_err(|e| anyhow::anyhow!("Failed to parse config.toml: {e}"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow::anyhow!("Failed to read config.toml: {e}")),
        }

        // 3. Overlay environment variables (highest priority)
        //    SYSLOG_*     → syslog listener settings
        //    SYSLOG_MCP_* → MCP server + storage settings
        env_override_str("SYSLOG_HOST", &mut config.syslog.host);
        env_override_parse("SYSLOG_PORT", &mut config.syslog.port)?;
        env_override_parse(
            "SYSLOG_MAX_MESSAGE_SIZE",
            &mut config.syslog.max_message_size,
        )?;
        env_override_parse("SYSLOG_BATCH_SIZE", &mut config.syslog.batch_size)?;
        env_override_parse("SYSLOG_FLUSH_INTERVAL", &mut config.syslog.flush_interval)?;

        env_override_str("SYSLOG_MCP_HOST", &mut config.mcp.host);
        env_override_parse("SYSLOG_MCP_PORT", &mut config.mcp.port)?;
        env_override_list("SYSLOG_MCP_ALLOWED_HOSTS", &mut config.mcp.allowed_hosts);
        env_override_list(
            "SYSLOG_MCP_ALLOWED_ORIGINS",
            &mut config.mcp.allowed_origins,
        );
        // Primary name: SYSLOG_MCP_TOKEN
        env_override_opt_str("SYSLOG_MCP_TOKEN", &mut config.mcp.api_token);
        // Deprecated: SYSLOG_MCP_API_TOKEN (removed in a future version)
        if config.mcp.api_token.is_none() {
            if let Ok(v) = std::env::var("SYSLOG_MCP_API_TOKEN") {
                if !v.is_empty() {
                    tracing::warn!(
                        "SYSLOG_MCP_API_TOKEN is deprecated; rename to SYSLOG_MCP_TOKEN"
                    );
                    config.mcp.api_token = Some(v);
                }
            }
        }
        env_override_path("SYSLOG_MCP_DB_PATH", &mut config.storage.db_path);
        env_override_parse("SYSLOG_MCP_POOL_SIZE", &mut config.storage.pool_size)?;
        env_override_parse(
            "SYSLOG_MCP_RETENTION_DAYS",
            &mut config.storage.retention_days,
        )?;
        env_override_parse(
            "SYSLOG_MCP_MAX_DB_SIZE_MB",
            &mut config.storage.max_db_size_mb,
        )?;
        env_override_parse(
            "SYSLOG_MCP_RECOVERY_DB_SIZE_MB",
            &mut config.storage.recovery_db_size_mb,
        )?;
        env_override_parse(
            "SYSLOG_MCP_MIN_FREE_DISK_MB",
            &mut config.storage.min_free_disk_mb,
        )?;
        env_override_parse(
            "SYSLOG_MCP_RECOVERY_FREE_DISK_MB",
            &mut config.storage.recovery_free_disk_mb,
        )?;
        env_override_parse(
            "SYSLOG_MCP_CLEANUP_INTERVAL_SECS",
            &mut config.storage.cleanup_interval_secs,
        )?;
        env_override_parse(
            "SYSLOG_MCP_CLEANUP_CHUNK_SIZE",
            &mut config.storage.cleanup_chunk_size,
        )?;

        env_override_bool("SYSLOG_API_ENABLED", &mut config.api.enabled)?;
        env_override_opt_str("SYSLOG_API_TOKEN", &mut config.api.api_token);

        env_override_bool(
            "SYSLOG_DOCKER_INGEST_ENABLED",
            &mut config.docker_ingest.enabled,
        )?;
        env_override_parse(
            "SYSLOG_DOCKER_RECONNECT_INITIAL_MS",
            &mut config.docker_ingest.reconnect_initial_ms,
        )?;
        env_override_parse(
            "SYSLOG_DOCKER_RECONNECT_MAX_MS",
            &mut config.docker_ingest.reconnect_max_ms,
        )?;
        if config.docker_ingest.enabled {
            if let Ok(path) = std::env::var("SYSLOG_DOCKER_HOSTS_FILE") {
                if !path.is_empty() {
                    let contents = std::fs::read_to_string(&path).map_err(|e| {
                        anyhow::anyhow!("Failed to read SYSLOG_DOCKER_HOSTS_FILE={path}: {e}")
                    })?;
                    let parsed: DockerHostsFile = toml::from_str(&contents).map_err(|e| {
                        anyhow::anyhow!("Failed to parse SYSLOG_DOCKER_HOSTS_FILE={path}: {e}")
                    })?;
                    config.docker_ingest.hosts = parsed.hosts;
                }
            }
        }

        // Validation
        if config.storage.pool_size == 0 {
            return Err(anyhow::anyhow!("SYSLOG_MCP_POOL_SIZE must be > 0"));
        }
        validate_storage_config(&config.storage)?;
        validate_host(&config.syslog.host)?;
        validate_host(&config.mcp.host)?;
        validate_auth_config(&config)?;
        validate_docker_ingest_config(&config.docker_ingest)?;

        Ok(config)
    }
}

// --- Env var helpers ---

fn env_override_str(key: &str, target: &mut String) {
    if let Ok(v) = std::env::var(key) {
        if !v.is_empty() {
            *target = v;
        }
    }
}

fn env_override_opt_str(key: &str, target: &mut Option<String>) {
    if let Ok(v) = std::env::var(key) {
        if !v.is_empty() {
            *target = Some(v);
        }
    }
}

fn env_override_path(key: &str, target: &mut PathBuf) {
    if let Ok(v) = std::env::var(key) {
        if !v.is_empty() {
            *target = PathBuf::from(v);
        }
    }
}

fn env_override_list(key: &str, target: &mut Vec<String>) {
    let Ok(v) = std::env::var(key) else {
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

fn env_override_bool(key: &str, target: &mut bool) -> anyhow::Result<()> {
    let Ok(v) = std::env::var(key) else {
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

fn validate_auth_config(config: &Config) -> anyhow::Result<()> {
    if token_is_blank(&config.mcp.api_token) {
        return Err(anyhow::anyhow!("mcp.api_token must not be empty"));
    }
    if config.api.enabled {
        match config.api.api_token.as_deref() {
            Some(token) if !token.trim().is_empty() => {}
            Some(_) => return Err(anyhow::anyhow!("api.api_token must not be empty")),
            None => {
                return Err(anyhow::anyhow!(
                    "SYSLOG_API_TOKEN is required when SYSLOG_API_ENABLED=true"
                ));
            }
        }
    } else if token_is_blank(&config.api.api_token) {
        return Err(anyhow::anyhow!("api.api_token must not be empty"));
    }
    Ok(())
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

fn token_is_blank(token: &Option<String>) -> bool {
    token
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
}

fn env_override_parse<T: std::str::FromStr>(key: &str, target: &mut T) -> anyhow::Result<()>
where
    T::Err: std::fmt::Display,
{
    if let Ok(v) = std::env::var(key) {
        if !v.is_empty() {
            *target = v
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid value for {key}={v}: {e}"))?;
        }
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

    Ok(())
}

#[cfg(test)]
impl StorageConfig {
    /// Returns a minimal StorageConfig for use in unit tests.
    pub(crate) fn for_test(db_path: std::path::PathBuf) -> Self {
        Self {
            db_path,
            pool_size: 1,
            retention_days: 90,
            wal_mode: false,
            max_db_size_mb: 1024,
            recovery_db_size_mb: 900,
            min_free_disk_mb: 0,
            recovery_free_disk_mb: 0,
            cleanup_interval_secs: 60,
            cleanup_chunk_size: 1,
        }
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
