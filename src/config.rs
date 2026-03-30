use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub syslog: SyslogConfig,
    pub storage: StorageConfig,
    pub mcp: McpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    /// Listen host (shared by UDP + TCP)
    pub host: String,
    /// Listen port (shared by UDP + TCP)
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
pub struct StorageConfig {
    /// Path to SQLite database
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// HTTP listen host
    pub host: String,
    /// HTTP listen port
    pub port: u16,
    /// Server name exposed via MCP
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// Optional bearer token for authenticating MCP requests.
    #[serde(default)]
    pub api_token: Option<String>,
}

impl McpConfig {
    /// Returns "host:port" for binding the MCP HTTP server.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// --- Defaults ---

fn default_max_message_size() -> usize { 8192 }
fn default_max_tcp_connections() -> usize { 512 }
fn default_tcp_idle_timeout_secs() -> u64 { 300 }
fn default_batch_size() -> usize { 100 }
fn default_flush_interval() -> u64 { 500 }
fn default_pool_size() -> u32 { 4 }
fn default_retention_days() -> u32 { 90 }
fn default_true() -> bool { true }
fn default_server_name() -> String { "syslog-mcp".into() }

impl Default for Config {
    fn default() -> Self {
        Self {
            syslog: SyslogConfig {
                host: "0.0.0.0".into(),
                port: 1514,
                max_message_size: default_max_message_size(),
                max_tcp_connections: default_max_tcp_connections(),
                tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
                batch_size: default_batch_size(),
                flush_interval: default_flush_interval(),
            },
            storage: StorageConfig {
                db_path: PathBuf::from("/data/syslog.db"),
                pool_size: default_pool_size(),
                retention_days: default_retention_days(),
                wal_mode: true,
            },
            mcp: McpConfig {
                host: "0.0.0.0".into(),
                port: 3100,
                server_name: default_server_name(),
                api_token: None,
            },
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        // 1. Start with defaults
        let mut config = Config::default();

        // 2. Overlay config.toml if present
        if let Ok(contents) = std::fs::read_to_string("config.toml") {
            config = toml::from_str(&contents)
                .map_err(|e| anyhow::anyhow!("Failed to parse config.toml: {e}"))?;
        }

        // 3. Overlay environment variables (highest priority)
        //    SYSLOG_*     → syslog listener settings
        //    SYSLOG_MCP_* → MCP server + storage settings
        env_override_str("SYSLOG_HOST", &mut config.syslog.host);
        env_override_parse("SYSLOG_PORT", &mut config.syslog.port)?;
        env_override_parse("SYSLOG_MAX_MESSAGE_SIZE", &mut config.syslog.max_message_size)?;
        env_override_parse("SYSLOG_BATCH_SIZE", &mut config.syslog.batch_size)?;
        env_override_parse("SYSLOG_FLUSH_INTERVAL", &mut config.syslog.flush_interval)?;

        env_override_str("SYSLOG_MCP_HOST", &mut config.mcp.host);
        env_override_parse("SYSLOG_MCP_PORT", &mut config.mcp.port)?;
        env_override_opt_str("SYSLOG_MCP_API_TOKEN", &mut config.mcp.api_token);
        env_override_path("SYSLOG_MCP_DB_PATH", &mut config.storage.db_path);
        env_override_parse("SYSLOG_MCP_POOL_SIZE", &mut config.storage.pool_size)?;
        env_override_parse("SYSLOG_MCP_RETENTION_DAYS", &mut config.storage.retention_days)?;

        // Validation
        if config.storage.pool_size == 0 {
            return Err(anyhow::anyhow!("SYSLOG_MCP_POOL_SIZE must be > 0"));
        }
        validate_host(&config.syslog.host)?;
        validate_host(&config.mcp.host)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn env_var_overrides_mcp_port() {
        std::env::set_var("SYSLOG_MCP_PORT", "3200");
        let result = Config::load();
        std::env::remove_var("SYSLOG_MCP_PORT");

        let cfg = result.expect("Config::load() should succeed");
        assert_eq!(cfg.mcp.port, 3200);
    }

    #[test]
    #[serial]
    fn env_var_overrides_syslog_port() {
        std::env::set_var("SYSLOG_PORT", "2514");
        let result = Config::load();
        std::env::remove_var("SYSLOG_PORT");

        let cfg = result.expect("Config::load() should succeed");
        assert_eq!(cfg.syslog.port, 2514);
        assert_eq!(cfg.syslog.bind_addr(), "0.0.0.0:2514");
    }

    #[test]
    #[serial]
    fn defaults_are_applied_without_env_vars() {
        // Clear any leaked env vars
        for key in [
            "SYSLOG_HOST", "SYSLOG_PORT", "SYSLOG_MCP_HOST", "SYSLOG_MCP_PORT",
            "SYSLOG_MCP_DB_PATH", "SYSLOG_MCP_POOL_SIZE", "SYSLOG_MCP_RETENTION_DAYS",
            "SYSLOG_MCP_API_TOKEN",
        ] {
            std::env::remove_var(key);
        }

        let cfg = Config::load().expect("Config::load() should succeed with defaults");
        assert_eq!(cfg.syslog.host, "0.0.0.0");
        assert_eq!(cfg.syslog.port, 1514);
        assert_eq!(cfg.syslog.bind_addr(), "0.0.0.0:1514");
        assert_eq!(cfg.mcp.host, "0.0.0.0");
        assert_eq!(cfg.mcp.port, 3100);
        assert_eq!(cfg.mcp.bind_addr(), "0.0.0.0:3100");
        assert_eq!(cfg.storage.pool_size, 4);
        assert_eq!(cfg.storage.retention_days, 90);
        assert!(cfg.storage.wal_mode);
        assert!(cfg.mcp.api_token.is_none());
    }

    #[test]
    #[serial]
    fn host_with_port_is_rejected() {
        std::env::set_var("SYSLOG_HOST", "0.0.0.0:1514");
        let result = Config::load();
        std::env::remove_var("SYSLOG_HOST");

        assert!(result.is_err(), "Host containing ':' should be rejected");
    }
}
