use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub syslog: SyslogConfig,
    pub storage: StorageConfig,
    pub mcp: McpConfig,
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

fn default_flush_interval_ms() -> u64 {
    500
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    /// UDP listen address
    pub udp_bind: String,
    /// TCP listen address
    pub tcp_bind: String,
    /// Max message size in bytes
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
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to SQLite database
    pub db_path: PathBuf,
    /// Connection pool size
    pub pool_size: u32,
    /// Days to retain logs before automatic deletion.
    ///
    /// Set to `0` to disable purging entirely (logs kept forever).
    /// When non-zero, an hourly background task deletes logs older than this many days.
    /// Validated at startup: the `if retention_days > 0` guard in `main.rs` enforces this.
    pub retention_days: u32,
    /// WAL mode (recommended for concurrent reads)
    pub wal_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// HTTP bind address for MCP server
    pub bind: String,
    /// Server name exposed via MCP
    pub server_name: String,
    /// Optional bearer token for authenticating MCP requests.
    ///
    /// When set, every request to `/mcp` and `/sse` must include:
    ///   `Authorization: Bearer <token>`
    /// Requests without a valid token receive HTTP 401.
    ///
    /// Leave unset (the default) to disable authentication — suitable for
    /// deployments where access is already controlled by a reverse proxy (e.g. SWAG).
    ///
    /// Configure via env var: `SYSLOG_MCP_MCP__API_TOKEN=your-secret-token-here`
    pub api_token: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            syslog: SyslogConfig {
                udp_bind: "0.0.0.0:1514".into(),
                tcp_bind: "0.0.0.0:1514".into(),
                max_message_size: 8192,
                max_tcp_connections: default_max_tcp_connections(),
                tcp_idle_timeout_secs: default_tcp_idle_timeout_secs(),
                batch_size: default_batch_size(),
                flush_interval_ms: default_flush_interval_ms(),
            },
            storage: StorageConfig {
                db_path: PathBuf::from("/data/syslog.db"),
                pool_size: 4,
                retention_days: 90,
                wal_mode: true,
            },
            mcp: McpConfig {
                bind: "0.0.0.0:3100".into(),
                server_name: "syslog-mcp".into(),
                api_token: None,
            },
        }
    }
}

fn validate_addr(field: &str, value: &str) -> anyhow::Result<()> {
    // Parse as a concrete SocketAddr (non-blocking, no DNS).
    // All config addresses are IP:port (e.g. "0.0.0.0:1514") — hostname
    // resolution is Tokio's job at bind time, not ours at config-load time.
    value
        .parse::<std::net::SocketAddr>()
        .map_err(|e| anyhow::anyhow!("Invalid {field} address '{value}': {e}"))?;
    Ok(())
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config: Config = Figment::new()
            .merge(Serialized::defaults(Config::default()))
            .merge(Toml::file("config.toml"))
            .merge(Env::prefixed("SYSLOG_MCP_").split("__"))
            .extract()?;

        if config.storage.pool_size == 0 {
            return Err(anyhow::anyhow!("storage.pool_size must be > 0"));
        }
        validate_addr("syslog.udp_bind", &config.syslog.udp_bind)?;
        validate_addr("syslog.tcp_bind", &config.syslog.tcp_bind)?;
        validate_addr("mcp.bind", &config.mcp.bind)?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Regression test for the SYSLOG_MCP_ prefix.
    ///
    /// History: the Dockerfile previously used SYSLOG_MCP__ (double underscore) which figment
    /// silently ignores — env vars had zero effect and defaults were used instead. The correct
    /// prefix is SYSLOG_MCP_ (single underscore); __ is only the nesting separator between
    /// section and key (e.g. MCP__BIND means section=mcp, key=bind).
    ///
    /// If this test fails it means Config::load() is no longer reading env vars at all, or the
    /// prefix has been changed back to double-underscore.
    ///
    /// NOTE: env var mutation is not thread-safe. Cargo runs tests in the same process by default.
    /// If additional env var tests are added in future, use the `serial_test` crate and mark all
    /// env var tests with `#[serial]` to prevent races.
    #[test]
    #[serial]
    fn env_var_overrides_mcp_bind() {
        // SYSLOG_MCP_MCP__BIND: prefix=SYSLOG_MCP_, section=MCP, key=BIND (split on __)
        std::env::set_var("SYSLOG_MCP_MCP__BIND", "127.0.0.1:3200");
        let result = Config::load();
        std::env::remove_var("SYSLOG_MCP_MCP__BIND");

        let cfg = result.expect("Config::load() should succeed with a valid bind address");
        assert_eq!(
            cfg.mcp.bind, "127.0.0.1:3200",
            "SYSLOG_MCP_MCP__BIND env var must override mcp.bind; \
             check that the figment prefix is SYSLOG_MCP_ (single underscore) and \
             that __ is used as the section/key separator"
        );
    }

    /// Verify that defaults are intact when no env vars are set.
    ///
    /// Guards against accidental removal of `Serialized::defaults(Config::default())` from the
    /// figment chain.
    #[test]
    #[serial]
    fn defaults_are_applied_without_env_vars() {
        // Ensure the env var from the other test is not leaking (defensive).
        std::env::remove_var("SYSLOG_MCP_MCP__BIND");

        let cfg = Config::load().expect("Config::load() should succeed with defaults");
        assert_eq!(cfg.mcp.bind, "0.0.0.0:3100");
        assert_eq!(cfg.syslog.udp_bind, "0.0.0.0:1514");
        assert_eq!(cfg.syslog.tcp_bind, "0.0.0.0:1514");
        assert_eq!(cfg.storage.pool_size, 4);
        assert_eq!(cfg.storage.retention_days, 90);
        assert!(cfg.storage.wal_mode);
        assert!(cfg.mcp.api_token.is_none());
    }
}
