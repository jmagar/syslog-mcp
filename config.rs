use figment::{providers::{Env, Serialized, Toml}, Figment};
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
    /// UDP listen address
    pub udp_bind: String,
    /// TCP listen address
    pub tcp_bind: String,
    /// Max message size in bytes
    pub max_message_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Path to SQLite database
    pub db_path: PathBuf,
    /// Connection pool size
    pub pool_size: u32,
    /// Days to retain logs (0 = forever)
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            syslog: SyslogConfig {
                udp_bind: "0.0.0.0:1514".into(),
                tcp_bind: "0.0.0.0:1514".into(),
                max_message_size: 8192,
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
            },
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config: Config = Figment::new()
            .merge(Serialized::defaults(Config::default()))
            .merge(Toml::file("config.toml"))
            .merge(Env::prefixed("SYSLOG_MCP_").split("__"))
            .extract()?;
        Ok(config)
    }
}
