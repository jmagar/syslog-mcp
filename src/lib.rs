//! Cortex log aggregation, investigation, and MCP/CLI/REST runtime.
//!
//! This crate contains the shared ingestion, storage, analysis, and transport
//! layers used by the `cortex` binary.

#![recursion_limit = "512"]

pub mod agent;
pub mod agent_command_ingest;
pub mod agent_deploy;
pub mod agent_observatory;
pub(crate) mod ai_project;
pub mod ai_transcript_ingest;
pub mod ai_watch;
pub mod api;
pub mod app;
pub mod artifact_evidence;
pub(crate) mod assessment;
pub mod color_policy;
pub mod command_log;
pub mod compose;
pub mod config;
pub mod deploy;
pub mod doctor;
pub mod enrich;
#[doc(hidden)]
pub mod env;
pub mod filetail;
pub mod git_observer;
pub(crate) mod hook_assessment;
pub(crate) mod hook_config;
pub(crate) mod skill_assessment;
pub(crate) use filetail as file_tail;
pub mod heartbeat;
pub mod heartbeat_agent;
pub mod inventory;
pub mod logging;
pub mod mcp;
pub(crate) mod mcp_assessment;
pub(crate) mod normalize;
pub(crate) mod notifications;
pub mod observability;
pub mod otlp;
pub mod receiver;
pub mod runtime;
pub mod scanner;
pub mod setup;
pub mod shell_history_ingest;
pub mod stream;
pub mod surfaces;
pub mod syslog_forward_ingest;
pub mod update;
pub mod web_app;

pub(crate) mod db;
pub(crate) mod docker_ingest;
pub(crate) mod ingest;
pub(crate) mod ingest_metadata;

#[cfg(test)]
#[path = "docs_tests.rs"]
mod docs_tests;

/// Test support: factory helpers for building [`mcp::AppState`] variants.
///
/// Gated by `cfg(any(test, feature = "test-support"))` so the helpers are
/// compiled in unit-test builds (crate-internal, via `#[cfg(test)]`) and for
/// integration tests that explicitly opt in with `--features test-support`.
/// They are `#[doc(hidden)]` so they don't pollute the public API surface.
///
/// All helpers take a `data_dir: &std::path::Path` so the caller controls the
/// lifetime of the temporary directory — no `tempfile` dep in this crate.
/// Integration tests pass `tempfile::TempDir::path()` or any other `Path`.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod testing {
    use std::{path::Path, sync::Arc};

    use crate::{
        app::CortexService,
        config::{McpConfig, StorageConfig},
        db,
        mcp::{AppState, AuthPolicy},
        otlp::OtlpCounters,
    };

    // Re-export db internals for integration tests (behind test-support feature).
    pub use crate::db::{DbPool, LogBatchEntry, init_pool, insert_logs_batch};

    /// Build an [`AppState`] with [`AuthPolicy::LoopbackDev`].
    /// `data_dir` must remain alive for the duration of the test.
    pub fn loopback_state(data_dir: &Path) -> AppState {
        state_with_policy(data_dir, AuthPolicy::LoopbackDev, None)
    }

    /// Build an [`AppState`] with [`AuthPolicy::Mounted`] + `auth_state: None`
    /// (static-bearer-only mode).
    pub fn bearer_state(data_dir: &Path, token: &str) -> AppState {
        state_with_policy(
            data_dir,
            AuthPolicy::Mounted { auth_state: None },
            Some(token.to_string()),
        )
    }

    /// Build an [`AppState`] with [`AuthPolicy::Mounted`] + a real
    /// [`lab_auth::state::AuthState`] (OAuth mode). Initialises the auth
    /// SQLite store and generates a fresh RSA signing key under `data_dir`.
    ///
    /// Google credentials are stubbed — no real Google requests are made.
    pub async fn oauth_state(data_dir: &Path) -> AppState {
        let auth_state = build_auth_state(data_dir).await;
        state_with_oauth(data_dir, Arc::new(auth_state), None)
    }

    /// Like [`oauth_state`] but also returns the [`lab_auth::state::AuthState`]
    /// so callers can issue tokens via `auth_state.signing_keys`.
    pub async fn oauth_state_with_auth_state(
        data_dir: &Path,
    ) -> (AppState, lab_auth::state::AuthState) {
        let auth_state = build_auth_state(data_dir).await;
        let state = state_with_oauth(data_dir, Arc::new(auth_state.clone()), None);
        (state, auth_state)
    }

    // ── private helpers ──────────────────────────────────────────────────────

    fn minimal_storage(data_dir: &Path) -> StorageConfig {
        StorageConfig {
            db_path: data_dir.join("syslog-test.db"),
            pool_size: 1,
            sqlite_page_cache_mb: 128,
            sqlite_mmap_mb: 256,
            heavy_read_concurrency: 1,
            wal_checkpoint_mb: 256,
            retention_days: 0,
            wal_mode: false,
            max_db_size_mb: 0,
            recovery_db_size_mb: 0,
            min_free_disk_mb: 0,
            recovery_free_disk_mb: 0,
            cleanup_interval_secs: 60,
            cleanup_chunk_size: 1,
            err_floor_window_hours: 24,
            err_floor_per_source_cap: 10_000,
        }
    }

    fn state_with_policy(data_dir: &Path, policy: AuthPolicy, token: Option<String>) -> AppState {
        let storage = minimal_storage(data_dir);
        let pool = Arc::new(db::init_pool(&storage).expect("test db pool should init"));
        AppState {
            service: CortexService::new(pool, storage),
            config: base_config(None, token),
            notifications_config: crate::config::NotificationsConfig::default(),
            otlp_counters: Arc::new(OtlpCounters::default()),
            auth_policy: policy,
            observability: Arc::new(crate::observability::RuntimeObservability::default()),
        }
    }

    fn state_with_oauth(
        data_dir: &Path,
        auth_state: Arc<lab_auth::state::AuthState>,
        token: Option<String>,
    ) -> AppState {
        let storage = minimal_storage(data_dir);
        let pool = Arc::new(db::init_pool(&storage).expect("test db pool should init"));
        AppState {
            service: CortexService::new(pool, storage),
            config: base_config(Some("https://syslog.example.com"), token),
            notifications_config: crate::config::NotificationsConfig::default(),
            otlp_counters: Arc::new(OtlpCounters::default()),
            auth_policy: AuthPolicy::Mounted {
                auth_state: Some(auth_state),
            },
            observability: Arc::new(crate::observability::RuntimeObservability::default()),
        }
    }

    fn base_config(public_url: Option<&str>, token: Option<String>) -> McpConfig {
        McpConfig {
            host: "127.0.0.1".into(),
            port: 3100,
            server_name: "cortex".into(),
            no_auth: false,
            trusted_gateway_no_auth: false,
            api_token: crate::config::Secret(token),
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            auth: crate::config::AuthConfig {
                public_url: public_url.map(|u| u.to_string()),
                ..Default::default()
            },
            forwarding_agents: Default::default(),
            static_token_is_admin: false,
        }
    }

    pub async fn build_auth_state(data_dir: &Path) -> lab_auth::state::AuthState {
        let vars: Vec<(String, String)> = vec![
            ("CORTEX_AUTH_MODE".into(), "oauth".into()),
            (
                "CORTEX_PUBLIC_URL".into(),
                "https://syslog.example.com".into(),
            ),
            ("CORTEX_GOOGLE_CLIENT_ID".into(), "test-client-id".into()),
            (
                "CORTEX_GOOGLE_CLIENT_SECRET".into(),
                "test-client-secret".into(),
            ),
            ("CORTEX_AUTH_ADMIN_EMAIL".into(), "admin@example.com".into()),
            (
                "CORTEX_AUTH_SQLITE_PATH".into(),
                data_dir
                    .join("auth.db")
                    .to_str()
                    .expect("auth.db path should be valid UTF-8")
                    .into(),
            ),
            (
                "CORTEX_AUTH_KEY_PATH".into(),
                data_dir
                    .join("auth-jwt.pem")
                    .to_str()
                    .expect("auth-jwt.pem path should be valid UTF-8")
                    .into(),
            ),
        ];

        let auth_config = lab_auth::config::AuthConfigBuilder::new()
            .env_prefix("CORTEX")
            .session_cookie_name("cortex_session")
            .scopes_supported(vec!["cortex:read".into(), "cortex:admin".into()])
            .default_scope("cortex:read")
            .resource_path("/mcp")
            .enable_dynamic_registration(true)
            .build_from_sources(vars)
            .expect("test auth config should build");

        lab_auth::state::AuthState::new(auth_config)
            .await
            .expect("test auth state should init")
    }
}
