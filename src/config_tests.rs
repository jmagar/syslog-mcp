use super::*;
use serial_test::serial;

#[test]
#[serial]
fn syslog_mcp_token_sets_api_token() {
    std::env::set_var("SYSLOG_MCP_TOKEN", "test-token");
    std::env::remove_var("SYSLOG_MCP_API_TOKEN");
    let result = Config::load();
    std::env::remove_var("SYSLOG_MCP_TOKEN");

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.mcp.api_token, Some("test-token".into()));
}

#[test]
#[serial]
fn deprecated_api_token_still_works() {
    std::env::remove_var("SYSLOG_MCP_TOKEN");
    std::env::set_var("SYSLOG_MCP_API_TOKEN", "legacy-token");
    let result = Config::load();
    std::env::remove_var("SYSLOG_MCP_API_TOKEN");

    let cfg = result.expect("Config::load() should succeed with deprecated var");
    assert_eq!(cfg.mcp.api_token, Some("legacy-token".into()));
}

#[test]
#[serial]
fn new_token_takes_precedence_over_deprecated() {
    std::env::set_var("SYSLOG_MCP_TOKEN", "new-token");
    std::env::set_var("SYSLOG_MCP_API_TOKEN", "old-token");
    let result = Config::load();
    std::env::remove_var("SYSLOG_MCP_TOKEN");
    std::env::remove_var("SYSLOG_MCP_API_TOKEN");

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.mcp.api_token, Some("new-token".into()));
}

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
        "SYSLOG_HOST",
        "SYSLOG_PORT",
        "SYSLOG_MCP_HOST",
        "SYSLOG_MCP_PORT",
        "SYSLOG_MCP_DB_PATH",
        "SYSLOG_MCP_POOL_SIZE",
        "SYSLOG_MCP_RETENTION_DAYS",
        "SYSLOG_MCP_TOKEN",
        "SYSLOG_MCP_API_TOKEN",
        "SYSLOG_MCP_MAX_DB_SIZE_MB",
        "SYSLOG_MCP_RECOVERY_DB_SIZE_MB",
        "SYSLOG_MCP_MIN_FREE_DISK_MB",
        "SYSLOG_MCP_RECOVERY_FREE_DISK_MB",
        "SYSLOG_MCP_CLEANUP_INTERVAL_SECS",
        "SYSLOG_MCP_CLEANUP_CHUNK_SIZE",
        "SYSLOG_API_ENABLED",
        "SYSLOG_API_TOKEN",
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
    assert_eq!(cfg.storage.max_db_size_mb, 1024);
    assert_eq!(cfg.storage.recovery_db_size_mb, 900);
    assert_eq!(cfg.storage.min_free_disk_mb, 512);
    assert_eq!(cfg.storage.recovery_free_disk_mb, 768);
    assert_eq!(cfg.storage.cleanup_interval_secs, 60);
    assert_eq!(cfg.storage.cleanup_chunk_size, 2_000);
    assert!(cfg.mcp.api_token.is_none());
    assert!(!cfg.api.enabled);
    assert!(cfg.api.api_token.is_none());
}

#[test]
#[serial]
fn api_enabled_requires_separate_token() {
    std::env::set_var("SYSLOG_API_ENABLED", "true");
    std::env::remove_var("SYSLOG_API_TOKEN");
    let result = Config::load();
    std::env::remove_var("SYSLOG_API_ENABLED");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("SYSLOG_API_TOKEN"));
}

#[test]
#[serial]
fn api_token_is_separate_from_mcp_token() {
    std::env::set_var("SYSLOG_API_ENABLED", "true");
    std::env::set_var("SYSLOG_API_TOKEN", "api-token");
    std::env::set_var("SYSLOG_MCP_TOKEN", "mcp-token");
    let result = Config::load();
    std::env::remove_var("SYSLOG_API_ENABLED");
    std::env::remove_var("SYSLOG_API_TOKEN");
    std::env::remove_var("SYSLOG_MCP_TOKEN");

    let cfg = result.expect("Config::load() should accept separately authenticated API");
    assert!(cfg.api.enabled);
    assert_eq!(cfg.api.api_token, Some("api-token".into()));
    assert_eq!(cfg.mcp.api_token, Some("mcp-token".into()));
}

#[test]
#[serial]
fn host_with_port_is_rejected() {
    std::env::set_var("SYSLOG_HOST", "0.0.0.0:1514");
    let result = Config::load();
    std::env::remove_var("SYSLOG_HOST");

    assert!(result.is_err(), "Host containing ':' should be rejected");
}

#[test]
fn defaults_include_storage_budget_settings() {
    let cfg = Config::default();
    assert_eq!(cfg.storage.max_db_size_mb, 1024);
    assert_eq!(cfg.storage.recovery_db_size_mb, 900);
    assert_eq!(cfg.storage.min_free_disk_mb, 512);
    assert_eq!(cfg.storage.recovery_free_disk_mb, 768);
    assert_eq!(cfg.storage.cleanup_interval_secs, 60);
}

#[test]
#[serial]
fn env_var_overrides_storage_budget_settings() {
    std::env::set_var("SYSLOG_MCP_MAX_DB_SIZE_MB", "2048");
    std::env::set_var("SYSLOG_MCP_RECOVERY_DB_SIZE_MB", "1800");
    std::env::set_var("SYSLOG_MCP_MIN_FREE_DISK_MB", "1024");
    std::env::set_var("SYSLOG_MCP_RECOVERY_FREE_DISK_MB", "1536");
    std::env::set_var("SYSLOG_MCP_CLEANUP_INTERVAL_SECS", "120");

    let result = Config::load();

    for key in [
        "SYSLOG_MCP_MAX_DB_SIZE_MB",
        "SYSLOG_MCP_RECOVERY_DB_SIZE_MB",
        "SYSLOG_MCP_MIN_FREE_DISK_MB",
        "SYSLOG_MCP_RECOVERY_FREE_DISK_MB",
        "SYSLOG_MCP_CLEANUP_INTERVAL_SECS",
    ] {
        std::env::remove_var(key);
    }

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.storage.max_db_size_mb, 2048);
    assert_eq!(cfg.storage.recovery_db_size_mb, 1800);
    assert_eq!(cfg.storage.min_free_disk_mb, 1024);
    assert_eq!(cfg.storage.recovery_free_disk_mb, 1536);
    assert_eq!(cfg.storage.cleanup_interval_secs, 120);
}

#[test]
#[serial]
fn rejects_invalid_storage_budget_relationships() {
    std::env::set_var("SYSLOG_MCP_MAX_DB_SIZE_MB", "100");
    std::env::set_var("SYSLOG_MCP_RECOVERY_DB_SIZE_MB", "100");
    let result = Config::load();
    std::env::remove_var("SYSLOG_MCP_MAX_DB_SIZE_MB");
    std::env::remove_var("SYSLOG_MCP_RECOVERY_DB_SIZE_MB");

    let err = result.expect_err("Config::load() should reject invalid recovery_db_size_mb");
    assert!(err.to_string().contains("recovery_db_size_mb"));
}

#[test]
#[serial]
fn rejects_cleanup_chunk_size_zero() {
    std::env::set_var("SYSLOG_MCP_CLEANUP_CHUNK_SIZE", "0");
    let result = Config::load();
    std::env::remove_var("SYSLOG_MCP_CLEANUP_CHUNK_SIZE");

    let err = result.expect_err("Config::load() should reject cleanup_chunk_size == 0");
    assert!(err.to_string().contains("cleanup_chunk_size"));
}

#[test]
#[serial]
fn rejects_cleanup_chunk_size_over_max() {
    std::env::set_var("SYSLOG_MCP_CLEANUP_CHUNK_SIZE", "1000001");
    let result = Config::load();
    std::env::remove_var("SYSLOG_MCP_CLEANUP_CHUNK_SIZE");

    let err = result.expect_err("Config::load() should reject cleanup_chunk_size > 1_000_000");
    assert!(
        err.to_string().contains("cleanup_chunk_size"),
        "Expected error referencing cleanup_chunk_size, got: {err}"
    );
}

#[test]
#[serial]
fn accepts_cleanup_chunk_size_at_max() {
    std::env::set_var("SYSLOG_MCP_CLEANUP_CHUNK_SIZE", "1000000");
    let result = Config::load();
    std::env::remove_var("SYSLOG_MCP_CLEANUP_CHUNK_SIZE");

    let cfg = result.expect("cleanup_chunk_size == 1_000_000 should be accepted");
    assert_eq!(cfg.storage.cleanup_chunk_size, 1_000_000);
}
