use super::*;
use serial_test::serial;

#[test]
#[serial]
fn cortex_token_sets_api_token() {
    crate::env::set_test_var("CORTEX_TOKEN", "test-token");
    crate::env::remove_test_var("CORTEX_API_TOKEN");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_TOKEN");

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.mcp.api_token, Some("test-token".into()));
}

#[test]
#[serial]
fn api_token_env_sets_api_token_not_mcp_token() {
    // cortex v1.0.0: the pre-v1 `SYSLOG_MCP_API_TOKEN` deprecated MCP-token alias was
    // dropped. Its post-rename name `CORTEX_API_TOKEN` now belongs exclusively to the
    // API/OTLP token (`config.api.api_token`) and must NOT set the MCP static token.
    crate::env::remove_test_var("CORTEX_TOKEN");
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_API_TOKEN", "api-token");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_API_TOKEN");
    crate::env::remove_test_var("CORTEX_HOST");

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.api.api_token, Some("api-token".into()));
    assert_eq!(cfg.mcp.api_token, None);
}

#[test]
#[serial]
fn api_admin_token_env_sets_admin_token() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_API_ADMIN_TOKEN", "api-admin-token");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_API_ADMIN_TOKEN");
    crate::env::remove_test_var("CORTEX_HOST");

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.api.admin_token, Some("api-admin-token".into()));
}

#[test]
#[serial]
fn env_var_overrides_mcp_port() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_PORT", "3200");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_PORT");

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.mcp.port, 3200);
}

#[test]
#[serial]
fn env_var_overrides_receiver_port() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_RECEIVER_PORT", "2514");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_RECEIVER_PORT");

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.receiver.port, 2514);
    assert_eq!(cfg.receiver.bind_addr(), "0.0.0.0:2514");
}

#[test]
fn unsupported_notification_blocks_are_rejected_explicitly() {
    for (surface, raw) in [
        (
            "[notifications.quiet_hours]",
            "[notifications.quiet_hours]\nenabled = true\n",
        ),
        (
            "[notifications.apprise]",
            "[notifications.apprise]\nbase_url = \"http://apprise:8000\"\n",
        ),
        (
            "[notifications.digest]",
            "[notifications.digest]\nenabled = true\n",
        ),
        (
            "[[notifications.rules]]",
            "[[notifications.rules]]\nid = \"legacy-rule\"\n",
        ),
    ] {
        let err = reject_unsupported_config_blocks(raw).unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("{surface} is not implemented")),
            "wrong error for {surface}: {err}"
        );
    }
}

#[test]
fn supported_notifications_config_is_not_rejected() {
    let raw = r#"
[notifications]
enabled = true
dispatcher_interval_secs = 15
"#;
    reject_unsupported_config_blocks(raw).unwrap();
}

#[test]
fn receiver_toml_section_deserializes_into_receiver_field() {
    // Guards the field/section coupling: the `[receiver]` TOML section must bind to
    // `Config.receiver`. A serde mismatch here compiles clean and only fails at runtime,
    // so this positive round-trip is the explicit guard (no env vars, pure deserialize).
    let raw = "[receiver]\nhost = \"10.0.0.5\"\nport = 2514\nbatch_size = 250\n";
    let cfg: Config = toml::from_str(raw).expect("[receiver] section should parse");
    assert_eq!(cfg.receiver.host, "10.0.0.5");
    assert_eq!(cfg.receiver.port, 2514);
    assert_eq!(cfg.receiver.batch_size, 250);
}

#[test]
fn named_forwarding_agents_deserialize_as_redacted_secrets() {
    let cfg: Config = toml::from_str(
        "[mcp.forwarding_agents]\nnode_a = \"agent-a-secret\"\nnode_b = \"agent-b-secret\"\n",
    )
    .expect("named forwarding credentials should parse");
    assert_eq!(
        cfg.mcp.forwarding_agents["node_a"].0.as_deref(),
        Some("agent-a-secret")
    );
    let debug = format!("{:?}", cfg.mcp.forwarding_agents);
    assert!(!debug.contains("agent-a-secret"));
    assert!(debug.contains("[REDACTED]"));
}

#[test]
fn named_forwarding_agents_fail_closed_without_disclosing_secrets() {
    for (principal, left, right) in [
        ("", "0123456789abcdef", "fedcba9876543210"),
        ("shared_bearer", "0123456789abcdef", "fedcba9876543210"),
        ("loopback", "0123456789abcdef", "fedcba9876543210"),
        ("bad label", "0123456789abcdef", "fedcba9876543210"),
        ("node-a", "short", "fedcba9876543210"),
        ("node-a", " 0123456789abcdef", "fedcba9876543210"),
        ("node-a", "0123456789abcdef", "0123456789abcdef"),
    ] {
        let mut config = Config::default();
        config
            .mcp
            .forwarding_agents
            .insert(principal.into(), Some(left.into()).into());
        config
            .mcp
            .forwarding_agents
            .insert("node-b".into(), Some(right.into()).into());
        let message = validate_auth_config(&config, false)
            .expect_err("invalid forwarding credentials must fail closed")
            .to_string();
        assert!(!message.contains(left));
        assert!(!message.contains(right));
    }

    let mut config = Config::default();
    config.mcp.forwarding_agents.insert(
        "node-a.example".into(),
        Some("0123456789abcdef".into()).into(),
    );
    config
        .mcp
        .forwarding_agents
        .insert("node_b".into(), Some("fedcba9876543210".into()).into());
    validate_auth_config(&config, false).expect("distinct strong mappings should be accepted");

    let mut config = Config::default();
    config.mcp.api_token = Some("0123456789abcdef".into()).into();
    config
        .mcp
        .forwarding_agents
        .insert("node-a".into(), Some("0123456789abcdef".into()).into());
    let message = validate_auth_config(&config, false)
        .expect_err("a named forwarding secret must not alias the shared bearer")
        .to_string();
    assert!(!message.contains("0123456789abcdef"));

    for admin in [false, true] {
        let mut config = Config::default();
        if admin {
            config.api.admin_token = Some("0123456789abcdef".into()).into();
        } else {
            config.api.api_token = Some("0123456789abcdef".into()).into();
        }
        config
            .mcp
            .forwarding_agents
            .insert("node-a".into(), Some("0123456789abcdef".into()).into());
        let message = validate_auth_config(&config, false)
            .expect_err("forwarding secrets must not alias REST service tokens")
            .to_string();
        assert!(!message.contains("0123456789abcdef"));
    }
}

#[test]
fn storage_defaults_include_sqlite_memory_guardrails() {
    let storage = StorageConfig::default();
    assert_eq!(storage.pool_size, 8);
    assert_eq!(storage.sqlite_page_cache_mb, 128);
    assert_eq!(storage.sqlite_mmap_mb, 256);
    assert_eq!(storage.heavy_read_concurrency, 1);
    assert_eq!(storage.wal_checkpoint_mb, 256);
    assert_eq!(
        storage.sqlite_page_cache_kib_per_connection().unwrap(),
        -16_384
    );
    assert_eq!(storage.sqlite_mmap_bytes(), 256 * 1024 * 1024);
}

#[test]
fn storage_page_cache_budget_is_divided_per_connection_without_hidden_floor() {
    let storage = StorageConfig {
        pool_size: 128,
        sqlite_page_cache_mb: 1,
        ..StorageConfig::default()
    };
    assert_eq!(storage.sqlite_page_cache_kib_per_connection().unwrap(), -8);
}

/// The pool budget is a partition, not an approximation: no connection may be
/// counted twice or left out. Pinned across the whole plausible range because
/// the fallback for undersized pools is where an off-by-one would hide.
#[test]
fn pool_budget_partitions_every_connection() {
    for pool_size in 0..=64u32 {
        let budget = PoolBudget::for_pool_size(pool_size);
        assert_eq!(
            budget.read_permits() as u32 + budget.reserved(),
            budget.pool_size(),
            "pool_size {pool_size} is not fully partitioned"
        );
        assert!(
            budget.read_permits() >= 1,
            "pool_size {pool_size} left no read permits"
        );
    }
}

/// The reserve must equal the resident rows of `UNPERMITTED_CONNECTION_LANES`.
///
/// This is the drift guard the bug needed. The reservation was documented as
/// "one connection for the writer" and stayed 1 while a dozen more writers were
/// added, because nothing tied the number to the set of writers. Adding a
/// resident lane to that table now moves the reserve, `MIN_POOL_SIZE`, and the
/// config validation together.
#[test]
fn reserved_connections_equal_the_resident_lane_table() {
    let resident: u32 = UNPERMITTED_CONNECTION_LANES
        .iter()
        .filter(|lane| matches!(lane.residency, LaneResidency::Resident))
        .map(|lane| lane.connections)
        .sum();
    assert_eq!(RESERVED_UNPERMITTED_CONNECTIONS, resident);
    assert_eq!(MIN_POOL_SIZE, resident + MIN_READ_PERMITS);
    assert!(
        UNPERMITTED_CONNECTION_LANES
            .iter()
            .all(|lane| lane.connections >= 1),
        "a lane that can hold zero connections does not belong in the table"
    );
}

/// Every declared lane cap must match the mechanism that enforces it. Only
/// `docker_checkpoint_loads` has a constant to compare against; the rest are
/// single supervised tasks or `Semaphore::new(1)` holders, asserted as 1 here so
/// widening one without revisiting the budget fails.
#[test]
fn lane_caps_match_their_enforcing_mechanism() {
    let cap = |name: &str| {
        UNPERMITTED_CONNECTION_LANES
            .iter()
            .find(|lane| lane.name == name)
            .unwrap_or_else(|| panic!("lane {name} missing from the table"))
            .connections
    };
    assert_eq!(
        cap("docker_checkpoint_loads"),
        u32::try_from(crate::docker_ingest::MAX_CONCURRENT_CHECKPOINT_LOADS).unwrap()
    );
    for single in [
        "ingest_batch_writer",
        "maintenance_permit",
        "notification_dispatcher_permit",
        "agent_observatory_projector",
        "agent_observatory_git_reconcile",
    ] {
        assert_eq!(
            cap(single),
            1,
            "{single} is no longer a single-connection lane"
        );
    }
}

/// The shipped default must leave the readers a workable share after the
/// reservation. `pool_size` is unchanged at 8; what changed is that 4 of those
/// are now held back rather than 1.
#[test]
fn default_pool_size_satisfies_the_budget() {
    let storage = StorageConfig::default();
    assert_eq!(storage.pool_size, 8);
    assert!(storage.pool_size >= MIN_POOL_SIZE);
    let budget = storage.pool_budget();
    assert_eq!(budget.reserved(), RESERVED_UNPERMITTED_CONNECTIONS);
    assert_eq!(budget.reserved(), 4);
    assert_eq!(budget.read_permits(), 4);
    assert!(budget.read_permits() >= MIN_READ_PERMITS as usize);
    validate_storage_config(&storage).expect("default storage config must validate");
}

#[test]
fn storage_rejects_pool_too_small_for_the_reserved_lanes() {
    let storage = StorageConfig {
        pool_size: MIN_POOL_SIZE - 1,
        ..StorageConfig::default()
    };
    let err = validate_storage_config(&storage).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("pool_size"), "wrong error: {message}");
    assert!(
        message.contains("ingest_batch_writer"),
        "the error must name the lanes the reserve is for: {message}"
    );
}

#[test]
fn storage_rejects_sqlite_page_cache_overflow() {
    let storage = StorageConfig {
        sqlite_page_cache_mb: u64::MAX,
        ..StorageConfig::default()
    };
    let err = validate_storage_config(&storage).unwrap_err();
    assert!(
        err.to_string().contains("sqlite_page_cache_mb"),
        "wrong error: {err}"
    );
}

#[test]
fn storage_rejects_sqlite_mmap_overflow() {
    let storage = StorageConfig {
        sqlite_mmap_mb: u64::MAX,
        ..StorageConfig::default()
    };
    let err = validate_storage_config(&storage).unwrap_err();
    assert!(
        err.to_string().contains("sqlite_mmap_mb"),
        "wrong error: {err}"
    );
}

#[test]
#[serial]
fn defaults_are_applied_without_env_vars() {
    // Clear any leaked env vars
    for key in [
        "CORTEX_RECEIVER_HOST",
        "CORTEX_RECEIVER_PORT",
        "CORTEX_MAX_MESSAGE_SIZE",
        "CORTEX_MAX_TCP_CONNECTIONS",
        "CORTEX_TCP_IDLE_TIMEOUT_SECS",
        "CORTEX_BATCH_SIZE",
        "CORTEX_FLUSH_INTERVAL",
        "CORTEX_HOST",
        "CORTEX_PORT",
        "CORTEX_ALLOWED_HOSTS",
        "CORTEX_ALLOWED_ORIGINS",
        "NO_AUTH",
        "CORTEX_NO_AUTH",
        "CORTEX_DB_PATH",
        "CORTEX_POOL_SIZE",
        "CORTEX_SQLITE_PAGE_CACHE_MB",
        "CORTEX_SQLITE_MMAP_MB",
        "CORTEX_HEAVY_READ_CONCURRENCY",
        "CORTEX_WAL_CHECKPOINT_MB",
        "CORTEX_RETENTION_DAYS",
        "CORTEX_TOKEN",
        "CORTEX_API_TOKEN",
        "CORTEX_MAX_DB_SIZE_MB",
        "CORTEX_RECOVERY_DB_SIZE_MB",
        "CORTEX_MIN_FREE_DISK_MB",
        "CORTEX_RECOVERY_FREE_DISK_MB",
        "CORTEX_CLEANUP_INTERVAL_SECS",
        "CORTEX_CLEANUP_CHUNK_SIZE",
        "CORTEX_API_TOKEN",
        "CORTEX_WRITE_CHANNEL_CAPACITY",
        "CORTEX_DOCKER_INGEST_ENABLED",
        "CORTEX_DOCKER_HOSTS_FILE",
        "CORTEX_DOCKER_RECONNECT_INITIAL_MS",
        "CORTEX_DOCKER_RECONNECT_MAX_MS",
        "CORTEX_AUTH_MODE",
        "CORTEX_PUBLIC_URL",
        "CORTEX_GOOGLE_CLIENT_ID",
        "CORTEX_GOOGLE_CLIENT_SECRET",
        "CORTEX_AUTH_ADMIN_EMAIL",
        "CORTEX_AUTH_ALLOWED_REDIRECT_URIS",
        "CORTEX_AUTH_DISABLE_STATIC_TOKEN_WITH_OAUTH",
    ] {
        crate::env::remove_test_var(key);
    }

    // Bind cortex to loopback so the non-loopback safety gate (added in
    // cortex-brt0.4) does not reject the unauthenticated default config.
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    let cfg = Config::load().expect("Config::load() should succeed with defaults");
    crate::env::remove_test_var("CORTEX_HOST");
    assert_eq!(cfg.receiver.host, "0.0.0.0");
    assert_eq!(cfg.receiver.port, 1514);
    assert_eq!(cfg.receiver.bind_addr(), "0.0.0.0:1514");
    assert_eq!(cfg.receiver.write_channel_capacity, 10_000);
    assert_eq!(cfg.mcp.host, "127.0.0.1");
    assert_eq!(cfg.mcp.port, 3100);
    assert!(!cfg.mcp.no_auth);
    assert_eq!(cfg.mcp.bind_addr(), "127.0.0.1:3100");
    assert!(cfg.mcp.allowed_hosts.is_empty());
    assert!(cfg.mcp.allowed_origins.is_empty());
    assert_eq!(cfg.storage.pool_size, 8);
    assert_eq!(cfg.storage.retention_days, 90);
    assert!(cfg.storage.wal_mode);
    assert_eq!(cfg.storage.max_db_size_mb, 1024);
    assert_eq!(cfg.storage.recovery_db_size_mb, 900);
    assert_eq!(cfg.storage.min_free_disk_mb, 512);
    assert_eq!(cfg.storage.recovery_free_disk_mb, 768);
    assert_eq!(cfg.storage.cleanup_interval_secs, 60);
    assert_eq!(cfg.storage.cleanup_chunk_size, 2_000);
    assert!(cfg.mcp.api_token.is_none());
    assert!(cfg.api.api_token.is_none());
    assert!(!cfg.docker_ingest.enabled);
    assert!(cfg.docker_ingest.hosts.is_empty());
    assert_eq!(cfg.docker_ingest.reconnect_initial_ms, 1_000);
    assert_eq!(cfg.docker_ingest.reconnect_max_ms, 30_000);
}

#[test]
#[serial]
fn inspection_load_does_not_require_the_runtime_database_mount() {
    let missing = std::env::temp_dir()
        .join("cortex-config-inspection-missing")
        .join("cortex.db");
    let _ = std::fs::remove_dir_all(missing.parent().unwrap());

    crate::env::set_test_var("CORTEX_DB_PATH", &missing);
    let inspection = Config::load_for_inspection();
    let query = Config::load_for_stdio();
    crate::env::remove_test_var("CORTEX_DB_PATH");

    assert!(
        inspection.is_ok(),
        "inspection should not need the DB mount"
    );
    assert!(
        query
            .unwrap_err()
            .to_string()
            .contains("parent directory does not exist"),
        "query mode must retain the runtime DB-path guard"
    );
}

#[test]
#[serial]
fn rejects_invalid_syslog_ingest_env_settings() {
    for (key, expected) in [
        ("CORTEX_MAX_MESSAGE_SIZE", "max_message_size"),
        ("CORTEX_MAX_TCP_CONNECTIONS", "max_tcp_connections"),
        ("CORTEX_TCP_IDLE_TIMEOUT_SECS", "tcp_idle_timeout_secs"),
        ("CORTEX_BATCH_SIZE", "batch_size"),
        ("CORTEX_FLUSH_INTERVAL", "flush_interval"),
        ("CORTEX_WRITE_CHANNEL_CAPACITY", "write_channel_capacity"),
    ] {
        crate::env::set_test_var(key, "0");
        let result = Config::load();
        crate::env::remove_test_var(key);

        let err = result.expect_err(&format!("Config::load should reject {key}=0"));
        assert!(
            err.to_string().contains(expected),
            "expected {key}=0 error to mention {expected}, got: {err}"
        );
    }
}

#[test]
fn rejects_invalid_syslog_ingest_toml_settings() {
    for (toml, expected) in [
        ("[receiver]\nmax_message_size = 0\n", "max_message_size"),
        (
            "[receiver]\nmax_tcp_connections = 0\n",
            "max_tcp_connections",
        ),
        (
            "[receiver]\ntcp_idle_timeout_secs = 0\n",
            "tcp_idle_timeout_secs",
        ),
        ("[receiver]\nbatch_size = 0\n", "batch_size"),
        ("[receiver]\nflush_interval = 0\n", "flush_interval"),
        (
            "[receiver]\nwrite_channel_capacity = 0\n",
            "write_channel_capacity",
        ),
    ] {
        let mut config: Config = toml::from_str(toml).unwrap();
        let err = validate_receiver_config(&config.receiver)
            .expect_err(&format!("validate_receiver_config should reject {toml}"));
        assert!(
            err.to_string().contains(expected),
            "expected TOML error to mention {expected}, got: {err}"
        );

        config.receiver = ReceiverConfig::default();
        validate_receiver_config(&config.receiver).unwrap();
    }
}

#[test]
#[serial]
fn env_var_overrides_write_channel_capacity() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_WRITE_CHANNEL_CAPACITY", "100000");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_WRITE_CHANNEL_CAPACITY");

    let cfg = result.expect("Config::load() should parse write channel capacity");
    assert_eq!(cfg.receiver.write_channel_capacity, 100_000);
}

#[test]
#[serial]
fn env_var_overrides_mcp_allowed_hosts_and_origins() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var(
        "CORTEX_ALLOWED_HOSTS",
        "syslog.example.com, syslog.example.com:443",
    );
    crate::env::set_test_var(
        "CORTEX_ALLOWED_ORIGINS",
        "https://app.example.com, https://syslog.example.com",
    );
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_ALLOWED_HOSTS");
    crate::env::remove_test_var("CORTEX_ALLOWED_ORIGINS");

    let cfg = result.expect("Config::load() should parse comma-separated RMCP allow lists");
    assert_eq!(
        cfg.mcp.allowed_hosts,
        vec!["syslog.example.com", "syslog.example.com:443"]
    );
    assert_eq!(
        cfg.mcp.allowed_origins,
        vec!["https://app.example.com", "https://syslog.example.com"]
    );
}

#[test]
#[serial]
fn env_var_can_clear_mcp_allowed_hosts_and_origins() {
    let mut hosts = vec!["syslog.example.com".to_string()];
    let mut origins = vec!["https://syslog.example.com".to_string()];
    crate::env::set_test_var("CORTEX_ALLOWED_HOSTS", "  , ");
    crate::env::set_test_var("CORTEX_ALLOWED_ORIGINS", "");

    env_override_list("CORTEX_ALLOWED_HOSTS", &mut hosts);
    env_override_list("CORTEX_ALLOWED_ORIGINS", &mut origins);

    crate::env::remove_test_var("CORTEX_ALLOWED_HOSTS");
    crate::env::remove_test_var("CORTEX_ALLOWED_ORIGINS");

    assert!(hosts.is_empty());
    assert!(origins.is_empty());
}

#[test]
#[serial]
fn api_token_loads_independently_of_mcp_token() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_API_TOKEN", "api-token");
    crate::env::set_test_var("CORTEX_TOKEN", "mcp-token");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_API_TOKEN");
    crate::env::remove_test_var("CORTEX_TOKEN");

    let cfg = result.expect("Config::load() should accept distinct API + MCP tokens");
    assert_eq!(cfg.api.api_token, Some("api-token".into()));
    assert_eq!(cfg.mcp.api_token, Some("mcp-token".into()));
}

#[test]
fn auth_validation_rejects_blank_mcp_token() {
    let mut cfg = Config::default();
    cfg.mcp.api_token = Some("  ".into()).into();

    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(err.to_string().contains("mcp.api_token"));
}

#[test]
fn auth_validation_rejects_blank_api_token() {
    let mut cfg = Config::default();
    cfg.api.api_token = Some("\t".into()).into();

    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(err.to_string().contains("api.api_token"));
}

#[test]
fn auth_validation_rejects_blank_api_admin_token() {
    let mut cfg = Config::default();
    cfg.api.admin_token = Some(" ".into()).into();
    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(err.to_string().contains("api.admin_token"));
}

#[test]
#[serial]
fn host_with_port_is_rejected() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_RECEIVER_HOST", "0.0.0.0:1514");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_RECEIVER_HOST");

    let err = result.expect_err("Host containing ':' should be rejected");
    assert!(
        err.to_string().contains("should not contain a port"),
        "wrong error: {err}"
    );
}

#[test]
fn defaults_include_storage_budget_settings() {
    let cfg = Config::default();
    assert_eq!(cfg.storage.max_db_size_mb, 1024);
    assert_eq!(cfg.storage.recovery_db_size_mb, 900);
    // syslog-mcp-w4hh: free-disk guardrail defaults to 0 (disabled) so cortex
    // does not self-wipe to chase external whole-filesystem pressure. The two
    // free-disk fields MUST default to 0 together to pass validate_storage_config.
    assert_eq!(cfg.storage.min_free_disk_mb, 0);
    assert_eq!(cfg.storage.recovery_free_disk_mb, 0);
    assert_eq!(cfg.storage.cleanup_interval_secs, 60);
}

#[test]
#[serial]
fn env_var_overrides_storage_budget_settings() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_MAX_DB_SIZE_MB", "2048");
    crate::env::set_test_var("CORTEX_RECOVERY_DB_SIZE_MB", "1800");
    crate::env::set_test_var("CORTEX_MIN_FREE_DISK_MB", "1024");
    crate::env::set_test_var("CORTEX_RECOVERY_FREE_DISK_MB", "1536");
    crate::env::set_test_var("CORTEX_CLEANUP_INTERVAL_SECS", "120");
    crate::env::set_test_var("CORTEX_SQLITE_PAGE_CACHE_MB", "64");
    crate::env::set_test_var("CORTEX_SQLITE_MMAP_MB", "128");
    crate::env::set_test_var("CORTEX_HEAVY_READ_CONCURRENCY", "2");
    crate::env::set_test_var("CORTEX_WAL_CHECKPOINT_MB", "32");

    let result = Config::load();

    for key in [
        "CORTEX_HOST",
        "CORTEX_MAX_DB_SIZE_MB",
        "CORTEX_RECOVERY_DB_SIZE_MB",
        "CORTEX_MIN_FREE_DISK_MB",
        "CORTEX_RECOVERY_FREE_DISK_MB",
        "CORTEX_CLEANUP_INTERVAL_SECS",
        "CORTEX_SQLITE_PAGE_CACHE_MB",
        "CORTEX_SQLITE_MMAP_MB",
        "CORTEX_HEAVY_READ_CONCURRENCY",
        "CORTEX_WAL_CHECKPOINT_MB",
    ] {
        crate::env::remove_test_var(key);
    }

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.storage.max_db_size_mb, 2048);
    assert_eq!(cfg.storage.recovery_db_size_mb, 1800);
    assert_eq!(cfg.storage.min_free_disk_mb, 1024);
    assert_eq!(cfg.storage.recovery_free_disk_mb, 1536);
    assert_eq!(cfg.storage.cleanup_interval_secs, 120);
    assert_eq!(cfg.storage.sqlite_page_cache_mb, 64);
    assert_eq!(cfg.storage.sqlite_mmap_mb, 128);
    assert_eq!(cfg.storage.heavy_read_concurrency, 2);
    assert_eq!(cfg.storage.wal_checkpoint_mb, 32);
}

#[test]
fn storage_rejects_zero_sqlite_memory_guardrails() {
    for (label, storage) in [
        (
            "sqlite_page_cache_mb",
            StorageConfig {
                sqlite_page_cache_mb: 0,
                ..StorageConfig::default()
            },
        ),
        (
            "heavy_read_concurrency",
            StorageConfig {
                heavy_read_concurrency: 0,
                ..StorageConfig::default()
            },
        ),
        (
            "wal_checkpoint_mb",
            StorageConfig {
                wal_checkpoint_mb: 0,
                ..StorageConfig::default()
            },
        ),
    ] {
        let err = validate_storage_config(&storage).unwrap_err();
        assert!(err.to_string().contains(label), "wrong error: {err}");
    }
}

#[test]
#[serial]
fn rejects_invalid_storage_budget_relationships() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_MAX_DB_SIZE_MB", "100");
    crate::env::set_test_var("CORTEX_RECOVERY_DB_SIZE_MB", "100");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_MAX_DB_SIZE_MB");
    crate::env::remove_test_var("CORTEX_RECOVERY_DB_SIZE_MB");

    let err = result.expect_err("Config::load() should reject invalid recovery_db_size_mb");
    assert!(err.to_string().contains("recovery_db_size_mb"));
}

#[test]
fn error_detection_validation_rejects_invalid_notify_min_severity() {
    // This validation is the guardrail the error scanner's notify-floor
    // `unwrap_or(u8::MAX)` fail-open relies on: an unparseable severity must be
    // rejected at load so a parse failure at use is genuinely unreachable.
    let mut cfg = ErrorDetectionConfig::default();
    assert!(
        validate_error_detection_config(&cfg).is_ok(),
        "default notify_min_severity must be valid"
    );

    cfg.notify_min_severity = "warn".to_string();
    assert!(
        validate_error_detection_config(&cfg).is_ok(),
        "a real syslog severity (alias) must be accepted"
    );

    cfg.notify_min_severity = "bogus".to_string();
    let err = validate_error_detection_config(&cfg)
        .expect_err("an invalid notify_min_severity must be rejected at load");
    assert!(
        err.to_string().contains("notify_min_severity"),
        "rejection message should name the offending field: {err}"
    );
}

#[test]
#[serial]
fn rejects_cleanup_chunk_size_zero() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_CLEANUP_CHUNK_SIZE", "0");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_CLEANUP_CHUNK_SIZE");

    let err = result.expect_err("Config::load() should reject cleanup_chunk_size == 0");
    assert!(err.to_string().contains("cleanup_chunk_size"));
}

#[test]
#[serial]
fn rejects_cleanup_chunk_size_over_max() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_CLEANUP_CHUNK_SIZE", "1000001");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_CLEANUP_CHUNK_SIZE");

    let err = result.expect_err("Config::load() should reject cleanup_chunk_size > 1_000_000");
    assert!(
        err.to_string().contains("cleanup_chunk_size"),
        "Expected error referencing cleanup_chunk_size, got: {err}"
    );
}

#[test]
#[serial]
fn accepts_cleanup_chunk_size_at_max() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_CLEANUP_CHUNK_SIZE", "1000000");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_CLEANUP_CHUNK_SIZE");

    let cfg = result.expect("cleanup_chunk_size == 1_000_000 should be accepted");
    assert_eq!(cfg.storage.cleanup_chunk_size, 1_000_000);
}

#[test]
fn docker_ingest_toml_hosts_parse() {
    let raw = r#"
        [docker_ingest]
        enabled = true
        reconnect_initial_ms = 250
        reconnect_max_ms = 10000
        [[docker_ingest.hosts]]
        name = "edge-host-a"
        base_url = "http://edge-host-a:2375"
        allow_insecure_http = true

        [[docker_ingest.hosts]]
        name = "app-host-b"
        base_url = "http://app-host-b:2375"
        allow_insecure_http = true
    "#;

    let config: Config = toml::from_str(raw).unwrap();
    assert!(config.docker_ingest.enabled);
    assert_eq!(config.docker_ingest.hosts.len(), 2);
    assert_eq!(config.docker_ingest.hosts[0].name, "edge-host-a");
    assert_eq!(
        config.docker_ingest.hosts[0].base_url,
        "http://edge-host-a:2375"
    );
    assert_eq!(config.docker_ingest.hosts[1].name, "app-host-b");
    assert_eq!(
        config.docker_ingest.hosts[1].base_url,
        "http://app-host-b:2375"
    );
}

#[test]
fn docker_ingest_requires_hosts_when_enabled() {
    let mut config = DockerIngestConfig {
        enabled: true,
        ..Default::default()
    };
    config.hosts.clear();

    let err = validate_docker_ingest_config(&config).unwrap_err();
    assert!(
        err.to_string()
            .contains("docker_ingest.hosts must not be empty")
    );
}

#[test]
fn docker_ingest_rejects_duplicate_host_names() {
    let config = DockerIngestConfig {
        enabled: true,
        hosts: vec![
            DockerHostConfig {
                name: "edge-host-a".into(),
                base_url: "http://edge-host-a:2375".into(),
                allow_insecure_http: true,
                excluded_containers: Vec::new(),
            },
            DockerHostConfig {
                name: "edge-host-a".into(),
                base_url: "http://10.0.0.10:2375".into(),
                allow_insecure_http: true,
                excluded_containers: Vec::new(),
            },
        ],
        ..Default::default()
    };

    let err = validate_docker_ingest_config(&config).unwrap_err();
    assert!(
        err.to_string()
            .contains("duplicate docker_ingest host name")
    );
}

#[test]
#[serial]
fn docker_ingest_loads_hosts_file_from_env() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("docker-hosts.toml");
    std::fs::write(
        &path,
        r#"
            [[hosts]]
            name = "edge-host-a"
            base_url = "http://edge-host-a:2375"
            allow_insecure_http = true
        "#,
    )
    .unwrap();

    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_DOCKER_INGEST_ENABLED", "true");
    crate::env::set_test_var("CORTEX_DOCKER_HOSTS_FILE", &path);
    // Ensure the host list env var doesn't override the file path under test
    crate::env::remove_test_var("CORTEX_DOCKER_HOSTS");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_DOCKER_INGEST_ENABLED");
    crate::env::remove_test_var("CORTEX_DOCKER_HOSTS_FILE");

    let config = result.expect("Config::load should parse docker host file");
    assert!(config.docker_ingest.enabled);
    assert_eq!(config.docker_ingest.hosts.len(), 1);
    assert_eq!(config.docker_ingest.hosts[0].name, "edge-host-a");
}

#[test]
#[serial]
fn docker_ingest_loads_excluded_containers_from_env() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_DOCKER_INGEST_ENABLED", "true");
    crate::env::set_test_var("CORTEX_DOCKER_HOSTS", "edge-host-a");
    crate::env::set_test_var(
        "CORTEX_DOCKER_EXCLUDED_CONTAINERS",
        "arcane-mcp, axon-qdrant",
    );

    let result = Config::load();

    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_DOCKER_INGEST_ENABLED");
    crate::env::remove_test_var("CORTEX_DOCKER_HOSTS");
    crate::env::remove_test_var("CORTEX_DOCKER_EXCLUDED_CONTAINERS");

    let config = result.expect("Config::load should parse excluded container list");
    assert_eq!(
        config.docker_ingest.excluded_containers,
        vec!["arcane-mcp".to_string(), "axon-qdrant".to_string()]
    );
}

#[test]
#[serial]
fn docker_ingest_ignores_hosts_file_when_disabled() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_DOCKER_INGEST_ENABLED", "false");
    crate::env::set_test_var(
        "CORTEX_DOCKER_HOSTS_FILE",
        "/tmp/cortex-missing-docker-hosts.toml",
    );
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_DOCKER_INGEST_ENABLED");
    crate::env::remove_test_var("CORTEX_DOCKER_HOSTS_FILE");

    let config = result.expect("disabled Docker ingest should ignore stale hosts file env");
    assert!(!config.docker_ingest.enabled);
}

#[test]
fn docker_ingest_rejects_insecure_http_without_explicit_opt_in() {
    let config = DockerIngestConfig {
        enabled: true,
        hosts: vec![DockerHostConfig {
            name: "edge-host-a".into(),
            base_url: "http://edge-host-a:2375".into(),
            allow_insecure_http: false,
            excluded_containers: Vec::new(),
        }],
        ..Default::default()
    };

    let err = validate_docker_ingest_config(&config).unwrap_err();
    assert!(err.to_string().contains("allow_insecure_http"));
}

// ---------------------------------------------------------------------------
// [mcp.auth] config schema (cortex-brt0.4)
// ---------------------------------------------------------------------------

/// Build a baseline loopback-bound config with a static token. Tests start
/// from this and mutate the AuthConfig in isolation.
fn loopback_config_with_token() -> Config {
    let mut cfg = Config::default();
    cfg.mcp.host = "127.0.0.1".into();
    cfg.mcp.api_token = Some("static-token".into()).into();
    cfg
}

fn valid_oauth_config_without_token() -> Config {
    let mut cfg = Config::default();
    cfg.mcp.api_token = None.into();
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.public_url = Some("https://syslog.example.com".into());
    cfg.mcp.auth.google_client_id = Some("id".into());
    cfg.mcp.auth.google_client_secret = Some("secret".into()).into();
    cfg.mcp.auth.admin_email = "admin@example.com".into();
    cfg
}

#[test]
fn auth_defaults_are_bearer_with_disable_static_token_enabled() {
    let cfg = AuthConfig::default();
    assert_eq!(cfg.mode, AuthMode::Bearer);
    assert!(cfg.public_url.is_none());
    assert!(cfg.google_client_id.is_none());
    assert!(cfg.google_client_secret.is_none());
    assert!(cfg.admin_email.is_empty());
    assert!(cfg.allowed_emails.is_empty());
    assert_eq!(cfg.access_token_ttl_secs, 3_600);
    assert_eq!(cfg.refresh_token_ttl_secs, 28_800);
    assert_eq!(cfg.auth_code_ttl_secs, 300);
    assert_eq!(cfg.register_rpm, 20);
    assert_eq!(cfg.authorize_rpm, 60);
    assert!(
        cfg.disable_static_token_with_oauth,
        "cortex default flips lab-auth's opt-in to opt-out"
    );
    assert!(cfg.allowed_client_redirect_uris.is_empty());
    assert_eq!(cfg.sqlite_path, std::path::PathBuf::from("auth.db"));
    assert_eq!(cfg.key_path, std::path::PathBuf::from("auth-jwt.pem"));
}

#[test]
#[serial]
fn config_load_defaults_to_bearer_mode() {
    crate::env::remove_test_var("CORTEX_AUTH_MODE");
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");

    let cfg = result.expect("loopback bind, no token, no oauth → permitted");
    assert_eq!(cfg.mcp.auth.mode, AuthMode::Bearer);
}

#[test]
#[serial]
fn cortex_auth_mode_env_flips_to_oauth() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_AUTH_MODE", "oauth");
    crate::env::set_test_var("CORTEX_PUBLIC_URL", "https://syslog.example.com");
    crate::env::set_test_var("CORTEX_GOOGLE_CLIENT_ID", "client-id");
    crate::env::set_test_var("CORTEX_GOOGLE_CLIENT_SECRET", "client-secret");
    crate::env::set_test_var("CORTEX_AUTH_ADMIN_EMAIL", "admin@example.com");
    let result = Config::load();
    for k in [
        "CORTEX_HOST",
        "CORTEX_AUTH_MODE",
        "CORTEX_PUBLIC_URL",
        "CORTEX_GOOGLE_CLIENT_ID",
        "CORTEX_GOOGLE_CLIENT_SECRET",
        "CORTEX_AUTH_ADMIN_EMAIL",
    ] {
        crate::env::remove_test_var(k);
    }

    let cfg = result.expect("oauth env overrides should satisfy startup validation");
    assert_eq!(cfg.mcp.auth.mode, AuthMode::OAuth);
    assert_eq!(cfg.mcp.auth.admin_email, "admin@example.com");
}

#[test]
#[serial]
fn cortex_auth_mode_env_rejects_invalid_value() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_AUTH_MODE", "magic");
    let result = Config::load();
    crate::env::remove_test_var("CORTEX_HOST");
    crate::env::remove_test_var("CORTEX_AUTH_MODE");

    let err = result.expect_err("bogus AUTH_MODE must be rejected");
    assert!(err.to_string().contains("CORTEX_AUTH_MODE"));
}

#[test]
#[serial]
fn auth_env_overrides_propagate_to_config() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_PUBLIC_URL", "https://syslog.example.com");
    crate::env::set_test_var("CORTEX_GOOGLE_CLIENT_ID", "id-from-env");
    crate::env::set_test_var("CORTEX_GOOGLE_CLIENT_SECRET", "secret-from-env");
    crate::env::set_test_var("CORTEX_AUTH_ADMIN_EMAIL", "admin-from-env@example.com");
    crate::env::set_test_var(
        "CORTEX_AUTH_ALLOWED_REDIRECT_URIS",
        "https://callback.example.com/callback,https://claude.ai/api/mcp/auth_callback",
    );
    crate::env::set_test_var("CORTEX_AUTH_DISABLE_STATIC_TOKEN_WITH_OAUTH", "false");
    // Stay in bearer mode so validation doesn't require an allowlist.
    crate::env::remove_test_var("CORTEX_AUTH_MODE");
    let result = Config::load();
    for k in [
        "CORTEX_HOST",
        "CORTEX_PUBLIC_URL",
        "CORTEX_GOOGLE_CLIENT_ID",
        "CORTEX_GOOGLE_CLIENT_SECRET",
        "CORTEX_AUTH_ADMIN_EMAIL",
        "CORTEX_AUTH_ALLOWED_REDIRECT_URIS",
        "CORTEX_AUTH_DISABLE_STATIC_TOKEN_WITH_OAUTH",
    ] {
        crate::env::remove_test_var(k);
    }

    let cfg = result.expect("env overrides should land in config");
    assert_eq!(
        cfg.mcp.auth.public_url.as_deref(),
        Some("https://syslog.example.com")
    );
    assert_eq!(
        cfg.mcp.auth.google_client_id.as_deref(),
        Some("id-from-env")
    );
    assert_eq!(
        cfg.mcp.auth.google_client_secret.as_deref(),
        Some("secret-from-env")
    );
    assert_eq!(cfg.mcp.auth.admin_email, "admin-from-env@example.com");
    assert_eq!(
        cfg.mcp.auth.allowed_client_redirect_uris,
        vec![
            "https://callback.example.com/callback".to_string(),
            "https://claude.ai/api/mcp/auth_callback".to_string(),
        ]
    );
    assert!(!cfg.mcp.auth.disable_static_token_with_oauth);
}

#[test]
fn oauth_mode_rejects_missing_public_url() {
    let mut cfg = loopback_config_with_token();
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.google_client_id = Some("id".into());
    cfg.mcp.auth.google_client_secret = Some("secret".into()).into();
    cfg.mcp.auth.admin_email = "admin@example.com".into();

    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(err.to_string().contains("CORTEX_PUBLIC_URL"));
}

#[test]
fn oauth_mode_rejects_missing_google_client_id() {
    let mut cfg = loopback_config_with_token();
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.public_url = Some("https://syslog.example.com".into());
    cfg.mcp.auth.google_client_secret = Some("secret".into()).into();
    cfg.mcp.auth.admin_email = "admin@example.com".into();

    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(err.to_string().contains("CORTEX_GOOGLE_CLIENT_ID"));
}

#[test]
fn oauth_mode_rejects_missing_google_client_secret() {
    let mut cfg = loopback_config_with_token();
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.public_url = Some("https://syslog.example.com".into());
    cfg.mcp.auth.google_client_id = Some("id".into());
    cfg.mcp.auth.admin_email = "admin@example.com".into();

    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(err.to_string().contains("CORTEX_GOOGLE_CLIENT_SECRET"));
}

#[test]
fn oauth_mode_rejects_empty_allowlist_and_admin() {
    let mut cfg = loopback_config_with_token();
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.public_url = Some("https://syslog.example.com".into());
    cfg.mcp.auth.google_client_id = Some("id".into());
    cfg.mcp.auth.google_client_secret = Some("secret".into()).into();
    // Both empty.
    cfg.mcp.auth.allowed_emails.clear();
    cfg.mcp.auth.admin_email.clear();

    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(
        err.to_string().contains("admin_email"),
        "wrong error: {err}"
    );
}

#[test]
fn oauth_mode_rejects_allowed_emails_without_admin_until_enforced() {
    let mut cfg = loopback_config_with_token();
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.public_url = Some("https://syslog.example.com".into());
    cfg.mcp.auth.google_client_id = Some("id".into());
    cfg.mcp.auth.google_client_secret = Some("secret".into()).into();
    cfg.mcp.auth.allowed_emails = vec!["admin@example.com".into()];

    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(
        err.to_string().contains("allowed_emails"),
        "wrong error: {err}"
    );
}

#[test]
fn oauth_mode_accepts_admin_email_alone() {
    let mut cfg = loopback_config_with_token();
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.public_url = Some("https://syslog.example.com".into());
    cfg.mcp.auth.google_client_id = Some("id".into());
    cfg.mcp.auth.google_client_secret = Some("secret".into()).into();
    cfg.mcp.auth.admin_email = "admin@example.com".into();

    validate_auth_config(&cfg, true).expect("admin_email alone counts as allowlist");
}

#[test]
fn oauth_mode_rejects_allowed_emails_even_with_admin_until_enforced() {
    let mut cfg = loopback_config_with_token();
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.public_url = Some("https://syslog.example.com".into());
    cfg.mcp.auth.google_client_id = Some("id".into());
    cfg.mcp.auth.google_client_secret = Some("secret".into()).into();
    cfg.mcp.auth.admin_email = "admin@example.com".into();
    cfg.mcp.auth.allowed_emails = vec!["ops@example.com".into()];

    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(
        err.to_string().contains("allowed_emails"),
        "wrong error: {err}"
    );
}

#[test]
fn bearer_and_oauth_can_coexist() {
    // Static token + OAuth fully configured = both pass validation.
    let mut cfg = loopback_config_with_token();
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.public_url = Some("https://syslog.example.com".into());
    cfg.mcp.auth.google_client_id = Some("id".into());
    cfg.mcp.auth.google_client_secret = Some("secret".into()).into();
    cfg.mcp.auth.admin_email = "admin@example.com".into();

    validate_auth_config(&cfg, true).expect("bearer + oauth coexistence");
    assert!(cfg.mcp.api_token.is_some());
    assert_eq!(cfg.mcp.auth.mode, AuthMode::OAuth);
}

#[test]
fn loopback_bind_with_no_auth_is_permitted() {
    let mut cfg = Config::default();
    cfg.mcp.host = "127.0.0.1".into();
    cfg.mcp.api_token = None.into();
    validate_auth_config(&cfg, true).expect("loopback dev mode");
}

#[test]
fn explicit_no_auth_rejects_non_loopback_bind_without_trusted_gateway() {
    let mut cfg = Config::default();
    cfg.mcp.host = "0.0.0.0".into();
    cfg.mcp.api_token = None.into();
    cfg.mcp.no_auth = true;
    let err = validate_auth_config(&cfg, true)
        .expect_err("non-loopback no_auth must require trusted gateway flag");
    assert!(err.to_string().contains("CORTEX_TRUSTED_GATEWAY_NO_AUTH"));
}

#[test]
fn explicit_trusted_gateway_no_auth_allows_non_loopback_bind_without_token() {
    let mut cfg = Config::default();
    cfg.mcp.host = "0.0.0.0".into();
    cfg.mcp.api_token = None.into();
    cfg.mcp.no_auth = true;
    cfg.mcp.trusted_gateway_no_auth = true;
    validate_auth_config(&cfg, true).expect("gateway-protected no-auth mode");
}

#[test]
fn explicit_no_auth_ignores_stale_oauth_fields() {
    let mut cfg = Config::default();
    cfg.mcp.host = "0.0.0.0".into();
    cfg.mcp.api_token = None.into();
    cfg.mcp.no_auth = true;
    cfg.mcp.trusted_gateway_no_auth = true;
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.allowed_emails = vec!["stale@example.com".into()];

    validate_auth_config(&cfg, true).expect("no_auth bypasses unused OAuth config");
}

#[test]
fn loopback_variants_pass_safety_gate() {
    for host in ["127.0.0.1", "::1", "127.0.0.5"] {
        let mut cfg = Config::default();
        cfg.mcp.host = host.into();
        cfg.mcp.api_token = None.into();
        validate_auth_config(&cfg, true)
            .unwrap_or_else(|err| panic!("{host} should be loopback: {err}"));
    }
}

#[test]
fn non_loopback_bind_without_auth_bails() {
    for host in ["0.0.0.0", "::", "localhost", "myhost.example.com"] {
        let mut cfg = Config::default();
        cfg.mcp.host = host.into();
        cfg.mcp.api_token = None.into();
        let err = validate_auth_config(&cfg, true)
            .err()
            .unwrap_or_else(|| panic!("{host} must be rejected without auth"));
        let msg = err.to_string();
        assert!(
            msg.contains("not a loopback") || msg.contains("loopback"),
            "wrong error for {host}: {msg}"
        );
    }
}

#[test]
fn non_loopback_bind_with_static_token_passes() {
    let mut cfg = Config::default();
    cfg.mcp.host = "0.0.0.0".into();
    cfg.mcp.api_token = Some("token".into()).into();
    validate_auth_config(&cfg, true).expect("static token unlocks non-loopback bind");
}

#[test]
fn non_loopback_bind_with_oauth_and_static_token_passes() {
    let mut cfg = valid_oauth_config_without_token();
    cfg.mcp.host = "0.0.0.0".into();
    cfg.mcp.api_token = Some("token".into()).into();
    validate_auth_config(&cfg, true).expect("oauth unlocks non-loopback bind");
}

#[test]
fn non_loopback_oauth_without_static_token_rejects_otlp_write_exposure() {
    let mut cfg = valid_oauth_config_without_token();
    cfg.mcp.host = "0.0.0.0".into();

    let err = validate_auth_config(&cfg, true).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("OTLP /v1/logs") && msg.contains("CORTEX_TOKEN"),
        "wrong error: {msg}"
    );
}

#[test]
fn loopback_oauth_without_static_token_keeps_dev_mode_allowed() {
    let mut cfg = valid_oauth_config_without_token();
    cfg.mcp.host = "127.0.0.1".into();
    validate_auth_config(&cfg, true).expect("loopback OTLP exposure is local-only");
}

#[test]
#[serial]
fn auth_mode_parses_lowercase_only() {
    let mut mode = AuthMode::Bearer;
    crate::env::set_test_var("__TEST_AUTH_MODE_PARSE", "OAUTH");
    env_override_auth_mode("__TEST_AUTH_MODE_PARSE", &mut mode).unwrap();
    crate::env::remove_test_var("__TEST_AUTH_MODE_PARSE");
    assert_eq!(mode, AuthMode::OAuth, "case-insensitive");
}

#[test]
fn auth_toml_section_parses() {
    let raw = r#"
        [mcp.auth]
        admin_email = "admin@example.com"
        allowed_emails = ["admin@example.com", "ops@example.com"]
        sqlite_path = "custom-auth.db"
        key_path = "custom-key.pem"
        access_token_ttl_secs = 1800
        refresh_token_ttl_secs = 14400
        auth_code_ttl_secs = 120
        register_rpm = 5
        authorize_rpm = 30
        disable_static_token_with_oauth = false
        allowed_client_redirect_uris = ["https://claude.ai/api/mcp/auth_callback"]
    "#;
    let cfg: Config = toml::from_str(raw).expect("auth section should parse");
    let auth = &cfg.mcp.auth;
    assert_eq!(auth.admin_email, "admin@example.com");
    assert_eq!(auth.allowed_emails.len(), 2);
    assert_eq!(auth.sqlite_path, std::path::PathBuf::from("custom-auth.db"));
    assert_eq!(auth.key_path, std::path::PathBuf::from("custom-key.pem"));
    assert_eq!(auth.access_token_ttl_secs, 1_800);
    assert_eq!(auth.refresh_token_ttl_secs, 14_400);
    assert_eq!(auth.auth_code_ttl_secs, 120);
    assert_eq!(auth.register_rpm, 5);
    assert_eq!(auth.authorize_rpm, 30);
    assert!(!auth.disable_static_token_with_oauth);
    assert_eq!(
        auth.allowed_client_redirect_uris,
        vec!["https://claude.ai/api/mcp/auth_callback".to_string()]
    );
}

#[test]
fn repo_local_config_uses_repo_local_db_path() {
    let cfg: Config =
        toml::from_str(include_str!("../config.toml")).expect("repo config.toml should parse");
    assert_eq!(
        cfg.storage.db_path,
        std::path::PathBuf::from("data/cortex.db"),
        "repo config.toml should use a writable repo-local DB path for local dev"
    );
}

#[test]
fn repo_local_oauth_config_rejects_allowed_emails_until_enforced() {
    let mut cfg: Config =
        toml::from_str(include_str!("../config.toml")).expect("repo config.toml should parse");
    cfg.mcp.auth.mode = AuthMode::OAuth;
    cfg.mcp.auth.public_url = Some("https://syslog.example.com".into());
    cfg.mcp.auth.google_client_id = Some("id".into());
    cfg.mcp.auth.google_client_secret = Some("secret".into()).into();
    cfg.mcp.auth.admin_email = "admin@example.com".into();
    cfg.mcp.auth.allowed_emails = vec!["ops@example.com".into()];

    let err = validate_auth_config(&cfg, true).unwrap_err();
    assert!(
        err.to_string().contains("allowed_emails"),
        "wrong error: {err}"
    );
}

// ---- syslog-mcp-w4hh: storage budget defaults + validation ----

/// The self-wipe stop-the-bleed: min_free_disk_mb defaults to 0 so cortex does
/// not treat external whole-FS pressure as a trigger to delete its own data.
#[test]
fn min_free_disk_mb_default_is_zero() {
    let storage = StorageConfig::default();
    assert_eq!(
        storage.min_free_disk_mb, 0,
        "min_free_disk_mb must default to 0 (no external-pressure self-wipe)"
    );
}

/// W2 MUST-FIX: StorageConfig::default() must PASS validate_storage_config.
/// validate_storage_config rejects recovery_free_disk_mb != 0 when
/// min_free_disk_mb == 0, so default_recovery_free_disk_mb must also be 0 — else
/// fresh deploys crash at startup. StorageConfig::for_test uses 0/0 and so cannot
/// catch this; this test asserts the real Default impl.
#[test]
fn default_storage_config_passes_validation() {
    let storage = StorageConfig::default();
    assert_eq!(
        storage.recovery_free_disk_mb, 0,
        "recovery_free_disk_mb must default to 0 to pair with min_free_disk_mb=0"
    );
    validate_storage_config(&storage)
        .expect("StorageConfig::default() must pass validate_storage_config (W2)");
}

/// A TOML config with no [storage] overrides must also deserialize to defaults
/// that pass validation — guards the serde-default path, not just Default::default.
#[test]
fn default_toml_storage_config_passes_validation() {
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(default)]
        storage: StorageConfig,
    }
    let parsed: Wrapper = toml::from_str("").expect("empty config must deserialize");
    validate_storage_config(&parsed.storage)
        .expect("default-deserialized StorageConfig must pass validation (W2)");
}

/// The err+ floor invariant: a window with a zero per-source cap is rejected.
#[test]
fn err_floor_window_with_zero_cap_is_rejected() {
    let storage = StorageConfig {
        err_floor_window_hours: 24,
        err_floor_per_source_cap: 0,
        ..StorageConfig::default()
    };
    let err = validate_storage_config(&storage).unwrap_err();
    assert!(
        err.to_string().contains("err_floor_per_source_cap"),
        "wrong error: {err}"
    );
}

#[test]
fn notifications_disabled_skips_apprise_checks() {
    let cfg = NotificationsConfig {
        enabled: false,
        ..NotificationsConfig::default()
    };
    assert!(validate_notifications_config(&cfg).is_ok());
}

#[test]
fn notifications_enabled_requires_apprise_url() {
    // Only target URLs set, no API base URL → reject.
    let cfg = NotificationsConfig {
        enabled: true,
        apprise_url: String::new(),
        apprise_urls: vec!["gotify://host/token".to_string()],
        ..NotificationsConfig::default()
    };
    let err = validate_notifications_config(&cfg).expect_err("missing apprise_url must fail");
    assert!(
        err.to_string().contains("apprise_url"),
        "wrong error: {err}"
    );
}

#[test]
fn notifications_enabled_requires_apprise_urls() {
    // API base URL set but no delivery targets → reject (the dispatcher would
    // otherwise log "no apprise URLs configured" and silently drop firings).
    let cfg = NotificationsConfig {
        enabled: true,
        apprise_url: "http://apprise:8000".to_string(),
        apprise_urls: vec![],
        ..NotificationsConfig::default()
    };
    let err = validate_notifications_config(&cfg).expect_err("empty apprise_urls must fail");
    assert!(
        err.to_string().contains("apprise_urls"),
        "wrong error: {err}"
    );
}

#[test]
fn notifications_enabled_with_both_passes() {
    let cfg = NotificationsConfig {
        enabled: true,
        apprise_url: "http://apprise:8000".to_string(),
        apprise_urls: vec!["gotify://host/token".to_string()],
        ..NotificationsConfig::default()
    };
    assert!(validate_notifications_config(&cfg).is_ok());
}

#[test]
fn notifications_whitespace_only_apprise_urls_rejected() {
    let cfg = NotificationsConfig {
        enabled: true,
        apprise_url: "http://apprise:8000".to_string(),
        apprise_urls: vec!["   ".to_string()],
        ..NotificationsConfig::default()
    };
    let err = validate_notifications_config(&cfg).expect_err("whitespace-only target must fail");
    assert!(
        err.to_string().contains("apprise_urls"),
        "wrong error: {err}"
    );
}

#[test]
#[serial]
fn env_override_populates_apprise_urls_list() {
    crate::env::set_test_var(
        "CORTEX_NOTIFICATIONS_APPRISE_URLS",
        "gotify://host/a, ntfy://ntfy.sh/b ",
    );
    let mut urls: Vec<String> = Vec::new();
    env_override_list("CORTEX_NOTIFICATIONS_APPRISE_URLS", &mut urls);
    crate::env::remove_test_var("CORTEX_NOTIFICATIONS_APPRISE_URLS");
    assert_eq!(urls, vec!["gotify://host/a", "ntfy://ntfy.sh/b"]);
}

#[test]
fn llm_config_defaults_match_locked_table() {
    let cfg = crate::config::LlmConfig::default();
    assert!(cfg.enabled);
    assert_eq!(cfg.max_concurrent, 1);
    assert_eq!(cfg.max_per_action_concurrent, 1);
    assert_eq!(cfg.max_invocations_per_minute, 3);
    assert_eq!(cfg.max_invocations_per_hour, 30);
    assert_eq!(cfg.failure_threshold, 3);
    assert_eq!(cfg.cooldown_secs, 300);
    assert_eq!(cfg.timeout_secs, 120);
    assert_eq!(cfg.max_prompt_bytes, 1_048_576);
    assert_eq!(cfg.max_output_bytes, 262_144);
    assert!(!cfg.background_enrichment_enabled);
    assert!(
        cfg.actions.is_empty(),
        "no actions configured by default until config.toml declares them"
    );
}

#[test]
fn llm_config_parses_from_toml_with_action_subtables() {
    let toml_str = r#"
        [llm]
        enabled = true
        max_concurrent = 2

        [llm.actions.ai_assess]
        enabled = true

        [llm.actions.background_enrich]
        enabled = false
    "#;
    let parsed: crate::config::Config = toml::from_str(toml_str).unwrap();
    assert_eq!(parsed.llm.max_concurrent, 2);
    // Fields not set in the [llm] table still take their defaults.
    assert_eq!(parsed.llm.max_invocations_per_minute, 3);
    assert!(parsed.llm.actions.get("ai_assess").unwrap().enabled);
    assert!(!parsed.llm.actions.get("background_enrich").unwrap().enabled);
}

#[test]
#[serial]
fn cortex_llm_enabled_env_var_overrides_config() {
    crate::env::set_test_var("CORTEX_LLM_ENABLED", "false");
    let mut cfg = crate::config::LlmConfig::default();
    env_override_bool("CORTEX_LLM_ENABLED", &mut cfg.enabled).unwrap();
    assert!(!cfg.enabled);
    crate::env::remove_test_var("CORTEX_LLM_ENABLED");
}

#[test]
#[serial]
fn recovery_db_size_auto_adjusts_when_max_db_size_raised() {
    // Regression test for syslog-mcp-0kjd5: when CORTEX_MAX_DB_SIZE_MB is set
    // significantly higher than the default (1024MB) but CORTEX_RECOVERY_DB_SIZE_MB
    // is not set, recovery should auto-adjust to 90% of max instead of staying
    // at the naive default of 900MB, which causes silent data loss.
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_MAX_DB_SIZE_MB", "51200");
    // Explicitly ensure CORTEX_RECOVERY_DB_SIZE_MB is NOT set
    crate::env::remove_test_var("CORTEX_RECOVERY_DB_SIZE_MB");

    let result = Config::load();
    crate::env::remove_test_var("CORTEX_MAX_DB_SIZE_MB");
    crate::env::remove_test_var("CORTEX_HOST");

    let cfg = result.expect("Config::load() should succeed");
    // 90% of 51200 = 46080
    assert_eq!(
        cfg.storage.max_db_size_mb, 51200,
        "max_db_size_mb should be 51200"
    );
    assert_eq!(
        cfg.storage.recovery_db_size_mb, 46080,
        "recovery_db_size_mb should auto-adjust to 90% of max (46080), not stay at naive default (900)"
    );
}

#[test]
#[serial]
fn recovery_db_size_preserves_explicit_setting() {
    // When CORTEX_RECOVERY_DB_SIZE_MB is explicitly set, it should be
    // preserved even if max_db_size_mb is high.
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_MAX_DB_SIZE_MB", "51200");
    crate::env::set_test_var("CORTEX_RECOVERY_DB_SIZE_MB", "40000");

    let result = Config::load();
    crate::env::remove_test_var("CORTEX_MAX_DB_SIZE_MB");
    crate::env::remove_test_var("CORTEX_RECOVERY_DB_SIZE_MB");
    crate::env::remove_test_var("CORTEX_HOST");

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.storage.max_db_size_mb, 51200);
    assert_eq!(
        cfg.storage.recovery_db_size_mb, 40000,
        "recovery_db_size_mb should preserve explicit setting (40000)"
    );
}

#[test]
#[serial]
fn recovery_db_size_no_adjust_when_max_near_default() {
    // When max_db_size_mb is near the default (1024MB), no auto-adjust
    // should occur even if recovery is at the naive default.
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_MAX_DB_SIZE_MB", "2048");
    crate::env::remove_test_var("CORTEX_RECOVERY_DB_SIZE_MB");

    let result = Config::load();
    crate::env::remove_test_var("CORTEX_MAX_DB_SIZE_MB");
    crate::env::remove_test_var("CORTEX_HOST");

    let cfg = result.expect("Config::load() should succeed");
    assert_eq!(cfg.storage.max_db_size_mb, 2048);
    assert_eq!(
        cfg.storage.recovery_db_size_mb, 900,
        "recovery_db_size_mb should stay at default (900) when max is only 2x default (2048)"
    );
}

#[test]
fn heartbeat_silence_zero_threshold_rejected_when_enabled() {
    let mut cfg = NotificationsConfig::default();
    cfg.evaluators.heartbeat_silence = true;
    cfg.evaluators.heartbeat_silence_threshold_secs = 0;
    let err = validate_notifications_config(&cfg).expect_err("zero threshold must fail");
    assert!(
        err.to_string().contains("heartbeat_silence_threshold_secs"),
        "wrong error: {err}"
    );
}

#[test]
fn stream_silence_zero_threshold_rejected_when_enabled() {
    let mut cfg = NotificationsConfig::default();
    cfg.evaluators.stream_silence = true;
    cfg.evaluators.stream_silence_threshold_secs = 0;
    let err = validate_notifications_config(&cfg).expect_err("zero threshold must fail");
    assert!(
        err.to_string().contains("stream_silence_threshold_secs"),
        "wrong error: {err}"
    );
}

#[test]
fn stream_silence_empty_kinds_rejected_when_enabled() {
    let mut cfg = NotificationsConfig::default();
    cfg.evaluators.stream_silence = true;
    cfg.evaluators.stream_silence_kinds = vec!["  ".to_string()];
    let err = validate_notifications_config(&cfg).expect_err("blank kinds must fail");
    assert!(
        err.to_string().contains("stream_silence_kinds"),
        "wrong error: {err}"
    );
}

#[test]
fn silence_forget_must_exceed_thresholds() {
    let mut cfg = NotificationsConfig::default();
    cfg.evaluators.silence_forget_secs = 3600; // == stream threshold default
    let err = validate_notifications_config(&cfg).expect_err("forget <= threshold must fail");
    assert!(
        err.to_string().contains("silence_forget_secs"),
        "wrong error: {err}"
    );
}

#[test]
fn silence_rules_disabled_skip_threshold_checks() {
    let mut cfg = NotificationsConfig::default();
    cfg.evaluators.heartbeat_silence = false;
    cfg.evaluators.stream_silence = false;
    cfg.evaluators.heartbeat_silence_threshold_secs = 0;
    cfg.evaluators.stream_silence_threshold_secs = 0;
    cfg.evaluators.silence_forget_secs = 0;
    assert!(validate_notifications_config(&cfg).is_ok());
}

#[test]
fn silence_defaults_pass_validation() {
    let cfg = NotificationsConfig::default();
    assert!(validate_notifications_config(&cfg).is_ok());
    assert_eq!(cfg.evaluators.heartbeat_silence_threshold_secs, 600);
    assert_eq!(cfg.evaluators.stream_silence_threshold_secs, 3600);
    assert_eq!(cfg.evaluators.silence_forget_secs, 604_800);
    assert!(
        cfg.evaluators
            .stream_silence_kinds
            .contains(&"agent-docker".to_string())
    );
}

#[test]
fn agent_observatory_defaults_are_safe_and_disabled() {
    let cfg = AgentObservatoryConfig::default();
    assert!(!cfg.enabled);
    assert!(cfg.git.enabled);
    assert_eq!(cfg.projector_poll_ms, 500);
    assert_eq!(cfg.projector_page_rows, 500);
    assert_eq!(cfg.projector_page_bytes, 4_194_304);
    assert_eq!(cfg.active_window_secs, 15);
    assert_eq!(cfg.stale_after_secs, 300);
    assert_eq!(cfg.abandoned_after_secs, 86_400);
    assert_eq!(cfg.stream.max_event_bytes, 65_536);
    assert!(!cfg.privacy.include_prompt_content);
    assert!(!cfg.privacy.include_tool_content);
    assert!(!cfg.privacy.include_user_identity);
}

#[test]
fn agent_observatory_full_toml_deserializes_and_unknown_fields_fail() {
    let raw = r#"
        [agent_observatory]
        enabled = true
        projector_poll_ms = 250
        projector_page_rows = 750
        projector_page_bytes = 8388608
        active_window_secs = 20
        stale_after_secs = 400
        abandoned_after_secs = 90000

        [agent_observatory.git]
        enabled = true
        roots = ["/workspace", "/srv/repos"]
        max_depth = 4
        max_repositories = 200
        reconcile_interval_secs = 90
        debounce_ms = 750
        command_timeout_ms = 7000
        max_commits_per_transition = 800
        store_changed_paths = false
        store_author_name = false
        store_author_email_hash = true

        [agent_observatory.stream]
        outbox_retention_secs = 172800
        replay_limit = 2000
        client_queue = 512
        max_clients = 300
        keepalive_secs = 20
        max_event_bytes = 131072

        [agent_observatory.privacy]
        include_prompt_content = true
        include_tool_content = true
        include_command_content = false
        include_paths = false
        include_user_identity = true
        hash_email = false

        [agent_observatory.retention]
        events_days = 120
        spans_days = 45
        metrics_days = 45
        repository_observations_days = 120
        removed_worktrees_days = 730
    "#;
    let cfg: Config = toml::from_str(raw).expect("complete observatory config should parse");
    assert!(cfg.agent_observatory.enabled);
    assert_eq!(
        cfg.agent_observatory.git.roots,
        vec!["/workspace", "/srv/repos"]
    );
    assert_eq!(cfg.agent_observatory.stream.client_queue, 512);
    assert!(cfg.agent_observatory.privacy.include_prompt_content);
    assert_eq!(cfg.agent_observatory.retention.removed_worktrees_days, 730);

    let unknown = "[agent_observatory]
enabled = false
unknown_knob = true
";
    let error = toml::from_str::<Config>(unknown).unwrap_err();
    assert!(
        error.to_string().contains("unknown field"),
        "wrong error: {error}"
    );
}

#[test]
fn agent_observatory_validation_rejects_zero_and_unsafe_limits() {
    let cfg = AgentObservatoryConfig {
        enabled: true,
        projector_poll_ms: 0,
        ..Default::default()
    };
    assert!(
        validate_agent_observatory_config(&cfg)
            .unwrap_err()
            .to_string()
            .contains("projector_poll_ms")
    );

    let cfg = AgentObservatoryConfig {
        enabled: true,
        projector_page_rows: 501,
        ..Default::default()
    };
    assert!(
        validate_agent_observatory_config(&cfg)
            .unwrap_err()
            .to_string()
            .contains("between 1 and 500")
    );

    let cfg = AgentObservatoryConfig {
        enabled: true,
        stale_after_secs: 15,
        ..Default::default()
    };
    assert!(
        validate_agent_observatory_config(&cfg)
            .unwrap_err()
            .to_string()
            .contains("stale_after_secs")
    );

    let cfg = AgentObservatoryConfig {
        enabled: true,
        stream: AgentObservatoryStreamConfig {
            max_event_bytes: 1_048_577,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        validate_agent_observatory_config(&cfg)
            .unwrap_err()
            .to_string()
            .contains("max_event_bytes")
    );

    let cfg = AgentObservatoryConfig {
        enabled: true,
        retention: AgentObservatoryRetentionConfig {
            events_days: 0,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        validate_agent_observatory_config(&cfg)
            .unwrap_err()
            .to_string()
            .contains("events_days")
    );
}

#[test]
#[serial]
fn agent_observatory_environment_overrides_toml_values() {
    crate::env::set_test_var("CORTEX_HOST", "127.0.0.1");
    crate::env::set_test_var("CORTEX_AGENT_OBSERVATORY_ENABLED", "true");
    crate::env::set_test_var("CORTEX_AGENT_OBSERVATORY_PROJECTOR_POLL_MS", "125");
    crate::env::set_test_var(
        "CORTEX_AGENT_OBSERVATORY_GIT_ROOTS",
        "/workspace,/srv/repos",
    );
    crate::env::set_test_var("CORTEX_AGENT_OBSERVATORY_STREAM_MAX_EVENT_BYTES", "131072");
    crate::env::set_test_var("CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_PATHS", "false");
    crate::env::set_test_var("CORTEX_AGENT_OBSERVATORY_RETENTION_EVENTS_DAYS", "180");
    let result = Config::load();
    for key in [
        "CORTEX_HOST",
        "CORTEX_AGENT_OBSERVATORY_ENABLED",
        "CORTEX_AGENT_OBSERVATORY_PROJECTOR_POLL_MS",
        "CORTEX_AGENT_OBSERVATORY_GIT_ROOTS",
        "CORTEX_AGENT_OBSERVATORY_STREAM_MAX_EVENT_BYTES",
        "CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_PATHS",
        "CORTEX_AGENT_OBSERVATORY_RETENTION_EVENTS_DAYS",
    ] {
        crate::env::remove_test_var(key);
    }
    let cfg = result.expect("observatory env overrides should load");
    assert!(cfg.agent_observatory.enabled);
    assert_eq!(cfg.agent_observatory.projector_poll_ms, 125);
    assert_eq!(
        cfg.agent_observatory.git.roots,
        vec!["/workspace", "/srv/repos"]
    );
    assert_eq!(cfg.agent_observatory.stream.max_event_bytes, 131_072);
    assert!(!cfg.agent_observatory.privacy.include_paths);
    assert_eq!(cfg.agent_observatory.retention.events_days, 180);
}
