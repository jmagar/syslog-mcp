use super::*;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serial_test::serial;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(unix)]
#[test]
fn unix_hostname_is_available_without_proc() {
    let _guard = EnvGuard::unset("HOSTNAME");
    assert_ne!(hostname(), "unknown");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_boot_identity_is_stable_across_calls_and_not_process_scoped() {
    let first = boot_id();
    let second = boot_id();
    assert_eq!(first, second);
    assert!(
        first.starts_with("darwin-boot-"),
        "unexpected boot id: {first}"
    );
    assert!(!first.starts_with("process-"));
}

struct EnvGuard {
    name: &'static str,
    previous: Option<String>,
}

impl EnvGuard {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = crate::env::var(name).ok();
        crate::env::set_test_var(name, value);
        Self { name, previous }
    }

    fn unset(name: &'static str) -> Self {
        let previous = crate::env::var(name).ok();
        crate::env::remove_test_var(name);
        Self { name, previous }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => {
                crate::env::set_test_var(self.name, value);
            }
            None => {
                crate::env::remove_test_var(self.name);
            }
        }
    }
}

#[tokio::test]
async fn fake_collector_emits_valid_v1_payload_defaults() {
    let collector = HeartbeatCollector::fake();
    let payload = collector
        .collect(
            "syslog_testhostid1234".to_string(),
            7,
            Duration::from_secs(DEFAULT_INTERVAL_SECS),
            0,
            Duration::from_millis(DEFAULT_PROBE_DEADLINE_MS),
            Duration::from_millis(DEFAULT_COLLECTION_DEADLINE_MS),
        )
        .await;

    assert_eq!(payload.schema_version, 1);
    assert_eq!(payload.host.host_id, "syslog_testhostid1234");
    assert_eq!(payload.sample.sequence, 7);
    assert_eq!(payload.agent.interval_secs, 30);
    assert!(!payload.sample.partial);
    assert!(payload.cpu.is_some());
    assert!(payload.memory.is_some());
    assert_eq!(payload.disks.len(), 1);
    assert_eq!(payload.networks.len(), 1);
    let json = serde_json::to_value(&payload).unwrap();
    assert!(json.get("networks").is_some());
    assert!(json.get("network").is_none());
}

#[tokio::test]
async fn unsupported_platform_emits_complete_host_only_heartbeat() {
    let collector = HeartbeatCollector::for_platform("windows");
    let payload = collector
        .collect(
            "windows-host".to_string(),
            1,
            Duration::from_secs(DEFAULT_INTERVAL_SECS),
            0,
            Duration::from_millis(DEFAULT_PROBE_DEADLINE_MS),
            Duration::from_millis(DEFAULT_COLLECTION_DEADLINE_MS),
        )
        .await;

    assert!(!payload.sample.partial);
    assert!(payload.sample.probe_errors.is_empty());
    assert!(payload.sample.skipped_probes.is_empty());
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[cfg(target_os = "linux")]
async fn linux_collector_constructs_probe_set_and_collects_core_proc_metrics() {
    let collector = HeartbeatCollector::linux();
    let payload = collector
        .collect(
            "syslog_testhostid1234".to_string(),
            11,
            Duration::from_secs(DEFAULT_INTERVAL_SECS),
            0,
            Duration::from_millis(DEFAULT_PROBE_DEADLINE_MS),
            Duration::from_millis(DEFAULT_COLLECTION_DEADLINE_MS),
        )
        .await;

    assert_eq!(payload.sample.sequence, 11);
    assert!(payload.cpu.is_some());
    assert!(payload.memory.is_some());
    assert!(payload.processes.is_some());
    assert!(
        payload.containers.is_some(),
        "container probe should report reachable=false when docker is absent"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[cfg(target_os = "linux")]
async fn linux_probe_collectors_read_proc_and_statvfs_successfully() {
    let cpu = LinuxCpuProbe.collect().await.unwrap();
    assert!(matches!(cpu, ProbeOutput::Cpu(_)));

    let memory = LinuxMemoryProbe.collect().await.unwrap();
    assert!(matches!(memory, ProbeOutput::Memory(_)));

    let disk = LinuxDiskCapacityProbe {
        mount: MountProbeTarget {
            path: PathBuf::from("/"),
            fs_type: Some("rootfs".to_string()),
        },
    }
    .collect()
    .await
    .unwrap();
    let ProbeOutput::Disk(disk) = disk else {
        panic!("expected disk output");
    };
    assert_eq!(disk.kind, "mount");
    assert_eq!(disk.name, "/");
    assert!(disk.bytes_total.unwrap_or_default() > 0);

    let processes = LinuxProcessProbe.collect().await.unwrap();
    let ProbeOutput::Processes(processes) = processes else {
        panic!("expected process output");
    };
    assert!(processes.total > 0);
}

#[test]
fn disk_mount_discovery_skips_runtime_pseudo_filesystems() {
    for fs_type in [
        "efivarfs",
        "fuse.portal",
        "iso9660",
        "nsfs",
        "overlay",
        "squashfs",
    ] {
        assert!(is_pseudo_fs(fs_type), "{fs_type} should not be probed");
    }
    for fs_type in ["ext4", "fuse.shfs", "xfs", "zfs"] {
        assert!(!is_pseudo_fs(fs_type), "{fs_type} should stay probeable");
    }
}

#[test]
#[serial]
fn config_from_env_honors_agent_stream_flags_and_fallbacks() {
    let _target = EnvGuard::set("CORTEX_HEARTBEAT_TARGET", "https://cortex.example.test");
    let _token = EnvGuard::set("CORTEX_HEARTBEAT_TOKEN", "heartbeat-token");
    let _docker = EnvGuard::set("CORTEX_AGENT_DOCKER", "1");
    let _docker_url = EnvGuard::set("CORTEX_AGENT_DOCKER_URL", "unix:///tmp/docker.sock");
    let _journald = EnvGuard::set("CORTEX_AGENT_JOURNALD", "true");
    let _syslog_file = EnvGuard::set("CORTEX_AGENT_SYSLOG_FILE", "/var/log/syslog");
    let _syslog_target = EnvGuard::set("CORTEX_SYSLOG_TARGET", "127.0.0.1:1514");
    let _syslog_forward_target = EnvGuard::set(
        "CORTEX_AGENT_SYSLOG_FORWARD_TARGET",
        "https://durable.example.test",
    );

    let config = HeartbeatAgentConfig::from_env(PathBuf::from("/tmp/host-id")).unwrap();

    assert_eq!(
        config.target.as_deref(),
        Some("https://cortex.example.test")
    );
    assert_eq!(config.token.as_deref(), Some("heartbeat-token"));
    assert!(config.docker);
    assert_eq!(config.docker_url, "unix:///tmp/docker.sock");
    assert!(config.journald);
    assert_eq!(
        config.syslog_file.as_deref(),
        Some(Path::new("/var/log/syslog"))
    );
    assert_eq!(config.syslog_target.as_deref(), Some("127.0.0.1:1514"));
    assert_eq!(
        config.syslog_forward_target.as_deref(),
        Some("https://durable.example.test")
    );
}

#[test]
#[serial]
fn legacy_syslog_target_uses_heartbeat_http_target_for_compatible_upgrade() {
    let _legacy = EnvGuard::set("CORTEX_SYSLOG_TARGET", "central.example.test:1514");
    let _durable = EnvGuard::unset("CORTEX_AGENT_SYSLOG_FORWARD_TARGET");
    let _heartbeat = EnvGuard::set(
        "CORTEX_HEARTBEAT_TARGET",
        "https://central.example.test:3100",
    );

    let config = HeartbeatAgentConfig::from_env(PathBuf::from("/tmp/host-id")).unwrap();

    assert_eq!(
        config.syslog_forward_target.as_deref(),
        Some("https://central.example.test:3100")
    );
}

#[test]
#[serial]
fn config_from_env_uses_cortex_url_and_token_fallbacks_and_ignores_blank_syslog_file() {
    let _heartbeat_target = EnvGuard::unset("CORTEX_HEARTBEAT_TARGET");
    let _heartbeat_token = EnvGuard::unset("CORTEX_HEARTBEAT_TOKEN");
    let _target = EnvGuard::set("CORTEX_URL", "http://fallback.example.test");
    let _token = EnvGuard::set("CORTEX_TOKEN", "fallback-token");
    let _docker = EnvGuard::set("CORTEX_AGENT_DOCKER", "false");
    let _journald = EnvGuard::set("CORTEX_AGENT_JOURNALD", "0");
    let _syslog_file = EnvGuard::set("CORTEX_AGENT_SYSLOG_FILE", "   ");

    let config = HeartbeatAgentConfig::from_env(PathBuf::from("/tmp/host-id")).unwrap();

    assert_eq!(
        config.target.as_deref(),
        Some("http://fallback.example.test")
    );
    assert_eq!(config.token.as_deref(), Some("fallback-token"));
    assert!(!config.docker);
    assert!(!config.journald);
    assert!(config.syslog_file.is_none());
    assert_eq!(config.docker_url, DEFAULT_DOCKER_URL);
}

#[tokio::test]
async fn collector_caps_disk_and_network_outputs_and_marks_partial() {
    let mut probes: Vec<Box<dyn HeartbeatProbe>> = Vec::new();
    for _ in 0..17 {
        probes.push(Box::new(FakeProbe::disk()));
    }
    for _ in 0..17 {
        probes.push(Box::new(FakeProbe::network()));
    }
    let collector = HeartbeatCollector::with_probes(probes);

    let payload = collector
        .collect(
            "syslog_testhostid1234".to_string(),
            1,
            Duration::from_secs(30),
            0,
            Duration::from_millis(100),
            Duration::from_millis(1_000),
        )
        .await;

    assert_eq!(payload.disks.len(), 16);
    assert_eq!(payload.networks.len(), 16);
    assert!(payload.sample.partial);
    assert!(
        payload
            .sample
            .skipped_probes
            .contains(&"disk_limit".to_string())
    );
    assert!(
        payload
            .sample
            .skipped_probes
            .contains(&"network_limit".to_string())
    );
}

#[tokio::test]
async fn failed_fake_probe_produces_partial_snapshot() {
    let collector = HeartbeatCollector::with_probes(vec![
        Box::new(FakeProbe::cpu()),
        Box::new(FakeProbe::failing("memory")),
        Box::new(FakeProbe::disk()),
    ]);

    let payload = collector
        .collect(
            "syslog_testhostid1234".to_string(),
            1,
            Duration::from_secs(30),
            0,
            Duration::from_millis(100),
            Duration::from_millis(500),
        )
        .await;

    assert!(payload.sample.partial);
    assert!(payload.cpu.is_some());
    assert_eq!(payload.disks.len(), 1);
    assert!(
        payload
            .sample
            .probe_errors
            .iter()
            .any(|error| error.contains("memory"))
    );
}

#[tokio::test]
async fn probe_deadline_skips_slow_probe_but_keeps_completed_data() {
    let collector = HeartbeatCollector::with_probes(vec![
        Box::new(FakeProbe::cpu()),
        Box::new(FakeProbe::memory().delayed(Duration::from_millis(100))),
        Box::new(FakeProbe::disk()),
    ]);

    let payload = collector
        .collect(
            "syslog_testhostid1234".to_string(),
            1,
            Duration::from_secs(30),
            0,
            Duration::from_millis(10),
            Duration::from_millis(200),
        )
        .await;

    assert!(payload.sample.partial);
    assert!(payload.cpu.is_some());
    assert!(payload.memory.is_none());
    assert!(
        payload
            .sample
            .skipped_probes
            .iter()
            .any(|probe| probe == "memory")
    );
}

#[test]
fn retry_buffer_is_bounded_and_drops_oldest() {
    let mut buffer = RetryBuffer::new(2);
    buffer.push(test_payload(1));
    buffer.push(test_payload(2));
    buffer.push(test_payload(3));

    assert_eq!(buffer.len(), 2);
    assert_eq!(buffer.pop_front().unwrap().sample.sequence, 2);
    assert_eq!(buffer.pop_front().unwrap().sample.sequence, 3);
}

#[test]
fn backoff_is_bounded() {
    assert_eq!(backoff_duration(0), Duration::from_millis(250));
    assert_eq!(backoff_duration(4), Duration::from_millis(4_000));
    assert_eq!(backoff_duration(20), Duration::from_millis(4_000));
}

#[test]
fn linux_meminfo_parser_returns_bounded_memory_snapshot() {
    let memory = parse_meminfo(
        "MemTotal:        1000 kB\nMemAvailable:     400 kB\nSwapTotal:        200 kB\nSwapFree:          50 kB\n",
    )
    .unwrap();

    assert_eq!(memory.mem_total_bytes, 1_024_000);
    assert_eq!(memory.mem_available_bytes, 409_600);
    assert_eq!(memory.mem_used_bytes, Some(614_400));
    assert_eq!(memory.swap_total_bytes, 204_800);
    assert_eq!(memory.swap_used_bytes, 153_600);
}

#[test]
fn linux_proc_parsers_extract_cpu_network_disk_and_process_state() {
    assert_eq!(
        parse_loadavg("0.10 0.20 0.30 1/100 123").unwrap(),
        (0.10, 0.20, 0.30)
    );
    assert_eq!(
        parse_diskstats_device("   8       0 sda 1 0 8 0 2 0 16 0 0 0 0 0 0 0 0\n", "sda"),
        Some((4096, 8192))
    );
    assert_eq!(
        parse_proc_stat_state("123 (syslog agent) S 1 2 3"),
        Some('S')
    );

    let network = parse_network_interface(
        "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 1000 1 2 0 0 0 0 0 2000 1 3 0 0 0 0 0\n",
        "eth0",
    )
    .unwrap()
    .unwrap();
    assert_eq!(network.rx_bytes, 1000);
    assert_eq!(network.tx_bytes, 2000);
    assert_eq!(network.rx_errors, 2);
    assert_eq!(network.tx_errors, 3);
}

#[test]
fn linux_parser_helpers_cover_pseudo_fs_mount_escaping_and_device_names() {
    assert!(is_pseudo_fs("proc"));
    assert!(!is_pseudo_fs("ext4"));
    assert_eq!(
        unescape_mount_path("/mnt/My\\040Disk/with\\011tab/line\\012slash\\134"),
        "/mnt/My Disk/with\ttab/line\nslash\\"
    );
    assert!(!is_disk_device_name("loop0"));
    assert!(!is_disk_device_name("sda1"));
    assert!(is_disk_device_name("sda"));
    assert!(is_disk_device_name("nvme0n1"));
    assert!(!is_disk_device_name("nvme0n1p1"));
    assert!(is_disk_device_name("mmcblk0"));
    assert!(!is_disk_device_name("mmcblk0p1"));
    assert!(is_disk_device_name("dm-0"));
    assert_eq!(clamp_u128_to_i64(i64::MAX as u128 + 500), i64::MAX);
}

#[test]
fn linux_rate_helpers_return_none_on_first_sample_and_rates_afterwards() {
    let previous = Mutex::new(None);
    let now = Instant::now();
    assert_eq!(rate_pair(&previous, now, 100, 200).unwrap(), (None, None));
    let (read, write) = rate_pair(&previous, now + Duration::from_secs(2), 300, 260).unwrap();
    assert_eq!(read, Some(100.0));
    assert_eq!(write, Some(30.0));

    let previous_network = Mutex::new(None);
    let current = NetworkCounters {
        rx_bytes: 100,
        tx_bytes: 200,
        rx_errors: 1,
        tx_errors: 2,
    };
    assert_eq!(
        network_rates(&previous_network, now, current).unwrap(),
        NetworkRates {
            rx_bytes_per_sec: None,
            tx_bytes_per_sec: None,
            rx_errors_per_sec: None,
            tx_errors_per_sec: None,
        }
    );
    let rates = network_rates(
        &previous_network,
        now + Duration::from_secs(4),
        NetworkCounters {
            rx_bytes: 500,
            tx_bytes: 1000,
            rx_errors: 5,
            tx_errors: 10,
        },
    )
    .unwrap();
    assert_eq!(
        rates,
        NetworkRates {
            rx_bytes_per_sec: Some(100.0),
            tx_bytes_per_sec: Some(200.0),
            rx_errors_per_sec: Some(1.0),
            tx_errors_per_sec: Some(2.0),
        }
    );
}

#[test]
fn generated_host_id_is_persisted_and_not_machine_id_shaped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("heartbeat-host-id");
    let first = load_or_create_host_id(&path).unwrap();
    let second = load_or_create_host_id(&path).unwrap();

    assert_eq!(first, second);
    assert!(first.starts_with("syslog_"));
    assert_ne!(first.len(), 32);
    assert_ne!(first.len(), 64);
}

#[test]
fn heartbeat_url_appends_path_to_bare_host() {
    assert_eq!(
        heartbeat_url("http://host:3100").unwrap(),
        "http://host:3100/v1/heartbeats"
    );
}

#[test]
fn heartbeat_url_strips_trailing_slash_before_appending() {
    assert_eq!(
        heartbeat_url("http://host:3100/").unwrap(),
        "http://host:3100/v1/heartbeats"
    );
}

#[test]
fn heartbeat_url_is_idempotent_when_path_already_present() {
    assert_eq!(
        heartbeat_url("http://host:3100/v1/heartbeats").unwrap(),
        "http://host:3100/v1/heartbeats"
    );
}

#[test]
fn heartbeat_url_rejects_non_http_scheme() {
    assert!(heartbeat_url("ftp://host:3100").is_err());
}

#[tokio::test]
async fn send_payload_posts_json_with_bearer_and_records_latency_on_accepted_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/heartbeats"))
        .and(header("authorization", "Bearer secret-token"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&server)
        .await;
    let client = reqwest::Client::new();
    let mut payload = test_payload(1);

    send_payload(&client, &server.uri(), Some("secret-token"), &mut payload)
        .await
        .unwrap();

    assert!(payload.agent.push_latency_ms.is_some());
}

#[tokio::test]
async fn send_payload_reports_non_accepted_status_and_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/heartbeats"))
        .respond_with(ResponseTemplate::new(503).set_body_string("try later"))
        .expect(1)
        .mount(&server)
        .await;
    let client = reqwest::Client::new();
    let mut payload = test_payload(1);

    let err = send_payload(&client, &server.uri(), None, &mut payload)
        .await
        .unwrap_err();

    let msg = err.to_string();
    assert!(msg.contains("503"));
    assert!(msg.contains("try later"));
    assert!(payload.agent.push_latency_ms.is_some());
}

#[tokio::test]
async fn flush_retry_buffer_stops_on_first_failed_retry_and_requeues_payload() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/heartbeats"))
        .respond_with(ResponseTemplate::new(500).set_body_string("still down"))
        .expect(1)
        .mount(&server)
        .await;
    let client = reqwest::Client::new();
    let mut retry = RetryBuffer::new(4);
    retry.push(test_payload(1));
    retry.push(test_payload(2));

    flush_retry_buffer(&client, &mut retry, &server.uri(), None).await;

    assert_eq!(retry.len(), 2);
    assert_eq!(retry.pop_front().unwrap().sample.sequence, 2);
    assert_eq!(retry.pop_front().unwrap().sample.sequence, 1);
}

#[tokio::test]
async fn flush_retry_buffer_drains_successful_retries_in_order() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/heartbeats"))
        .respond_with(ResponseTemplate::new(202))
        .expect(2)
        .mount(&server)
        .await;
    let client = reqwest::Client::new();
    let mut retry = RetryBuffer::new(4);
    retry.push(test_payload(1));
    retry.push(test_payload(2));

    flush_retry_buffer(&client, &mut retry, &server.uri(), None).await;

    assert!(retry.is_empty());
}

#[test]
fn retry_buffer_zero_limit_discards_all_pushes() {
    let mut buffer = RetryBuffer::new(0);
    buffer.push(test_payload(1));
    buffer.push(test_payload(2));
    assert_eq!(buffer.len(), 0);
    assert!(buffer.is_empty());
}

#[test]
fn parse_meminfo_errors_on_missing_mem_total() {
    let result = parse_meminfo("MemAvailable: 400 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("MemTotal"));
}

#[test]
fn parse_meminfo_errors_on_missing_mem_available() {
    let result = parse_meminfo("MemTotal: 1000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("MemAvailable"));
}

#[test]
fn host_id_validation_rejects_short_or_unsafe_values_and_accepts_generated_shape() {
    assert!(validate_host_id("syslog_valid-host_id123").is_ok());
    assert!(validate_host_id("short").is_err());
    assert!(validate_host_id("syslog bad spaces").is_err());
    assert_eq!(hex_bytes(&[0x00, 0x1f, 0xa5, 0xff]), "001fa5ff");
}

#[test]
fn parse_docker_states_maps_all_known_states() {
    let containers = parse_docker_states(
        "running\nexited\ndead\ncreated\nremoving\npaused\nrestarting\nunknown_future_state\n",
    );
    assert!(containers.reachable);
    assert_eq!(containers.running, 1);
    assert_eq!(containers.exited, 5); // exited + dead + created + removing + paused
    assert_eq!(containers.restarting, 1);
    // unknown_future_state should be ignored without panicking
}

fn test_payload(sequence: i64) -> HeartbeatPayload {
    HeartbeatPayload {
        schema_version: 1,
        host: HeartbeatHost {
            host_id: "syslog_testhostid1234".to_string(),
            hostname: "host".to_string(),
            os: "linux".to_string(),
            kernel: None,
            architecture: "x86_64".to_string(),
            boot_id: "boot".to_string(),
            timezone: None,
        },
        sample: HeartbeatSample {
            sequence,
            sampled_at: "2026-05-25T00:00:00.000Z".to_string(),
            uptime_secs: 1,
            monotonic_ms: 1,
            collection_ms: 1,
            partial: false,
            probe_errors: Vec::new(),
            skipped_probes: Vec::new(),
        },
        agent: HeartbeatAgentInfo {
            version: "0.0.0".to_string(),
            mode: "always_on".to_string(),
            interval_secs: 30,
            push_latency_ms: None,
            retry_backlog: 0,
        },
        cpu: None,
        memory: None,
        disks: Vec::new(),
        networks: Vec::new(),
        processes: None,
        containers: None,
    }
}

// ENV-001: remote transcript-forwarding environment compatibility.

#[test]
fn transcript_forward_env_resolution_precedence_is_stable() {
    use TranscriptForwardEnvWarning::{ConflictingValues, LegacyAlias};

    let cases = [
        (None, None, false, None),
        (Some("true"), None, true, None),
        (Some("1"), None, true, None),
        (Some("false"), None, false, None),
        (None, Some("true"), true, Some(LegacyAlias)),
        (None, Some("false"), false, Some(LegacyAlias)),
        (Some("true"), Some("true"), true, Some(LegacyAlias)),
        (Some("false"), Some("false"), false, Some(LegacyAlias)),
        (Some("true"), Some("false"), true, Some(ConflictingValues)),
        (Some("false"), Some("true"), false, Some(ConflictingValues)),
    ];

    for (current, legacy, enabled, warning) in cases {
        assert_eq!(
            resolve_ai_transcript_forward_env(current, legacy),
            TranscriptForwardEnvResolution { enabled, warning },
            "current={current:?}, legacy={legacy:?}"
        );
    }
    assert_eq!(
        LegacyAlias.code(),
        "agent_ai_transcript_forward_legacy_alias"
    );
    assert_eq!(
        ConflictingValues.code(),
        "agent_ai_transcript_forward_conflict"
    );
}

#[test]
#[serial]
fn transcript_forward_env_current_value_is_authoritative_in_config() {
    let _new = EnvGuard::set(AI_TRANSCRIPT_FORWARD_ENV, "false");
    let _legacy = EnvGuard::set(AI_TRANSCRIPT_FORWARD_LEGACY_ENV, "true");
    let config = HeartbeatAgentConfig::from_env(PathBuf::from("/tmp/host-id")).unwrap();
    assert!(!config.ai_transcripts);
}

#[test]
#[serial]
fn transcript_forward_env_legacy_value_is_honored_in_config() {
    let _new = EnvGuard::unset(AI_TRANSCRIPT_FORWARD_ENV);
    let _legacy = EnvGuard::set(AI_TRANSCRIPT_FORWARD_LEGACY_ENV, "true");
    let config = HeartbeatAgentConfig::from_env(PathBuf::from("/tmp/host-id")).unwrap();
    assert!(config.ai_transcripts);
}

#[test]
fn transcript_forward_env_does_not_gate_local_sessions_watch_service() {
    let unit = crate::setup::ai_watch_service_unit(
        Path::new("/home/test/.local/bin/cortex"),
        Path::new("/home/test/.config/cortex/sessions-watch.env"),
        Path::new("/home/test/.cortex/data/cortex.db"),
        Path::new("/home/test/.local/state/cortex"),
        Path::new("/home/test"),
    );

    assert!(unit.contains("sessions watch --no-initial-scan --json"));
    assert!(!unit.contains(AI_TRANSCRIPT_FORWARD_ENV));
    assert!(!unit.contains(AI_TRANSCRIPT_FORWARD_LEGACY_ENV));
}

/// A host with the docker CLI present but no usable daemon must report the
/// runtime as unreachable, not fail the probe.
///
/// Reporting an error here left `containers` as `None` and marked the whole
/// sample partial, and it made behaviour depend on the environment: a host with
/// no docker at all reported `reachable: false`, while a host with docker but a
/// dead or permission-denied daemon — a CI container, for instance — reported a
/// probe error instead. Both are the same fact about the host.
#[tokio::test]
#[serial]
async fn container_probe_reports_unreachable_when_docker_ps_fails() {
    let dir = tempfile::tempdir().unwrap();
    let fake_docker = dir.path().join("docker");
    std::fs::write(
        &fake_docker,
        "#!/bin/sh\necho 'Cannot connect to the Docker daemon' >&2\nexit 1\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake_docker, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    // `PATH` overrides live in a process-global map that every subprocess spawn
    // in this test binary resolves against, so this has to both prepend rather
    // than replace and restore on drop. A bare, unrestored fixture directory
    // outlives the test and leaves every later `sh`, `git`, or `docker` spawn
    // in the binary resolving against a deleted temp dir. `cargo nextest` hides
    // that behind one process per test; plain `cargo test` does not.
    let mut search_path = vec![dir.path().to_path_buf()];
    if let Some(existing) = crate::env::var_os("PATH") {
        search_path.extend(std::env::split_paths(&existing));
    }
    let _path = EnvGuard::set("PATH", std::env::join_paths(search_path).unwrap());

    let output = LinuxContainerProbe.collect().await.expect(
        "a failing `docker ps` is an unreachable runtime, not a probe error — \
         it must not propagate as Err",
    );

    let ProbeOutput::Containers(containers) = output else {
        panic!("expected a Containers probe output");
    };
    assert!(!containers.reachable, "daemon is not reachable");
    assert_eq!(containers.running, 0);
    assert!(containers.details.is_empty());
}
