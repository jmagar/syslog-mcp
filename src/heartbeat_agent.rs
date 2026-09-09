use std::collections::VecDeque;
use std::ffi::CString;
use std::fs;
use std::future::Future;
use std::io::{BufRead, BufReader};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use getrandom::fill as random_fill;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

pub const DEFAULT_INTERVAL_SECS: u64 = 30;
pub const DEFAULT_PROBE_DEADLINE_MS: u64 = 2_000;
pub const DEFAULT_COLLECTION_DEADLINE_MS: u64 = 5_000;
pub const DEFAULT_RETRY_BUFFER_LIMIT: usize = 32;
pub const DEFAULT_TARGET: &str = "http://127.0.0.1:3100";
pub const DEFAULT_DOCKER_URL: &str = "unix:///var/run/docker.sock";
pub const AI_TRANSCRIPT_FORWARD_ENV: &str = "CORTEX_AGENT_AI_TRANSCRIPT_FORWARD";
pub const AI_TRANSCRIPT_FORWARD_LEGACY_ENV: &str = "CORTEX_AGENT_AI_TRANSCRIPTS";
pub const OPTIONAL_ENV_KEYS: &[&str] = &[
    "CORTEX_AGENT_FILE_TAILS",
    AI_TRANSCRIPT_FORWARD_ENV,
    AI_TRANSCRIPT_FORWARD_LEGACY_ENV,
    "CORTEX_AGENT_AI_TRANSCRIPT_CHECKPOINT",
    "CORTEX_AGENT_COMMAND_FORWARD",
    "CORTEX_AGENT_COMMAND_SPOOL",
    "CORTEX_AGENT_SHELL_HISTORY_FORWARD",
    "CORTEX_AGENT_SHELL_HISTORY_CHECKPOINT",
    "CORTEX_AGENT_SYSLOG_FORWARD_SPOOL",
    "CORTEX_AGENT_SYSLOG_FORWARD_TARGET",
    "CORTEX_AGENT_AUTO_UPDATE",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TranscriptForwardEnvWarning {
    LegacyAlias,
    ConflictingValues,
}

impl TranscriptForwardEnvWarning {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::LegacyAlias => "agent_ai_transcript_forward_legacy_alias",
            Self::ConflictingValues => "agent_ai_transcript_forward_conflict",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TranscriptForwardEnvResolution {
    pub(crate) enabled: bool,
    pub(crate) warning: Option<TranscriptForwardEnvWarning>,
}

fn parse_forward_flag(value: &str) -> bool {
    value.eq_ignore_ascii_case("true") || value == "1"
}

pub(crate) fn resolve_ai_transcript_forward_env(
    current: Option<&str>,
    legacy: Option<&str>,
) -> TranscriptForwardEnvResolution {
    match (current, legacy) {
        (Some(current), Some(legacy)) => {
            let enabled = parse_forward_flag(current);
            let warning = if enabled == parse_forward_flag(legacy) {
                TranscriptForwardEnvWarning::LegacyAlias
            } else {
                TranscriptForwardEnvWarning::ConflictingValues
            };
            TranscriptForwardEnvResolution {
                enabled,
                warning: Some(warning),
            }
        }
        (Some(current), None) => TranscriptForwardEnvResolution {
            enabled: parse_forward_flag(current),
            warning: None,
        },
        (None, Some(legacy)) => TranscriptForwardEnvResolution {
            enabled: parse_forward_flag(legacy),
            warning: Some(TranscriptForwardEnvWarning::LegacyAlias),
        },
        (None, None) => TranscriptForwardEnvResolution {
            enabled: false,
            warning: None,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatAgentConfig {
    pub target: Option<String>,
    pub token: Option<String>,
    pub interval: Duration,
    pub probe_deadline: Duration,
    pub collection_deadline: Duration,
    pub retry_buffer_limit: usize,
    pub once: bool,
    pub emit: bool,
    pub json: bool,
    pub host_id_path: PathBuf,
    /// Forward local Docker container logs to cortex syslog receiver.
    pub docker: bool,
    /// Docker endpoint URL (unix socket or HTTP).
    pub docker_url: String,
    /// Forward journald entries to cortex syslog receiver.
    pub journald: bool,
    /// Tail a host syslog file and forward new lines to cortex syslog receiver.
    pub syslog_file: Option<PathBuf>,
    /// App log files to tail, each forwarded raw under a fixed tag
    /// (`CORTEX_AGENT_FILE_TAILS`, `PATH:TAG` comma-separated).
    pub file_tails: Vec<crate::agent::syslog_file::FileTailSource>,
    /// Override TCP syslog target (`host:port`).  Derived from `target` when absent.
    pub syslog_target: Option<String>,
    /// Explicit HTTP endpoint for receipt-backed syslog forwarding. When
    /// absent, the heartbeat target is used.
    pub syslog_forward_target: Option<String>,
    /// Local durable queue for receipt-backed syslog delivery.
    pub syslog_forward_spool_path: PathBuf,
    /// Forward local AI transcript (Claude/Codex) changes to the central
    /// server's `/v1/ai-transcripts` endpoint using `target`/`token`.
    pub ai_transcripts: bool,
    /// Local state file tracking per-file forwarded line counts.
    pub ai_transcript_checkpoint_path: PathBuf,
    /// Forward the local agent-command spool to the central server's
    /// `/v1/agent-commands` endpoint, on a fixed interval.
    pub agent_command_forward: bool,
    pub agent_command_spool_path: PathBuf,
    /// Forward local shell history (zsh/bash + atuin) to the central
    /// server's `/v1/shell-history` endpoint, on a fixed interval.
    pub shell_history_forward: bool,
    pub shell_history_checkpoint_path: PathBuf,
}

impl HeartbeatAgentConfig {
    pub fn from_env(host_id_path: PathBuf) -> Result<Self> {
        let target = crate::env::var("CORTEX_HEARTBEAT_TARGET")
            .ok()
            .or_else(|| crate::env::var("CORTEX_URL").ok())
            .or_else(|| Some(DEFAULT_TARGET.to_string()));
        let token = crate::env::var("CORTEX_HEARTBEAT_TOKEN")
            .ok()
            .or_else(|| crate::env::var("CORTEX_TOKEN").ok());
        let docker = crate::env::var("CORTEX_AGENT_DOCKER")
            .ok()
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let docker_url = crate::env::var("CORTEX_AGENT_DOCKER_URL")
            .unwrap_or_else(|_| DEFAULT_DOCKER_URL.to_string());
        let journald = crate::env::var("CORTEX_AGENT_JOURNALD")
            .ok()
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let syslog_file = crate::env::var("CORTEX_AGENT_SYSLOG_FILE")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from);
        let file_tails = crate::env::var("CORTEX_AGENT_FILE_TAILS")
            .ok()
            .map(|spec| crate::agent::syslog_file::parse_file_tails(&spec))
            .unwrap_or_default();
        let syslog_target = crate::env::var("CORTEX_SYSLOG_TARGET").ok();
        let explicit_syslog_forward_target = crate::env::var("CORTEX_AGENT_SYSLOG_FORWARD_TARGET")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let syslog_forward_target = if explicit_syslog_forward_target.is_some() {
            explicit_syslog_forward_target
        } else if syslog_target.is_some() {
            tracing::warn!(
                warning_code = "legacy_syslog_target_migrated",
                legacy_env = "CORTEX_SYSLOG_TARGET",
                replacement_env = "CORTEX_AGENT_SYSLOG_FORWARD_TARGET",
                "legacy TCP syslog target is ignored; durable forwarding uses the heartbeat HTTP target"
            );
            target.clone()
        } else {
            None
        };
        let syslog_forward_spool_path = match crate::env::var(
            "CORTEX_AGENT_SYSLOG_FORWARD_SPOOL",
        ) {
            Ok(path) => PathBuf::from(path),
            Err(_) => crate::setup::cortex_home_dir()
                .context(
                    "cannot resolve a durable Cortex state directory for the syslog forwarding spool; set CORTEX_AGENT_SYSLOG_FORWARD_SPOOL explicitly",
                )?
                .join("syslog-forward-spool.json"),
        };
        let current_transcript_forward = crate::env::var(AI_TRANSCRIPT_FORWARD_ENV).ok();
        let legacy_transcript_forward = crate::env::var(AI_TRANSCRIPT_FORWARD_LEGACY_ENV).ok();
        let transcript_forward = resolve_ai_transcript_forward_env(
            current_transcript_forward.as_deref(),
            legacy_transcript_forward.as_deref(),
        );
        if let Some(warning) = transcript_forward.warning {
            match warning {
                TranscriptForwardEnvWarning::LegacyAlias => tracing::warn!(
                    warning_code = warning.code(),
                    legacy_env = AI_TRANSCRIPT_FORWARD_LEGACY_ENV,
                    replacement_env = AI_TRANSCRIPT_FORWARD_ENV,
                    "deprecated remote transcript-forwarding environment alias is configured"
                ),
                TranscriptForwardEnvWarning::ConflictingValues => tracing::warn!(
                    warning_code = warning.code(),
                    legacy_env = AI_TRANSCRIPT_FORWARD_LEGACY_ENV,
                    replacement_env = AI_TRANSCRIPT_FORWARD_ENV,
                    "conflicting remote transcript-forwarding environment values; replacement wins"
                ),
            }
        }
        let ai_transcripts = transcript_forward.enabled;
        let ai_transcript_checkpoint_path =
            crate::env::var("CORTEX_AGENT_AI_TRANSCRIPT_CHECKPOINT")
                .ok()
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    crate::setup::cortex_home_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("ai-transcript-forward-checkpoint.json")
                });
        let agent_command_forward = crate::env::var("CORTEX_AGENT_COMMAND_FORWARD")
            .ok()
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let agent_command_spool_path = crate::env::var("CORTEX_AGENT_COMMAND_SPOOL")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                crate::setup::default_agent_command_spool_path()
                    .unwrap_or_else(|_| PathBuf::from("agent-command.jsonl"))
            });
        let shell_history_forward = crate::env::var("CORTEX_AGENT_SHELL_HISTORY_FORWARD")
            .ok()
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let shell_history_checkpoint_path =
            crate::env::var("CORTEX_AGENT_SHELL_HISTORY_CHECKPOINT")
                .ok()
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    crate::setup::cortex_home_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join("shell-history-forward-checkpoint.json")
                });
        Ok(Self {
            target,
            token,
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECS),
            probe_deadline: Duration::from_millis(DEFAULT_PROBE_DEADLINE_MS),
            collection_deadline: Duration::from_millis(DEFAULT_COLLECTION_DEADLINE_MS),
            retry_buffer_limit: DEFAULT_RETRY_BUFFER_LIMIT,
            once: false,
            emit: false,
            json: false,
            host_id_path,
            docker,
            docker_url,
            journald,
            syslog_file,
            file_tails,
            syslog_target,
            syslog_forward_target,
            syslog_forward_spool_path,
            ai_transcripts,
            ai_transcript_checkpoint_path,
            agent_command_forward,
            agent_command_spool_path,
            shell_history_forward,
            shell_history_checkpoint_path,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatPayload {
    pub schema_version: u8,
    pub host: HeartbeatHost,
    pub sample: HeartbeatSample,
    pub agent: HeartbeatAgentInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<HeartbeatCpu>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<HeartbeatMemory>,
    pub disks: Vec<HeartbeatDisk>,
    pub networks: Vec<HeartbeatNetwork>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<HeartbeatProcesses>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers: Option<HeartbeatContainers>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatHost {
    pub host_id: String,
    pub hostname: String,
    pub os: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    pub architecture: String,
    pub boot_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatSample {
    pub sequence: i64,
    pub sampled_at: String,
    pub uptime_secs: i64,
    pub monotonic_ms: i64,
    pub collection_ms: i64,
    pub partial: bool,
    pub probe_errors: Vec<String>,
    pub skipped_probes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatAgentInfo {
    pub version: String,
    pub mode: String,
    pub interval_secs: i64,
    pub push_latency_ms: Option<i64>,
    pub retry_backlog: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatCpu {
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub usage_pct: Option<f64>,
    pub user_pct: Option<f64>,
    pub system_pct: Option<f64>,
    pub iowait_pct: Option<f64>,
    pub steal_pct: Option<f64>,
    pub core_count: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatMemory {
    pub mem_total_bytes: i64,
    pub mem_available_bytes: i64,
    pub mem_used_bytes: Option<i64>,
    pub swap_total_bytes: i64,
    pub swap_used_bytes: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatDisk {
    pub kind: String,
    pub name: String,
    pub fs_type: Option<String>,
    pub bytes_total: Option<i64>,
    pub bytes_free: Option<i64>,
    pub bytes_used: Option<i64>,
    pub read_bytes_per_sec: Option<f64>,
    pub write_bytes_per_sec: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatNetwork {
    pub interface: String,
    pub rx_bytes_per_sec: Option<f64>,
    pub tx_bytes_per_sec: Option<f64>,
    pub rx_errors_per_sec: Option<f64>,
    pub tx_errors_per_sec: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatProcesses {
    pub total: i64,
    pub running: Option<i64>,
    pub sleeping: Option<i64>,
    pub zombies: i64,
    pub top: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatContainers {
    pub runtime: Option<String>,
    pub reachable: bool,
    pub running: i64,
    pub exited: i64,
    pub restarting: i64,
    pub unhealthy: i64,
    pub details: Vec<serde_json::Value>,
}

pub enum ProbeOutput {
    Cpu(HeartbeatCpu),
    Memory(HeartbeatMemory),
    Disk(HeartbeatDisk),
    Network(HeartbeatNetwork),
    Processes(HeartbeatProcesses),
    Containers(HeartbeatContainers),
    /// The target disappeared after discovery (for example an ephemeral veth).
    /// Expected host churn must not make the entire sample partial.
    Ignored,
}

pub trait HeartbeatProbe: Send + Sync {
    fn name(&self) -> &'static str;
    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + '_>>;
}

pub struct HeartbeatCollector {
    probes: Vec<Box<dyn HeartbeatProbe>>,
    started: Instant,
}

impl HeartbeatCollector {
    #[cfg(test)]
    pub fn fake() -> Self {
        Self {
            probes: vec![
                Box::new(FakeProbe::cpu()),
                Box::new(FakeProbe::memory()),
                Box::new(FakeProbe::disk()),
                Box::new(FakeProbe::network()),
                Box::new(FakeProbe::processes()),
                Box::new(FakeProbe::containers()),
            ],
            started: Instant::now(),
        }
    }

    pub fn linux() -> Self {
        let mut probes: Vec<Box<dyn HeartbeatProbe>> = vec![
            Box::new(LinuxCpuProbe),
            Box::new(LinuxMemoryProbe),
            Box::new(LinuxProcessProbe),
            Box::new(LinuxContainerProbe),
        ];

        for mount in discover_mounts().into_iter().take(8) {
            probes.push(Box::new(LinuxDiskCapacityProbe { mount }));
        }
        for device in discover_disk_devices().into_iter().take(8) {
            probes.push(Box::new(LinuxDiskIoProbe {
                device,
                previous: Mutex::new(None),
            }));
        }
        for interface in discover_network_interfaces().into_iter().take(16) {
            probes.push(Box::new(LinuxNetworkProbe {
                interface,
                previous: Mutex::new(None),
            }));
        }

        Self {
            probes,
            started: Instant::now(),
        }
    }

    pub fn for_platform(os: &str) -> Self {
        if os == "linux" {
            return Self::linux();
        }
        // Current resource probes are Linux-specific. A host-only heartbeat is
        // more accurate on Windows than reporting unsupported /proc probes as
        // collection failures.
        Self {
            probes: Vec::new(),
            started: Instant::now(),
        }
    }

    pub fn with_probes(probes: Vec<Box<dyn HeartbeatProbe>>) -> Self {
        Self {
            probes,
            started: Instant::now(),
        }
    }

    pub async fn collect(
        &self,
        host_id: String,
        sequence: i64,
        interval: Duration,
        retry_backlog: usize,
        probe_deadline: Duration,
        collection_deadline: Duration,
    ) -> HeartbeatPayload {
        let started = Instant::now();
        let mut cpu = None;
        let mut memory = None;
        let mut disks = Vec::new();
        let mut networks = Vec::new();
        let mut processes = None;
        let mut containers = None;
        let mut probe_errors = Vec::new();
        let mut skipped_probes = Vec::new();

        for probe in &self.probes {
            let elapsed = started.elapsed();
            if elapsed >= collection_deadline {
                skipped_probes.push(probe.name().to_string());
                continue;
            }
            let remaining = collection_deadline.saturating_sub(elapsed);
            let deadline = probe_deadline.min(remaining);
            match timeout(deadline, probe.collect()).await {
                Ok(Ok(output)) => match output {
                    ProbeOutput::Cpu(value) => cpu = Some(value),
                    ProbeOutput::Memory(value) => memory = Some(value),
                    ProbeOutput::Disk(value) if disks.len() < 16 => disks.push(value),
                    ProbeOutput::Network(value) if networks.len() < 16 => networks.push(value),
                    ProbeOutput::Processes(value) => processes = Some(value),
                    ProbeOutput::Containers(value) => containers = Some(value),
                    ProbeOutput::Ignored => {}
                    ProbeOutput::Disk(_) => skipped_probes.push("disk_limit".to_string()),
                    ProbeOutput::Network(_) => skipped_probes.push("network_limit".to_string()),
                },
                Ok(Err(error)) => probe_errors.push(bounded_probe_error(probe.name(), &error)),
                Err(_) => {
                    skipped_probes.push(probe.name().to_string());
                    probe_errors.push(format!("{} timed out", probe.name()));
                }
            }
        }

        let partial = !probe_errors.is_empty() || !skipped_probes.is_empty();
        HeartbeatPayload {
            schema_version: 1,
            host: HeartbeatHost {
                host_id,
                hostname: hostname(),
                os: std::env::consts::OS.to_string(),
                kernel: kernel_release(),
                architecture: std::env::consts::ARCH.to_string(),
                boot_id: boot_id(),
                timezone: crate::env::var("TZ").ok(),
            },
            sample: HeartbeatSample {
                sequence,
                sampled_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                uptime_secs: self.started.elapsed().as_secs() as i64,
                monotonic_ms: self.started.elapsed().as_millis() as i64,
                collection_ms: started.elapsed().as_millis() as i64,
                partial,
                probe_errors,
                skipped_probes,
            },
            agent: HeartbeatAgentInfo {
                version: env!("CARGO_PKG_VERSION").to_string(),
                mode: "always_on".to_string(),
                interval_secs: interval.as_secs() as i64,
                push_latency_ms: None,
                retry_backlog: retry_backlog as i64,
            },
            cpu,
            memory,
            disks,
            networks,
            processes,
            containers,
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
pub struct FakeProbe {
    name: &'static str,
    output: fn() -> ProbeOutput,
    delay: Duration,
    fail: bool,
}

#[cfg(test)]
impl FakeProbe {
    pub fn cpu() -> Self {
        Self::new("cpu", || {
            ProbeOutput::Cpu(HeartbeatCpu {
                load1: 0.10,
                load5: 0.12,
                load15: 0.08,
                usage_pct: Some(4.2),
                user_pct: Some(2.1),
                system_pct: Some(1.4),
                iowait_pct: Some(0.1),
                steal_pct: Some(0.0),
                core_count: 4,
            })
        })
    }

    pub fn memory() -> Self {
        Self::new("memory", || {
            ProbeOutput::Memory(HeartbeatMemory {
                mem_total_bytes: 8 * 1024 * 1024 * 1024,
                mem_available_bytes: 5 * 1024 * 1024 * 1024,
                mem_used_bytes: Some(3 * 1024 * 1024 * 1024),
                swap_total_bytes: 0,
                swap_used_bytes: 0,
            })
        })
    }

    pub fn disk() -> Self {
        Self::new("disk", || {
            ProbeOutput::Disk(HeartbeatDisk {
                kind: "mount".to_string(),
                name: "/".to_string(),
                fs_type: Some("stubfs".to_string()),
                bytes_total: Some(100 * 1024 * 1024 * 1024),
                bytes_free: Some(40 * 1024 * 1024 * 1024),
                bytes_used: Some(60 * 1024 * 1024 * 1024),
                read_bytes_per_sec: Some(0.0),
                write_bytes_per_sec: Some(0.0),
            })
        })
    }

    pub fn network() -> Self {
        Self::new("network", || {
            ProbeOutput::Network(HeartbeatNetwork {
                interface: "stub0".to_string(),
                rx_bytes_per_sec: Some(0.0),
                tx_bytes_per_sec: Some(0.0),
                rx_errors_per_sec: Some(0.0),
                tx_errors_per_sec: Some(0.0),
            })
        })
    }

    pub fn processes() -> Self {
        Self::new("processes", || {
            ProbeOutput::Processes(HeartbeatProcesses {
                total: 1,
                running: Some(1),
                sleeping: Some(0),
                zombies: 0,
                top: Vec::new(),
            })
        })
    }

    pub fn containers() -> Self {
        Self::new("containers", || {
            ProbeOutput::Containers(HeartbeatContainers {
                runtime: Some("docker".to_string()),
                reachable: false,
                running: 0,
                exited: 0,
                restarting: 0,
                unhealthy: 0,
                details: Vec::new(),
            })
        })
    }

    pub fn failing(name: &'static str) -> Self {
        Self {
            name,
            output: || {
                ProbeOutput::Processes(HeartbeatProcesses {
                    total: 0,
                    running: None,
                    sleeping: None,
                    zombies: 0,
                    top: Vec::new(),
                })
            },
            delay: Duration::ZERO,
            fail: true,
        }
    }

    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    fn new(name: &'static str, output: fn() -> ProbeOutput) -> Self {
        Self {
            name,
            output,
            delay: Duration::ZERO,
            fail: false,
        }
    }
}

#[cfg(test)]
impl HeartbeatProbe for FakeProbe {
    fn name(&self) -> &'static str {
        self.name
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + '_>> {
        Box::pin(async move {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.fail {
                bail!("fake probe failure");
            }
            Ok((self.output)())
        })
    }
}

#[derive(Debug, Clone)]
struct MountProbeTarget {
    path: PathBuf,
    fs_type: Option<String>,
}

struct LinuxCpuProbe;

impl HeartbeatProbe for LinuxCpuProbe {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + '_>> {
        Box::pin(async {
            let raw = tokio::fs::read_to_string("/proc/loadavg")
                .await
                .context("read /proc/loadavg")?;
            let (load1, load5, load15) = parse_loadavg(&raw)?;
            Ok(ProbeOutput::Cpu(HeartbeatCpu {
                load1,
                load5,
                load15,
                usage_pct: None,
                user_pct: None,
                system_pct: None,
                iowait_pct: None,
                steal_pct: None,
                core_count: std::thread::available_parallelism()
                    .map(|count| count.get() as i64)
                    .unwrap_or(1),
            }))
        })
    }
}

struct LinuxMemoryProbe;

impl HeartbeatProbe for LinuxMemoryProbe {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + '_>> {
        Box::pin(async {
            let raw = tokio::fs::read_to_string("/proc/meminfo")
                .await
                .context("read /proc/meminfo")?;
            Ok(ProbeOutput::Memory(parse_meminfo(&raw)?))
        })
    }
}

struct LinuxDiskCapacityProbe {
    mount: MountProbeTarget,
}

impl HeartbeatProbe for LinuxDiskCapacityProbe {
    fn name(&self) -> &'static str {
        "disk_capacity"
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + '_>> {
        Box::pin(async move {
            let (bytes_total, bytes_free) = statvfs_bytes(&self.mount.path)?;
            Ok(ProbeOutput::Disk(HeartbeatDisk {
                kind: "mount".to_string(),
                name: self.mount.path.display().to_string(),
                fs_type: self.mount.fs_type.clone(),
                bytes_total: Some(bytes_total),
                bytes_free: Some(bytes_free),
                bytes_used: Some(bytes_total.saturating_sub(bytes_free)),
                read_bytes_per_sec: None,
                write_bytes_per_sec: None,
            }))
        })
    }
}

struct LinuxDiskIoProbe {
    device: String,
    previous: Mutex<Option<DiskRateState>>,
}

impl HeartbeatProbe for LinuxDiskIoProbe {
    fn name(&self) -> &'static str {
        "disk_io"
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + '_>> {
        Box::pin(async move {
            let now = Instant::now();
            let raw = tokio::fs::read_to_string("/proc/diskstats")
                .await
                .context("read /proc/diskstats")?;
            let Some((read_bytes, write_bytes)) = parse_diskstats_device(&raw, &self.device) else {
                bail!("device {} not found in /proc/diskstats", self.device);
            };
            let (read_rate, write_rate) = rate_pair(&self.previous, now, read_bytes, write_bytes)?;
            Ok(ProbeOutput::Disk(HeartbeatDisk {
                kind: "block_io".to_string(),
                name: self.device.clone(),
                fs_type: None,
                bytes_total: None,
                bytes_free: None,
                bytes_used: None,
                read_bytes_per_sec: read_rate,
                write_bytes_per_sec: write_rate,
            }))
        })
    }
}

struct LinuxNetworkProbe {
    interface: String,
    previous: Mutex<Option<NetworkRateState>>,
}

impl HeartbeatProbe for LinuxNetworkProbe {
    fn name(&self) -> &'static str {
        "network"
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + '_>> {
        Box::pin(async move {
            let now = Instant::now();
            let raw = tokio::fs::read_to_string("/proc/net/dev")
                .await
                .context("read /proc/net/dev")?;
            let Some(counters) = parse_network_interface(&raw, &self.interface)? else {
                return Ok(ProbeOutput::Ignored);
            };
            let rates = network_rates(&self.previous, now, counters)?;
            Ok(ProbeOutput::Network(HeartbeatNetwork {
                interface: self.interface.clone(),
                rx_bytes_per_sec: rates.rx_bytes_per_sec,
                tx_bytes_per_sec: rates.tx_bytes_per_sec,
                rx_errors_per_sec: rates.rx_errors_per_sec,
                tx_errors_per_sec: rates.tx_errors_per_sec,
            }))
        })
    }
}

struct LinuxProcessProbe;

impl HeartbeatProbe for LinuxProcessProbe {
    fn name(&self) -> &'static str {
        "processes"
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + '_>> {
        Box::pin(async { Ok(ProbeOutput::Processes(collect_process_counts()?)) })
    }
}

struct LinuxContainerProbe;

impl HeartbeatProbe for LinuxContainerProbe {
    fn name(&self) -> &'static str {
        "containers"
    }

    fn collect(&self) -> Pin<Box<dyn Future<Output = Result<ProbeOutput>> + Send + '_>> {
        Box::pin(async {
            match crate::env::tokio_command("docker")
                .args(["ps", "-a", "--format", "{{.State}}"])
                .output()
                .await
            {
                Ok(output) if output.status.success() => Ok(ProbeOutput::Containers(
                    parse_docker_states(&String::from_utf8_lossy(&output.stdout)),
                )),
                Ok(output) => {
                    // Docker is installed but unusable: no daemon running,
                    // socket permission denied, or the CLI failing for any
                    // other reason. That is precisely what `reachable: false`
                    // reports, so emit it as telemetry rather than a probe
                    // error — an unreachable runtime is a fact about the host,
                    // not a failure to collect one.
                    //
                    // Reporting it as an error instead left `containers` as
                    // `None` on the payload and marked the whole sample
                    // partial, which is both misleading (the host genuinely has
                    // no reachable containers) and environment-dependent: any
                    // host with the docker CLI but no usable daemon — a CI
                    // container, for instance — behaved differently from a host
                    // with no docker at all.
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::debug!(
                        status = %output.status,
                        stderr = %stderr.trim(),
                        "docker ps unavailable; reporting containers unreachable"
                    );
                    Ok(ProbeOutput::Containers(HeartbeatContainers {
                        runtime: None,
                        reachable: false,
                        running: 0,
                        exited: 0,
                        restarting: 0,
                        unhealthy: 0,
                        details: Vec::new(),
                    }))
                }
                // Docker not installed, or present but not executable by this
                // user — both mean the runtime is unreachable, not that the
                // probe failed.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    Ok(ProbeOutput::Containers(HeartbeatContainers {
                        runtime: None,
                        reachable: false,
                        running: 0,
                        exited: 0,
                        restarting: 0,
                        unhealthy: 0,
                        details: Vec::new(),
                    }))
                }
                Err(error) => Err(anyhow::Error::from(error).context("spawn docker ps")),
            }
        })
    }
}

fn parse_loadavg(raw: &str) -> Result<(f64, f64, f64)> {
    let mut parts = raw.split_whitespace();
    let load1 = parts
        .next()
        .ok_or_else(|| anyhow!("missing load1"))?
        .parse::<f64>()?;
    let load5 = parts
        .next()
        .ok_or_else(|| anyhow!("missing load5"))?
        .parse::<f64>()?;
    let load15 = parts
        .next()
        .ok_or_else(|| anyhow!("missing load15"))?
        .parse::<f64>()?;
    Ok((load1, load5, load15))
}

fn parse_meminfo(raw: &str) -> Result<HeartbeatMemory> {
    let mut mem_total = None;
    let mut mem_available = None;
    let mut swap_total = 0;
    let mut swap_free = 0;
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next().and_then(|value| value.parse::<i64>().ok()) else {
            continue;
        };
        let bytes = value.saturating_mul(1024);
        match key.trim_end_matches(':') {
            "MemTotal" => mem_total = Some(bytes),
            "MemAvailable" => mem_available = Some(bytes),
            "SwapTotal" => swap_total = bytes,
            "SwapFree" => swap_free = bytes,
            _ => {}
        }
    }
    let mem_total_bytes = mem_total.ok_or_else(|| anyhow!("MemTotal missing from meminfo"))?;
    let mem_available_bytes =
        mem_available.ok_or_else(|| anyhow!("MemAvailable missing from meminfo"))?;
    Ok(HeartbeatMemory {
        mem_total_bytes,
        mem_available_bytes,
        mem_used_bytes: Some(mem_total_bytes.saturating_sub(mem_available_bytes)),
        swap_total_bytes: swap_total,
        swap_used_bytes: swap_total.saturating_sub(swap_free),
    })
}

fn discover_mounts() -> Vec<MountProbeTarget> {
    let file = match fs::File::open("/proc/self/mounts") {
        Ok(file) => file,
        Err(error) => {
            tracing::warn!(error = %error, "failed to open /proc/self/mounts; disk probes will be absent");
            return Vec::new();
        }
    };
    let mut mounts = Vec::new();
    for line in BufReader::new(file).lines().filter_map(|result| {
        result
            .map_err(|error| tracing::warn!(error = %error, "error reading /proc/self/mounts line"))
            .ok()
    }) {
        let mut parts = line.split_whitespace();
        let _source = parts.next();
        let Some(mount_path) = parts.next() else {
            continue;
        };
        let Some(fs_type) = parts.next() else {
            continue;
        };
        if is_pseudo_fs(fs_type) {
            continue;
        }
        let path = PathBuf::from(unescape_mount_path(mount_path));
        if mounts
            .iter()
            .any(|mount: &MountProbeTarget| mount.path == path)
        {
            continue;
        }
        mounts.push(MountProbeTarget {
            path,
            fs_type: Some(fs_type.to_string()),
        });
    }
    mounts
}

fn is_pseudo_fs(fs_type: &str) -> bool {
    matches!(
        fs_type,
        "autofs"
            | "binfmt_misc"
            | "bpf"
            | "cgroup"
            | "cgroup2"
            | "configfs"
            | "debugfs"
            | "devpts"
            | "devtmpfs"
            | "efivarfs"
            | "fuse.portal"
            | "fuse.snapfuse"
            | "fusectl"
            | "hugetlbfs"
            | "iso9660"
            | "mqueue"
            | "nsfs"
            | "overlay"
            | "proc"
            | "pstore"
            | "ramfs"
            | "rootfs"
            | "securityfs"
            | "squashfs"
            | "sysfs"
            | "tmpfs"
            | "tracefs"
    )
}

fn unescape_mount_path(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn statvfs_bytes(path: &Path) -> Result<(i64, i64)> {
    #[cfg(unix)]
    {
        let c_path = CString::new(path.as_os_str().as_bytes())?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("statvfs {}", path.display()));
        }
        let stat = unsafe { stat.assume_init() };
        let block_size = stat.f_frsize as u128;
        let total = (stat.f_blocks as u128).saturating_mul(block_size);
        let free = (stat.f_bavail as u128).saturating_mul(block_size);
        Ok((clamp_u128_to_i64(total), clamp_u128_to_i64(free)))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("statvfs is only available on unix")
    }
}

fn discover_disk_devices() -> Vec<String> {
    let raw = match fs::read_to_string("/proc/diskstats") {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(error = %error, "failed to read /proc/diskstats; disk I/O probes will be absent");
            return Vec::new();
        }
    };
    raw.lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .filter(|name| is_disk_device_name(name))
        .map(ToString::to_string)
        .take(8)
        .collect()
}

fn is_disk_device_name(name: &str) -> bool {
    if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("fd") {
        return false;
    }
    // NVMe whole disks end in n\d+, partitions end in n\d+p\d+
    if let Some(rest) = name.strip_prefix("nvme") {
        return !rest.contains('p');
    }
    // eMMC whole disks: mmcblk\d+, partitions: mmcblk\d+p\d+
    if let Some(rest) = name.strip_prefix("mmcblk") {
        return !rest.contains('p');
    }
    // device-mapper (dm-0, dm-1) — include whole device
    if name.starts_with("dm-") {
        return true;
    }
    // SCSI/SATA: whole disks (sda, sdb) have no trailing digit; partitions (sda1) do
    !name.chars().last().is_some_and(|ch| ch.is_ascii_digit())
}

fn parse_diskstats_device(raw: &str, device: &str) -> Option<(i64, i64)> {
    for line in raw.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 || parts[2] != device {
            continue;
        }
        let sectors_read = parts.get(5)?.parse::<u128>().ok()?;
        let sectors_written = parts.get(9)?.parse::<u128>().ok()?;
        return Some((
            clamp_u128_to_i64(sectors_read.saturating_mul(512)),
            clamp_u128_to_i64(sectors_written.saturating_mul(512)),
        ));
    }
    None
}

fn discover_network_interfaces() -> Vec<String> {
    let raw = match fs::read_to_string("/proc/net/dev") {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(error = %error, "failed to read /proc/net/dev; network probes will be absent");
            return Vec::new();
        }
    };
    raw.lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .filter(|name| !name.is_empty() && *name != "lo")
        .map(ToString::to_string)
        .take(16)
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct NetworkCounters {
    rx_bytes: i64,
    tx_bytes: i64,
    rx_errors: i64,
    tx_errors: i64,
}

#[derive(Debug, Clone, Copy)]
struct DiskRateState {
    sampled_at: Instant,
    read_bytes: i64,
    write_bytes: i64,
}

#[derive(Debug, Clone, Copy)]
struct NetworkRateState {
    sampled_at: Instant,
    counters: NetworkCounters,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct NetworkRates {
    rx_bytes_per_sec: Option<f64>,
    tx_bytes_per_sec: Option<f64>,
    rx_errors_per_sec: Option<f64>,
    tx_errors_per_sec: Option<f64>,
}

fn parse_network_interface(raw: &str, interface: &str) -> Result<Option<NetworkCounters>> {
    for line in raw.lines().skip(2) {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != interface {
            continue;
        }
        let parts: Vec<&str> = values.split_whitespace().collect();
        if parts.len() < 16 {
            bail!("malformed /proc/net/dev row for {interface}");
        }
        return Ok(Some(NetworkCounters {
            rx_bytes: clamp_u128_to_i64(parts[0].parse::<u128>()?),
            tx_bytes: clamp_u128_to_i64(parts[8].parse::<u128>()?),
            rx_errors: clamp_u128_to_i64(parts[2].parse::<u128>()?),
            tx_errors: clamp_u128_to_i64(parts[10].parse::<u128>()?),
        }));
    }
    Ok(None)
}

fn rate_pair(
    previous: &Mutex<Option<DiskRateState>>,
    now: Instant,
    first: i64,
    second: i64,
) -> Result<(Option<f64>, Option<f64>)> {
    let mut guard = previous
        .lock()
        .map_err(|_| anyhow!("heartbeat probe state lock poisoned"))?;
    let rates = guard.map(|last| {
        let elapsed = now.saturating_duration_since(last.sampled_at).as_secs_f64();
        if elapsed <= 0.0 {
            return (None, None);
        }
        (
            Some(first.saturating_sub(last.read_bytes).max(0) as f64 / elapsed),
            Some(second.saturating_sub(last.write_bytes).max(0) as f64 / elapsed),
        )
    });
    *guard = Some(DiskRateState {
        sampled_at: now,
        read_bytes: first,
        write_bytes: second,
    });
    Ok(rates.unwrap_or((None, None)))
}

fn network_rates(
    previous: &Mutex<Option<NetworkRateState>>,
    now: Instant,
    current: NetworkCounters,
) -> Result<NetworkRates> {
    let mut guard = previous
        .lock()
        .map_err(|_| anyhow!("heartbeat probe state lock poisoned"))?;
    let rates = guard.map(|last| {
        let elapsed = now.saturating_duration_since(last.sampled_at).as_secs_f64();
        if elapsed <= 0.0 {
            return NetworkRates {
                rx_bytes_per_sec: None,
                tx_bytes_per_sec: None,
                rx_errors_per_sec: None,
                tx_errors_per_sec: None,
            };
        }
        NetworkRates {
            rx_bytes_per_sec: Some(
                current
                    .rx_bytes
                    .saturating_sub(last.counters.rx_bytes)
                    .max(0) as f64
                    / elapsed,
            ),
            tx_bytes_per_sec: Some(
                current
                    .tx_bytes
                    .saturating_sub(last.counters.tx_bytes)
                    .max(0) as f64
                    / elapsed,
            ),
            rx_errors_per_sec: Some(
                current
                    .rx_errors
                    .saturating_sub(last.counters.rx_errors)
                    .max(0) as f64
                    / elapsed,
            ),
            tx_errors_per_sec: Some(
                current
                    .tx_errors
                    .saturating_sub(last.counters.tx_errors)
                    .max(0) as f64
                    / elapsed,
            ),
        }
    });
    *guard = Some(NetworkRateState {
        sampled_at: now,
        counters: current,
    });
    Ok(rates.unwrap_or(NetworkRates {
        rx_bytes_per_sec: None,
        tx_bytes_per_sec: None,
        rx_errors_per_sec: None,
        tx_errors_per_sec: None,
    }))
}

fn collect_process_counts() -> Result<HeartbeatProcesses> {
    let mut total = 0i64;
    let mut running = 0i64;
    let mut sleeping = 0i64;
    let mut zombies = 0i64;
    let mut top = Vec::new();
    for entry in fs::read_dir("/proc").context("read /proc")? {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let stat_path = entry.path().join("stat");
        let Ok(stat) = fs::read_to_string(stat_path) else {
            continue;
        };
        total += 1;
        let state = parse_proc_stat_state(&stat);
        match state {
            Some('R') => running += 1,
            Some('Z') => zombies += 1,
            Some(_) => sleeping += 1,
            None => {}
        }
        if top.len() < 8 {
            top.push(serde_json::json!({
                "pid": name,
                "state": state.map(|state| state.to_string()),
            }));
        }
    }
    Ok(HeartbeatProcesses {
        total,
        running: Some(running),
        sleeping: Some(sleeping),
        zombies,
        top,
    })
}

fn parse_proc_stat_state(raw: &str) -> Option<char> {
    let end = raw.rfind(')')?;
    raw[end + 1..].split_whitespace().next()?.chars().next()
}

fn parse_docker_states(raw: &str) -> HeartbeatContainers {
    let mut running = 0;
    let mut exited = 0;
    let mut restarting = 0;
    for state in raw.lines().map(str::trim).filter(|state| !state.is_empty()) {
        match state {
            "running" => running += 1,
            "exited" | "dead" | "created" | "removing" | "paused" => exited += 1,
            "restarting" => restarting += 1,
            _ => {}
        }
    }
    HeartbeatContainers {
        runtime: Some("docker".to_string()),
        reachable: true,
        running,
        exited,
        restarting,
        unhealthy: 0,
        details: Vec::new(),
    }
}

fn clamp_u128_to_i64(value: u128) -> i64 {
    value.min(i64::MAX as u128) as i64
}

pub struct RetryBuffer {
    limit: usize,
    queue: VecDeque<HeartbeatPayload>,
}

impl RetryBuffer {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            queue: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn push(&mut self, payload: HeartbeatPayload) {
        if self.limit == 0 {
            return;
        }
        while self.queue.len() >= self.limit {
            if let Some(evicted) = self.queue.pop_front() {
                tracing::warn!(
                    host_id = %evicted.host.host_id,
                    sequence = evicted.sample.sequence,
                    limit = self.limit,
                    "retry buffer full; oldest heartbeat evicted and lost",
                );
            }
        }
        self.queue.push_back(payload);
    }

    fn pop_front(&mut self) -> Option<HeartbeatPayload> {
        self.queue.pop_front()
    }
}

pub fn backoff_duration(attempt: u32) -> Duration {
    let millis = 250u64.saturating_mul(1u64 << attempt.min(4));
    Duration::from_millis(millis.min(4_000))
}

pub async fn run_agent(config: HeartbeatAgentConfig) -> Result<()> {
    let host_id = load_or_create_host_id(&config.host_id_path)?;

    // If we are running immediately after a self-update, confirm it settled or
    // roll back to the previous binary. May re-exec and not return.
    if let Err(error) = crate::agent::self_update::confirm_or_rollback() {
        tracing::error!(error = %error, "agent update rollback check failed");
    }

    // Server-coordinated auto-update keeps the agent binary in lockstep with the
    // cortex server it reports to. Opt out with CORTEX_AGENT_AUTO_UPDATE=false.
    let auto_update = crate::env::var("CORTEX_AGENT_AUTO_UPDATE")
        .map(|v| !(v.eq_ignore_ascii_case("false") || v == "0"))
        .unwrap_or(true);
    let mut update_confirmed = false;

    // Spawn Docker / journald / file-tail / AI-transcript forwarding streams as a background task.
    if config.docker
        || config.journald
        || config.syslog_file.is_some()
        || !config.file_tails.is_empty()
        || config.ai_transcripts
        || config.agent_command_forward
        || config.shell_history_forward
    {
        let syslog_target = config
            .syslog_target
            .clone()
            .or_else(|| {
                config
                    .target
                    .as_deref()
                    .and_then(crate::agent::AgentStreamsConfig::syslog_target_from_heartbeat)
            })
            .unwrap_or_else(|| "127.0.0.1:1514".to_string());
        let streams = crate::agent::AgentStreamsConfig {
            docker: config.docker,
            docker_url: config.docker_url.clone(),
            journald: config.journald,
            syslog_file: config.syslog_file.clone(),
            file_tails: config.file_tails.clone(),
            syslog_target,
            syslog_forward_target: config
                .syslog_forward_target
                .clone()
                .or_else(|| config.target.clone())
                .unwrap_or_else(|| DEFAULT_TARGET.to_string()),
            syslog_forward_token: config.token.clone(),
            syslog_forward_spool_path: config.syslog_forward_spool_path.clone(),
            hostname: hostname(),
            ai_transcripts: config.ai_transcripts,
            ai_transcript_target: config
                .target
                .clone()
                .unwrap_or_else(|| DEFAULT_TARGET.to_string()),
            ai_transcript_token: config.token.clone(),
            ai_transcript_checkpoint_path: config.ai_transcript_checkpoint_path.clone(),
            agent_command_forward: config.agent_command_forward,
            agent_command_spool_path: config.agent_command_spool_path.clone(),
            agent_command_target: config
                .target
                .clone()
                .unwrap_or_else(|| DEFAULT_TARGET.to_string()),
            agent_command_token: config.token.clone(),
            shell_history_forward: config.shell_history_forward,
            shell_history_target: config
                .target
                .clone()
                .unwrap_or_else(|| DEFAULT_TARGET.to_string()),
            shell_history_token: config.token.clone(),
            shell_history_checkpoint_path: config.shell_history_checkpoint_path.clone(),
        };
        tokio::spawn(crate::agent::run_agent_streams(streams));
    }

    let collector = HeartbeatCollector::for_platform(std::env::consts::OS);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build heartbeat reqwest::Client")?;
    let update_client = crate::agent::self_update::build_update_client()?;
    let update_in_flight = Arc::new(AtomicBool::new(false));
    let update_retry_after = Arc::new(Mutex::new(None::<(String, Instant)>));
    let mut retry = RetryBuffer::new(config.retry_buffer_limit);
    let mut sequence = chrono::Utc::now().timestamp_millis();
    let mut attempt = 0u32;
    let mut cadence = tokio::time::interval(config.interval);
    cadence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        cadence.tick().await;
        let mut payload = collector
            .collect(
                host_id.clone(),
                sequence,
                config.interval,
                retry.len(),
                config.probe_deadline,
                config.collection_deadline,
            )
            .await;

        if config.emit {
            println!("{}", serde_json::to_string_pretty(&payload)?);
            return Ok(());
        }

        let target = config.target.as_deref().ok_or_else(|| {
            anyhow!("heartbeat agent requires --target or CORTEX_HEARTBEAT_TARGET")
        })?;

        flush_retry_buffer(&client, &mut retry, target, config.token.as_deref()).await;
        payload.agent.retry_backlog = retry.len() as i64;
        match send_payload(&client, target, config.token.as_deref(), &mut payload).await {
            Ok(directive) => {
                attempt = 0;
                // First successful heartbeat after a swap finalizes the update.
                if !update_confirmed {
                    crate::agent::self_update::confirm_update_success();
                    update_confirmed = true;
                }
                if let Some(directive) = directive {
                    let update_needed = crate::agent::self_update::update_needed(&directive);
                    if auto_update && update_needed {
                        let cooling_down = update_retry_after
                            .lock()
                            .ok()
                            .and_then(|guard| guard.as_ref().cloned())
                            .is_some_and(|(version, retry_at)| {
                                version == directive.version && Instant::now() < retry_at
                            });
                        if cooling_down {
                            tracing::debug!(
                                target_version = %directive.version,
                                "agent self-update is in per-version retry cooldown"
                            );
                        } else if update_in_flight
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                        {
                            // Self-update runs outside the heartbeat cadence and only one
                            // attempt may be active at a time. Slow or repeated directives
                            // therefore cannot make the host appear silent or race the swap.
                            let update_client = update_client.clone();
                            let update_target = target.to_string();
                            let update_token = config.token.clone();
                            let update_in_flight = Arc::clone(&update_in_flight);
                            let update_retry_after = Arc::clone(&update_retry_after);
                            tokio::spawn(async move {
                                let result = timeout(
                                    crate::agent::self_update::SELF_UPDATE_DEADLINE,
                                    crate::agent::self_update::maybe_update(
                                        &update_client,
                                        &update_target,
                                        update_token.as_deref(),
                                        &directive,
                                    ),
                                )
                                .await;
                                update_in_flight.store(false, Ordering::Release);

                                match result {
                                    Ok(Ok(())) => {}
                                    Ok(Err(error)) => {
                                        set_update_retry_cooldown(
                                            &update_retry_after,
                                            &directive.version,
                                        );
                                        tracing::warn!(
                                            error = format!("{error:#}"),
                                            "agent self-update failed; staying on current binary"
                                        )
                                    }
                                    Err(_) => {
                                        set_update_retry_cooldown(
                                            &update_retry_after,
                                            &directive.version,
                                        );
                                        tracing::warn!(
                                            timeout_secs =
                                                crate::agent::self_update::SELF_UPDATE_DEADLINE
                                                    .as_secs(),
                                            "agent self-update exceeded deadline; heartbeat loop remains active"
                                        )
                                    }
                                }
                            });
                        } else {
                            tracing::debug!(
                                target_version = %directive.version,
                                "agent self-update already in progress; skipping duplicate directive"
                            );
                        }
                    } else if !auto_update && update_needed {
                        tracing::info!(
                            target_version = %directive.version,
                            "agent update available (CORTEX_AGENT_AUTO_UPDATE disabled)"
                        );
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "heartbeat push failed; queued for retry");
                retry.push(payload);
                if config.once {
                    return Err(error);
                }
                tokio::time::sleep(backoff_duration(attempt)).await;
                attempt = attempt.saturating_add(1);
            }
        }

        if config.once {
            return Ok(());
        }

        sequence += 1;
    }
}

fn set_update_retry_cooldown(state: &Mutex<Option<(String, Instant)>>, version: &str) {
    // Per-process randomness prevents a fleet from retrying a temporarily
    // unavailable release asset in lockstep after the base five-minute delay.
    let mut jitter = [0u8; 1];
    let jitter_secs = if random_fill(&mut jitter).is_ok() {
        u64::from(jitter[0]) % 60
    } else {
        version
            .bytes()
            .fold(0u64, |sum, byte| sum + u64::from(byte))
            % 60
    };
    if let Ok(mut guard) = state.lock() {
        *guard = Some((
            version.to_string(),
            Instant::now() + Duration::from_secs(300 + jitter_secs),
        ));
    }
}

async fn flush_retry_buffer(
    client: &reqwest::Client,
    retry: &mut RetryBuffer,
    target: &str,
    token: Option<&str>,
) {
    let initial = retry.len();
    for _ in 0..initial {
        let Some(mut payload) = retry.pop_front() else {
            return;
        };
        payload.agent.retry_backlog = retry.len() as i64;
        if let Err(error) = send_payload(client, target, token, &mut payload).await {
            tracing::warn!(error = %error, "heartbeat retry failed");
            retry.push(payload);
            return;
        }
    }
}

/// Minimal view of the heartbeat `202` ack body. Only the optional auto-update
/// directive is consumed; all other fields are ignored.
#[derive(Debug, Deserialize)]
struct HeartbeatAck {
    #[serde(default)]
    agent_update: Option<crate::agent::self_update::AgentUpdateDirective>,
}

/// Returns the server's auto-update directive when one is advertised in the
/// heartbeat ack, otherwise `None`.
async fn send_payload(
    client: &reqwest::Client,
    target: &str,
    token: Option<&str>,
    payload: &mut HeartbeatPayload,
) -> Result<Option<crate::agent::self_update::AgentUpdateDirective>> {
    let url = heartbeat_url(target)?;
    let started = Instant::now();
    let mut request = client.post(url).json(payload);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.context("heartbeat POST failed")?;
    payload.agent.push_latency_ms = Some(started.elapsed().as_millis() as i64);
    if response.status().as_u16() == 202 {
        let body = response.text().await.unwrap_or_default();
        let directive = serde_json::from_str::<HeartbeatAck>(&body)
            .ok()
            .and_then(|ack| ack.agent_update);
        return Ok(directive);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    bail!("heartbeat POST returned {status}: {body}");
}

fn heartbeat_url(target: &str) -> Result<String> {
    let trimmed = target.trim_end_matches('/');
    if trimmed.ends_with("/v1/heartbeats") {
        return Ok(trimmed.to_string());
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Ok(format!("{trimmed}/v1/heartbeats"));
    }
    bail!("heartbeat target must start with http:// or https://");
}

pub fn load_or_create_host_id(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(existing) => {
            let host_id = existing.trim();
            validate_host_id(host_id)?;
            Ok(host_id.to_string())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let host_id = generate_host_id()?;
            write_private(path, &format!("{host_id}\n"))?;
            Ok(host_id)
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn validate_host_id(host_id: &str) -> Result<()> {
    if host_id.len() < 16
        || !host_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        bail!("invalid heartbeat host_id in config");
    }
    Ok(())
}

fn generate_host_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    random_fill(&mut bytes).context("generate heartbeat host id")?;
    Ok(format!("syslog_{}", hex_bytes(&bytes)))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn bounded_probe_error(name: &str, error: &anyhow::Error) -> String {
    let mut text = format!("{name}: {error}");
    text.truncate(240);
    text
}

fn hostname() -> String {
    if let Ok(hostname) = crate::env::var("HOSTNAME")
        && !hostname.is_empty()
    {
        return hostname;
    }
    match std::fs::read_to_string("/proc/sys/kernel/hostname") {
        Ok(name) => {
            let name = name.trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
        Err(error) => tracing::debug!(error = %error, "Linux proc hostname unavailable"),
    }
    #[cfg(unix)]
    if let Some(name) = unix_hostname() {
        return name;
    }
    tracing::warn!("could not determine hostname; using 'unknown'");
    "unknown".to_string()
}

#[cfg(unix)]
fn unix_hostname() -> Option<String> {
    let mut bytes = [0_u8; 256];
    // SAFETY: `bytes` is writable for its full advertised length. gethostname
    // writes at most that many bytes; we find the first NUL (or use the full
    // buffer) before validating UTF-8.
    if unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return None;
    }
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..len])
        .ok()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
}

fn kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn boot_id() -> String {
    match std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        Ok(value) => {
            let trimmed = value.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
        Err(error) => tracing::debug!(error = %error, "Linux proc boot_id unavailable"),
    }
    #[cfg(target_os = "macos")]
    if let Some(id) = macos_boot_id() {
        return id;
    }
    tracing::warn!("stable platform boot identity unavailable; falling back to process ID");
    format!("process-{}", std::process::id())
}

#[cfg(target_os = "macos")]
fn macos_boot_id() -> Option<String> {
    let mut boot = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = std::mem::size_of::<libc::timeval>();
    let name = b"kern.boottime\0";
    // SAFETY: `boot` and `len` point to initialized writable storage of the
    // declared size, the sysctl name is NUL-terminated, and no new value is
    // supplied for this read-only query.
    let result = unsafe {
        libc::sysctlbyname(
            name.as_ptr().cast(),
            (&raw mut boot).cast(),
            &raw mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (result == 0 && len == std::mem::size_of::<libc::timeval>() && boot.tv_sec > 0)
        .then(|| format!("darwin-boot-{}-{}", boot.tv_sec, boot.tv_usec))
}

#[cfg(test)]
#[path = "heartbeat_agent_tests.rs"]
mod tests;
