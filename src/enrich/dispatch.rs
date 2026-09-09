//! Dispatcher — picks a parser per (source_kind, app_name, container_name)
//! and merges its output onto the entry.
//!
//! Spec: docs/superpowers/specs/2026-05-16-enrichment-framework-design.md §4
//!
//! # Performance note: single metadata_json parse
//! `metadata_json` is parsed exactly once per `dispatch()` call at the top of
//! the function and passed as `Option<&Value>` to all helpers. Previously
//! `read_source_kind` and `read_container_name` each parsed the same JSON
//! independently (up to 4 parses per entry in the full dispatch+apply path).
//! The value lives on the stack and does not outlive the function, so no
//! `Arc<Value>` is needed.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;
use serde_json::Value;

use crate::db::LogBatchEntry;
use crate::enrich::output::{merge_output_with_metadata, record_error};
use crate::enrich::parsers::{
    AdguardParser, AutheliaParser, DockerEventParser, Fail2banParser, KernelParser, SwagParser,
};
use crate::enrich::{Parser, ParserInput, SourceKind};

const LRU_CAP: usize = 256;

/// Maps operator-renamed container names to canonical parser keys.
fn container_to_canonical(container: &str) -> &'static str {
    match container {
        "authelia" | "authelia-main" | "authelia-prod" | "authelia-master" => "authelia",
        "swag" | "swag-main" | "nginx" | "nginx-proxy" => "swag",
        "adguardhome" | "adguard" | "adguardhome-main" => "adguard",
        "fail2ban" | "fail2ban-main" => "fail2ban",
        _ => "",
    }
}

// Static singleton parser instances.
static KERNEL: KernelParser = KernelParser;
static DOCKER_EVENT: DockerEventParser = DockerEventParser;
static AUTHELIA: AutheliaParser = AutheliaParser;
static SWAG: SwagParser = SwagParser;
static ADGUARD: AdguardParser = AdguardParser;
static FAIL2BAN: Fail2banParser = Fail2banParser;

pub struct EnrichmentPipeline {
    by_name: HashMap<&'static str, &'static dyn Parser>,
    docker_event: &'static DockerEventParser,
    unknown_apps: Mutex<LruCache<String, ()>>,
}

impl EnrichmentPipeline {
    pub fn new() -> Self {
        let mut by_name: HashMap<&'static str, &'static dyn Parser> = HashMap::new();
        by_name.insert("kernel", &KERNEL);
        by_name.insert("authelia", &AUTHELIA);
        by_name.insert("swag", &SWAG);
        by_name.insert("adguard", &ADGUARD);
        by_name.insert("adguard-query", &ADGUARD); // API poller app_name
        by_name.insert("fail2ban", &FAIL2BAN);

        Self {
            by_name,
            docker_event: &DOCKER_EVENT,
            unknown_apps: Mutex::new(LruCache::new(
                NonZeroUsize::new(LRU_CAP).expect("LRU_CAP > 0"),
            )),
        }
    }

    pub fn dispatch(&self, entry: &mut LogBatchEntry) {
        let mut metadata: serde_json::Map<String, Value> = entry
            .metadata_json
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok())
            .unwrap_or_default();

        // docker-event short-circuit — routed by source_kind, not app_name.
        if extract_source_kind(&metadata) == Some("docker-event") {
            self.apply(entry, self.docker_event, &mut metadata);
            return;
        }

        // Container-name lookup (higher priority than app_name for Docker sources).
        if let Some(container) = extract_container_name(&metadata) {
            let canon = container_to_canonical(container);
            if !canon.is_empty()
                && let Some(&parser) = self.by_name.get(canon)
            {
                self.apply(entry, parser, &mut metadata);
                return;
            }
        }

        // Fast path: configured parser keys are lowercase already, so avoid a
        // lowercase allocation for the overwhelmingly common case.
        if let Some(app) = entry.app_name.as_deref() {
            if let Some(&parser) = self.by_name.get(app) {
                self.apply(entry, parser, &mut metadata);
                return;
            }
            let app_lower = if app.bytes().any(|byte| byte.is_ascii_uppercase()) {
                Some(app.to_ascii_lowercase())
            } else {
                None
            };
            let lookup = app_lower.as_deref().unwrap_or(app);
            if let Some(&parser) = self.by_name.get(lookup) {
                self.apply(entry, parser, &mut metadata);
                return;
            }
            if let Ok(mut lru) = self.unknown_apps.lock()
                && lru.put(lookup.to_string(), ()).is_none()
            {
                tracing::debug!(
                    app_name = lookup,
                    "enrich: no parser registered for app_name"
                );
            }
        }
    }

    fn apply(
        &self,
        entry: &mut LogBatchEntry,
        parser: &'static dyn Parser,
        metadata: &mut serde_json::Map<String, Value>,
    ) {
        let source_kind = to_source_kind(extract_source_kind(metadata));
        let container = extract_container_name(metadata);
        // Keep all immutable entry borrows inside this scope; once parse()
        // returns they end before merge_output mutates the entry. This avoids
        // cloning message/raw/app/severity on every parser invocation.
        let result = parser.parse(ParserInput {
            app_name: entry.app_name.as_deref(),
            container_name: container,
            message: &entry.message,
            raw: &entry.raw,
            source_kind,
            severity: &entry.severity,
        });
        match result {
            Ok(out) => merge_output_with_metadata(entry, parser.namespace(), out, metadata),
            Err(e) => record_error(entry, parser.name(), &e.to_string()),
        }
    }
}

impl Default for EnrichmentPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the `source_kind` string from an already-parsed metadata value.
/// Returns `None` if the metadata is absent, the key is missing, or the value
/// is not a string.
fn extract_source_kind(meta: &serde_json::Map<String, Value>) -> Option<&str> {
    meta.get("source_kind")?.as_str()
}

/// Map a raw `source_kind` string onto the [`SourceKind`] enum.
fn to_source_kind(raw: Option<&str>) -> SourceKind {
    match raw {
        Some("syslog-udp") => SourceKind::SyslogUdp,
        Some("syslog-tcp") => SourceKind::SyslogTcp,
        Some("docker-stream") => SourceKind::DockerStream,
        Some("docker-event") => SourceKind::DockerEvent,
        Some("otlp") => SourceKind::Otlp,
        Some("adguard-api") => SourceKind::AdguardApi,
        Some("unifi-api") => SourceKind::UnifiApi,
        Some("agent") => SourceKind::Agent,
        Some("shell-history") => SourceKind::ShellHistory,
        Some("agent-command") => SourceKind::AgentCommand,
        Some("file-tail") => SourceKind::FileTail,
        Some("agent-file-tail") => SourceKind::AgentFileTail,
        _ => SourceKind::SyslogTcp,
    }
}

/// Extract the `container_name` string from an already-parsed metadata value.
///
/// `docker_ingest/parser.rs` stamps `container_name` at the root of
/// `metadata_json` (not under a "docker" sub-object), so look for it directly.
fn extract_container_name(meta: &serde_json::Map<String, Value>) -> Option<&str> {
    meta.get("container_name")?.as_str()
}

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod dispatch_tests;
