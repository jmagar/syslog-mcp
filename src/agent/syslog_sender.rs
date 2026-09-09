//! Durable, receipt-backed syslog forwarding for Cortex agents.
//!
//! TCP syslog is deliberately not used for the reliable path: it has no
//! receipt semantics. Frames are persisted locally, POSTed to the authenticated
//! receiver, and removed only after their exact idempotency receipt arrives.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::syslog_forward_ingest::{
    SyslogForwardGap, SyslogForwardRecord, SyslogForwardRequest, SyslogForwardResponse,
};

pub(super) const MAX_SOURCE_SPOOL_RECORDS: usize = 1_024;
pub(super) const MAX_SOURCE_SPOOL_BYTES: usize = 1024 * 1024;
pub(super) const MAX_SPOOL_RECORDS: usize = 4_096;
pub(super) const MAX_SPOOL_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_SPOOL_GAPS: usize = 512;
pub(super) const MAX_SPOOL_AGE_SECS: i64 = 86_400;
const MAX_BATCH_RECORDS: usize = 100;
const MAX_BATCH_BYTES: usize = 512 * 1024;
const MAX_FORWARD_RECORD_BYTES: usize = 64 * 1024;
const RECONNECT_MAX_MS: u64 = 30_000;
const PERSIST_COMMAND_CAPACITY: usize = 128;

/// Payload-free forwarding health that is safe to log or expose in status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyslogForwardStatus {
    pub queued_records: usize,
    pub queued_bytes: usize,
    pub pending_gaps: usize,
    pub gap_overflow_intervals: u64,
    pub oldest_age_secs: Option<u64>,
    pub evicted_records: u64,
    pub last_error_code: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct SpoolState {
    source_instance: String,
    #[serde(default = "default_epoch")]
    source_epoch: u64,
    #[serde(default)]
    next_sequence: u64,
    #[serde(default)]
    next_sequences: HashMap<String, u64>,
    #[serde(default)]
    records: VecDeque<SyslogForwardRecord>,
    #[serde(default)]
    gaps: VecDeque<SyslogForwardGap>,
    /// Gap identities become immutable after their first dispatch. Persisting
    /// this set keeps a lost response plus restart from changing the retry ID.
    #[serde(default)]
    dispatched_gap_keys: HashSet<String>,
    /// Number of loss intervals that could not be retained because the gap
    /// queue itself reached its hard bound. This is durable degradation
    /// telemetry; it never pretends the omitted interval was delivered.
    #[serde(default)]
    gap_overflow_intervals: u64,
    #[serde(default)]
    evicted_records: u64,
    #[serde(default)]
    last_dispatched_source: Option<String>,
}

#[path = "syslog_sender/spool.rs"]
mod spool;
#[cfg(test)]
use spool::should_report_gap_overflow;
use spool::{
    evict_aggregate_to_quota, evict_source_to_quota, gap_footprint_bytes, load_spool,
    next_source_key, push_gap, save_spool, source_key_of,
};

fn default_epoch() -> u64 {
    1
}

impl Default for SpoolState {
    fn default() -> Self {
        Self {
            source_instance: random_source_instance(),
            source_epoch: 1,
            next_sequence: 0,
            next_sequences: HashMap::new(),
            records: VecDeque::new(),
            gaps: VecDeque::new(),
            dispatched_gap_keys: HashSet::new(),
            gap_overflow_intervals: 0,
            evicted_records: 0,
            last_dispatched_source: None,
        }
    }
}

struct SenderState {
    spool_path: PathBuf,
    spool: SpoolState,
    /// An unreadable original spool is an operator-recovery condition, not a
    /// transient delivery error. Retain the status signal even after later
    /// batches succeed through the separate recovery spool.
    recovery_required: bool,
    last_error_code: Option<&'static str>,
}

/// Local collection never waits for the remote receiver. A full/outage path
/// stays bounded and creates a durable payload-free gap before any eviction.
pub struct SyslogSender {
    state: Arc<Mutex<SenderState>>,
    persist_tx: mpsc::Sender<PersistCommand>,
    /// The sender is normally retained by the agent for its entire lifetime.
    /// Keeping the abort handle means a dropped/restarted agent cannot leave an
    /// orphaned delivery loop running against the durable spool.
    delivery_task: tokio::task::AbortHandle,
}

enum PersistCommand {
    Enqueue {
        source_key: String,
        line: String,
        reply: oneshot::Sender<Result<()>>,
    },
    NextRequest {
        reply: oneshot::Sender<Result<Option<SyslogForwardRequest>>>,
    },
    ApplyReceipts {
        request: SyslogForwardRequest,
        receipts: Vec<String>,
        reply: oneshot::Sender<Result<()>>,
    },
}

impl SyslogSender {
    pub fn new(target: String, token: Option<String>, spool_path: PathBuf) -> Self {
        let loaded = load_spool(&spool_path);
        let state = Arc::new(Mutex::new(SenderState {
            spool: loaded.spool,
            spool_path: loaded.spool_path,
            recovery_required: loaded.error_code.is_some(),
            last_error_code: loaded.error_code,
        }));
        let notify = Arc::new(Notify::new());
        let (persist_tx, persist_rx) = mpsc::channel(PERSIST_COMMAND_CAPACITY);
        let owner_state = Arc::clone(&state);
        let owner_notify = Arc::clone(&notify);
        std::thread::Builder::new()
            .name("cortex-syslog-spool".into())
            .spawn(move || persistence_owner(owner_state, owner_notify, persist_rx))
            .expect("spawn syslog spool persistence owner");
        let delivery_task = tokio::spawn(delivery_loop(
            target,
            token,
            Arc::clone(&state),
            Arc::clone(&notify),
            persist_tx.clone(),
        ));
        Self {
            state,
            persist_tx,
            delivery_task: delivery_task.abort_handle(),
        }
    }

    pub async fn send(&self, line: String) -> Result<()> {
        self.send_from("syslog", line).await
    }

    pub async fn send_from(&self, source_key: &str, line: String) -> Result<()> {
        let (reply, receive) = oneshot::channel();
        self.persist_tx
            .send(PersistCommand::Enqueue {
                source_key: source_key.to_owned(),
                line,
                reply,
            })
            .await
            .map_err(|_| anyhow!("syslog spool persistence owner stopped"))?;
        receive
            .await
            .map_err(|_| anyhow!("syslog spool persistence owner stopped"))?
    }

    /// Compatibility API for high-rate tailers. Failure is not silent: it is a
    /// payload-free diagnostic and the caller's stream can restart normally.
    pub fn try_send(&self, line: String) {
        self.try_send_from("syslog", line);
    }

    pub fn try_send_from(&self, source_key: &str, line: String) {
        let (reply, receive) = oneshot::channel();
        // Close the reply side before handoff so the persistence owner can
        // deterministically report any durable-write failure.
        drop(receive);
        if let Err(error) = self.persist_tx.try_send(PersistCommand::Enqueue {
            source_key: source_key.to_owned(),
            line,
            reply,
        }) {
            tracing::error!(
                reason_code = "local_spool_backpressure",
                source_key = %stable_source_key(source_key),
                error = %error,
                "syslog frame could not enter the bounded persistence queue"
            );
        }
    }

    pub fn status(&self) -> SyslogForwardStatus {
        let state = self.state.lock().expect("syslog sender state poisoned");
        let oldest_at = state
            .spool
            .records
            .iter()
            .map(|record| record.observed_at.as_str())
            .chain(state.spool.gaps.iter().map(|gap| gap.observed_at.as_str()))
            .filter_map(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .min();
        let oldest_age_secs =
            oldest_at.map(|at| Utc::now().signed_duration_since(at).num_seconds().max(0) as u64);
        SyslogForwardStatus {
            queued_records: state.spool.records.len(),
            queued_bytes: state
                .spool
                .records
                .iter()
                .map(|r| r.line.len())
                .sum::<usize>()
                + state
                    .spool
                    .gaps
                    .iter()
                    .map(gap_footprint_bytes)
                    .sum::<usize>(),
            pending_gaps: state.spool.gaps.len(),
            gap_overflow_intervals: state.spool.gap_overflow_intervals,
            oldest_age_secs,
            evicted_records: state.spool.evicted_records,
            last_error_code: if state.spool.gap_overflow_intervals > 0 {
                Some("gap_evidence_overflow")
            } else {
                state.last_error_code
            },
        }
    }

    #[cfg(test)]
    fn enqueue(&self, source_key: &str, line: String) -> Result<()> {
        enqueue(&self.state, source_key, line)
    }
}

#[path = "syslog_sender/persistence.rs"]
mod persistence;
use persistence::persistence_owner;
#[cfg(test)]
use persistence::{apply_receipts, enqueue, next_request};

impl Drop for SyslogSender {
    fn drop(&mut self) {
        self.delivery_task.abort();
    }
}

async fn delivery_loop(
    target: String,
    token: Option<String>,
    state: Arc<Mutex<SenderState>>,
    notify: Arc<Notify>,
    persist_tx: mpsc::Sender<PersistCommand>,
) {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    else {
        tracing::error!(
            reason_code = "client_init_failed",
            "syslog forwarding client could not start"
        );
        return;
    };
    let mut attempt = 0u32;
    loop {
        if target.trim().is_empty() {
            set_error(&state, "no_delivery_target");
            notify.notified().await;
            continue;
        }
        let (reply, receive) = oneshot::channel();
        if persist_tx
            .send(PersistCommand::NextRequest { reply })
            .await
            .is_err()
        {
            return;
        }
        let request = match receive
            .await
            .unwrap_or_else(|_| Err(anyhow!("syslog spool persistence owner stopped")))
        {
            Ok(Some(request)) => request,
            Ok(None) => {
                notify.notified().await;
                continue;
            }
            Err(error) => {
                tracing::error!(
                    reason_code = "local_spool_persist_failed",
                    error = format!("{error:#}"),
                    "syslog dispatch state could not be retained"
                );
                set_error(&state, "local_spool_persist_failed");
                let delay = retry_delay_ms(attempt, None, random_u64());
                retry_sleep(&mut attempt, delay).await;
                continue;
            }
        };
        let mut call = client
            .post(format!(
                "{}/v1/syslog-forward",
                target.trim_end_matches('/')
            ))
            .json(&request);
        if let Some(token) = token.as_deref() {
            call = call.bearer_auth(token);
        }
        match call.send().await {
            Ok(response) if response.status().is_success() => {
                let status = response.status();
                match response.json::<SyslogForwardResponse>().await {
                    Ok(response) => {
                        let (reply, receive) = oneshot::channel();
                        let checkpoint = if persist_tx
                            .send(PersistCommand::ApplyReceipts {
                                request: request.clone(),
                                receipts: response.receipts,
                                reply,
                            })
                            .await
                            .is_err()
                        {
                            Err(anyhow!("syslog spool persistence owner stopped"))
                        } else {
                            receive.await.unwrap_or_else(|_| {
                                Err(anyhow!("syslog spool persistence owner stopped"))
                            })
                        };
                        match checkpoint {
                            Ok(()) => {
                                attempt = 0;
                                set_error(&state, "none");
                            }
                            Err(error) => {
                                let invalid_receipts =
                                    error.downcast_ref::<InvalidReceiptSet>().is_some();
                                let reason_code = if invalid_receipts {
                                    "invalid_receipt_response"
                                } else {
                                    "local_spool_persist_failed"
                                };
                                tracing::error!(
                                    reason_code,
                                    error = format!("{error:#}"),
                                    "syslog receipt could not be checkpointed"
                                );
                                set_error(&state, reason_code);
                                let delay = retry_delay_ms(attempt, None, random_u64());
                                retry_sleep(&mut attempt, delay).await;
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            reason_code = "invalid_receipt_response",
                            status = %status,
                            error = %error,
                            "syslog receiver response rejected"
                        );
                        set_error(&state, "invalid_receipt_response");
                        let delay = retry_delay_ms(attempt, None, random_u64());
                        retry_sleep(&mut attempt, delay).await;
                    }
                }
            }
            Ok(response) => {
                let retry_after = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok());
                let plan = retry_plan(
                    response.status().as_u16(),
                    attempt,
                    retry_after,
                    random_u64(),
                );
                tracing::warn!(status = %response.status(), reason_code = plan.reason_code, "syslog forwarding deferred");
                set_error(&state, plan.reason_code);
                retry_sleep(&mut attempt, plan.delay_ms).await;
            }
            Err(error) => {
                tracing::warn!(
                    reason_code = "transport_unavailable",
                    error = %error,
                    "syslog forwarding deferred"
                );
                set_error(&state, "transport_unavailable");
                let delay = retry_delay_ms(attempt, None, random_u64());
                retry_sleep(&mut attempt, delay).await;
            }
        }
    }
}

#[path = "syslog_sender/retry.rs"]
mod retry;
use retry::*;

pub fn format_rfc5424(
    pri: u8,
    timestamp: &str,
    hostname: &str,
    app_name: &str,
    procid: &str,
    msg: &str,
) -> String {
    let msg = msg.replace('\n', " ");
    let app = sanitise_field(app_name, "cortex-agent");
    let proc = sanitise_field(procid, "-");
    format!("<{pri}>1 {timestamp} {hostname} {app} {proc} - - {msg}")
}
pub const PRI_LOCAL0_INFO: u8 = 16 * 8 + 6;
pub const PRI_LOCAL0_WARN: u8 = 16 * 8 + 4;
pub const PRI_LOCAL0_ERR: u8 = 16 * 8 + 3;
pub fn local0_pri(severity: u8) -> u8 {
    16 * 8 + severity.min(7)
}
fn sanitise_field<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() || value.len() > 48 || !value.bytes().all(|b| b.is_ascii_graphic()) {
        fallback
    } else {
        value
    }
}

#[cfg(test)]
#[path = "syslog_sender_tests.rs"]
mod tests;
