//! Retry classification, backoff, and sender identity helpers.

use super::*;
use chrono::{SecondsFormat, Utc};
use getrandom::fill as random_fill;
use sha2::{Digest, Sha256};
use tokio::time::sleep;

pub(super) struct RetryPlan {
    pub(super) reason_code: &'static str,
    pub(super) delay_ms: u64,
}

pub(super) fn retry_plan(
    status: u16,
    attempt: u32,
    retry_after: Option<u64>,
    entropy: u64,
) -> RetryPlan {
    let reason_code = if status == 429 {
        "receiver_backpressure"
    } else if (500..=599).contains(&status) {
        "receiver_unavailable"
    } else {
        "receiver_rejected"
    };
    RetryPlan {
        reason_code,
        delay_ms: retry_delay_ms(attempt, retry_after, entropy),
    }
}

pub(super) fn retry_delay_ms(attempt: u32, retry_after: Option<u64>, entropy: u64) -> u64 {
    if let Some(seconds) = retry_after {
        return seconds.saturating_mul(1_000).min(RECONNECT_MAX_MS);
    }
    let backoff = backoff_ms(attempt);
    let jitter_window = (backoff / 10).max(1);
    backoff.saturating_add(entropy % (jitter_window + 1))
}

pub(super) async fn retry_sleep(attempt: &mut u32, delay: u64) {
    *attempt = attempt.saturating_add(1);
    sleep(Duration::from_millis(delay)).await;
}
pub(super) fn set_error(state: &Arc<Mutex<SenderState>>, code: &'static str) {
    let mut state = state.lock().expect("syslog sender state poisoned");
    state.last_error_code = if state.recovery_required {
        Some("spool_recovery_required")
    } else {
        (code != "none").then_some(code)
    };
}
pub(super) fn backoff_ms(attempt: u32) -> u64 {
    500u64
        .saturating_mul(1u64 << attempt.min(6))
        .min(RECONNECT_MAX_MS)
}
pub(super) fn delivery_key(source: &str, epoch: u64, sequence: u64, kind: &str) -> String {
    format!("{source}:{epoch}:{sequence}:{kind}")
}
pub(super) fn stable_source_key(source_key: &str) -> String {
    let digest = Sha256::digest(source_key.as_bytes());
    format!("source-{}", hex::encode(&digest[..12]))
}
pub(super) fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}
pub(super) fn random_source_instance() -> String {
    let mut bytes = [0; 16];
    random_fill(&mut bytes).expect("OS random source identity");
    hex::encode(bytes)
}

pub(super) fn random_u64() -> u64 {
    let mut bytes = [0; 8];
    random_fill(&mut bytes).expect("OS random retry jitter");
    u64::from_le_bytes(bytes)
}

#[derive(Debug)]
pub(super) struct InvalidReceiptSet;

impl std::fmt::Display for InvalidReceiptSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .write_str("syslog receiver returned an incomplete, duplicate, or unknown receipt set")
    }
}

impl std::error::Error for InvalidReceiptSet {}
