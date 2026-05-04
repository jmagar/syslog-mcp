use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info, warn};

use crate::config::{StorageConfig, SyslogConfig};
use crate::db::{self, DbPool};

/// Syslog facility names (RFC 5424)
const WRITE_CHANNEL_CAPACITY: usize = 10_000;
const INGEST_SUMMARY_INTERVAL_SECS: u64 = 60;
const FACILITIES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
];

pub async fn start_with_storage_state(
    config: SyslogConfig,
    storage: StorageConfig,
    pool: Arc<DbPool>,
    storage_state: Arc<Mutex<Option<db::StorageBudgetState>>>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<db::LogBatchEntry>(WRITE_CHANNEL_CAPACITY);

    // Spawn the batched writer
    let writer_pool = pool.clone();
    let writer_storage = storage.clone();
    let writer_storage_state = storage_state.clone();
    let batch_size = config.batch_size;
    let flush_interval = tokio::time::Duration::from_millis(config.flush_interval);
    tokio::spawn(async move {
        batch_writer(
            rx,
            writer_pool,
            writer_storage,
            writer_storage_state,
            batch_size,
            flush_interval,
        )
        .await;
    });

    let bind_addr = config.bind_addr();

    // Spawn UDP listener
    let udp_tx = tx.clone();
    let udp_bind = bind_addr.clone();
    let max_size = config.max_message_size;
    tokio::spawn(async move {
        if let Err(e) = udp_listener(&udp_bind, max_size, udp_tx).await {
            error!(error = %e, "UDP syslog listener failed");
        }
    });

    // Spawn TCP listener
    let tcp_tx = tx.clone();
    let tcp_bind = bind_addr.clone();
    let max_tcp_connections = config.max_tcp_connections;
    let tcp_idle_timeout_secs = config.tcp_idle_timeout_secs;
    tokio::spawn(async move {
        if let Err(e) = tcp_listener(
            &tcp_bind,
            tcp_tx,
            max_size,
            max_tcp_connections,
            tcp_idle_timeout_secs,
        )
        .await
        {
            error!(error = %e, "TCP syslog listener failed");
        }
    });

    info!(
        bind = %bind_addr,
        batch_size = config.batch_size,
        flush_interval_ms = config.flush_interval,
        max_message_size = config.max_message_size,
        max_tcp_connections = config.max_tcp_connections,
        tcp_idle_timeout_secs = config.tcp_idle_timeout_secs,
        write_channel_capacity = WRITE_CHANNEL_CAPACITY,
        "Syslog listeners started"
    );

    Ok(())
}

/// UDP syslog receiver
async fn udp_listener(
    bind: &str,
    max_size: usize,
    tx: mpsc::Sender<db::LogBatchEntry>,
) -> Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    info!(bind = %bind, "UDP syslog listener bound");

    let mut buf = vec![0u8; max_size];
    let mut backpressure = false;
    let mut received_packets: u64 = 0;
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                received_packets += 1;
                let raw = String::from_utf8_lossy(&buf[..len]).to_string();
                debug!(
                    src = %addr,
                    len,
                    packet_index = received_packets,
                    queue_depth = queue_depth(&tx),
                    "UDP syslog received"
                );

                // Log backpressure only on state transitions to avoid log storms.
                let at_capacity = tx.capacity() == 0;
                if at_capacity && !backpressure {
                    warn!(
                        src = %addr,
                        queue_depth = queue_depth(&tx),
                        channel_capacity = WRITE_CHANNEL_CAPACITY,
                        "syslog write channel full — backpressure applied"
                    );
                    backpressure = true;
                } else if !at_capacity && backpressure {
                    info!(
                        src = %addr,
                        queue_depth = queue_depth(&tx),
                        channel_capacity = WRITE_CHANNEL_CAPACITY,
                        "syslog write channel cleared — backpressure lifted"
                    );
                    backpressure = false;
                }

                if tx.send(parse_syslog(&raw, addr.to_string())).await.is_err() {
                    error!("Write channel closed");
                    break;
                }
            }
            Err(e) => {
                error!(error = %e, "UDP recv error");
            }
        }
    }
    Ok(())
}

/// Per-connection handler for TCP syslog streams.
async fn handle_tcp_connection(
    stream: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    tx: mpsc::Sender<db::LogBatchEntry>,
    max_size: usize,
    idle_timeout_secs: u64,
) {
    info!(peer = %addr, "TCP syslog connection accepted");
    // Persistent forwarders like rsyslog reuse a single TCP session for many
    // syslog frames, so max_size must apply per message line, not to the whole
    // connection lifetime.
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();
    let mut backpressure = false;
    let mut line_count: u64 = 0;
    let mut total_bytes: usize = 0;
    let mut peer_hostname: Option<String> = None;
    let started = Instant::now();
    let close_reason = loop {
        // Idle timeout: if no data arrives within idle_timeout_secs, drop the connection.
        // This is an idle (per-read) timeout, not a wall-clock timeout, so
        // persistent forwarders sending continuous messages are never killed.
        let next = tokio::time::timeout(
            tokio::time::Duration::from_secs(idle_timeout_secs),
            lines.next_line(),
        );
        match next.await {
            Ok(Ok(Some(line))) => {
                if line.is_empty() {
                    continue;
                }
                if line.len() > max_size {
                    warn!(
                        peer = %addr,
                        line_count,
                        line_bytes = line.len(),
                        max_message_size = max_size,
                        "Dropping oversized TCP syslog line"
                    );
                    continue;
                }
                line_count += 1;
                total_bytes += line.len();
                // Log backpressure only on state transitions.
                let at_capacity = tx.capacity() == 0;
                if at_capacity && !backpressure {
                    warn!(
                        peer = %addr,
                        queue_depth = queue_depth(&tx),
                        channel_capacity = WRITE_CHANNEL_CAPACITY,
                        line_count,
                        "syslog write channel full — backpressure applied"
                    );
                    backpressure = true;
                } else if !at_capacity && backpressure {
                    info!(
                        peer = %addr,
                        queue_depth = queue_depth(&tx),
                        channel_capacity = WRITE_CHANNEL_CAPACITY,
                        line_count,
                        "syslog write channel cleared — backpressure lifted"
                    );
                    backpressure = false;
                }
                debug!(
                    peer = %addr,
                    line_count,
                    line_bytes = line.len(),
                    queue_depth = queue_depth(&tx),
                    "TCP syslog line received"
                );
                let entry = parse_syslog(&line, addr.to_string());
                if peer_hostname.is_none() {
                    peer_hostname = Some(entry.hostname.clone());
                    info!(
                        peer = %addr,
                        hostname = %entry.hostname,
                        source_ip = %source_addr_ip(&entry.source_ip),
                        "TCP syslog sender identified"
                    );
                }
                if tx.send(entry).await.is_err() {
                    break "write_channel_closed";
                }
            }
            Ok(Ok(None)) => break "eof",
            Ok(Err(e)) => {
                error!(peer = %addr, error = %e, "TCP syslog read error");
                break "read_error";
            }
            Err(_) => {
                warn!(peer = %addr, idle_timeout_secs, "TCP syslog connection timed out");
                break "idle_timeout";
            }
        }
    };
    info!(
        peer = %addr,
        hostname = peer_hostname.as_deref().unwrap_or("unknown"),
        close_reason,
        line_count,
        total_bytes,
        elapsed_ms = started.elapsed().as_millis(),
        "TCP syslog connection closed"
    );
}

/// TCP syslog receiver (newline-delimited).
///
/// Caps concurrent connections at `max_connections` via a semaphore; each
/// connection is subject to an `idle_timeout_secs` idle timeout (per read)
/// to evict zombie connections.
async fn tcp_listener(
    bind: &str,
    tx: mpsc::Sender<db::LogBatchEntry>,
    max_size: usize,
    max_connections: usize,
    idle_timeout_secs: u64,
) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %bind, max_connections, idle_timeout_secs, "TCP syslog listener bound");
    let sem = Arc::new(Semaphore::new(max_connections));
    let mut accept_backoff_ms: u64 = 100;
    let mut reject_logged = false;
    let mut last_reject_log = std::time::Instant::now();
    let mut total_rejected: u64 = 0;

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                accept_backoff_ms = 100; // reset on success
                match Arc::clone(&sem).try_acquire_owned() {
                    Ok(permit) => {
                        let available_permits = sem.available_permits();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_tcp_connection(stream, addr, tx, max_size, idle_timeout_secs)
                                .await;
                        });
                        debug!(
                            peer = %addr,
                            active_connections = max_connections.saturating_sub(available_permits),
                            max_connections,
                            "TCP syslog connection dispatched"
                        );
                    }
                    Err(tokio::sync::TryAcquireError::NoPermits) => {
                        total_rejected += 1;
                        // Emit warn! only on first rejection and once per 10 seconds
                        // thereafter to avoid log storms under connection floods.
                        if !reject_logged
                            || last_reject_log.elapsed() >= std::time::Duration::from_secs(10)
                        {
                            warn!(
                                peer = %addr,
                                max_connections,
                                total_rejected,
                                "TCP connection limit reached — rejecting connection"
                            );
                            reject_logged = true;
                            last_reject_log = std::time::Instant::now();
                        }
                        // stream is dropped here, closing the connection
                    }
                    Err(tokio::sync::TryAcquireError::Closed) => {
                        error!(
                            "TCP connection semaphore unexpectedly closed — TCP listener exiting"
                        );
                        break;
                    }
                }
            }
            Err(e) => {
                error!(error = %e, accept_backoff_ms, "TCP accept error");
                // Exponential backoff: double each time, cap at 5s, reset on success.
                tokio::time::sleep(tokio::time::Duration::from_millis(accept_backoff_ms)).await;
                accept_backoff_ms = (accept_backoff_ms * 2).min(5000);
                continue;
            }
        }
    }
    Ok(())
}

/// Batch writer — collects messages and writes in batches for throughput
async fn batch_writer(
    mut rx: mpsc::Receiver<db::LogBatchEntry>,
    pool: Arc<DbPool>,
    storage: StorageConfig,
    storage_state: Arc<Mutex<Option<db::StorageBudgetState>>>,
    batch_size: usize,
    flush_interval: tokio::time::Duration,
) {
    let mut batch: Vec<db::LogBatchEntry> = Vec::with_capacity(batch_size);
    let mut storage_blocked = false;
    let mut summary = IngestSummary::default();
    let mut summary_deadline = tokio::time::Instant::now()
        + tokio::time::Duration::from_secs(INGEST_SUMMARY_INTERVAL_SECS);
    info!(
        batch_size,
        flush_interval_ms = flush_interval.as_millis(),
        "Batch writer started"
    );

    loop {
        let deadline = tokio::time::sleep(flush_interval);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(parsed) => {
                            batch.push(parsed);
                            debug!(
                                batch_len = batch.len(),
                                queue_depth = rx.max_capacity().saturating_sub(rx.capacity()),
                                queue_capacity = rx.max_capacity(),
                                "Queued parsed syslog entry"
                            );
                            if !batch.is_empty() && batch.len() % batch_size == 0 {
                                break;
                            }
                        }
                        None => {
                            // Channel closed, flush remaining
                            if !batch.is_empty() {
                                flush_batch(
                                    &pool,
                                    &storage,
                                    &storage_state,
                                    &mut batch,
                                    &mut storage_blocked,
                                    &mut summary,
                                )
                                .await;
                            }
                            emit_ingest_summary(&mut summary);
                            info!("Write channel closed, exiting batch writer");
                            return;
                        }
                    }
                }
                _ = &mut deadline => {
                    break;
                }
            }
        }

        if !batch.is_empty() {
            flush_batch(
                &pool,
                &storage,
                &storage_state,
                &mut batch,
                &mut storage_blocked,
                &mut summary,
            )
            .await;
        }

        if tokio::time::Instant::now() >= summary_deadline {
            emit_ingest_summary(&mut summary);
            summary_deadline = tokio::time::Instant::now()
                + tokio::time::Duration::from_secs(INGEST_SUMMARY_INTERVAL_SECS);
        }
    }
}

async fn flush_batch(
    pool: &Arc<DbPool>,
    storage: &StorageConfig,
    storage_state: &Arc<Mutex<Option<db::StorageBudgetState>>>,
    batch: &mut Vec<db::LogBatchEntry>,
    storage_blocked: &mut bool,
    summary: &mut IngestSummary,
) {
    let pool = Arc::clone(pool);
    let batch_to_write = std::mem::take(batch);
    let count = batch_to_write.len();
    let started = Instant::now();
    debug!(count, "Attempting batch flush");
    let enforcement = storage_state
        .lock()
        .expect("storage state mutex poisoned")
        .clone();
    if let Some(state) = enforcement {
        if state.write_blocked {
            let err = anyhow::anyhow!(
                "storage budget exceeded: logical_db_size_bytes={}, free_disk_bytes={:?}",
                state.metrics.logical_db_size_bytes,
                state.metrics.free_disk_bytes
            );
            if !*storage_blocked {
                error!(
                    error = %err,
                    count,
                    retained_batch = batch_to_write.len(),
                    elapsed_ms = started.elapsed().as_millis(),
                    max_db_size_mb = storage.max_db_size_mb,
                    min_free_disk_mb = storage.min_free_disk_mb,
                    "Storage budget exceeded — retaining batch until space recovers"
                );
                *storage_blocked = true;
            }
            *batch = batch_to_write;
            tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
            return;
        }
    }
    match tokio::task::spawn_blocking(
        move || match db::insert_logs_batch(&pool, &batch_to_write) {
            Ok(n) => Ok((n, batch_to_write)),
            Err(e) => Err((e, batch_to_write, false)),
        },
    )
    .await
    {
        Ok(Ok((n, inserted_batch))) => {
            summary.record_batch(&inserted_batch[..n.min(inserted_batch.len())]);
            if *storage_blocked {
                info!(
                    count = n,
                    elapsed_ms = started.elapsed().as_millis(),
                    "storage budget recovered — writes resumed"
                );
                *storage_blocked = false;
            }
            debug!(
                count = n,
                elapsed_ms = started.elapsed().as_millis(),
                "Flushed log batch"
            );
        }
        Ok(Err((e, failed_batch, blocked_by_storage))) => {
            // Cap retained batch to prevent unbounded growth on persistent write failures
            if failed_batch.len() < 1000 {
                if blocked_by_storage {
                    if !*storage_blocked {
                        error!(
                            error = %e,
                            count,
                            retained_batch = failed_batch.len(),
                            elapsed_ms = started.elapsed().as_millis(),
                            "Storage budget exceeded — retaining batch until space recovers"
                        );
                        *storage_blocked = true;
                    }
                } else {
                    error!(
                        error = %e,
                        count,
                        retained_batch = failed_batch.len(),
                        elapsed_ms = started.elapsed().as_millis(),
                        "Failed to flush log batch — retaining for next flush"
                    );
                }
                *batch = failed_batch;
                // Brief pause before the next flush attempt to avoid hammering a failing DB
                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
            } else {
                error!(
                    error = %e,
                    count,
                    retained_batch = failed_batch.len(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "Failed to flush log batch — batch too large to retain, discarding"
                );
            }
        }
        Err(e) => {
            // spawn_blocking panicked — batch is unrecoverable
            error!(
                error = %e,
                count,
                elapsed_ms = started.elapsed().as_millis(),
                "spawn_blocking panicked during flush — batch discarded"
            );
        }
    }
}

fn queue_depth<T>(tx: &mpsc::Sender<T>) -> usize {
    WRITE_CHANNEL_CAPACITY.saturating_sub(tx.capacity())
}

#[derive(Default)]
struct IngestSummary {
    total_logs: usize,
    host_counts: HashMap<String, usize>,
    source_ip_counts: HashMap<String, usize>,
    sender_counts: HashMap<(String, String), usize>,
}

impl IngestSummary {
    fn record_batch(&mut self, entries: &[db::LogBatchEntry]) {
        self.total_logs += entries.len();
        for entry in entries {
            *self.host_counts.entry(entry.hostname.clone()).or_insert(0) += 1;
            let source_ip = source_addr_ip(&entry.source_ip);
            *self.source_ip_counts.entry(source_ip.clone()).or_insert(0) += 1;
            *self
                .sender_counts
                .entry((entry.hostname.clone(), source_ip))
                .or_insert(0) += 1;
        }
    }

    fn reset(&mut self) {
        self.total_logs = 0;
        self.host_counts.clear();
        self.source_ip_counts.clear();
        self.sender_counts.clear();
    }
}

fn emit_ingest_summary(summary: &mut IngestSummary) {
    if summary.total_logs == 0 {
        return;
    }

    let top_senders = summarize_top_senders(&summary.sender_counts, 5);
    info!(
        interval_secs = INGEST_SUMMARY_INTERVAL_SECS,
        total_logs = summary.total_logs,
        unique_hosts = summary.host_counts.len(),
        unique_source_ips = summary.source_ip_counts.len(),
        top_senders = %top_senders,
        "Syslog ingest summary"
    );
    summary.reset();
}

fn summarize_top_senders(counts: &HashMap<(String, String), usize>, limit: usize) -> String {
    let mut entries: Vec<_> = counts.iter().collect();
    entries.sort_by(|a, b| {
        b.1.cmp(a.1)
            .then_with(|| a.0 .0.cmp(&b.0 .0))
            .then_with(|| a.0 .1.cmp(&b.0 .1))
    });
    entries
        .into_iter()
        .take(limit)
        .map(|((host, source_ip), count)| format!("{host}@{source_ip}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn source_addr_ip(source_addr: &str) -> String {
    source_addr
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| source_addr.to_string())
}

/// Truncate a string to at most `max` bytes, respecting UTF-8 char boundaries.
fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    // Walk back from `max` to find a valid char boundary.
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Returns true if `s` looks like an ISO 8601 timestamp (YYYY-MM-DDTHH:…).
/// UniFi OS incorrectly puts a timestamp in the syslog hostname field.
///
/// Validates separator positions AND digit positions to avoid false positives
/// on strings that happen to have `-` and `T` at the right offsets.
fn looks_like_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2].is_ascii_digit()
        && b[3].is_ascii_digit()
        && b[5].is_ascii_digit()
        && b[6].is_ascii_digit()
        && b[8].is_ascii_digit()
        && b[9].is_ascii_digit()
}

/// Extract a single value from a CEF extension string (`key1=val1 key2=val2 …`).
///
/// Values may contain spaces; the next `WORD=` boundary (a space followed by a word
/// containing no spaces and then `=`) terminates the current value.
fn cef_ext_value(extensions: &str, key: &str) -> Option<String> {
    // Match only at the start of the string or after a space (word boundary).
    // Avoid format! allocations: check starts_with("key=") directly, then scan
    // for " key=" using manual byte search on the raw string slice.
    let key_eq_len = key.len() + 1; // length of "key="
    let start =
        if extensions.starts_with(key) && extensions.as_bytes().get(key.len()) == Some(&b'=') {
            key_eq_len
        } else {
            // Find " key=" without allocating: search for ' ' then check the slice after it
            let bytes = extensions.as_bytes();
            let key_bytes = key.as_bytes();
            let mut found = None;
            let mut i = 0;
            while i + key_eq_len < bytes.len() {
                if bytes[i] == b' '
                    && bytes[i + 1..].starts_with(key_bytes)
                    && bytes.get(i + 1 + key.len()) == Some(&b'=')
                {
                    found = Some(i + 1 + key_eq_len);
                    break;
                }
                i += 1;
            }
            found?
        };
    let rest = &extensions[start..];

    let mut end = rest.len();
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b' ' {
            let after = &rest[i + 1..];
            if let Some(eq) = after.find('=') {
                // It's a key boundary only if there are no spaces before the '='
                if !after[..eq].contains(' ') {
                    end = i;
                    break;
                }
            }
        }
        i += 1;
    }

    let value = rest[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Parsed fields extracted from a CEF syslog message.
struct CefFields {
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub message: Option<String>,
}

/// Extract hostname, app_name, and message from a reconstructed CEF syslog body.
///
/// `text` is `app_name_fragment + " " + message_body` as produced by syslog_loose
/// when parsing a UniFi CEF message. The function finds the embedded `CEF:` block,
/// parses the pipe-delimited header, and extracts extension fields.
///
/// Returns a `CefFields` with:
/// - hostname  : `UNIFIdeviceName` extension value; falls back to CEF Device Product (field 2)
/// - app_name  : CEF event name (field 5, e.g. "Test Syslog", "Admin Made Config Changes")
/// - message   : `msg` extension value; falls back to the full CEF string
fn extract_cef_fields(text: &str) -> CefFields {
    let cef_pos = match text.find("CEF:") {
        Some(p) => p,
        None => {
            return CefFields {
                hostname: None,
                app_name: None,
                message: None,
            }
        }
    };

    let cef_str = &text[cef_pos..];
    // CEF header has exactly 8 pipe-delimited fields; splitn keeps the rest in field 7
    let parts: Vec<&str> = cef_str.splitn(8, '|').collect();
    if parts.len() < 8 {
        return CefFields {
            hostname: None,
            app_name: None,
            message: None,
        };
    }

    let event_name = parts[5].to_string();
    let extensions = parts[7];

    let hostname =
        cef_ext_value(extensions, "UNIFIdeviceName").or_else(|| Some(parts[2].to_string())); // fallback: CEF Device Product

    let message = cef_ext_value(extensions, "msg").unwrap_or_else(|| cef_str.to_string());

    CefFields {
        hostname,
        app_name: Some(event_name),
        message: Some(message),
    }
}

/// Parse a raw syslog message (RFC 3164 / RFC 5424 / loose).
///
/// Handles UniFi CEF messages where the hostname field contains a timestamp
/// and the real device name is embedded in the CEF extension `UNIFIdeviceName`.
///
/// `source_ip` is the actual network sender address (e.g. "192.168.1.10:514"),
/// recorded separately from the hostname claimed in the message body.
fn parse_syslog(raw: &str, source_ip: String) -> db::LogBatchEntry {
    let msg = syslog_loose::parse_message(raw, syslog_loose::Variant::Either);

    let severity_num = msg.severity.map(|s| s as u8).unwrap_or(6); // default info
    let facility_num = msg.facility.map(|f| f as u8);

    let severity = db::SEVERITY_LEVELS
        .get(severity_num as usize)
        .unwrap_or(&"info")
        .to_string();

    let facility = facility_num.and_then(|f| FACILITIES.get(f as usize).map(|s| s.to_string()));

    let timestamp = msg
        .timestamp
        .map(|dt| dt.with_timezone(&Utc).to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let raw_hostname = msg.hostname.map(|h| h.to_string()).unwrap_or_default();
    let raw_app_name = msg.appname.map(|a| a.to_string());
    let process_id = msg.procid.map(|p| match p {
        syslog_loose::ProcId::PID(n) => n.to_string(),
        syslog_loose::ProcId::Name(s) => s.to_string(),
    });
    let raw_message = msg.msg.to_string();

    // ── Format dispatch ────────────────────────────────────────────────────────
    // This is the extension point for vendor-specific syslog formats.
    //
    // Contract for every branch:
    //   • hostname  — the logical device name (String, non-empty; fall back to
    //                 raw_hostname or "unknown" when the format provides none)
    //   • app_name  — the originating process / event category (Option<String>)
    //   • message   — the human-readable log body (String, non-empty)
    //
    // Field precedence rule:
    //   Vendor-specific fields extracted from the message body OVERRIDE the
    //   values parsed from the syslog header (raw_hostname, raw_app_name,
    //   raw_message). The syslog header is used only as a fallback when the
    //   vendor format does not supply a value.
    //
    // To add a new vendor format (e.g. Fortinet, Cisco, Palo Alto CEF):
    //   1. Add a detector function analogous to looks_like_timestamp().
    //   2. Add a field-extractor function analogous to extract_cef_fields().
    //   3. Add an `else if <detector>` branch here that calls your extractor
    //      and returns (hostname, app_name, message) following the contract.
    //   4. The final `else` branch is the standard RFC 3164/5424 path and must
    //      remain the last arm — it handles all unrecognised messages.
    // ───────────────────────────────────────────────────────────────────────────
    let (hostname, app_name, message) = if looks_like_timestamp(&raw_hostname)
        && (raw_app_name.as_deref().unwrap_or("").contains("CEF:") || raw_message.contains("CEF:"))
    {
        // SECURITY NOTE: The hostname stored here is extracted from the CEF message
        // body (UNIFIdeviceName extension field), NOT validated against the network
        // source. Any LAN device can craft a CEF message with an arbitrary
        // UNIFIdeviceName and impersonate a legitimate host. `source_ip` is the
        // only trustworthy identity — it reflects the actual network sender address
        // recorded by the OS at socket accept time and cannot be spoofed by message
        // content.
        //
        // Reconstruct full_text only for CEF messages (syslog_loose splits
        // "The Mothership CEF:…" across app_name and message for UniFi RFC 5424).
        let full_text = match &raw_app_name {
            Some(app) => format!("{app} {raw_message}"),
            None => raw_message.clone(),
        };
        let cef = extract_cef_fields(&full_text);
        if cef.hostname.is_none() && cef.app_name.is_none() && cef.message.is_none() {
            let preview = &full_text[..full_text.len().min(200)];
            warn!(msg = preview, "CEF heuristic triggered but all fields are None — malformed CEF body, using raw fallback");
        }
        // When the CEF-extracted hostname differs from the syslog-header hostname,
        // emit a debug log to aid forensic analysis. A mismatch is normal for
        // UniFi (header has a timestamp), but an unexpected mismatch from a device
        // that does not put a timestamp in the header may indicate spoofing.
        if let Some(ref cef_host) = cef.hostname {
            if !raw_hostname.is_empty() && cef_host != &raw_hostname {
                debug!(
                    cef_hostname = %cef_host,
                    syslog_header_hostname = %raw_hostname,
                    source_ip = %source_ip,
                    "CEF hostname differs from syslog-header hostname; \
                     CEF value is from message content and is not network-verified"
                );
            }
        }
        (
            truncate(&cef.hostname.unwrap_or_else(|| raw_hostname.clone()), 255).to_string(),
            cef.app_name
                .or(raw_app_name)
                .map(|s| truncate(&s, 128).to_string()),
            truncate(&cef.message.unwrap_or(raw_message), 8192).to_string(),
        )
    } else {
        let hostname = if raw_hostname.is_empty() {
            "unknown".to_string()
        } else {
            raw_hostname
        };
        (hostname, raw_app_name, raw_message)
    };

    db::LogBatchEntry {
        timestamp,
        hostname,
        facility,
        severity,
        app_name,
        process_id,
        message,
        raw: raw.to_string(),
        source_ip,
    }
}

#[cfg(test)]
#[path = "syslog_tests.rs"]
mod tests;
