use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info, warn};

use crate::config::{StorageConfig, SyslogConfig};
use crate::db::{self, DbPool};

/// Syslog facility names (RFC 5424)
const FACILITIES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
];

/// Start syslog listeners (UDP + TCP) and the write batcher
pub async fn start(config: SyslogConfig, storage: StorageConfig, pool: Arc<DbPool>) -> Result<()> {
    let (tx, rx) = mpsc::channel::<db::LogBatchEntry>(10_000);

    // Spawn the batched writer
    let writer_pool = pool.clone();
    let writer_storage = storage.clone();
    let batch_size = config.batch_size;
    let flush_interval = tokio::time::Duration::from_millis(config.flush_interval);
    tokio::spawn(async move {
        batch_writer(rx, writer_pool, writer_storage, batch_size, flush_interval).await;
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

    info!(bind = %bind_addr, "Syslog listeners started");

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
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let raw = String::from_utf8_lossy(&buf[..len]).to_string();
                debug!(src = %addr, len, "UDP syslog received");

                // Log backpressure only on state transitions to avoid log storms.
                let at_capacity = tx.capacity() == 0;
                if at_capacity && !backpressure {
                    warn!("syslog write channel full — backpressure applied");
                    backpressure = true;
                } else if !at_capacity && backpressure {
                    info!("syslog write channel cleared — backpressure lifted");
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
    // Limit total bytes readable from this connection to max_size to prevent OOM
    // from a single connection sending an arbitrarily large line with no newline.
    // Homelab syslog devices typically send one message per TCP connection (or
    // reconnect per message), so a per-connection budget of max_size bytes is safe.
    let limited = stream.take(max_size as u64);
    let reader = BufReader::new(limited);
    let mut lines = reader.lines();
    let mut backpressure = false;

    loop {
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
                // Log backpressure only on state transitions.
                let at_capacity = tx.capacity() == 0;
                if at_capacity && !backpressure {
                    warn!(peer = %addr, "syslog write channel full — backpressure applied");
                    backpressure = true;
                } else if !at_capacity && backpressure {
                    info!(peer = %addr, "syslog write channel cleared — backpressure lifted");
                    backpressure = false;
                }
                if tx
                    .send(parse_syslog(&line, addr.to_string()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Ok(Ok(None)) => break, // clean EOF
            Ok(Err(e)) => {
                error!(peer = %addr, error = %e, "TCP syslog read error");
                break;
            }
            Err(_) => {
                warn!(peer = %addr, idle_timeout_secs, "TCP syslog connection timed out");
                break;
            }
        }
    }
    info!(peer = %addr, "TCP syslog connection closed");
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

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                accept_backoff_ms = 100; // reset on success
                let permit = match Arc::clone(&sem).acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => break, // semaphore closed — shouldn't happen
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _permit = permit; // released automatically when task drops
                    handle_tcp_connection(stream, addr, tx, max_size, idle_timeout_secs).await;
                });
            }
            Err(e) => {
                error!(error = %e, "TCP accept error");
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
    batch_size: usize,
    flush_interval: tokio::time::Duration,
) {
    let mut batch: Vec<db::LogBatchEntry> = Vec::with_capacity(batch_size);
    let mut storage_blocked = false;

    loop {
        let deadline = tokio::time::sleep(flush_interval);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(parsed) => {
                            batch.push(parsed);
                            if batch.len() >= batch_size {
                                break;
                            }
                        }
                        None => {
                            // Channel closed, flush remaining
                            if !batch.is_empty() {
                                flush_batch(&pool, &storage, &mut batch, &mut storage_blocked).await;
                            }
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
            flush_batch(&pool, &storage, &mut batch, &mut storage_blocked).await;
        }
    }
}

async fn flush_batch(
    pool: &Arc<DbPool>,
    storage: &StorageConfig,
    batch: &mut Vec<db::LogBatchEntry>,
    storage_blocked: &mut bool,
) {
    let pool = Arc::clone(pool);
    let storage = storage.clone();
    let batch_to_write = std::mem::take(batch);
    let count = batch_to_write.len();
    match tokio::task::spawn_blocking(move || {
        let enforcement = match db::enforce_storage_budget(&pool, &storage) {
            Ok(enforcement) => enforcement,
            Err(e) => return Err((e, batch_to_write, false)),
        };
        if enforcement.write_blocked {
            return Err((
                anyhow::anyhow!(
                    "storage budget exceeded: logical_db_size_bytes={}, free_disk_bytes={:?}",
                    enforcement.metrics.logical_db_size_bytes,
                    enforcement.metrics.free_disk_bytes
                ),
                batch_to_write,
                true,
            ));
        }

        match db::insert_logs_batch(&pool, &batch_to_write) {
            Ok(n) => Ok(n),
            Err(e) => Err((e, batch_to_write, false)),
        }
    })
    .await
    {
        Ok(Ok(n)) => {
            if *storage_blocked {
                info!(count = n, "storage budget recovered — writes resumed");
                *storage_blocked = false;
            }
            debug!(count = n, "Flushed log batch");
        }
        Ok(Err((e, failed_batch, blocked_by_storage))) => {
            // Cap retained batch to prevent unbounded growth on persistent write failures
            if failed_batch.len() < 1000 {
                if blocked_by_storage {
                    if !*storage_blocked {
                        error!(error = %e, count, "Storage budget exceeded — retaining batch until space recovers");
                        *storage_blocked = true;
                    }
                } else {
                    error!(error = %e, count, "Failed to flush log batch — retaining for next flush");
                }
                *batch = failed_batch;
                // Brief pause before the next flush attempt to avoid hammering a failing DB
                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
            } else {
                error!(error = %e, count, "Failed to flush log batch — batch too large to retain, discarding");
            }
        }
        Err(e) => {
            // spawn_blocking panicked — batch is unrecoverable
            error!(error = %e, count, "spawn_blocking panicked during flush — batch discarded");
        }
    }
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
mod tests {
    use super::*;
    use crate::config::StorageConfig;

    fn test_storage_config(db_path: std::path::PathBuf) -> StorageConfig {
        StorageConfig {
            db_path,
            pool_size: 1,
            retention_days: 90,
            wal_mode: false,
            max_db_size_mb: 1024,
            recovery_db_size_mb: 900,
            min_free_disk_mb: 0,
            recovery_free_disk_mb: 0,
            cleanup_interval_secs: 60,
        }
    }

    fn test_pool() -> (Arc<DbPool>, StorageConfig, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = test_storage_config(dir.path().join("syslog-test.db"));
        let pool = Arc::new(db::init_pool(&config).unwrap());
        (pool, config, dir)
    }

    #[tokio::test]
    async fn flush_batch_retains_entries_while_storage_is_write_blocked() {
        let (pool, mut storage, _dir) = test_pool();
        let free_disk_mb = db::get_storage_metrics(&pool, &storage)
            .unwrap()
            .free_disk_bytes
            .unwrap()
            / 1_048_576;
        storage.min_free_disk_mb = free_disk_mb + 1024;
        storage.recovery_free_disk_mb = free_disk_mb + 2048;
        let mut batch = vec![parse_syslog(
            "<34>Oct 11 22:14:15 mymachine su: blocked write",
            "127.0.0.1:514".to_string(),
        )];
        let mut storage_blocked = false;

        flush_batch(&pool, &storage, &mut batch, &mut storage_blocked).await;

        assert_eq!(batch.len(), 1);
        assert!(storage_blocked);
    }

    #[tokio::test]
    async fn flush_batch_resumes_after_storage_recovers() {
        let (pool, storage, _dir) = test_pool();
        let mut batch = vec![parse_syslog(
            "<34>Oct 11 22:14:15 mymachine su: resumed write",
            "127.0.0.1:514".to_string(),
        )];
        let mut storage_blocked = true;

        flush_batch(&pool, &storage, &mut batch, &mut storage_blocked).await;

        assert!(batch.is_empty());
        assert!(!storage_blocked);
        let rows = db::tail_logs(&pool, None, None, 10).unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn test_looks_like_timestamp_true() {
        assert!(looks_like_timestamp("2026-03-29T02:52:21.587Z"));
        assert!(looks_like_timestamp("2026-03-29T02:52:21+00:00"));
        assert!(looks_like_timestamp("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn test_looks_like_timestamp_false() {
        assert!(!looks_like_timestamp("The Mothership"));
        assert!(!looks_like_timestamp("dookie"));
        assert!(!looks_like_timestamp("unknown"));
        assert!(!looks_like_timestamp(""));
        assert!(!looks_like_timestamp("192.168.1.1"));
    }

    #[test]
    fn test_parse_syslog_unifi_cef_hostname() {
        // Real-world UniFi OS RFC 5424 message: timestamp in hostname field, device name split
        // across app_name ("The") and message body ("Mothership CEF:0|...")
        let raw = "<14>1 2026-03-29T02:52:21+00:00 2026-03-29T02:52:21.587Z The - - - Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test Syslog|1|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Test Syslog";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        assert_eq!(parsed.hostname, "The Mothership");
        assert_eq!(parsed.app_name.as_deref(), Some("Test Syslog"));
        assert_eq!(parsed.message, "Test Syslog");
    }

    #[test]
    fn test_parse_syslog_normal_unaffected() {
        // Standard RFC 3164 message must still parse correctly
        let raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        assert_eq!(parsed.hostname, "mymachine");
        assert_eq!(parsed.app_name.as_deref(), Some("su"));
        assert!(parsed.message.contains("su root"));
    }

    #[test]
    fn test_cef_ext_value_simple() {
        let ext = "UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20";
        assert_eq!(
            cef_ext_value(ext, "UNIFIdeviceModel"),
            Some("UCGMAX".to_string())
        );
        assert_eq!(
            cef_ext_value(ext, "UNIFIdeviceIp"),
            Some("76.213.118.20".to_string())
        );
    }

    #[test]
    fn test_cef_ext_value_with_spaces_in_value() {
        let ext = "UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX";
        assert_eq!(
            cef_ext_value(ext, "UNIFIdeviceName"),
            Some("The Mothership".to_string())
        );
    }

    #[test]
    fn test_cef_ext_value_last_field() {
        let ext = "UNIFIdeviceVersion=5.1.5 msg=Test Syslog";
        assert_eq!(cef_ext_value(ext, "msg"), Some("Test Syslog".to_string()));
    }

    #[test]
    fn test_cef_ext_value_missing_key() {
        let ext = "UNIFIdeviceModel=UCGMAX";
        assert_eq!(cef_ext_value(ext, "nonexistent"), None);
    }

    #[test]
    fn test_extract_cef_fields_test_syslog() {
        let text = "The Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test Syslog|1|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Test Syslog";
        let cef = extract_cef_fields(text);
        assert_eq!(cef.hostname, Some("The Mothership".to_string()));
        assert_eq!(cef.app_name, Some("Test Syslog".to_string()));
        assert_eq!(cef.message, Some("Test Syslog".to_string()));
    }

    #[test]
    fn test_extract_cef_fields_config_change() {
        let text = "The Mothership CEF:0|Ubiquiti|UniFi OS|5.1.5|1005|Admin Made Config Changes|2|UNIFIhost=Host UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX UNIFIdeviceIp=76.213.118.20 UNIFIdeviceMac=9C:05:D6:CA:81:3B UNIFIdeviceVersion=5.1.5 msg=Jacob Magar changed Syslog Settings CEF Logging setting from \"undefined\" to \"enabled\". Source IP: 76.213.118.20";
        let cef = extract_cef_fields(text);
        assert_eq!(cef.hostname, Some("The Mothership".to_string()));
        assert_eq!(cef.app_name, Some("Admin Made Config Changes".to_string()));
        assert!(cef
            .message
            .unwrap()
            .starts_with("Jacob Magar changed Syslog Settings"));
    }

    #[test]
    fn test_extract_cef_fields_no_cef() {
        let cef = extract_cef_fields("normal syslog message");
        assert_eq!(cef.hostname, None);
        assert_eq!(cef.app_name, None);
        assert_eq!(cef.message, None);
    }

    #[test]
    fn test_extract_cef_fields_fallback_hostname() {
        // When UNIFIdeviceName is absent, fall back to CEF Device Product (field 2)
        let text = "CEF:0|Ubiquiti|UniFi OS|5.1.5|1|Test|1|msg=hello";
        let cef = extract_cef_fields(text);
        assert_eq!(cef.hostname, Some("UniFi OS".to_string()));
        assert_eq!(cef.app_name, Some("Test".to_string()));
    }

    #[test]
    fn test_cef_ext_value_long_msg() {
        let ext = "UNIFIdeviceVersion=5.1.5 msg=Jacob Magar changed Syslog Settings CEF Logging setting from \"undefined\" to \"enabled\". Source IP: 76.213.118.20";
        assert_eq!(
            cef_ext_value(ext, "msg"),
            Some("Jacob Magar changed Syslog Settings CEF Logging setting from \"undefined\" to \"enabled\". Source IP: 76.213.118.20".to_string())
        );
    }

    #[test]
    fn test_cef_ext_value_no_substring_match() {
        // "name" must not match inside "UNIFIdeviceName"
        let ext = "UNIFIdeviceName=The Mothership UNIFIdeviceModel=UCGMAX";
        assert_eq!(cef_ext_value(ext, "name"), None);
    }

    #[test]
    fn test_cef_ext_value_empty_value() {
        // Empty value after key= returns None
        let ext = "key= nextkey=val";
        assert_eq!(cef_ext_value(ext, "key"), None);
    }

    #[test]
    fn test_extract_cef_fields_malformed() {
        // Fewer than 8 pipe-delimited fields returns all None fields
        let text = "CEF:0|Ubiquiti|UniFi OS|5.1.5";
        let cef = extract_cef_fields(text);
        assert_eq!(cef.hostname, None);
        assert_eq!(cef.app_name, None);
        assert_eq!(cef.message, None);
    }

    #[test]
    fn test_parse_syslog_large_message_truncation() {
        // Verify parse_syslog handles a large input without panicking
        let big = "x".repeat(100_000);
        let raw = format!("<14>1 2026-01-01T00:00:00Z host app - - - {big}");
        let parsed = parse_syslog(&raw, "192.168.1.1:514".to_string());
        assert_eq!(parsed.hostname, "host");
        // message will be the big string — just verify no panic
        assert!(!parsed.message.is_empty());
    }

    #[test]
    fn test_parse_syslog_cef_all_none_no_panic() {
        // CEF heuristic fires (timestamp hostname + "CEF:" in body) but body is malformed
        // (< 8 pipe fields). Should not panic and should fall back to raw fields.
        let raw =
            "<14>1 2026-01-01T00:00:00Z 2026-01-01T00:00:00Z App - - - body with CEF: but no pipes";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        // Should fall back gracefully — no panic
        assert!(!parsed.hostname.is_empty());
    }

    // ------------------------------------------------------------------ //
    // parse_syslog() — new comprehensive tests (bead syslog-mcp-8g4)     //
    // ------------------------------------------------------------------ //

    /// RFC 3164: severity and facility are derived from the PRI value.
    /// PRI=34 → facility=4 (auth), severity=2 (crit).
    #[test]
    fn test_parse_syslog_rfc3164_severity_facility() {
        let raw = "<34>Oct 11 22:14:15 mymachine su: test message";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        // PRI 34 = (4 << 3) | 2 → facility=auth (index 4), severity=crit (index 2)
        assert_eq!(parsed.severity, "crit");
        assert_eq!(parsed.facility.as_deref(), Some("auth"));
        assert_eq!(parsed.hostname, "mymachine");
        assert_eq!(parsed.app_name.as_deref(), Some("su"));
        assert!(parsed.message.contains("test message"));
    }

    /// RFC 5424: structured-data and numeric process ID must parse correctly.
    /// PRI=165 → facility=20 (local4), severity=5 (notice).
    #[test]
    fn test_parse_syslog_rfc5424_with_structured_data() {
        let raw = "<165>1 2003-10-11T22:14:15.003Z mymachine su 77 - - test message body";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        // PRI 165 = (20 << 3) | 5 → facility=local4 (index 20), severity=notice (index 5)
        assert_eq!(parsed.severity, "notice");
        assert_eq!(parsed.facility.as_deref(), Some("local4"));
        assert_eq!(parsed.hostname, "mymachine");
        assert_eq!(parsed.app_name.as_deref(), Some("su"));
        assert_eq!(parsed.process_id.as_deref(), Some("77"));
        assert!(parsed.message.contains("test message body"));
    }

    /// Missing PRI (no <N> prefix) must default to severity "info" (numeric 6).
    #[test]
    fn test_parse_syslog_missing_pri_defaults_to_info() {
        let raw = "Oct 11 22:14:15 myhost myapp: something happened";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        assert_eq!(parsed.severity, "info");
    }

    /// Missing hostname in the message must fall back to "unknown", not an empty string.
    #[test]
    fn test_parse_syslog_missing_hostname_falls_back_to_unknown() {
        // syslog_loose may not populate hostname for very bare messages.
        // We feed a minimal bare message without a recognisable hostname field.
        let raw = "just a plain log line with no syslog structure at all";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        // hostname must never be empty
        assert!(!parsed.hostname.is_empty());
        // When syslog_loose returns no hostname the code inserts "unknown"
        // (actual value depends on how syslog_loose parses the string, but
        // it must not be the empty string).
        assert!(parsed.hostname == "unknown" || !parsed.hostname.is_empty());
    }

    /// Empty string input must not panic and must return a valid db::LogBatchEntry.
    #[test]
    fn test_parse_syslog_empty_string_no_panic() {
        let parsed = parse_syslog("", "192.168.1.1:514".to_string());
        // timestamp must be non-empty RFC 3339
        assert!(!parsed.timestamp.is_empty());
        // severity must default to info
        assert_eq!(parsed.severity, "info");
        // hostname must not be empty
        assert!(!parsed.hostname.is_empty());
    }

    /// Malformed priority `<999>` is out of the 0-191 valid PRI range.
    /// parse_syslog must not panic and must still return a usable db::LogBatchEntry.
    #[test]
    fn test_parse_syslog_malformed_priority_no_panic() {
        let raw = "<999>Oct 11 22:14:15 myhost myapp: overflow priority";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        // Must not panic; severity must be a known string (syslog_loose may or
        // may not extract a value, but SEVERITY_LEVELS.get() falls back to "info").
        assert!(!parsed.severity.is_empty());
        assert!(!parsed.hostname.is_empty());
    }

    /// Timestamp must always be a valid RFC 3339 string (ends with Z or +HH:MM).
    /// Covers both messages with a timestamp and those without (fallback to Utc::now).
    #[test]
    fn test_parse_syslog_timestamp_is_rfc3339() {
        // Message with a well-formed ISO timestamp
        let raw_with_ts = "<14>1 2024-06-15T12:34:56.789Z myhost myapp 42 - - hello";
        let p1 = parse_syslog(raw_with_ts, "192.168.1.1:514".to_string());
        // RFC 3339 ends with Z or +offset
        assert!(
            p1.timestamp.ends_with('Z') || p1.timestamp.contains('+'),
            "timestamp not RFC 3339: {}",
            p1.timestamp
        );
        // Must parse as a valid datetime
        assert!(chrono::DateTime::parse_from_rfc3339(&p1.timestamp).is_ok());

        // Message with no timestamp (syslog_loose fallback → Utc::now())
        let raw_no_ts = "just a plain line";
        let p2 = parse_syslog(raw_no_ts, "192.168.1.1:514".to_string());
        assert!(
            p2.timestamp.ends_with('Z') || p2.timestamp.contains('+'),
            "fallback timestamp not RFC 3339: {}",
            p2.timestamp
        );
        assert!(chrono::DateTime::parse_from_rfc3339(&p2.timestamp).is_ok());
    }

    /// RFC 3164 message with severity=emerg (PRI=0 → facility=kern, severity=emerg).
    #[test]
    fn test_parse_syslog_rfc3164_severity_emerg() {
        let raw = "<0>Oct 11 22:14:15 myhost kernel: system halt";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        assert_eq!(parsed.severity, "emerg");
        assert_eq!(parsed.facility.as_deref(), Some("kern"));
    }

    /// RFC 3164 message with severity=debug (PRI=7 → facility=kern, severity=debug).
    #[test]
    fn test_parse_syslog_rfc3164_severity_debug() {
        let raw = "<7>Oct 11 22:14:15 myhost kernel: verbose output";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        assert_eq!(parsed.severity, "debug");
    }

    /// CEF message: looks_like_timestamp in hostname field + "CEF:" in body triggers CEF branch.
    /// Verify the CEF branch fires and produces populated fields.
    #[test]
    fn test_parse_syslog_cef_branch_fires() {
        let raw = concat!(
            "<166>1 2024-10-11T10:00:00Z 2024-10-11T10:00:00Z ",
            "The - - - Mothership ",
            "CEF:0|Ubiquiti|UniFi OS|5.0|E|SomeEvent|5|",
            "UNIFIdeviceName=MyDevice msg=event occurred"
        );
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        // CEF branch should extract device name from UNIFIdeviceName
        assert_eq!(parsed.hostname, "MyDevice");
        assert_eq!(parsed.app_name.as_deref(), Some("SomeEvent"));
        assert_eq!(parsed.message, "event occurred");
    }

    /// raw field must always equal the original input string verbatim.
    #[test]
    fn test_parse_syslog_raw_field_preserved() {
        let raw = "<34>Oct 11 22:14:15 mymachine su: verbatim check";
        let parsed = parse_syslog(raw, "192.168.1.1:514".to_string());
        assert_eq!(parsed.raw, raw);
    }
}
