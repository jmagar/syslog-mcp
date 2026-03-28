use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::SyslogConfig;
use crate::db::{self, DbPool};

/// Syslog severity levels (RFC 5424)
const SEVERITIES: &[&str] = &[
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

/// Syslog facility names (RFC 5424)
const FACILITIES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

/// Parsed syslog message ready for storage
#[derive(Debug)]
struct ParsedLog {
    timestamp: String,
    hostname: String,
    facility: Option<String>,
    severity: String,
    app_name: Option<String>,
    process_id: Option<String>,
    message: String,
    raw: String,
}

/// Start syslog listeners (UDP + TCP) and the write batcher
pub async fn start(config: SyslogConfig, pool: Arc<DbPool>) -> Result<()> {
    let (tx, rx) = mpsc::channel::<ParsedLog>(10_000);

    // Spawn the batched writer
    let writer_pool = pool.clone();
    tokio::spawn(async move {
        batch_writer(rx, writer_pool).await;
    });

    // Spawn UDP listener
    let udp_tx = tx.clone();
    let udp_bind = config.udp_bind.clone();
    let max_size = config.max_message_size;
    tokio::spawn(async move {
        if let Err(e) = udp_listener(&udp_bind, max_size, udp_tx).await {
            error!(error = %e, "UDP syslog listener failed");
        }
    });

    // Spawn TCP listener
    let tcp_tx = tx.clone();
    let tcp_bind = config.tcp_bind.clone();
    tokio::spawn(async move {
        if let Err(e) = tcp_listener(&tcp_bind, tcp_tx).await {
            error!(error = %e, "TCP syslog listener failed");
        }
    });

    info!(
        udp = %config.udp_bind,
        tcp = %config.tcp_bind,
        "Syslog listeners started"
    );

    Ok(())
}

/// UDP syslog receiver
async fn udp_listener(bind: &str, max_size: usize, tx: mpsc::Sender<ParsedLog>) -> Result<()> {
    let socket = UdpSocket::bind(bind).await?;
    info!(bind = %bind, "UDP syslog listener bound");

    let mut buf = vec![0u8; max_size];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, addr)) => {
                let raw = String::from_utf8_lossy(&buf[..len]).to_string();
                debug!(src = %addr, len, "UDP syslog received");

                if tx.capacity() == 0 {
                    warn!("syslog write channel full — backpressure applied");
                }
                if tx.send(parse_syslog(&raw)).await.is_err() {
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

/// TCP syslog receiver (newline-delimited, octet-counting)
async fn tcp_listener(bind: &str, tx: mpsc::Sender<ParsedLog>) -> Result<()> {
    let listener = TcpListener::bind(bind).await?;
    info!(bind = %bind, "TCP syslog listener bound");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    info!(peer = %addr, "TCP syslog connection accepted");
                    let reader = BufReader::new(stream);
                    let mut lines = reader.lines();

                    loop {
                        match lines.next_line().await {
                            Ok(Some(line)) => {
                                if line.is_empty() {
                                    continue;
                                }
                                if tx.capacity() == 0 {
                                    warn!(peer = %addr, "syslog write channel full — backpressure applied");
                                }
                                if tx.send(parse_syslog(&line)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(None) => break, // clean EOF
                            Err(e) => {
                                error!(peer = %addr, error = %e, "TCP syslog read error");
                                break;
                            }
                        }
                    }
                    info!(peer = %addr, "TCP syslog connection closed");
                });
            }
            Err(e) => {
                error!(error = %e, "TCP accept error");
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Batch writer — collects messages and writes in batches for throughput
async fn batch_writer(mut rx: mpsc::Receiver<ParsedLog>, pool: Arc<DbPool>) {
    let batch_size = 100;
    let flush_interval = tokio::time::Duration::from_millis(500);

    let mut batch: Vec<db::LogBatchEntry> = Vec::with_capacity(batch_size);

    loop {
        let deadline = tokio::time::sleep(flush_interval);
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(parsed) => {
                            batch.push((
                                parsed.timestamp,
                                parsed.hostname,
                                parsed.facility,
                                parsed.severity,
                                parsed.app_name,
                                parsed.process_id,
                                parsed.message,
                                parsed.raw,
                            ));
                            if batch.len() >= batch_size {
                                break;
                            }
                        }
                        None => {
                            // Channel closed, flush remaining
                            if !batch.is_empty() {
                                flush_batch(&pool, &mut batch).await;
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
            flush_batch(&pool, &mut batch).await;
        }
    }
}

async fn flush_batch(
    pool: &Arc<DbPool>,
    batch: &mut Vec<db::LogBatchEntry>,
) {
    let pool = Arc::clone(pool);
    let batch_to_write = std::mem::take(batch);
    let count = batch_to_write.len();
    match tokio::task::spawn_blocking(move || {
        // Return the batch back on error so the caller can retain it for the next flush
        match db::insert_logs_batch(&pool, &batch_to_write) {
            Ok(n) => Ok(n),
            Err(e) => Err((e, batch_to_write)),
        }
    })
    .await
    {
        Ok(Ok(n)) => {
            debug!(count = n, "Flushed log batch");
        }
        Ok(Err((e, failed_batch))) => {
            error!(error = %e, count, "Failed to flush log batch — retaining for next flush");
            *batch = failed_batch;
        }
        Err(e) => {
            // spawn_blocking panicked — batch is unrecoverable
            error!(error = %e, count, "spawn_blocking panicked during flush — batch discarded");
        }
    }
}

/// Parse a raw syslog message (RFC 3164 / RFC 5424 / loose)
fn parse_syslog(raw: &str) -> ParsedLog {
    let msg = syslog_loose::parse_message(raw, syslog_loose::Variant::Either);

    let severity_num = msg.severity.map(|s| s as u8).unwrap_or(6); // default to info
    let facility_num = msg.facility.map(|f| f as u8);

    let severity = SEVERITIES
        .get(severity_num as usize)
        .unwrap_or(&"info")
        .to_string();

    let facility = facility_num.and_then(|f| FACILITIES.get(f as usize).map(|s| s.to_string()));

    let timestamp = msg
        .timestamp
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let hostname = msg
        .hostname
        .map(|h| h.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let app_name = msg.appname.map(|a| a.to_string());
    let process_id = msg.procid.map(|p| match p {
        syslog_loose::ProcId::PID(n) => n.to_string(),
        syslog_loose::ProcId::Name(s) => s.to_string(),
    });

    ParsedLog {
        timestamp,
        hostname,
        facility,
        severity,
        app_name,
        process_id,
        message: msg.msg.to_string(),
        raw: raw.to_string(),
    }
}
