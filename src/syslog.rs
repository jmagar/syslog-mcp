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

                if let Some(parsed) = parse_syslog(&raw) {
                    if tx.send(parsed).await.is_err() {
                        error!("Write channel closed");
                        break;
                    }
                } else {
                    warn!(raw = %raw.chars().take(200).collect::<String>(), "Failed to parse syslog message");
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

                    while let Ok(Some(line)) = lines.next_line().await {
                        if line.is_empty() {
                            continue;
                        }
                        if let Some(parsed) = parse_syslog(&line) {
                            if tx.send(parsed).await.is_err() {
                                break;
                            }
                        } else {
                            warn!(raw = %line.chars().take(200).collect::<String>(), "Failed to parse TCP syslog");
                        }
                    }
                    info!(peer = %addr, "TCP syslog connection closed");
                });
            }
            Err(e) => {
                error!(error = %e, "TCP accept error");
            }
        }
    }
}

/// Batch writer — collects messages and writes in batches for throughput
async fn batch_writer(mut rx: mpsc::Receiver<ParsedLog>, pool: Arc<DbPool>) {
    let batch_size = 100;
    let flush_interval = tokio::time::Duration::from_millis(500);

    let mut batch: Vec<(String, String, Option<String>, String, Option<String>, Option<String>, String, String)> =
        Vec::with_capacity(batch_size);

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
                                flush_batch(&pool, &mut batch);
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
            flush_batch(&pool, &mut batch);
        }
    }
}

fn flush_batch(
    pool: &DbPool,
    batch: &mut Vec<(String, String, Option<String>, String, Option<String>, Option<String>, String, String)>,
) {
    match db::insert_logs_batch(pool, batch) {
        Ok(n) => {
            debug!(count = n, "Flushed log batch");
        }
        Err(e) => {
            error!(error = %e, count = batch.len(), "Failed to flush log batch");
        }
    }
    batch.clear();
}

/// Parse a raw syslog message (RFC 3164 / RFC 5424 / loose)
fn parse_syslog(raw: &str) -> Option<ParsedLog> {
    let msg = syslog_loose::parse_message(raw);

    let severity_num = msg.severity.map(|s| s as u8).unwrap_or(6); // default to info
    let facility_num = msg.facility.map(|f| f as u8);

    let severity = SEVERITIES
        .get(severity_num as usize)
        .unwrap_or(&"info")
        .to_string();

    let facility = facility_num.and_then(|f| FACILITIES.get(f as usize).map(|s| s.to_string()));

    let timestamp = msg
        .timestamp
        .map(|ts| match ts {
            syslog_loose::IncompleteDate::Complete(dt) => dt.to_rfc3339(),
            syslog_loose::IncompleteDate::HadYear(dt) => dt.to_rfc3339(),
            syslog_loose::IncompleteDate::HadMonth(dt) => dt.to_rfc3339(),
            syslog_loose::IncompleteDate::HadTimezone(nt) => {
                // No date info, use today's date
                let now = Utc::now().date_naive();
                now.and_time(nt).and_utc().to_rfc3339()
            }
            syslog_loose::IncompleteDate::None(nt) => {
                let now = Utc::now().date_naive();
                now.and_time(nt).and_utc().to_rfc3339()
            }
        })
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

    Some(ParsedLog {
        timestamp,
        hostname,
        facility,
        severity,
        app_name,
        process_id,
        message: msg.msg.to_string(),
        raw: raw.to_string(),
    })
}
