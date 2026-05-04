use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, error, info, warn};

use crate::db;

use super::parser::parse_syslog;
use super::writer::{queue_depth, source_addr_ip};
use super::WRITE_CHANNEL_CAPACITY;

/// UDP syslog receiver.
pub(super) async fn udp_listener(
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
pub(super) async fn handle_tcp_connection(
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
        // Idle timeout is per read, not wall-clock lifetime.
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
pub(super) async fn tcp_listener(
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
                accept_backoff_ms = 100;
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
                tokio::time::sleep(tokio::time::Duration::from_millis(accept_backoff_ms)).await;
                accept_backoff_ms = (accept_backoff_ms * 2).min(5000);
                continue;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "listener_tests.rs"]
mod tests;
