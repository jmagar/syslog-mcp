use std::sync::Arc;

use parking_lot::Mutex;
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::config::{ReceiverConfig, StorageConfig};
use crate::db::{self, DbPool};
use crate::ingest;
use crate::observability::{ListenerState, RuntimeObservability};

pub(crate) mod enrichment;
mod listener;
pub(crate) mod parser;
pub(crate) mod writer;

#[cfg(test)]
#[path = "receiver_tests.rs"]
mod tests;

/// Initial restart delay after a listener exits.
const LISTENER_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Restart delay ceiling for a crash-looping listener.
const LISTENER_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// An attempt that survives this long resets the backoff ladder.
const LISTENER_STABLE_RUN: Duration = Duration::from_secs(60);

pub async fn start_with_storage_state(
    config: ReceiverConfig,
    storage: StorageConfig,
    pool: Arc<DbPool>,
    storage_state: Arc<Mutex<Option<db::StorageBudgetState>>>,
) -> Result<()> {
    // Default enrichment for the legacy convenience entry point: Authelia
    // and AdGuard reclassification are still applied (gating is "ungated"
    // when no source-IP prefix is configured), but secret scrubbing stays
    // on (default). Production runtime uses RuntimeCore which builds
    // enrichment from Config including operator overrides.
    let observability = Arc::new(RuntimeObservability::default());
    let ingest_tx = ingest::start_writer_from_receiver_config(
        &config,
        storage,
        pool,
        storage_state,
        crate::receiver::enrichment::EnrichmentConfig::default(),
        Arc::clone(&observability),
    );
    start_listeners(config, ingest_tx, observability)
        .await
        .map(|_handles| ())
}

/// Run one listener under supervision: restart on error or panic with
/// exponential backoff, and publish liveness to `RuntimeObservability` so
/// /health can report a dead listener (bead syslog-mcp-7f0y).
///
/// Each attempt runs in its own spawned task so a panic (e.g. from a poison
/// packet in the parse path) surfaces as a `JoinError` here instead of
/// killing the supervisor. The previous design spawned the listener bare:
/// one panic ended ingestion permanently while /health stayed green.
async fn supervise_listener<F, Fut>(
    name: &'static str,
    observability: Arc<RuntimeObservability>,
    set_state: fn(&RuntimeObservability, ListenerState),
    shutdown: CancellationToken,
    make_listener: F,
) where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let mut backoff = LISTENER_BACKOFF_INITIAL;
    loop {
        set_state(&observability, ListenerState::Alive);
        let started = tokio::time::Instant::now();
        // A stopped supervisor must never detach its socket-owning child.
        let mut listener = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(make_listener()));
        let outcome = tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                // UDP/TCP listeners wait in recv/accept and do not own the
                // runtime token. Abort their per-attempt task to close the
                // socket before returning from this supervisor.
                listener.abort();
                let _ = listener.await;
                set_state(&observability, ListenerState::Down);
                tracing::debug!(listener = name, "syslog listener supervisor stopped cleanly");
                return;
            }
            outcome = &mut listener => outcome,
        };
        set_state(&observability, ListenerState::Down);
        match outcome {
            Ok(Ok(())) => {
                // Listeners loop forever today; a clean exit still warrants
                // a restart so ingestion never silently stops.
                warn!(listener = name, "listener exited cleanly; restarting");
            }
            Ok(Err(e)) => {
                error!(listener = name, error = %e, "listener failed; restarting");
            }
            Err(join_err) if join_err.is_panic() => {
                error!(listener = name, panic = %join_err, "listener panicked; restarting");
            }
            Err(join_err) => {
                error!(listener = name, error = %join_err, "listener task cancelled; restarting");
            }
        }
        if started.elapsed() >= LISTENER_STABLE_RUN {
            backoff = LISTENER_BACKOFF_INITIAL;
        }
        warn!(
            listener = name,
            backoff_secs = backoff.as_secs(),
            "restarting listener after backoff"
        );
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::debug!(listener = name, "syslog listener supervisor stopped during backoff");
                return;
            }
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(LISTENER_BACKOFF_MAX);
        if backoff == LISTENER_BACKOFF_MAX {
            error!(
                listener = name,
                backoff_secs = backoff.as_secs(),
                "listener is in a sustained crash-loop; backoff ceiling reached"
            );
        }
    }
}

/// Supervisor `JoinHandle` pair returned by [`start_listeners`].
///
/// Both handles wrap the `supervise_listener` loop for a single protocol.
/// They never exit under normal operation; an unexpected exit means the
/// supervisor itself panicked or was aborted. Pass them to
/// [`RuntimeCore::start_syslog`] which spawns a monitoring task and stores the
/// monitor handle in [`MaintenanceHandles`].
pub(crate) struct ListenerHandles {
    pub udp: tokio::task::JoinHandle<()>,
    pub tcp: tokio::task::JoinHandle<()>,
}

pub(crate) async fn start_listeners(
    config: ReceiverConfig,
    ingest: ingest::IngestTx,
    observability: Arc<RuntimeObservability>,
) -> Result<ListenerHandles> {
    start_listeners_with_shutdown(config, ingest, observability, CancellationToken::new()).await
}

/// Start supervised syslog listeners that terminate when `shutdown` is
/// cancelled. RuntimeCore uses its maintenance token here so graceful server
/// shutdown owns the otherwise unbounded listener loops.
pub(crate) async fn start_listeners_with_shutdown(
    config: ReceiverConfig,
    ingest: ingest::IngestTx,
    observability: Arc<RuntimeObservability>,
    shutdown: CancellationToken,
) -> Result<ListenerHandles> {
    let bind_addr = config.bind_addr();
    let allowed_cidrs = Arc::new(listener::parse_allowed_cidrs(&config.allowed_source_cidrs)?);

    let udp_ingest = ingest.clone();
    let udp_bind = bind_addr.clone();
    let max_size = config.max_message_size;
    let udp_allowed_cidrs = Arc::clone(&allowed_cidrs);
    let udp_handle = tokio::spawn(supervise_listener(
        "udp_syslog",
        Arc::clone(&observability),
        |obs, state| obs.set_udp_listener_state(state),
        shutdown.clone(),
        move || {
            let bind = udp_bind.clone();
            let ingest = udp_ingest.clone();
            let allowed_cidrs = Arc::clone(&udp_allowed_cidrs);
            async move { listener::udp_listener(&bind, max_size, ingest, allowed_cidrs).await }
        },
    ));

    let tcp_ingest = ingest.clone();
    let tcp_bind = bind_addr.clone();
    let max_tcp_connections = config.max_tcp_connections;
    let tcp_idle_timeout_secs = config.tcp_idle_timeout_secs;
    let tcp_allowed_cidrs = Arc::clone(&allowed_cidrs);
    let tcp_handle = tokio::spawn(supervise_listener(
        "tcp_syslog",
        Arc::clone(&observability),
        |obs, state| obs.set_tcp_listener_state(state),
        shutdown,
        move || {
            let bind = tcp_bind.clone();
            let ingest = tcp_ingest.clone();
            let allowed_cidrs = Arc::clone(&tcp_allowed_cidrs);
            async move {
                listener::tcp_listener(
                    &bind,
                    ingest,
                    max_size,
                    max_tcp_connections,
                    tcp_idle_timeout_secs,
                    allowed_cidrs,
                )
                .await
            }
        },
    ));

    info!(
        bind = %bind_addr,
        max_message_size = config.max_message_size,
        max_tcp_connections = config.max_tcp_connections,
        tcp_idle_timeout_secs = config.tcp_idle_timeout_secs,
        write_channel_capacity = config.write_channel_capacity,
        "Syslog listeners started (supervised)"
    );

    Ok(ListenerHandles {
        udp: udp_handle,
        tcp: tcp_handle,
    })
}
