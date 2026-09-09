use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use super::*;

/// A panicking listener attempt must not kill supervision: the supervisor
/// marks the listener down, backs off, and restarts it (bead syslog-mcp-7f0y).
/// `start_paused` makes the backoff sleeps instant.
#[tokio::test(start_paused = true)]
async fn supervisor_restarts_listener_after_panic() {
    let obs = Arc::new(RuntimeObservability::default());
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_in = Arc::clone(&attempts);
    tokio::spawn(supervise_listener(
        "test_listener",
        Arc::clone(&obs),
        |o, s| o.set_udp_listener_state(s),
        CancellationToken::new(),
        move || {
            let attempts = Arc::clone(&attempts_in);
            async move {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    panic!("poison packet");
                }
                // Second attempt: run forever like a healthy listener.
                std::future::pending::<()>().await;
                Ok(())
            }
        },
    ));

    tokio::time::timeout(Duration::from_secs(300), async {
        while attempts.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The restarted attempt must be marked alive again.
        while obs.udp_listener_state() != ListenerState::Alive {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("supervisor should restart the listener after a panic");

    assert!(attempts.load(Ordering::SeqCst) >= 2);
    assert!(!obs.any_listener_down());
}

/// A listener that exits with an error is marked down until the restart
/// succeeds; while it keeps failing, `any_listener_down` reports true so
/// /health can fail and Docker can restart the container.
#[tokio::test(start_paused = true)]
async fn supervisor_marks_listener_down_while_failing() {
    let obs = Arc::new(RuntimeObservability::default());
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_in = Arc::clone(&attempts);
    tokio::spawn(supervise_listener(
        "test_listener",
        Arc::clone(&obs),
        |o, s| o.set_tcp_listener_state(s),
        CancellationToken::new(),
        move || {
            let attempts = Arc::clone(&attempts_in);
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("bind failed")
            }
        },
    ));

    // Let several attempts fail.
    tokio::time::timeout(Duration::from_secs(300), async {
        while attempts.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("supervisor should keep retrying a failing listener");

    // Between attempts (during backoff) the listener reports down. Sample
    // until we observe it — with paused time this is deterministic enough
    // to catch within the timeout.
    tokio::time::timeout(Duration::from_secs(300), async {
        while obs.tcp_listener_state() != ListenerState::Down {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("failing listener should be observable as down");
    assert!(obs.any_listener_down());
}

/// A listener that runs stably past `LISTENER_STABLE_RUN` resets the backoff
/// ladder. After the stable run ends, the next restart uses `LISTENER_BACKOFF_INITIAL`
/// rather than the doubled value it would have after the first failure.
#[tokio::test(start_paused = true)]
async fn supervisor_resets_backoff_after_stable_run() {
    let obs = Arc::new(RuntimeObservability::default());
    let attempts = Arc::new(AtomicU32::new(0));
    // Record the wall-clock instant at which each attempt *exits* (fails).
    // This gives us the reference point for measuring how long the subsequent
    // backoff sleep lasts — independent of how long the attempt itself ran.
    let exit_times: Arc<parking_lot::Mutex<Vec<tokio::time::Instant>>> =
        Arc::new(parking_lot::Mutex::new(Vec::new()));
    // Record when attempt 3 *starts* so we can compute the gap from attempt 2's exit.
    let attempt3_start: Arc<parking_lot::Mutex<Option<tokio::time::Instant>>> =
        Arc::new(parking_lot::Mutex::new(None));

    let attempts_in = Arc::clone(&attempts);
    let exits_in = Arc::clone(&exit_times);
    let start3_in = Arc::clone(&attempt3_start);

    tokio::spawn(supervise_listener(
        "test_listener",
        Arc::clone(&obs),
        |o, s| o.set_udp_listener_state(s),
        CancellationToken::new(),
        move || {
            let attempts = Arc::clone(&attempts_in);
            let exits = Arc::clone(&exits_in);
            let start3 = Arc::clone(&start3_in);
            async move {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                match n {
                    0 => {
                        // First attempt: fail immediately → triggers LISTENER_BACKOFF_INITIAL wait.
                        exits.lock().push(tokio::time::Instant::now());
                        anyhow::bail!("first fail")
                    }
                    1 => {
                        // Second attempt: survive past LISTENER_STABLE_RUN, then fail.
                        // This should reset the backoff back to LISTENER_BACKOFF_INITIAL.
                        tokio::time::sleep(LISTENER_STABLE_RUN + Duration::from_secs(1)).await;
                        exits.lock().push(tokio::time::Instant::now());
                        anyhow::bail!("stable then fail")
                    }
                    _ => {
                        // Third attempt: record start time, then run forever.
                        *start3.lock() = Some(tokio::time::Instant::now());
                        std::future::pending::<()>().await;
                        Ok(())
                    }
                }
            }
        },
    ));

    // Wait for three attempts to start (attempt 3 records its start).
    tokio::time::timeout(Duration::from_secs(300), async {
        while attempt3_start.lock().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("supervisor should reach three attempts");

    let exits = exit_times.lock();
    assert_eq!(exits.len(), 2, "expected exit times for attempts 0 and 1");
    let start3 = attempt3_start.lock().unwrap();

    // The gap from attempt 1's exit to attempt 3's start is the backoff sleep.
    // After a stable run, backoff resets to LISTENER_BACKOFF_INITIAL (1 s).
    // Without the reset it would be LISTENER_BACKOFF_INITIAL * 2 (2 s).
    // Allow a 500 ms scheduling margin.
    let gap = start3.duration_since(exits[1]);
    assert!(
        gap <= LISTENER_BACKOFF_INITIAL + Duration::from_millis(500),
        "backoff after stable run should be ~LISTENER_BACKOFF_INITIAL ({:?}), got {:?}",
        LISTENER_BACKOFF_INITIAL,
        gap
    );
}

/// Listeners that never started (stdio/query-only mode) must not be treated
/// as down by the health probe.
#[test]
fn not_started_listeners_are_not_down() {
    let obs = RuntimeObservability::default();
    assert_eq!(obs.udp_listener_state(), ListenerState::NotStarted);
    assert_eq!(obs.tcp_listener_state(), ListenerState::NotStarted);
    assert!(!obs.any_listener_down());
}

#[tokio::test]
async fn start_listeners_wires_udp_and_tcp_supervisors_on_ephemeral_loopback_port() {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("receiver.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    let storage_state = Arc::new(Mutex::new(None));
    let observability = Arc::new(RuntimeObservability::default());
    let config = ReceiverConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        max_message_size: 1024,
        max_tcp_connections: 4,
        tcp_idle_timeout_secs: 1,
        batch_size: 10,
        flush_interval: 10,
        write_channel_capacity: 16,
        allowed_source_cidrs: Vec::new(),
    };
    let ingest = ingest::start_writer_from_receiver_config(
        &config,
        storage,
        pool,
        storage_state,
        crate::receiver::enrichment::EnrichmentConfig::default(),
        Arc::clone(&observability),
    );

    let handles = start_listeners(config, ingest.clone(), Arc::clone(&observability))
        .await
        .expect("listeners start");
    tokio::time::timeout(Duration::from_secs(1), async {
        while observability.udp_listener_state() != ListenerState::Alive
            || observability.tcp_listener_state() != ListenerState::Alive
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("listener supervisors report alive");

    handles.udp.abort();
    handles.tcp.abort();
    ingest.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn listener_supervisors_stop_cleanly_when_runtime_shutdown_is_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let storage = StorageConfig::for_test(dir.path().join("receiver-shutdown.db"));
    let pool = Arc::new(db::init_pool(&storage).unwrap());
    let storage_state = Arc::new(Mutex::new(None));
    let observability = Arc::new(RuntimeObservability::default());
    let config = ReceiverConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        max_message_size: 1024,
        max_tcp_connections: 4,
        tcp_idle_timeout_secs: 1,
        batch_size: 10,
        flush_interval: 10,
        write_channel_capacity: 16,
        allowed_source_cidrs: Vec::new(),
    };
    let ingest = ingest::start_writer_from_receiver_config(
        &config,
        storage,
        pool,
        storage_state,
        crate::receiver::enrichment::EnrichmentConfig::default(),
        Arc::clone(&observability),
    );
    let shutdown = CancellationToken::new();
    let handles = start_listeners_with_shutdown(
        config,
        ingest.clone(),
        Arc::clone(&observability),
        shutdown.clone(),
    )
    .await
    .expect("listeners start");

    tokio::time::timeout(Duration::from_secs(1), async {
        while observability.udp_listener_state() != ListenerState::Alive
            || observability.tcp_listener_state() != ListenerState::Alive
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("listener supervisors report alive");

    shutdown.cancel();
    tokio::time::timeout(Duration::from_millis(250), async {
        handles.udp.await.expect("UDP supervisor stops cleanly");
        handles.tcp.await.expect("TCP supervisor stops cleanly");
    })
    .await
    .expect("cancellation must not wait for listener receive/accept");
    assert_eq!(observability.udp_listener_state(), ListenerState::Down);
    assert_eq!(observability.tcp_listener_state(), ListenerState::Down);
    ingest.shutdown(Duration::from_secs(1)).await;
}

async fn assert_supervisor_releases_bound_socket(abort_supervisor: bool) {
    let observability = Arc::new(RuntimeObservability::default());
    let shutdown = CancellationToken::new();
    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    let bound_tx = Arc::new(Mutex::new(Some(bound_tx)));
    let supervisor = tokio::spawn(supervise_listener(
        "socket_shutdown_test",
        observability,
        |obs, state| obs.set_udp_listener_state(state),
        shutdown.clone(),
        move || {
            let bound_tx = Arc::clone(&bound_tx);
            async move {
                let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                bound_tx
                    .lock()
                    .take()
                    .unwrap()
                    .send(socket.local_addr()?)
                    .unwrap();
                let mut buffer = [0u8; 1];
                socket.recv_from(&mut buffer).await?;
                Ok(())
            }
        },
    ));
    let address = tokio::time::timeout(Duration::from_secs(2), bound_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(tokio::net::UdpSocket::bind(address).await.is_err());
    if abort_supervisor {
        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
    } else {
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), supervisor)
            .await
            .unwrap()
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if tokio::net::UdpSocket::bind(address).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stopping the supervisor must release the actual listener socket");
}

#[tokio::test]
async fn supervisor_cancellation_releases_bound_socket() {
    assert_supervisor_releases_bound_socket(false).await;
}

#[tokio::test]
async fn supervisor_abort_releases_bound_socket() {
    assert_supervisor_releases_bound_socket(true).await;
}
