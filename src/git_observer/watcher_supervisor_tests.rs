use super::{
    GitFullReconcileReason, GitWatchScheduledAction, GitWatchSupervisorErrorKind,
    GitWatchSupervisorOptions, git_watch_supervisor,
};
use crate::git_observer::watcher::GitWatchAction;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn options() -> GitWatchSupervisorOptions {
    GitWatchSupervisorOptions {
        overflow_min_interval: Duration::from_secs(60),
        periodic_interval: Duration::from_secs(60),
    }
}
#[test]
fn hundred_overflow_notifications_emit_one_full_reconcile_per_interval() {
    let start = Instant::now();
    let (handle, mut supervisor) = git_watch_supervisor(start, options()).unwrap();
    for _ in 0..100 {
        handle.signal_overflow();
    }
    assert_eq!(
        supervisor.poll(start, []),
        vec![GitWatchScheduledAction::FullReconcile {
            reason: GitFullReconcileReason::Overflow,
        }]
    );
    supervisor
        .complete_full_reconcile(true, start + Duration::from_secs(1))
        .unwrap();

    for _ in 0..100 {
        handle.signal_overflow();
    }
    assert!(
        supervisor
            .poll(start + Duration::from_secs(59), [])
            .is_empty()
    );
    assert_eq!(
        supervisor.poll(start + Duration::from_secs(60), []),
        vec![GitWatchScheduledAction::FullReconcile {
            reason: GitFullReconcileReason::OverflowAndPeriodic,
        }]
    );
}

#[test]
fn periodic_tick_repairs_missed_events_and_coalesces_skipped_intervals() {
    let start = Instant::now();
    let (_handle, mut supervisor) = git_watch_supervisor(start, options()).unwrap();
    assert!(
        supervisor
            .poll(start + Duration::from_secs(59), [])
            .is_empty()
    );
    assert_eq!(
        supervisor.poll(start + Duration::from_secs(60), []),
        vec![GitWatchScheduledAction::FullReconcile {
            reason: GitFullReconcileReason::Periodic,
        }]
    );
    supervisor
        .complete_full_reconcile(true, start + Duration::from_secs(61))
        .unwrap();

    assert_eq!(
        supervisor.poll(start + Duration::from_secs(300), []),
        vec![GitWatchScheduledAction::FullReconcile {
            reason: GitFullReconcileReason::Periodic,
        }]
    );
    supervisor
        .complete_full_reconcile(true, start + Duration::from_secs(301))
        .unwrap();
    assert!(
        supervisor
            .poll(start + Duration::from_secs(301), [])
            .is_empty()
    );
}

#[test]
fn overflow_and_periodic_due_at_same_tick_coalesce_to_one_request() {
    let start = Instant::now();
    let (handle, mut supervisor) = git_watch_supervisor(start, options()).unwrap();
    handle.signal_overflow();
    assert_eq!(
        supervisor.poll(start + Duration::from_secs(60), []),
        vec![GitWatchScheduledAction::FullReconcile {
            reason: GitFullReconcileReason::OverflowAndPeriodic,
        }]
    );
    assert!(supervisor.full_reconcile_in_flight());
}

#[test]
fn failed_full_reconcile_requeues_without_suppressing_direct_repository_work() {
    let start = Instant::now();
    let (handle, mut supervisor) = git_watch_supervisor(start, options()).unwrap();
    handle.signal_overflow();
    assert_eq!(
        supervisor.poll(start, []),
        vec![GitWatchScheduledAction::FullReconcile {
            reason: GitFullReconcileReason::Overflow,
        }]
    );
    supervisor
        .complete_full_reconcile(false, start + Duration::from_secs(1))
        .unwrap();

    assert_eq!(
        supervisor.poll(
            start + Duration::from_secs(2),
            [GitWatchAction::ReconcileRepository {
                repository_key: "repo-a".to_string(),
            }],
        ),
        vec![GitWatchScheduledAction::ReconcileRepository {
            repository_key: "repo-a".to_string(),
        }]
    );
    assert_eq!(
        supervisor.poll(start + Duration::from_secs(60), []),
        vec![GitWatchScheduledAction::FullReconcile {
            reason: GitFullReconcileReason::OverflowAndPeriodic,
        }]
    );
}

#[test]
fn queue_full_reconcile_and_atomic_signals_coalesce_while_direct_actions_pass_through() {
    let start = Instant::now();
    let (handle, mut supervisor) = git_watch_supervisor(start, options()).unwrap();
    for _ in 0..100 {
        handle.signal_overflow();
    }
    assert_eq!(
        supervisor.poll(
            start,
            [
                GitWatchAction::FullReconcile,
                GitWatchAction::DiscoverRepositories {
                    project_root: PathBuf::from("/workspace"),
                },
            ],
        ),
        vec![
            GitWatchScheduledAction::DiscoverRepositories {
                project_root: PathBuf::from("/workspace"),
            },
            GitWatchScheduledAction::FullReconcile {
                reason: GitFullReconcileReason::Overflow,
            },
        ]
    );

    handle.signal_overflow();
    assert_eq!(
        supervisor.poll(
            start + Duration::from_secs(1),
            [GitWatchAction::ReconcileRepository {
                repository_key: "repo-b".to_string(),
            }],
        ),
        vec![GitWatchScheduledAction::ReconcileRepository {
            repository_key: "repo-b".to_string(),
        }]
    );
}

#[test]
fn completion_and_option_errors_are_typed() {
    let start = Instant::now();
    let error = git_watch_supervisor(
        start,
        GitWatchSupervisorOptions {
            overflow_min_interval: Duration::ZERO,
            ..options()
        },
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        GitWatchSupervisorErrorKind::InvalidOverflowMinInterval
    );

    let error = git_watch_supervisor(
        start,
        GitWatchSupervisorOptions {
            periodic_interval: Duration::ZERO,
            ..options()
        },
    )
    .unwrap_err();
    assert_eq!(
        error.kind,
        GitWatchSupervisorErrorKind::InvalidPeriodicInterval
    );

    let (_handle, mut supervisor) = git_watch_supervisor(start, options()).unwrap();
    let error = supervisor.complete_full_reconcile(true, start).unwrap_err();
    assert_eq!(error.kind, GitWatchSupervisorErrorKind::NoReconcileInFlight);
}
