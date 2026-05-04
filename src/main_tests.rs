use super::background_interval;

#[tokio::test]
async fn background_interval_waits_full_period_before_first_tick() {
    let delay = tokio::time::Duration::from_millis(25);
    let mut interval = background_interval(delay);
    let started = std::time::Instant::now();
    interval.tick().await;
    assert!(
        started.elapsed() >= tokio::time::Duration::from_millis(20),
        "first tick should wait roughly one full period before firing"
    );
}
