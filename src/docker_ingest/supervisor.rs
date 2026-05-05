use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use futures_util::StreamExt;
use tokio::task::JoinHandle;

use crate::config::{DockerHostConfig, DockerIngestConfig};
use crate::db::DbPool;
use crate::ingest::IngestTx;

use super::checkpoint::load_checkpoint;
use super::client::DockerHostClient;
use super::models::ContainerMeta;
use super::parser::log_output_to_entry;

pub(crate) fn spawn_all(
    config: DockerIngestConfig,
    pool: Arc<DbPool>,
    ingest: IngestTx,
) -> Vec<JoinHandle<()>> {
    if !config.enabled {
        return Vec::new();
    }

    config
        .hosts
        .clone()
        .into_iter()
        .map(|host| {
            let config = config.clone();
            let pool = Arc::clone(&pool);
            let ingest = ingest.clone();
            tokio::spawn(async move {
                run_host_forever(config, host, pool, ingest).await;
            })
        })
        .collect()
}

async fn run_host_forever(
    config: DockerIngestConfig,
    host: DockerHostConfig,
    pool: Arc<DbPool>,
    ingest: IngestTx,
) {
    let mut delay_ms = config.reconnect_initial_ms;
    loop {
        let reset_backoff = match run_host_once(&config, &host, Arc::clone(&pool), ingest.clone())
            .await
        {
            Ok(()) => {
                tracing::warn!(host = %host.name, "Docker ingest host stream ended; reconnecting");
                true
            }
            Err(e) => {
                tracing::warn!(
                    host = %host.name,
                    error = %e,
                    delay_ms,
                    "Docker ingest host failed; retrying"
                );
                false
            }
        };
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        delay_ms = if reset_backoff {
            config.reconnect_initial_ms
        } else {
            (delay_ms * 2).min(config.reconnect_max_ms)
        };
    }
}

async fn run_host_once(
    config: &DockerIngestConfig,
    host: &DockerHostConfig,
    pool: Arc<DbPool>,
    ingest: IngestTx,
) -> Result<()> {
    let event_since_unix = chrono::Utc::now().timestamp().saturating_sub(60);
    let client = DockerHostClient::connect(&host.base_url)?;
    let containers = client.list_containers().await?;
    tracing::info!(
        host = %host.name,
        container_count = containers.len(),
        "Docker ingest discovered containers"
    );

    let mut log_tasks: HashMap<String, JoinHandle<()>> = HashMap::new();
    for container in containers {
        spawn_log_task_if_absent(
            config,
            host,
            &client,
            Arc::clone(&pool),
            ingest.clone(),
            &mut log_tasks,
            container,
        );
    }

    let result = follow_container_events(
        config,
        host,
        &client,
        pool,
        ingest,
        &mut log_tasks,
        event_since_unix,
    )
    .await;
    for handle in log_tasks.into_values() {
        handle.abort();
    }
    result
}

async fn follow_container_events(
    config: &DockerIngestConfig,
    host: &DockerHostConfig,
    client: &DockerHostClient,
    pool: Arc<DbPool>,
    ingest: IngestTx,
    log_tasks: &mut HashMap<String, JoinHandle<()>>,
    event_since_unix: i64,
) -> Result<()> {
    let docker = client.docker();
    let mut events = docker.events(Some(DockerHostClient::container_events_options(
        event_since_unix,
    )));
    while let Some(event) = events.next().await {
        let event = event?;
        let action = event.action.unwrap_or_default();
        let Some(actor) = event.actor else {
            continue;
        };
        let Some(id) = actor.id else {
            continue;
        };

        match action.as_str() {
            "start" | "restart" | "rename" => {
                prune_finished_tasks(log_tasks);
                if action == "rename" {
                    if let Some(handle) = log_tasks.remove(&id) {
                        handle.abort();
                    }
                }
                let containers = client.list_containers().await?;
                for container in containers.into_iter().filter(|c| c.id == id) {
                    spawn_log_task_if_absent(
                        config,
                        host,
                        client,
                        Arc::clone(&pool),
                        ingest.clone(),
                        log_tasks,
                        container,
                    );
                }
            }
            "die" | "destroy" | "stop" => {
                if let Some(handle) = log_tasks.remove(&id) {
                    handle.abort();
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn prune_finished_tasks(tasks: &mut HashMap<String, JoinHandle<()>>) {
    tasks.retain(|_, handle| !handle.is_finished());
}

fn spawn_log_task_if_absent(
    config: &DockerIngestConfig,
    host: &DockerHostConfig,
    client: &DockerHostClient,
    pool: Arc<DbPool>,
    ingest: IngestTx,
    tasks: &mut HashMap<String, JoinHandle<()>>,
    container: ContainerMeta,
) {
    if tasks.contains_key(&container.id) {
        return;
    }
    let docker = client.docker();
    let host_name = host.name.clone();
    let reconnect_initial_ms = config.reconnect_initial_ms;
    let reconnect_max_ms = config.reconnect_max_ms;
    let container_id = container.id.clone();
    let task_container_id = container_id.clone();
    let handle = tokio::spawn(async move {
        let mut delay_ms = reconnect_initial_ms;
        loop {
            match follow_container_logs_once(
                &docker,
                &pool,
                &ingest,
                &host_name,
                &task_container_id,
                &container,
            )
            .await
            {
                Ok(()) => tracing::warn!(
                    host = %host_name,
                    container_id = %task_container_id,
                    delay_ms,
                    "Docker log stream ended; reconnecting"
                ),
                Err(e) => tracing::warn!(
                    host = %host_name,
                    container_id = %task_container_id,
                    error = %e,
                    delay_ms,
                    "Docker log stream failed; retrying"
                ),
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 2).min(reconnect_max_ms);
        }
    });
    tasks.insert(container_id, handle);
}

async fn follow_container_logs_once(
    docker: &bollard::Docker,
    pool: &Arc<DbPool>,
    ingest: &IngestTx,
    host_name: &str,
    container_id: &str,
    container: &ContainerMeta,
) -> Result<()> {
    let checkpoint = load_checkpoint(pool, host_name, container_id)?
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(&ts).ok());
    let since_unix = checkpoint.map(|dt| dt.timestamp()).unwrap_or(0);
    let mut logs = docker.logs(
        container_id,
        Some(DockerHostClient::logs_options(since_unix)),
    );

    while let Some(output) = logs.next().await {
        match log_output_to_entry(host_name, container, output?) {
            Ok(Some(entry)) => {
                if checkpoint
                    .as_ref()
                    .is_some_and(|checkpoint| entry_is_at_or_before_checkpoint(&entry, checkpoint))
                {
                    continue;
                }
                if ingest.send(entry).await.is_err() {
                    anyhow::bail!("Docker ingest channel closed");
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(
                host = %host_name,
                container_id = %container_id,
                error = %e,
                "Failed to parse Docker log frame"
            ),
        }
    }
    Ok(())
}

fn entry_is_at_or_before_checkpoint(
    entry: &crate::db::LogBatchEntry,
    checkpoint: &chrono::DateTime<chrono::FixedOffset>,
) -> bool {
    entry
        .docker_checkpoint
        .as_ref()
        .and_then(|docker_checkpoint| {
            chrono::DateTime::parse_from_rfc3339(&docker_checkpoint.timestamp).ok()
        })
        .is_some_and(|entry_ts| entry_ts <= *checkpoint)
}

#[cfg(test)]
mod tests {
    use crate::db::{DockerCheckpoint, LogBatchEntry};

    use super::entry_is_at_or_before_checkpoint;

    fn docker_entry(timestamp: &str) -> LogBatchEntry {
        LogBatchEntry {
            timestamp: timestamp.into(),
            hostname: "edge-host-a".into(),
            facility: Some("local0".into()),
            severity: "info".into(),
            app_name: Some("nginx".into()),
            process_id: Some("abcdef123456".into()),
            message: "line".into(),
            raw: format!("{timestamp} line"),
            source_ip: "docker://edge-host-a/abcdef123456/stdout".into(),
            docker_checkpoint: Some(DockerCheckpoint {
                host_name: "edge-host-a".into(),
                container_id: "abcdef123456".into(),
                timestamp: timestamp.into(),
            }),
        }
    }

    #[test]
    fn checkpoint_filter_skips_only_entries_at_or_before_precise_checkpoint() {
        let checkpoint =
            chrono::DateTime::parse_from_rfc3339("2026-05-05T01:02:03.500000000Z").unwrap();

        assert!(entry_is_at_or_before_checkpoint(
            &docker_entry("2026-05-05T01:02:03.123456789Z"),
            &checkpoint
        ));
        assert!(entry_is_at_or_before_checkpoint(
            &docker_entry("2026-05-05T01:02:03.500000000Z"),
            &checkpoint
        ));
        assert!(!entry_is_at_or_before_checkpoint(
            &docker_entry("2026-05-05T01:02:03.500000001Z"),
            &checkpoint
        ));
    }
}
