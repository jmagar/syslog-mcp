use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bollard::Docker;
use bollard::models::EventMessage;
use bollard::query_parameters::{
    EventsOptionsBuilder, ListContainersOptionsBuilder, LogsOptionsBuilder,
};
use chrono::Utc;
use futures_util::StreamExt;
use tokio::task::JoinSet;
use tokio::time::sleep;

use super::syslog_sender::{
    PRI_LOCAL0_INFO, PRI_LOCAL0_WARN, SyslogSender, format_rfc5424, local0_pri,
};
use crate::docker_ingest::{
    docker_event_severity, docker_event_source_action, docker_event_timestamp,
};

const CONTAINER_POLL_SECS: u64 = 30;

/// Message prefix marker carrying structured agent Docker identity metadata.
/// Single definition — the receiver enrichment path
/// (`src/receiver/enrichment.rs`) imports this constant, extracts the JSON
/// payload into `metadata_json`, and strips the marker from `message`.
pub(crate) const AGENT_DOCKER_META_MARKER: &str = "[cortex-agent-docker-meta:";

/// Denormalised `metadata_json.source_kind` value for agent-attested Docker
/// identity. Single definition — the agent emits it in the marker payload
/// and the receiver enrichment path re-sets it from this constant (never
/// from the sender-controlled payload); the resolver adapters stamp it on
/// observations.
pub(crate) const AGENT_DOCKER_SOURCE_KIND: &str = "agent-docker";

struct ContainerInfo {
    id: String,
    name: String,
    app_name: String,
    image: Option<String>,
    labels: HashMap<String, String>,
}

/// Stream Docker container logs from a local socket and forward as RFC 5424
/// syslog to the given sender.  Runs until cancelled or a fatal error occurs.
pub async fn run_docker_forwarder(
    docker_url: &str,
    hostname: &str,
    sender: Arc<SyslogSender>,
) -> Result<()> {
    let docker = connect(docker_url).context("connect to Docker")?;
    docker.ping().await.context("Docker ping")?;
    tracing::info!(docker_url, "docker forwarder connected");

    tokio::try_join!(
        run_docker_log_forwarder(&docker, hostname, Arc::clone(&sender)),
        run_docker_event_forwarder(&docker, hostname, sender),
    )?;
    Ok(())
}

fn event_stream_ended() -> Result<()> {
    bail!("Docker event stream ended unexpectedly")
}

async fn run_docker_log_forwarder(
    docker: &Docker,
    hostname: &str,
    sender: Arc<SyslogSender>,
) -> Result<()> {
    let mut active: HashMap<String, tokio::task::AbortHandle> = HashMap::new();
    let mut tasks: JoinSet<String> = JoinSet::new(); // yields container_id on exit

    loop {
        // Reap completed followers before deciding which running containers
        // need a new follower. Doing this after the spawn pass leaves a
        // stopped-and-quickly-restarted container's completed handle in
        // `active` for one extra 30-second poll cycle, so its replacement
        // follower can be delayed by nearly a minute.
        while let Ok(Some(res)) =
            tokio::time::timeout(Duration::from_millis(1), tasks.join_next()).await
        {
            if let Ok(id) = res {
                active.remove(&id);
            }
        }

        let containers = list_containers(docker).await?;
        let live_ids: std::collections::HashSet<String> =
            containers.iter().map(|c| c.id.clone()).collect();

        // Remove handles for containers that are no longer running.
        active.retain(|id, handle| {
            if !live_ids.contains(id) {
                handle.abort();
                false
            } else {
                true
            }
        });

        // Spawn a follower for any new container.
        for c in containers {
            if active.contains_key(&c.id) {
                continue;
            }
            let docker2 = docker.clone();
            let sender2 = Arc::clone(&sender);
            let hostname = hostname.to_string();
            let id = c.id.clone();
            let id2 = id.clone();
            let handle = tasks.spawn(async move {
                if let Err(e) = follow_container(&docker2, &hostname, &c, sender2).await {
                    tracing::debug!(
                        container = c.name,
                        error = %e,
                        "container log stream ended"
                    );
                }
                id
            });
            active.insert(id2, handle);
        }

        sleep(Duration::from_secs(CONTAINER_POLL_SECS)).await;
    }
}

async fn run_docker_event_forwarder(
    docker: &Docker,
    hostname: &str,
    sender: Arc<SyslogSender>,
) -> Result<()> {
    let filters = HashMap::from([("type".to_string(), vec!["container".to_string()])]);
    // This is a live-forwarding path. Replaying a lookback window after an
    // agent reconnect could deliver the same lifecycle event multiple times
    // and falsely satisfy restart-loop thresholds.
    let options = EventsOptionsBuilder::default().filters(&filters).build();
    let mut events = docker.events(Some(options));

    while let Some(event) = events.next().await {
        if let Some(line) = docker_event_line(hostname, &event?) {
            sender.send_from("docker-events", line).await?;
        }
    }
    event_stream_ended()
}

fn docker_event_line(hostname: &str, event: &EventMessage) -> Option<String> {
    let action = event.action.as_deref()?;
    let actor = event.actor.as_ref()?;
    let severity = docker_event_severity(action, actor)?;
    let normalized_action = docker_event_source_action(action);
    if normalized_action.is_empty() {
        return None;
    }
    let container_id = actor.id.as_deref()?;
    let attributes = actor.attributes.as_ref();
    let attr = |key: &str| {
        attributes
            .and_then(|attrs| attrs.get(key))
            .map(String::as_str)
    };
    let container_name =
        attr("name").unwrap_or_else(|| &container_id[..container_id.len().min(12)]);
    let image = attr("image");
    let compose_project = attr("com.docker.compose.project");
    let compose_service = attr("com.docker.compose.service");
    let exit_code = attr("exitCode")
        .or_else(|| attr("exit_code"))
        .and_then(|value| value.parse::<i32>().ok());
    let metadata = serde_json::json!({
        "source_kind": AGENT_DOCKER_SOURCE_KIND,
        "agent_docker": {
            "host": hostname,
            "container_id": container_id,
            "container_name": container_name,
            "compose_project": compose_project,
            "compose_service": compose_service,
            "image": image,
            "stream": "event",
            "event_action": normalized_action,
            "exit_code": exit_code,
        }
    });
    let mut message = format!(
        "{AGENT_DOCKER_META_MARKER}{metadata}] docker container event: {normalized_action} container={container_name}"
    );
    if let Some(exit_code) = exit_code {
        message.push_str(&format!(" exit_code={exit_code}"));
    }
    let pri = local0_pri(match severity {
        "err" => 3,
        "warning" => 4,
        "notice" => 5,
        "info" => 6,
        _ => return None,
    });
    let timestamp = docker_event_timestamp(event);
    Some(format_rfc5424(
        pri,
        &timestamp,
        hostname,
        compose_service.unwrap_or(container_name),
        &container_id[..container_id.len().min(12)],
        &message,
    ))
}

async fn follow_container(
    docker: &Docker,
    hostname: &str,
    container: &ContainerInfo,
    sender: Arc<SyslogSender>,
) -> Result<()> {
    let since = Utc::now().timestamp() - 1;
    let opts = LogsOptionsBuilder::default()
        .stdout(true)
        .stderr(true)
        .timestamps(true)
        .follow(true)
        .since(since.clamp(0, i32::MAX as i64) as i32)
        .build();

    // The container identity is constant for the lifetime of this follow, so
    // both stream-tagged metadata prefixes are rendered once instead of
    // rebuilding the serde_json value per log line.
    let meta_prefix = |stream: &str| {
        let metadata = container_identity_metadata(
            hostname,
            &container.id,
            &container.name,
            stream,
            container.image.as_deref(),
            &container.labels,
        );
        format!("{AGENT_DOCKER_META_MARKER}{metadata}] ")
    };
    let stdout_prefix = meta_prefix("stdout");
    let stderr_prefix = meta_prefix("stderr");

    let mut stream = docker.logs(&container.id, Some(opts));
    while let Some(output) = stream.next().await {
        let (is_stderr, bytes) = match output? {
            bollard::container::LogOutput::StdOut { message } => (false, message),
            bollard::container::LogOutput::StdErr { message } => (true, message),
            _ => continue,
        };

        let raw = String::from_utf8_lossy(&bytes);
        let msg = raw.trim_end_matches(['\r', '\n']);
        if msg.is_empty() {
            continue;
        }
        let pri = if is_stderr {
            PRI_LOCAL0_WARN
        } else {
            PRI_LOCAL0_INFO
        };
        let prefix = if is_stderr {
            &stderr_prefix
        } else {
            &stdout_prefix
        };
        // An RFC 5424 APP-NAME over 48 bytes (or empty / non-graphic) is
        // REPLACED wholesale with the `cortex-agent` fallback by
        // `sanitise_field` -- not truncated -- so canonical identity rides in
        // the metadata prefix instead. The receiver strips it into
        // `metadata_json.agent_docker`.
        let msg = format!("{prefix}{msg}");
        let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let line = format_rfc5424(
            pri,
            &ts,
            hostname,
            &container.app_name,
            &container.id[..12],
            &msg,
        );
        sender
            .send_from(&format!("docker:{}", container.id), line)
            .await?;
    }
    Ok(())
}

async fn list_containers(docker: &Docker) -> Result<Vec<ContainerInfo>> {
    let opts = ListContainersOptionsBuilder::default().all(false).build();
    let summaries = docker.list_containers(Some(opts)).await?;
    Ok(summaries
        .into_iter()
        .filter_map(|s| {
            let id = s.id?;
            let name = container_display_name(&id, s.names);
            let labels: HashMap<String, String> = s.labels.unwrap_or_default();
            if !should_forward_container_logs(&name, &labels) {
                return None;
            }
            let app_name = container_app_name(&name, &labels);
            Some(ContainerInfo {
                id,
                name,
                app_name,
                image: s.image,
                labels,
            })
        })
        .collect())
}

fn container_display_name(id: &str, names: Option<Vec<String>>) -> String {
    names
        .and_then(|ns| ns.into_iter().next())
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_else(|| id.chars().take(12).collect())
}

/// Structured agent-attested Docker identity metadata for one log line.
/// This is the canonical resolver proof shape: `metadata_json.agent_docker`
/// with required host/container_id/container_name/stream and optional
/// compose_project/compose_service/image.
fn container_identity_metadata(
    host: &str,
    container_id: &str,
    container_name: &str,
    stream: &str,
    image: Option<&str>,
    labels: &HashMap<String, String>,
) -> serde_json::Value {
    serde_json::json!({
        "source_kind": AGENT_DOCKER_SOURCE_KIND,
        "agent_docker": {
            "host": host,
            "container_id": container_id,
            "container_name": container_name,
            "compose_project": labels.get("com.docker.compose.project"),
            "compose_service": labels.get("com.docker.compose.service"),
            "image": image,
            "stream": stream,
        }
    })
}

/// Flat, non-slash syslog APP-NAME for a container's forwarded log lines.
///
/// Canonical service identity (compose project/service, container id/name,
/// image) now rides in structured, resolver-verified
/// `metadata_json.agent_docker` (see `container_identity_metadata`) rather
/// than in this string. Formatting APP-NAME as a `{project}/{service}/{name}`
/// slash-triplet is therefore both unnecessary and actively harmful: the
/// canonical entity-resolution vocabulary
/// (`db::entity_resolution::classify_legacy_shape`) classifies any 2+-slash
/// app label as a legacy `SlashTriplet` shape and permanently excludes it
/// from graph `app`-entity projection (see `db::graph`'s `extract_log_row`
/// handling and the migration-41+ legacy-shape cleanup in `db::pool`), which
/// would silently drop all graph app identity for these logs with no
/// resolver replacement. Emitting a flat name keeps APP-NAME human-readable
/// for raw-text search/display while canonical identity resolution happens
/// exclusively through the metadata marker.
fn container_app_name(name: &str, labels: &HashMap<String, String>) -> String {
    labels
        .get("com.docker.compose.service")
        .cloned()
        .unwrap_or_else(|| name.to_string())
}

fn should_forward_container_logs(name: &str, labels: &HashMap<String, String>) -> bool {
    if name == "cortex" {
        return false;
    }

    !matches!(
        (
            labels.get("com.docker.compose.project").map(String::as_str),
            labels.get("com.docker.compose.service").map(String::as_str),
        ),
        (Some("cortex"), Some("cortex"))
    )
}

fn connect(docker_url: &str) -> Result<Docker> {
    if docker_url.starts_with("unix://") || docker_url.starts_with("npipe://") {
        return Docker::connect_with_socket(docker_url, 120, bollard::API_DEFAULT_VERSION)
            .context("bollard socket connect");
    }

    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioExecutor;
    use std::sync::Arc as StdArc;

    let mut http = HttpConnector::new();
    http.set_keepalive(Some(Duration::from_secs(30)));
    http.set_keepalive_interval(Some(Duration::from_secs(30)));
    http.set_keepalive_retries(Some(3));

    let client = StdArc::new(Client::builder(TokioExecutor::new()).build(http));
    let url = docker_url.to_string();
    Docker::connect_with_custom_transport(
        move |req| {
            let client = StdArc::clone(&client);
            Box::pin(async move {
                client
                    .request(req)
                    .await
                    .map_err(bollard::errors::Error::from)
            })
        },
        Some(url),
        120,
        bollard::API_DEFAULT_VERSION,
    )
    .context("bollard http connect")
}

#[cfg(test)]
#[path = "docker_tests.rs"]
mod tests;
