use anyhow::{Result, anyhow, bail};

use super::args::StatsCommand;
use super::parse_admin::{parse_compose, parse_db, parse_setup, parse_stats, parse_status};
use super::parse_logs::{
    parse_correlate, parse_errors, parse_filter, parse_hosts, parse_incident,
    parse_ingest_rate_args, parse_patterns, parse_search, parse_tail, parse_timeline,
};
use super::{CliCommand, commands, parse_config, suggest};

mod assess;
mod sessions;

use self::assess::parse_assess;
use self::sessions::parse_sessions_command;

pub(crate) const TOP_LEVEL_COMMANDS: &[&str] = &[
    "search",
    "filter",
    "tail",
    "hosts",
    "sessions",
    "assess",
    "analysis",
    "state",
    "status",
    "ingest",
    "alerts",
    "entity",
    "graph",
    "heartbeat",
    "correlate",
    "stats",
    "compose",
    "setup",
    "db",
    "config",
    "timeline",
    "apps",
    "artifactevents",
    "completions",
];

pub(crate) fn parse_command(args: Vec<String>) -> Result<CliCommand> {
    let (command, rest) = args
        .split_first()
        .ok_or_else(|| anyhow!("CLI command is required"))?;
    match command.as_str() {
        "search" => parse_search(rest),
        "filter" => parse_filter(rest),
        "tail" => parse_tail(rest),
        "hosts" => parse_hosts(rest),
        "sessions" => parse_sessions_command(rest),
        "assess" => parse_assess(rest),
        "analysis" => parse_analysis(rest),
        "state" => commands::state::parse_state(rest),
        "status" => parse_status(rest),
        "ingest" => parse_ingest(rest),
        "alerts" => parse_alerts(rest),
        "heartbeat" => parse_heartbeat(rest),
        "correlate" => parse_correlate_domain(rest),
        "stats" => parse_stats_domain(rest),
        "compose" => parse_compose(rest),
        "setup" => parse_setup(rest),
        "db" => parse_db(rest),
        "config" => parse_config::parse_config(rest),
        "timeline" => parse_timeline(rest),
        "entity" => commands::graph::parse_entity(rest),
        "graph" => commands::graph::parse_graph(rest),
        "apps" => commands::apps::parse_apps(rest),
        "artifactevents" => commands::artifact_evidence::parse_artifact_evidence(rest),
        "__complete" => Ok(CliCommand::Complete(rest.to_vec())),
        "completions" => Ok(CliCommand::Completions(rest.to_vec())),
        _ if cortex::surfaces::removed_cli_surface(command).is_some() => {
            bail!("{}", removed_command_message(command))
        }
        _ => bail!(
            "{}",
            suggest::unknown_command("CLI command", command, TOP_LEVEL_COMMANDS)
        ),
    }
}

fn parse_required_subcommand<'a>(
    domain: &str,
    args: &'a [String],
    expected: &[&str],
) -> Result<(&'a str, &'a [String])> {
    let (subcommand, rest) = args
        .split_first()
        .ok_or_else(|| anyhow!("{domain} requires a subcommand: {}", expected.join(", ")))?;
    Ok((subcommand.as_str(), rest))
}

fn parse_analysis(args: &[String]) -> Result<CliCommand> {
    let (subcommand, rest) = parse_required_subcommand(
        "analysis",
        args,
        &["errors", "incident", "patterns", "anomalies", "compare"],
    )?;
    match subcommand {
        "errors" => parse_errors(rest),
        "incident" => parse_incident(rest),
        "patterns" => parse_patterns(rest),
        "anomalies" => commands::anomalies::parse_anomalies(rest),
        "compare" => commands::compare::parse_compare(rest),
        _ => bail!(
            "{}",
            suggest::unknown_command(
                "analysis subcommand",
                subcommand,
                &["errors", "incident", "patterns", "anomalies", "compare"],
            )
        ),
    }
}

fn parse_ingest(args: &[String]) -> Result<CliCommand> {
    commands::ingest::parse_ingest(args)
}

fn parse_alerts(args: &[String]) -> Result<CliCommand> {
    let Some((subcommand, rest)) = args.split_first() else {
        return commands::alerts::parse_alerts(args);
    };
    let mut delegated = Vec::new();
    match subcommand.as_str() {
        "signatures"
            if !matches!(
                rest.first().map(String::as_str),
                Some("list" | "ack" | "unack")
            ) =>
        {
            delegated.push("signatures".to_string());
            delegated.push("list".to_string());
            delegated.extend_from_slice(rest);
            commands::alerts::parse_alerts(&delegated)
        }
        "notifications" if !matches!(rest.first().map(String::as_str), Some("recent" | "test")) => {
            delegated.push("notifications".to_string());
            delegated.push("recent".to_string());
            delegated.extend_from_slice(rest);
            commands::alerts::parse_alerts(&delegated)
        }
        _ => commands::alerts::parse_alerts(args),
    }
}

fn parse_correlate_domain(args: &[String]) -> Result<CliCommand> {
    let (subcommand, rest) =
        parse_required_subcommand("correlate", args, &["events", "state", "topic"])?;
    match subcommand {
        "events" => parse_correlate(rest),
        "state" => commands::correlate_state::parse_correlate_state(rest),
        "topic" => commands::topic_correlate::parse_topic_correlate(rest),
        _ => bail!(
            "{}",
            suggest::unknown_command(
                "correlate subcommand",
                subcommand,
                &["events", "state", "topic"],
            )
        ),
    }
}

fn parse_stats_domain(args: &[String]) -> Result<CliCommand> {
    match args.first().map(String::as_str) {
        Some("ingestrate") => Ok(CliCommand::Stats(StatsCommand::IngestRate(
            parse_ingest_rate_args(&args[1..])?,
        ))),
        Some("summary") => parse_stats(&args[1..]),
        Some(other) if !other.starts_with('-') => bail!(
            "{}",
            suggest::unknown_command("stats subcommand", other, &["summary", "ingestrate"])
        ),
        _ => parse_stats(args),
    }
}

fn removed_command_message(command: &str) -> String {
    let surface = cortex::surfaces::removed_cli_surface(command).expect("checked by caller");
    let replacement = surface
        .replacement
        .expect("removed CLI surfaces must carry replacement");
    format!("removed CLI command: {command}\n\nUse `cortex {replacement}`.")
}

fn parse_heartbeat(args: &[String]) -> Result<CliCommand> {
    let (command, rest) = args
        .split_first()
        .ok_or_else(|| anyhow!("heartbeat subcommand is required"))?;
    match command.as_str() {
        "agent" => parse_heartbeat_agent(rest),
        _ => bail!(
            "{}",
            suggest::unknown_command("heartbeat subcommand", command, &["agent"])
        ),
    }
}

fn parse_heartbeat_agent(args: &[String]) -> Result<CliCommand> {
    let mut out = super::HeartbeatAgentArgs {
        env_file: None,
        target: None,
        token: None,
        interval_secs: cortex::heartbeat_agent::DEFAULT_INTERVAL_SECS,
        probe_deadline_ms: cortex::heartbeat_agent::DEFAULT_PROBE_DEADLINE_MS,
        collection_deadline_ms: cortex::heartbeat_agent::DEFAULT_COLLECTION_DEADLINE_MS,
        retry_buffer: cortex::heartbeat_agent::DEFAULT_RETRY_BUFFER_LIMIT,
        once: false,
        emit: false,
        json: false,
        host_id_path: None,
        docker: false,
        docker_url: None,
        journald: false,
        syslog_target: None,
        ai_transcripts: false,
        agent_command_forward: false,
        shell_history_forward: false,
    };
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--env-file" => {
                i += 1;
                out.env_file = Some(required_value(args, i, "--env-file")?);
            }
            "--target" => {
                i += 1;
                out.target = Some(required_value(args, i, "--target")?);
            }
            "--token" => {
                i += 1;
                out.token = Some(required_value(args, i, "--token")?);
            }
            "--interval-secs" => {
                i += 1;
                out.interval_secs = parse_u64_value(args, i, "--interval-secs")?;
            }
            "--probe-deadline-ms" => {
                i += 1;
                out.probe_deadline_ms = parse_u64_value(args, i, "--probe-deadline-ms")?;
            }
            "--collection-deadline-ms" => {
                i += 1;
                out.collection_deadline_ms = parse_u64_value(args, i, "--collection-deadline-ms")?;
            }
            "--retry-buffer" => {
                i += 1;
                out.retry_buffer = parse_usize_value(args, i, "--retry-buffer")?;
            }
            "--host-id-path" => {
                i += 1;
                out.host_id_path = Some(required_value(args, i, "--host-id-path")?);
            }
            "--docker-url" => {
                i += 1;
                out.docker_url = Some(required_value(args, i, "--docker-url")?);
            }
            "--syslog-target" => {
                i += 1;
                out.syslog_target = Some(required_value(args, i, "--syslog-target")?);
            }
            "--once" => out.once = true,
            "--emit" => out.emit = true,
            "--json" => out.json = true,
            "--docker" => out.docker = true,
            "--journald" => out.journald = true,
            "--ai-transcripts" => out.ai_transcripts = true,
            "--agent-command-forward" => out.agent_command_forward = true,
            "--shell-history-forward" => out.shell_history_forward = true,
            other => bail!(
                "{}",
                suggest::unknown_option(
                    "heartbeat agent",
                    other,
                    &[
                        "--target",
                        "--env-file",
                        "--token",
                        "--interval-secs",
                        "--probe-deadline-ms",
                        "--collection-deadline-ms",
                        "--retry-buffer",
                        "--host-id-path",
                        "--docker",
                        "--docker-url",
                        "--journald",
                        "--syslog-target",
                        "--ai-transcripts",
                        "--agent-command-forward",
                        "--shell-history-forward",
                        "--once",
                        "--emit",
                        "--json",
                    ],
                )
            ),
        }
        i += 1;
    }
    if out.interval_secs == 0 {
        bail!("--interval-secs must be greater than zero");
    }
    if out.probe_deadline_ms == 0 {
        bail!("--probe-deadline-ms must be greater than zero");
    }
    if out.collection_deadline_ms == 0 {
        bail!("--collection-deadline-ms must be greater than zero");
    }
    Ok(CliCommand::Heartbeat(super::HeartbeatCommand::Agent(out)))
}

fn required_value(args: &[String], index: usize, flag: &str) -> Result<String> {
    let value = args
        .get(index)
        .ok_or_else(|| anyhow!("{flag} requires a value"))?;
    if value.starts_with('-') || value.trim().is_empty() {
        bail!("{flag} requires a value");
    }
    Ok(value.clone())
}

fn parse_u64_value(args: &[String], index: usize, flag: &str) -> Result<u64> {
    required_value(args, index, flag)?
        .parse()
        .map_err(|_| anyhow!("{flag} must be an integer"))
}

fn parse_usize_value(args: &[String], index: usize, flag: &str) -> Result<usize> {
    required_value(args, index, flag)?
        .parse()
        .map_err(|_| anyhow!("{flag} must be an integer"))
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
