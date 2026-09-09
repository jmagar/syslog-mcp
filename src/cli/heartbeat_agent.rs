use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use cortex::heartbeat_agent::{HeartbeatAgentConfig, run_agent};

use super::{HeartbeatAgentArgs, HeartbeatCommand};

pub(crate) async fn run_heartbeat_no_db(command: HeartbeatCommand) -> Result<()> {
    match command {
        HeartbeatCommand::Agent(args) => run_agent(args.into_config()?).await,
    }
}

impl HeartbeatAgentArgs {
    fn into_config(self) -> Result<HeartbeatAgentConfig> {
        let host_id_path = self
            .host_id_path
            .map(PathBuf::from)
            .unwrap_or_else(default_host_id_path);
        let mut config = HeartbeatAgentConfig::from_env(host_id_path)?;
        if let Some(target) = self.target {
            config.target = Some(target);
        }
        if let Some(token) = self.token {
            config.token = Some(token);
        }
        config.interval = Duration::from_secs(self.interval_secs);
        config.probe_deadline = Duration::from_millis(self.probe_deadline_ms);
        config.collection_deadline = Duration::from_millis(self.collection_deadline_ms);
        config.retry_buffer_limit = self.retry_buffer;
        config.once = self.once;
        config.emit = self.emit;
        config.json = self.json;
        if self.docker {
            config.docker = true;
        }
        if let Some(url) = self.docker_url {
            config.docker_url = url;
        }
        if self.journald {
            config.journald = true;
        }
        if let Some(target) = self.syslog_target {
            config.syslog_target = Some(target);
        }
        if self.ai_transcripts {
            config.ai_transcripts = true;
        }
        if self.agent_command_forward {
            config.agent_command_forward = true;
        }
        if self.shell_history_forward {
            config.shell_history_forward = true;
        }
        Ok(config)
    }
}

pub(crate) fn default_host_id_path() -> PathBuf {
    cortex::setup::cortex_home_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("heartbeat-host-id")
}

#[cfg(test)]
#[path = "heartbeat_agent_tests.rs"]
mod tests;
