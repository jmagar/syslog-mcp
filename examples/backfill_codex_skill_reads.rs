//! Explicit source-host recovery; never resets the running agent checkpoint.
use cortex::agent::ai_transcript::{AiTranscriptForwardConfig, backfill_codex_skill_reads};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let target = std::env::var("CORTEX_RECOVERY_TARGET")?;
    let token = std::env::var("CORTEX_RECOVERY_TOKEN").ok();
    let root = std::path::PathBuf::from(std::env::var("CORTEX_RECOVERY_ROOT")?);
    let mut config = AiTranscriptForwardConfig::new(target, token, root.join("unused-checkpoint"));
    config.roots = vec![root];
    if let Ok(hostname) = std::env::var("CORTEX_RECOVERY_HOSTNAME") {
        config.hostname = hostname;
    }
    let acknowledged = backfill_codex_skill_reads(config).await?;
    println!(
        "Acknowledged {acknowledged} completed Codex skill-read records (replays are deduplicated)."
    );
    Ok(())
}
