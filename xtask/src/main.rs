//! cortex repository maintenance tasks.
//!
//! The single subsystem here is release versioning: a declarative,
//! `release/components.toml`-driven port of axon's `xtask` version system,
//! trimmed to cortex's single component. Run via `cargo xtask <command>`.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod pre_push;
mod version;

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "cortex repository maintenance tasks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify every version-bearing file matches the canonical source and that
    /// plugin manifests carry no top-level version key.
    CheckVersionSync,
    /// Release gate: version sync plus a CHANGELOG entry for the current version.
    CheckReleaseVersions,
    /// Bump every version-bearing file to the next patch/minor/major version.
    BumpVersion {
        #[arg(value_enum)]
        level: version::BumpLevel,
    },
    /// Re-apply the canonical version (Cargo.toml) to every other
    /// version-bearing file. Fixup step for release-please: its native
    /// `rust` strategy bumps Cargo.toml/Cargo.lock/CHANGELOG.md directly but
    /// can't reach every carrier (regex patterns such as server.json's image
    /// tag, and the nested harness lockfiles under tests/live/).
    SyncVersion,
    /// Run the path-aware local pre-push router.
    PrePush(pre_push::PrePushArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = std::env::current_dir()?;
    match cli.command {
        Command::CheckVersionSync => version::check_sync(&root)?,
        Command::CheckReleaseVersions => version::check_release(&root)?,
        Command::BumpVersion { level } => version::bump(&root, level)?,
        Command::SyncVersion => version::sync_version(&root)?,
        Command::PrePush(args) => pre_push::run(&root, args)?,
    }
    Ok(())
}
