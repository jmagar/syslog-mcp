//! Lifetime owner for isolated workers and their shared refresh credentials.
#[cfg(unix)]
use anyhow::Context;
use anyhow::{Result, bail};
use std::{fs::File, path::Path};

pub(super) struct Worker {
    pub child: Option<tokio::process::Child>,
    pub resources: std::sync::Arc<Resources>,
}

pub(super) struct Resources {
    pub home: tempfile::TempDir,
    pub cwd: tempfile::TempDir,
    // Separate lock inode: auth storage may rewrite the credential file.
    _auth_lock: File,
}

impl Worker {
    pub async fn prepare(source_home: &Path) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = source_home;
            bail!("Codex assessment credential isolation currently requires Unix");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let source = source_home.join("auth.json").canonicalize().context(
                "Codex assessment requires auth.json in CORTEX_CODEX_HOME; authenticate Codex first",
            )?;
            if !source.is_file() {
                bail!("Codex assessment auth.json must be a regular file");
            }
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(source.with_file_name("cortex-assessment-auth.lock"))?;
            loop {
                match lock.try_lock() {
                    Ok(()) => break,
                    Err(std::fs::TryLockError::WouldBlock) => {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                    Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
                }
            }
            let home = tempfile::Builder::new()
                .prefix("cortex-codex-home-")
                .tempdir()?;
            let cwd = tempfile::Builder::new()
                .prefix("cortex-codex-assess-")
                .tempdir()?;
            // Codex file credentials are updated in place. Share only that file,
            // not configuration, plugins, instructions or the rest of CODEX_HOME.
            // Refresh writes survive failures/cancellation without a copy-back race.
            std::os::unix::fs::symlink(source, home.path().join("auth.json"))?;
            Ok(Self {
                child: None,
                resources: std::sync::Arc::new(Resources {
                    home,
                    cwd,
                    _auth_lock: lock,
                }),
            })
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            child.start_kill()?;
            child.wait().await?;
        }
        self.child = None;
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Initiate termination synchronously before cancellation releases
            // authority. Keep the lock and directories until the child is reaped.
            let _ = child.start_kill();
            let resources = self.resources.clone();
            tokio::spawn(async move {
                let _resources = resources;
                let _ = child.wait().await;
            });
        }
    }
}
