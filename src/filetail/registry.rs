use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use parking_lot::Mutex;

use super::models::FileTailSource;

#[derive(Debug)]
pub(crate) struct FileTailRegistry {
    path: PathBuf,
    state_lock: Mutex<()>,
    mutation_lock: Mutex<()>,
    #[cfg(test)]
    write_count: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    fail_checkpoint_writes: std::sync::atomic::AtomicBool,
}

impl FileTailRegistry {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            state_lock: Mutex::new(()),
            mutation_lock: Mutex::new(()),
            #[cfg(test)]
            write_count: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_checkpoint_writes: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn path_from_storage_db(db_path: &Path) -> PathBuf {
        db_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("file-tails.json")
    }

    pub(crate) fn list(&self) -> Result<Vec<FileTailSource>> {
        let _guard = self.state_lock.lock();
        self.read_locked()
    }

    pub(crate) fn get(&self, id: &str) -> Result<Option<FileTailSource>> {
        let _guard = self.state_lock.lock();
        Ok(self
            .read_locked()?
            .into_iter()
            .find(|source| source.id == id))
    }

    #[cfg(test)]
    pub(crate) fn upsert(&self, source: FileTailSource) -> Result<()> {
        let _guard = self.state_lock.lock();
        let mut sources = self.read_locked()?;
        sources.retain(|existing| existing.id != source.id);
        sources.push(source);
        sources.sort_by(|a, b| a.id.cmp(&b.id));
        self.write_locked(&sources)
    }

    pub(crate) fn insert_if_absent(&self, source: FileTailSource) -> Result<()> {
        let _guard = self.state_lock.lock();
        let mut sources = self.read_locked()?;
        if sources.iter().any(|existing| existing.id == source.id) {
            anyhow::bail!("file tail source already exists: {}", source.id);
        }
        sources.push(source);
        sources.sort_by(|a, b| a.id.cmp(&b.id));
        self.write_locked(&sources)
    }

    pub(crate) fn mutate_with_reconcile<M, R>(&self, mutate: M, reconcile: R) -> Result<()>
    where
        M: FnOnce(&Self) -> Result<()>,
        R: FnOnce() -> Result<()>,
    {
        let _mutation_guard = self.mutation_lock.lock();
        let before = self.list()?;
        mutate(self)?;

        if let Err(reconcile_error) = reconcile() {
            let rollback = {
                let _state_guard = self.state_lock.lock();
                self.restore_locked(before)
            };
            return match rollback {
                Ok(()) => Err(anyhow::anyhow!(
                    "file-tail reconcile failed; registry mutation rolled back: {reconcile_error}"
                )),
                Err(rollback_error) => Err(anyhow::anyhow!(
                    "file-tail reconcile failed: {reconcile_error}; registry rollback failed: {rollback_error}"
                )),
            };
        }

        Ok(())
    }

    pub(crate) fn remove(&self, id: &str) -> Result<()> {
        let _guard = self.state_lock.lock();
        let mut sources = self.read_locked()?;
        let before = sources.len();
        sources.retain(|existing| existing.id != id);
        if sources.len() == before {
            anyhow::bail!("file tail source not found: {id}");
        }
        self.write_locked(&sources)
    }

    pub(crate) fn set_enabled(&self, id: &str, enabled: bool, now: &str) -> Result<()> {
        let _guard = self.state_lock.lock();
        let mut sources = self.read_locked()?;
        let source = sources
            .iter_mut()
            .find(|source| source.id == id)
            .with_context(|| format!("file tail source not found: {id}"))?;
        source.enabled = enabled;
        source.updated_at = now.to_string();
        self.write_locked(&sources)
    }

    pub(crate) fn update_checkpoint(
        &self,
        id: &str,
        dev: u64,
        ino: u64,
        offset: u64,
        now: &str,
    ) -> Result<()> {
        #[cfg(test)]
        if self
            .fail_checkpoint_writes
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            anyhow::bail!("injected file-tail checkpoint persistence failure");
        }
        let _guard = self.state_lock.lock();
        let mut sources = self.read_locked()?;
        let source = sources
            .iter_mut()
            .find(|source| source.id == id)
            .with_context(|| format!("file tail source not found: {id}"))?;
        source.checkpoint_dev = Some(dev);
        source.checkpoint_ino = Some(ino);
        source.checkpoint_offset = Some(offset);
        source.updated_at = now.to_string();
        self.write_locked(&sources)
    }

    fn read_locked(&self) -> Result<Vec<FileTailSource>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let raw = std::fs::read_to_string(&self.path)
            .with_context(|| format!("read {}", self.path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {}", self.path.display()))
    }

    fn write_locked(&self, sources: &[FileTailSource]) -> Result<()> {
        #[cfg(test)]
        self.write_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let tmp = self.path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(sources)?;
        std::fs::write(&tmp, body).with_context(|| format!("write {}", tmp.display()))?;
        atomic_replace(&tmp, &self.path)
            .with_context(|| format!("replace {}", self.path.display()))?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn write_count(&self) -> usize {
        self.write_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn set_fail_checkpoint_writes(&self, fail: bool) {
        self.fail_checkpoint_writes
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    fn restore_locked(&self, mut before: Vec<FileTailSource>) -> Result<()> {
        let current = self.read_locked()?;
        for source in &mut before {
            let Some(live) = current.iter().find(|live| live.id == source.id) else {
                continue;
            };
            let checkpoint_changed = (
                live.checkpoint_dev,
                live.checkpoint_ino,
                live.checkpoint_offset,
            ) != (
                source.checkpoint_dev,
                source.checkpoint_ino,
                source.checkpoint_offset,
            );
            if checkpoint_changed {
                source.checkpoint_dev = live.checkpoint_dev;
                source.checkpoint_ino = live.checkpoint_ino;
                source.checkpoint_offset = live.checkpoint_offset;
                source.updated_at.clone_from(&live.updated_at);
            }
        }
        self.write_locked(&before)
    }
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers that live
    // through the call. Flags request same-volume atomic replacement and a
    // durable metadata flush.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
