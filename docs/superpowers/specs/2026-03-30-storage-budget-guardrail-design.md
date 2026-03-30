# Storage Budget Guardrail Design

## Summary

`syslog-mcp` currently controls growth only with age-based retention (`retention_days`). That is not sufficient to protect a user's disk when log volume spikes or retention is disabled. This design adds a storage budget guardrail that:

- caps the SQLite database itself,
- protects minimum free space on the filesystem hosting the database,
- automatically deletes the oldest logs to recover space,
- blocks new writes if recovery cannot restore a safe budget.

The new guardrail is additive. Existing age-based retention remains the normal long-term pruning policy; the new storage budget path is an emergency protection mechanism.

## Goals

- Prevent the database from consuming enough space to destabilize the host.
- Recover automatically before writes are blocked.
- Fail closed when the system is still out of budget after cleanup.
- Keep configuration simple and consistent with existing `SYSLOG_MCP_*` conventions.
- Make the storage state visible in logs and stats.

## Non-Goals

- Perfect preservation of all logs under disk pressure.
- Cross-filesystem quota management outside the DB filesystem.
- Replacing SQLite or changing the existing log schema beyond what is needed for enforcement.

## Recommended Approach

Use periodic storage enforcement plus write-time hard-stop protection.

This combines:

- a background task that measures DB size and free disk, then runs oldest-first cleanup when soft thresholds are crossed,
- a lightweight pre-insert check in the batch writer so the process can stop writes quickly when the hard budget is still unsafe after cleanup.

This approach fits the current architecture:

- `src/main.rs` already runs an hourly retention task,
- `src/syslog.rs` already funnels writes through a single batch writer path,
- `src/db.rs` already contains retention SQL and DB stats logic.

## Configuration

Add the following fields to `StorageConfig` and expose them via `config.toml` and `SYSLOG_MCP_*` environment variables:

- `max_db_size_mb: u64`
  - Soft trigger for emergency cleanup based on SQLite file size.
  - `0` disables the DB-size limit.
- `recovery_db_size_mb: u64`
  - Cleanup target after a DB-size breach.
  - Must be lower than `max_db_size_mb` when both are enabled.
- `min_free_disk_mb: u64`
  - Soft trigger for emergency cleanup based on free space in the DB filesystem.
  - `0` disables the free-space limit.
- `recovery_free_disk_mb: u64`
  - Cleanup target after a free-space breach.
  - Must be higher than `min_free_disk_mb` when both are enabled.
- `cleanup_interval_secs: u64`
  - Frequency of background storage enforcement.
  - Default should be short enough to react promptly without constant churn.

### Suggested Defaults

- `max_db_size_mb = 1024`
- `recovery_db_size_mb = 900`
- `min_free_disk_mb = 512`
- `recovery_free_disk_mb = 768`
- `cleanup_interval_secs = 60`

These defaults are intentionally conservative. They provide a buffer below the trigger thresholds so cleanup does not thrash on every cycle.

### Loader Compatibility

The current `Config::load()` implementation deserializes `config.toml` directly into the full struct, replacing the default config object instead of merging field-by-field. Because of that, simply documenting defaults is not enough. Implementation must also preserve backward compatibility for existing `config.toml` files by doing one of the following:

- add serde defaults for every new storage field so omitted keys continue to load successfully, or
- change config loading to merge parsed values onto `Config::default()` instead of replacing the whole struct.

The preferred approach is serde defaults on the new fields because it is the smaller, lower-risk change.

## Runtime Model

### 1. Storage Health Evaluation

Add a storage health evaluator in `src/db.rs` that reports:

- current logical DB size in MB,
- current free space in MB for the DB filesystem,
- which thresholds are breached,
- whether the system is healthy, reclaiming, or write-blocked.

For `max_db_size_mb`, the DB-size budget should be defined as logical in-use SQLite size, not raw `.db` file length on disk. In WAL mode, deleting rows usually frees pages for reuse inside SQLite without shrinking the main file immediately, so a physical file-size cap would be noisy and may never recover without a heavier operation like `VACUUM`.

The logical DB size should therefore be derived from SQLite page accounting, for example `(page_count - freelist_count) * page_size`, with WAL bytes treated separately as part of the free-disk protection story rather than the logical DB budget.

After cleanup, enforcement should still checkpoint WAL so transient WAL growth is pushed back into the main database state as quickly as practical. The free-disk limit remains the primary mechanism for protecting actual filesystem capacity.

### 2. Background Enforcement Task

Add a new periodic task in `src/main.rs`, separate from age retention:

- runs every `cleanup_interval_secs`,
- evaluates storage health,
- if any soft threshold is breached, deletes oldest logs in bounded chunks,
- stops once all enabled recovery targets are satisfied,
- logs the before/after measurements and rows deleted.

The task should be independent of whether new logs are arriving. A DB that is already too large should recover even when traffic is idle.

### 3. Write-Time Hard Stop

Add a lightweight pre-insert check in the batch writer path in `src/syslog.rs`:

- before writing a batch, check whether storage is still above an unsafe threshold,
- if unsafe, do not insert the batch,
- emit a clear error that includes the active measurements and thresholds,
- continue retrying on later flush cycles so writes can resume automatically once space is healthy again.

This preserves the existing "retain and retry" model better than dropping batches immediately. If the process remains blocked long enough to exhaust the in-memory queue, data loss can still occur; that is already true for persistent write failures today and should be documented explicitly.

## Cleanup Semantics

Emergency cleanup is oldest-first deletion by `received_at`, not by the syslog message `timestamp`. This matches the existing retention trust model and avoids a skewed or malicious device clock making fresh logs appear artificially old.

Emergency cleanup is intentionally separate from `retention_days`:

- `retention_days` is normal lifecycle management,
- storage-budget cleanup is emergency pressure relief.

Cleanup deletes only enough data to reach the configured recovery targets, not just the trigger threshold. This buffer reduces repeated oscillation around the limit.

For clarity:

- `max_db_size_mb` and `recovery_db_size_mb` apply to logical live SQLite usage,
- `min_free_disk_mb` and `recovery_free_disk_mb` apply to actual filesystem free space.

Because free-disk protection is about physical space, the implementation also needs an explicit shrink strategy after row deletion when `min_free_disk_mb` is still breached. The preferred design is:

- enable `auto_vacuum=INCREMENTAL` for new databases during initialization,
- migrate existing databases to incremental auto-vacuum with the required `VACUUM` step once at upgrade time,
- after emergency deletes and WAL checkpoint, run bounded `PRAGMA incremental_vacuum` work before deciding that free-space recovery has failed.

This gives the free-disk limit a physical reclamation path without making full `VACUUM` part of the steady-state emergency loop.

Deletion should happen in bounded chunks, not one unbounded transaction. Each chunk should:

- select the oldest candidate rows by `received_at`,
- delete them,
- commit,
- re-measure storage health,
- stop as soon as recovery is achieved.

Chunking keeps the server responsive and limits long-running write locks.

## Failure Handling

- If cleanup succeeds and thresholds are back within recovery targets, writes remain enabled.
- If cleanup runs but cannot achieve recovery, the system enters or remains in a write-blocked state.
- If cleanup itself fails, log the error and keep writes blocked when the system is still unsafe.
- When the system returns to a healthy state, emit a distinct "writes resumed" log entry.
- Warning logs near threshold crossings should be rate-limited enough to stay useful.

The guiding rule is simple: if the server cannot confidently protect the host's disk, it should stop accepting new writes.

## Observability

Extend stats and logs so operators can diagnose storage pressure quickly.

Emergency cleanup must also keep the `hosts` table logically consistent enough for `list_hosts` and stats to remain trustworthy after deletions. The implementation should reconcile affected host rows after each cleanup cycle by updating:

- `log_count`,
- `first_seen`,
- `last_seen`,
- and deleting `hosts` rows that no longer have any backing logs.

Reconciliation can be limited to hosts touched by the deleted chunk rather than rebuilding the entire table every cycle.

### Logging

Add structured logs for:

- threshold breach detection,
- cleanup start and finish,
- rows deleted per cleanup cycle,
- failure to reclaim enough space,
- write blocking,
- write resumption.

### MCP Stats

Extend `get_stats` output to include storage health fields such as:

- current logical DB size,
- current physical DB file size if practical,
- current free disk,
- enabled thresholds,
- write-blocked status,
- last cleanup outcome if practical.

`get_stats` must label these metrics clearly so operators can distinguish the logical DB budget from the on-disk file footprint. Enforcement should key off the logical DB size metric, while disk-safety decisions continue to rely on free-disk measurements.

This makes the guardrail visible to existing MCP clients without requiring direct shell access.

## Data Flow

1. Syslog listener receives messages and queues them for batch insert.
2. Batch writer checks whether the system is currently safe to write.
3. If safe, insert batch normally.
4. Background enforcement periodically measures storage health.
5. If thresholds are breached, it deletes oldest logs until recovery targets are met or cleanup is exhausted.
6. If recovery fails, the writer remains blocked until later enforcement cycles observe healthy storage again.

## Validation Rules

Configuration validation should reject:

- `pool_size == 0` (existing rule),
- `recovery_db_size_mb >= max_db_size_mb` when `max_db_size_mb > 0`,
- `recovery_db_size_mb == 0` when `max_db_size_mb > 0`,
- `recovery_free_disk_mb <= min_free_disk_mb` when `min_free_disk_mb > 0`,
- `recovery_free_disk_mb == 0` when `min_free_disk_mb > 0`,
- `cleanup_interval_secs == 0`,
- `cleanup_interval_secs < 5`.

Each trigger limit must be independently disable-able with `0`. Recovery targets may be `0` only when the corresponding trigger is also `0`; otherwise they must be non-zero and on the safe side of the trigger threshold.

## Testing Strategy

Add tests for:

- config parsing and validation for all new fields,
- DB-size cleanup to the configured recovery target,
- free-space-triggered cleanup behavior using a test seam around the disk-space probe,
- hard-limit write rejection when cleanup cannot recover enough space,
- automatic write resumption after storage becomes healthy,
- disabled-limit behavior (`0` values),
- WAL checkpoint and size-accounting edge cases where applicable.

The test shape should favor isolated DB/unit tests over broad integration tests whenever possible.

## Documentation Changes

Update:

- `config.toml` comments,
- `README.md`,
- `CLAUDE.md`.

The docs must clearly state:

- the defaults,
- how to disable each limit,
- that emergency cleanup permanently deletes oldest logs,
- that writes can be blocked to protect the host,
- that retention and storage-budget cleanup are separate mechanisms.

## Risks

- Measuring DB size imprecisely around WAL growth could cause cleanup to run later than expected.
- Free-space checks are platform-sensitive and need a robust implementation path.
- Under sustained ingest pressure, in-memory buffering can still overflow while writes are blocked.
- Aggressive defaults could surprise users on small systems; overly loose defaults reduce the feature's value.

These risks are acceptable if surfaced in docs and verified with focused tests.

## Open Implementation Notes

- Prefer keeping the storage policy in Rust config rather than relying on SQLite-only page limits.
- Reuse existing retention-style SQL patterns where practical instead of introducing a separate archival mechanism.
- Keep the guardrail additive and easy to reason about. Operators should be able to answer: what triggered cleanup, how much was deleted, and whether writes are currently blocked.
