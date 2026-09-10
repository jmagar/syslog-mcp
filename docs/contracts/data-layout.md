---
title: "Data Directory Layout Contract (V1)"
created: 2026-05-16
updated: 2026-08-24
---

# Data Directory Layout Contract (V1)

## 1. Purpose & status

Contract derived from `src/config.rs` (`storage.db_path`, `mcp.auth.sqlite_path`, `mcp.auth.key_path` and their resolution rules), `src/runtime.rs::build_auth_policy` + `enforce_restrictive_permissions` (file-mode enforcement for the auth files), `docker-compose.yml` (UID/GID + bind-mount), `Dockerfile` (container UID), and the agent design spec at `docs/superpowers/specs/2026-05-16-agent-mode-design.md` (agent-side files).

Goal: an operator should be able to back up, restore, move, audit secrets, and reason about filesystem permissions for `cortex` without surprise. Companion contracts: `docs/contracts/config-schema.md` (the knobs that name these files), `docs/contracts/runtime-lifecycle.md` (when files are opened, closed, and what crash safety guarantees apply).

## 2. Logical layout

The "data directory" is the **parent directory of `[storage].db_path`**. With the default `db_path = /data/cortex.db`, the data dir is `/data`. All auth files default to **relative** paths and `src/runtime.rs::resolve_auth_path` joins them to this parent, so a single `/data` bind-mount captures every stateful file the server writes.

```
<DATA_DIR>/                       # default: /data (container) or ${CORTEX_DATA_VOLUME}
├── cortex.db                     # primary SQLite DB (logs + FTS5)
├── cortex.db-wal                 # WAL sidecar — transient
├── cortex.db-shm                 # shared-memory sidecar — transient
├── auth.db                       # OAuth state (only when auth.mode = oauth)  — SECRET
├── auth.db-wal                   # WAL sidecar for auth.db — transient
├── auth.db-shm                   # shared-memory sidecar for auth.db — transient
├── auth-jwt.pem                  # JWT signing private key (PEM)  — SECRET
└── integration-credential.key    # HMAC key for auth.credential_generation  — SECRET
```

**No log files live here.** All ingested log records are stored *inside* `cortex.db`. The data dir contains only the DB and auth state; this is a deliberate property of the design so a single mount is the entire backup surface.

### Agent hosts (Epic A — planned)

On each fleet host running the agent binary (separate from the server), the agent stores its own state under `$XDG_STATE_HOME` / `$XDG_CONFIG_HOME`:

```
~/.config/cortex/agent-token             # long-lived auth token        — SECRET, 0600
~/.local/state/cortex/agent-buffer.redb  # local replay buffer (redb)   — bounded; safe to delete
```

These are agent-side files; the server data dir does **not** contain them.

## 3. File inventory

| Path | Owner | Required mode | Required UID | Sensitivity | Notes |
|---|---|---|---|---|---|
| `<DATA_DIR>/` | server | `0700` (recommended) or `0755` | `${CORTEX_UID}:${CORTEX_GID}` (default `1000:1000`) | mixed (contains secrets) | Created by the operator before container start. |
| `<DATA_DIR>/cortex.db` | SQLite via SQLx | `0600` (recommended); writable by runtime UID | runtime UID | **non-secret** under the V1 threat model — message text and ingest metadata only | No application-level encryption. Treat as confidential if your logs contain credentials (use `[enrichment].scrub_prompts` for AI-source records). |
| `<DATA_DIR>/cortex.db-wal` | SQLite | inherited from `cortex.db` | runtime UID | transient | Created on first WAL transaction. Auto-rebuilt if deleted while server is stopped. |
| `<DATA_DIR>/cortex.db-shm` | SQLite | inherited | runtime UID | transient | Memory-mapped; never grows large. |
| `<DATA_DIR>/auth.db` | lab-auth via SQLx | **`0600` enforced** (`src/runtime.rs::enforce_restrictive_permissions`) | runtime UID | **SECRET** | Contains issued OAuth tokens / sessions. Created only when `auth.mode = oauth`. |
| `<DATA_DIR>/auth.db-wal`, `auth.db-shm` | lab-auth | inherited | runtime UID | **SECRET (transient)** | Same as syslog WAL/SHM. |
| `<DATA_DIR>/auth-jwt.pem` | lab-auth | **`0600` enforced** | runtime UID | **SECRET — most sensitive file** | JWT signing private key. Losing this invalidates all issued tokens. Compromising this lets an attacker forge tokens. |
| `<DATA_DIR>/integration-credential.key` | server (`src/api/credential_generation.rs`) | **`0600` enforced** (created `0600`; tightened on load) | runtime UID | **SECRET** | 32 random bytes (hex). Keys the HMAC-SHA256 that publishes `auth.credential_generation` in the integration profile, so the value cannot be brute-forced from the API token alone. Created on first start with `CORTEX_API_TOKEN` set; symlinks refused; a corrupt file fails startup instead of regenerating. Back it up with `cortex.db`. |
| `~/.cortex/.env` (on the operator account, not under DATA_DIR) | `cortex setup` | `0600` written by setup | operator user | **SECRET** (contains tokens, OAuth secret) | Read by `src/config.rs::load_setup_env_file`. Refused if it is a symlink. |
| `~/.cortex/config.toml` | operator-edited | `0600` recommended | operator user | mixed | Layered before env per config-schema §2. |
| Agent host: `~/.config/cortex/agent-token` | agent binary | **`0600`** | agent UID | **SECRET** | Long-lived bearer-equivalent. Replace immediately after `cortex agent rotate`. |
| Agent host: `~/.local/state/cortex/agent-buffer.redb` | agent binary | `0600` recommended | agent UID | **possibly SECRET** (cached log lines) | Bounded local replay buffer; size-capped by agent config. |

### Path resolution rules (server side)

- `storage.db_path` is honored verbatim if absolute; the env-set parent must exist (validated at startup).
- `mcp.auth.sqlite_path` and `mcp.auth.key_path` are joined to `<DATA_DIR>` when relative. The defaults are relative (`auth.db`, `auth-jwt.pem`) so the single-mount property holds out of the box.
- Setting an absolute `key_path` (e.g. on a separate volume mounted only with `ro`+`exec`) is supported. Operators wanting key-on-different-disk should set it absolute and ensure the new parent is writable at startup (lab-auth needs to (re)create the file if missing).

## 4. UID / GID rules

Pulled from `docker-compose.yml` and the `Dockerfile`.

| Variable | Default | Where set | Effect |
|---|---|---|---|
| `CORTEX_UID` | `1000` | Compose `user:` line | Numeric UID the process runs as inside the container. |
| `CORTEX_GID` | `1000` | Compose `user:` line | Numeric GID. |
| `CORTEX_FILE_TAIL_GROUP` | `adm` | Compose `group_add:` line | Supplementary group for reading group-owned logs mounted at `/file-tail-root`. |

- **The data dir MUST be owned by the chosen UID before container start.** The container has no `chown`-on-startup step (and shouldn't — running as root for that purpose defeats the unprivileged-user posture).
- **WSL gotcha.** Bind-mounted Linux volumes from a Windows host may appear with `uid=0 gid=0` regardless of the host UID. Symptom: SQLite startup fails with `unable to open database file`. Fix on the host before first run:
  ```bash
  sudo chown -R 1000:1000 ./data
  sudo chmod 0700 ./data
  ```
- **Bare-metal systemd deployments** (`use_docker = false`): the systemd unit runs as the operator user; `<DATA_DIR>` is typically `$XDG_DATA_HOME/cortex` and is already owned by that UID, so the WSL gotcha does not apply.

## 5. Backup procedure (normative)

The data dir is the entire stateful surface. Backing it up is sufficient and necessary; there is nothing else to capture.

### Online (server running)

Use SQLite's online backup API. **Do NOT `cp cortex.db` while the server is running** — that captures an inconsistent WAL snapshot that may fail to open or silently drop recent writes.

```bash
# Logs DB
sqlite3 /data/cortex.db ".backup /backup/syslog-$(date +%F).db"

# Auth DB (only when auth.mode = oauth)
sqlite3 /data/auth.db ".backup /backup/auth-$(date +%F).db"

# JWT key — read while running is safe (file is rewritten only on first init, never updated mid-run)
install -m 0600 /data/auth-jwt.pem /backup/auth-jwt-$(date +%F).pem
```

The bundled CLI exposes the same operation: `cortex db backup --output /backup/cortex.db` calls SQLite's backup API under the hood.

### Offline (server stopped)

After a graceful `cortex compose down` (or `systemctl stop`):

```bash
# WAL/SHM sidecars may be absent after a clean shutdown — use cp with fallback
BACKUP=/backup/cortex-$(date +%F)
mkdir -p "$BACKUP"
cp /data/cortex.db "$BACKUP/cortex.db"
cp /data/auth-jwt.pem "$BACKUP/auth-jwt.pem" 2>/dev/null || true
cp /data/auth.db "$BACKUP/auth.db" 2>/dev/null || true
(cp /data/cortex.db-wal "$BACKUP/cortex.db-wal" 2>/dev/null || true)
(cp /data/cortex.db-shm "$BACKUP/cortex.db-shm" 2>/dev/null || true)
(cp /data/auth.db-wal   "$BACKUP/auth.db-wal"   2>/dev/null || true)
(cp /data/auth.db-shm   "$BACKUP/auth.db-shm"   2>/dev/null || true)
tar -czf "$BACKUP.tar.gz" -C "$(dirname "$BACKUP")" "$(basename "$BACKUP")"
rm -rf "$BACKUP"
```

Include the `-wal` and `-shm` sidecars when offline — together they form one consistent snapshot. The fallback `|| true` handles the case where the DB was shut down cleanly and the sidecars do not exist.

### What to back up if OAuth is configured

`auth.db` + `auth-jwt.pem` **must** be backed up alongside `cortex.db` when `auth.mode = oauth`. Losing the JWT key alone invalidates every issued token; losing the DB alone invalidates every active session. Losing both is recoverable only by re-running OAuth onboarding for every user.

## 6. Restore procedure

1. **Stop the server** (`cortex compose down` or `systemctl stop cortex`). Restoring under a running process risks corrupting the SQLite WAL handshake.
2. **Place files** into `<DATA_DIR>` at the same names. For an online-backup restore, only `cortex.db` (and `auth.db` if applicable) need be present — the WAL/SHM sidecars are auto-rebuilt on first connection.
3. **Verify ownership and modes**:
   ```bash
   chown -R ${CORTEX_UID:-1000}:${CORTEX_GID:-1000} /data
   chmod 0600 /data/auth.db   /data/auth-jwt.pem  # if OAuth
   ```
4. **Start the server.** It will replay any WAL present, rebuild SHM, and apply pending schema migrations.
5. **Verify** with `curl -sf http://localhost:3100/health` (per `docs/contracts/runtime-lifecycle.md` §5) and `cortex db integrity`.

## 7. Safe-to-delete matrix

| File | Safe to delete while running? | Safe to delete while stopped? | Effect |
|---|---|---|---|
| `cortex.db` | **No** | **No (data loss)** | Deletes every ingested log. Schema is recreated on next start; the resulting DB is empty. |
| `cortex.db-wal` | **No** (active transactions held here) | **Yes** | Stopped: WAL is rebuilt on next start. Running: corrupts in-flight transactions. |
| `cortex.db-shm` | **No** (memory-mapped) | **Yes** | Same as WAL. |
| `auth.db` | **No** (active sessions held) | **Yes** | All OAuth sessions invalidated. Users must re-authenticate via Google; refresh tokens stop working. |
| `auth.db-wal` / `auth.db-shm` | **No** | **Yes** | Same WAL/SHM rules as syslog. |
| `auth-jwt.pem` | **No** (signing key in active use) | **Yes (regenerates on start)** | Catastrophic: **all** issued OAuth access tokens AND refresh tokens become unverifiable. Forces every user to re-authenticate. lab-auth regenerates a new key on next start. |
| `integration-credential.key` | **No** (profile already published from it) | **Yes (regenerates on start)** | `auth.credential_generation` changes once, so every pinned integration must re-trust. The API token itself is unaffected. |
| `agent-token` (agent host) | **No** | rotates instead | Forces re-enrollment with `cortex agent enroll <token>`. |
| `agent-buffer.redb` (agent host) | tolerated; agent recreates | safe | Loses any logs buffered locally during a server outage that hadn't yet been replayed. |

## 8. Snapshot & move procedure

To migrate the data dir to a new disk / host while preserving every byte:

1. **Stop the server** on the source host.
2. **Copy preserving mode/ownership**: `rsync -aAX /data/ <new-mount>/data/`. Verify `auth.db` and `auth-jwt.pem` retain mode `0600` and owner `1000:1000` post-copy (`stat -c '%a %U:%G %n' …`).
3. **Update `storage.db_path`** (and any absolute `mcp.auth.*_path` values) if the new mount lives at a different path. For Compose deployments, this is usually unchanged — only `CORTEX_DATA_VOLUME` (the host-side bind) moves.
4. **Update Compose**: change the `volumes:` source to the new bind path or named volume. Leave the in-container `/data` target alone.
5. **Start the server.** Confirm `/health` returns 200 and `cortex db integrity` passes.
6. **Optionally retain the old mount** for one retention period before deleting, in case the new disk is itself faulty.

Cross-host moves additionally require ensuring the new host's UID `1000` (or whatever `CORTEX_UID` is set to) owns the data. The WSL gotcha (§4) applies to fresh host installs.

## 9. Storage budget — what determines max disk usage

The data dir's footprint is governed by `[storage]` knobs (see `docs/contracts/config-schema.md` §4):

- **Soft cap on logical DB size**: `storage.max_db_size_mb` (default `1024`, plugin default `8192`). When exceeded, oldest rows are deleted in `cleanup_chunk_size` batches until `recovery_db_size_mb` is reached.
- **Minimum free disk floor**: `storage.min_free_disk_mb` (default `0`, disabled). When enabled and the filesystem's free space drops below this, the storage task blocks new writes until free space reaches `recovery_free_disk_mb`; it does not delete rows to chase external whole-filesystem pressure.
- **Age-based purge**: `storage.retention_days` (default `90`). Hourly task deletes rows older than this regardless of size.
- **AdGuard tag exception**: AdGuard query records (`adguard-allowed`, `adguard-query`, `adguard-rewrite`) are hard-capped at 7 days (`ADGUARD_RETENTION_DAYS` in `src/runtime.rs`) because their volume otherwise dominates the FTS5 index.
- **Write-block on full**: if DB-size eviction cannot free enough space, or the free-disk guard is enabled and below threshold, `writer_storage_blocked` flips to `true` in `/health` and new writes are dropped (counters: `writer_logs_retained`, `writer_logs_discarded`). `writer_logs_retained` counts **distinct rows**, each once — the writer re-flushes its whole retained batch every 250 ms while blocked, so a per-attempt total would climb by the backlog size several times a second and misreport the volume of held data by orders of magnitude. `writer_logs_retained_current` is the level: how many rows are held right now, back to `0` when the backlog drains.
- **WAL growth**: SQLite's WAL grows during long transactions and shrinks on checkpoint. Cortex attempts bounded PASSIVE checkpoints after the WAL reaches `storage.wal_checkpoint_mb`; `cortex db checkpoint --mode truncate` forces a shrink when needed.

There is no explicit cap on `auth.db` size — it stays small (sessions only) and is bounded operationally by user count + refresh-token TTL.

## 10. Unresolved questions

- **`auth.db` retention.** lab-auth currently retains expired session rows; the V1 storage budget task does not touch `auth.db`. At homelab scale this never matters; at scale the file may grow unbounded over years. Manual purge via `sqlite3 auth.db "DELETE FROM sessions WHERE expires_at < strftime('%s','now')-86400"` is the workaround until lab-auth adds a retention task.
- **Encryption-at-rest.** V1 has none. Operators handling logs that contain sensitive data should rely on filesystem-level encryption (LUKS / ZFS native encryption) or the `[enrichment].scrub_prompts` knob for AI-source content.
- **No checksum/manifest file.** There is no `.manifest` describing expected file modes for `cortex dr` to audit against. Adding one (similar to systemd-tmpfiles) is deferred — for now, `enforce_restrictive_permissions` is the only programmatic mode-tightening step, and it runs on every startup for `auth.db` and `auth-jwt.pem` only.
