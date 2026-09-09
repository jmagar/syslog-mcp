---
title: "Deploy Runbook — cortex"
created: 2026-03-30
updated: 2026-07-30
---

# Deploy Runbook — cortex

## Rolling Update

```bash
# 1. Pull latest code
git pull origin main

# 2. Diagnose the current owner before mutation
cortex compose doctor

# 3. Run smoke test against current running instance (optional)
bash scripts/smoke-test.sh

# 4. Pull/build as needed, then start the resolved Compose service
cortex compose pull
cortex compose up

# 5. Wait for health check to pass (30s interval, 3 retries)
cortex compose status   # should show healthy Compose ownership
# or:
curl -sf http://localhost:3100/health

# 6. Verify logs are flowing
cortex compose logs --tail 20
```

## Automatic Local Deploy

The active devhost deployment is the local source-built Compose stack
(`docker-compose.yml`, image `cortex-cortex`). GitHub publishes GHCR images, but
that does not update this local stack by itself. Install the user timer below to
keep the server aligned with `origin/main`:

```bash
mkdir -p ~/.config/systemd/user
cp config/systemd/cortex-auto-deploy.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now cortex-auto-deploy.timer
systemctl --user start cortex-auto-deploy.service
systemctl --user status cortex-auto-deploy.timer cortex-auto-deploy.service
```

The service runs `scripts/auto-deploy.sh`: it refuses dirty/non-`main`
checkouts, fast-forwards from `origin/main`, rebuilds the local image, recreates
the `cortex` service, waits for `/health`, and verifies the in-container
`cortex --version` matches `Cargo.toml`.

## Rollback

Which rollback path applies depends on the compose file in use:

- **`docker-compose.yml` (default)** builds the image from source — rolling
  back means checking out the previous commit/tag and rebuilding.
- **`docker-compose.prod.yml`** pulls tagged images from ghcr.io — rolling
  back means pinning `CORTEX_VERSION` to the previous tag.

```bash
# Option 1: prod compose — pin the previous image tag
cortex compose down --yes
CORTEX_VERSION=<previous-tag> docker compose -f docker-compose.prod.yml up -d

# Option 2: default compose — rebuild from the previous commit/tag
cortex compose down --yes
git checkout <previous-tag>
docker compose build
cortex compose up
```

## Health Check

The container includes a built-in healthcheck
(`curl -sf http://localhost:3100/health || exit 1`). Docker will mark the
container unhealthy after 3 consecutive failures (30s interval, 5s timeout).
Note that `/health` returns 503 when a started syslog listener has died, so
an unhealthy container can mean ingest is down even though HTTP is up —
check `/health/full` (`syslog_udp_listener_state` /
`syslog_tcp_listener_state`) to distinguish.

```bash
# Check container health status
docker inspect --format='{{.State.Health.Status}}' cortex
```

## Pre-deploy Checklist

- [ ] `cargo test` passes locally
- [ ] `cargo clippy` has no warnings
- [ ] No uncommitted changes (`git status` clean)
- [ ] Database backup taken (see backup section below)
- [ ] For populated databases, review [Heavy SQLite Migration Upgrade](#heavy-sqlite-migration-upgrade) before restarting

## Database Backup Before Deploy

The image does not ship a `sqlite3` binary — use the built-in `cortex db
backup` command (WAL-safe, no downtime):

```bash
# Inside the container
docker compose exec cortex cortex db backup --output /data/syslog-pre-deploy.db

# Or from the host, when the DB path is reachable (bind mount)
bash scripts/backup.sh             # writes ./backups/syslog-<timestamp>.db
cortex db backup --output /path/to/backup.db
```

`scripts/backup.sh` performs a WAL-safe checkpoint and SQLite `.backup` from
the host and also captures `auth.db` / `auth-jwt.pem` when present. For
scheduled backups, see "Automated backups (systemd timer)" below.

## Heavy SQLite Migration Upgrade

Most schema migrations run automatically at startup and are safe for normal rolling updates. Some migrations are intentionally heavier, such as creating an index on a populated `logs` table. Those can hold SQLite's write lock for several minutes before `/health` responds or syslog listeners start, so treat them as a planned ingest maintenance window on large databases.

Use this path when release notes, startup logs, or `docs/CONFIG.md` indicate a heavy migration:

```bash
# 1. Confirm current database size and baseline counts.
docker compose exec cortex cortex db status --json

# 2. Take a WAL-safe backup (no sqlite3 in the image — use the built-in command).
docker compose exec cortex cortex db backup --output /data/syslog-pre-heavy-migration.db

# 3. Build or pull the new version, then start it.
docker compose build
docker compose up -d

# 4. Watch for migration start/completion lines.
docker compose logs -f cortex

# 5. Verify health and storage state after completion.
curl -sf http://localhost:3100/health
mcporter call --config config/mcporter.json cortex.cortex action=stats
```

Expected operator signals:

- Startup logs include `Migration N: starting ...` before a heavyweight operation.
- Completion logs include the migration name and elapsed time.
- `/health` may fail until the migration commits.
- UDP senders can lose packets while the listener is unavailable; TCP senders may reconnect or buffer depending on their own config.
- The first startup against a pre-existing database also runs a **one-time
  `auto_vacuum=INCREMENTAL` conversion VACUUM**, logged loudly at startup. It
  can take minutes on large databases; treat it like a heavy migration.

Rollback while a migration is running is a restore operation, not a partial schema edit. Stop the new process, restore the WAL-safe backup to `/data/cortex.db`, then start the previous image or binary.

## Docker Ingest Integration Check

The default `scripts/smoke-test.sh` covers live UDP and TCP ingest plus MCP actions. Current Docker log coverage is split: host-local cortex agent parity is covered by agent deployment tests, and the legacy central pull path is covered by a mocked Docker HTTP fixture. Run an explicit fixture-backed integration check only when changing the legacy pull path:

1. Start a disposable Docker-compatible HTTP fixture. If it is docker-socket-proxy, use `CONTAINERS=1`, `EVENTS=1`, `PING=1`, `VERSION=1`, and `POST=0`.
2. Start cortex with `CORTEX_DOCKER_INGEST_ENABLED=true` and `CORTEX_DOCKER_HOSTS=<fixture-host>`.
3. Run a short-lived container that writes a unique marker to stdout and stderr.
4. Verify `search` or `tail` returns the marker and that stream rows use `source_ip=docker://<host>/<container>/<stream>`.
5. Restart or recreate the disposable container and verify lifecycle rows use `source_ip=docker-event://<host>/<container>/<action>` with `facility=docker`.
5. Stop the fixture and confirm cortex logs reconnect/backoff without crashing.

## Restore

Restoring a backup is a stop-the-world operation — never copy a backup over a
live WAL-mode database.

```bash
# 1. Stop the service.
cortex compose down --yes        # or: docker compose down

# 2a. Default named volume: restore through a one-shot helper using the same
#     stable volume name as Compose. Backups are on the off-volume host mount.
docker run --rm \
  -v "${CORTEX_VOLUME_NAME:-cortex-data}:/data" \
  -v "${CORTEX_BACKUP_DIR:-$HOME/.cortex/backups}:/backups:ro" \
  debian:bookworm-slim sh -c \
  'cp /backups/syslog-<timestamp>.db /data/cortex.db && \
   test ! -f /backups/auth-<timestamp>.db || cp /backups/auth-<timestamp>.db /data/auth.db; \
   test ! -f /backups/auth-jwt-<timestamp>.pem || cp /backups/auth-jwt-<timestamp>.pem /data/auth-jwt.pem; \
   rm -f /data/cortex.db-wal /data/cortex.db-shm /data/auth.db-wal /data/auth.db-shm'

# 2b. Bind-mounted /data: copy directly to the configured host directory.
cp /path/to/backups/syslog-<timestamp>.db /absolute/data/path/cortex.db
cp /path/to/backups/auth-<timestamp>.db /absolute/data/path/auth.db
cp /path/to/backups/auth-jwt-<timestamp>.pem /absolute/data/path/auth-jwt.pem
rm -f /absolute/data/path/cortex.db-wal /absolute/data/path/cortex.db-shm

# 3. Fix bind-mount ownership. The container runs as a non-root UID (1000 by
#    default) and writes auth.db / auth-jwt.pem with that UID — a restore
#    done as root or your login user leaves files the container cannot open.
docker run --rm -v "${CORTEX_VOLUME_NAME:-cortex-data}:/data" debian:bookworm-slim \
  chown 1000:1000 /data/cortex.db
#    (also restore + chown auth.db / auth-jwt.pem if you backed them up)

# 4. Verify integrity before starting (direct SQLite — the HTTP API is down).
( unset CORTEX_USE_HTTP; cortex db integrity )   # PRAGMA integrity_check

# 5. Restart and verify.
cortex compose up
curl -sf http://localhost:3100/health          # 200 = HTTP up and listeners alive
cortex stats --json                            # totals match the backup's era
mcporter call --config config/mcporter.json cortex.cortex action=ingest_rate
#    ingest_rate should show fresh writes within a minute once senders reconnect
```

If `cortex db integrity` reports errors, do not start the service — pick an
older backup.

## Automated backups (systemd timer)

The repo ships ready-made user units in `config/systemd/`:
`cortex-backup.service` and `cortex-backup.timer` (daily, with a randomized
delay so fleet hosts don't all fire at once). They invoke `scripts/backup.sh`
with a configurable `BACKUP_DIR`.

```bash
# User units (recommended for the ~/.cortex layout)
mkdir -p ~/.config/systemd/user
cp config/systemd/cortex-backup.{service,timer} ~/.config/systemd/user/
# Edit WorkingDirectory / Environment=BACKUP_DIR / CORTEX_DB_PATH as needed
systemctl --user daemon-reload
systemctl --user enable --now cortex-backup.timer
systemctl --user list-timers cortex-backup.timer

# Or system-wide
sudo cp config/systemd/cortex-backup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cortex-backup.timer
```

Keep backups on a different disk or host than the live database — a full-disk
or dead-drive event otherwise takes the backups with it. A simple pattern is
an rsync step after the timer fires (e.g. `rsync -a ~/.cortex/backups/
backup-host:/backups/cortex/`, in this homelab: replicate to `backuphost`), or
point `BACKUP_DIR` at a mount that is itself replicated.
