# Deploy Runbook — syslog-mcp

## Rolling Update

```bash
# 1. Pull latest code
git pull origin main

# 2. Build new image
docker compose build

# 3. Run smoke test against current running instance (optional)
bash bin/smoke-test.sh

# 4. Rolling restart — new container replaces old
docker compose up -d

# 5. Wait for health check to pass (30s interval, 3 retries)
docker compose ps   # should show "healthy"
# or:
curl -sf http://localhost:3100/health

# 6. Verify logs are flowing
docker compose logs -f --tail=20 syslog-mcp
```

## Rollback

```bash
# Option 1: Revert to previous image (if tagged)
docker compose down
git checkout <previous-tag>
docker compose build
docker compose up -d

# Option 2: Revert to previous commit
git log --oneline -5   # find the good commit
git revert HEAD         # or git reset --hard <sha>
docker compose build && docker compose up -d
```

## Health Check

The container includes a built-in healthcheck (`wget -q --spider http://localhost:3100/health`).
Docker will mark the container unhealthy after 3 consecutive failures (30s interval, 5s timeout).

```bash
# Check container health status
docker inspect --format='{{.State.Health.Status}}' syslog-mcp
```

## Pre-deploy Checklist

- [ ] `cargo test` passes locally
- [ ] `cargo clippy` has no warnings
- [ ] No uncommitted changes (`git status` clean)
- [ ] Database backup taken (see backup section below)

## Database Backup Before Deploy

```bash
# WAL-safe online backup (no downtime)
docker compose exec syslog-mcp sqlite3 /data/syslog.db ".backup /data/syslog-pre-deploy.db"
```
