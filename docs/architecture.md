---
title: "cortex architecture"
created: 2026-05-18
updated: 2026-07-30
---

# cortex architecture

cortex is one binary, but operationally it is three sub-products sharing a
SQLite database and a service layer:

1. **Log intelligence core** — syslog UDP/TCP ingest, OTLP `/v1/logs`,
   host-local agent Docker log ingest, legacy central pull Docker compatibility,
   AI transcript indexing, FTS5 search, and the
   56-action `cortex` MCP tool plus the `/api/*` REST mirror. Source: `src/receiver/`,
   `src/ingest.rs`, `src/otlp.rs`, `src/agent/`, `src/docker_ingest/`, `src/db/`,
   `src/mcp/`, `src/api.rs`, `src/app/`.
2. **Fleet SSH inventory / investigation graph** — SSH- and API-based homelab
   inventory collection into `~/.cortex/inventory`, the normalized
   `homelab.json` cache, heartbeat telemetry, and the rebuildable graph
   projection behind the `map`/`graph` actions. Source: `src/inventory/`,
   `src/heartbeat.rs`, `src/heartbeat_agent.rs`.
3. **Deployment tooling** — install/repair of the shared `~/.cortex` Docker
   Compose layout, live Compose-owner resolution, and diagnostics. Source:
   `src/compose/`, `src/setup/`, `src/deploy.rs`, `src/doctor.rs`.

## Module map

| Module | Sub-product | Purpose |
| --- | --- | --- |
| `config.rs` | all | Layered config: defaults → `config.toml` → `~/.cortex/.env` → process env; startup validation (non-loopback auth gate) |
| `runtime.rs` + `runtime/` | all | `RuntimeCore`: wires pool, ingest, auth policy; spawns the maintenance tasks below |
| `app/` | core | `CortexService` service layer — shared limits/validation for MCP, REST, and CLI |
| `db/` | core | SQLite pool + 58 sequential migrations, FTS5 queries, retention and storage-budget maintenance |
| `receiver/` + `receiver.rs` | core | UDP + TCP listeners (supervised with restart + backoff), RFC 3164/5424 + CEF parsing |
| `ingest.rs` | core | mpsc channel + batch writer (one pool connection reserved for this writer) |
| `otlp.rs` | core | OTLP/HTTP `POST /v1/logs` (protobuf, 4 MiB cap) |
| `agent/`, `heartbeat_agent.rs` | inventory | Host-local cortex agent, including Docker log streaming from the local socket |
| `docker_ingest/` | core | Legacy central pull container stdout/stderr + lifecycle events via explicit remote Docker Engine HTTP endpoints |
| `mcp/` | core | RMCP Streamable HTTP server, `ACTION_SPECS` registry, scope gates, `/health` + `/health/full` |
| `api.rs` | core | Always-on `/api/*` REST surface (93 method/path bindings), bearer-token gated |
| `scanner/`, `sessions_watch.rs` | core | AI transcript scanning/scrubbing and the host-side watch daemon |
| `inventory/` | inventory | Collectors (SSH, Docker, UniFi/Unraid/media APIs), redaction, normalized cache |
| `heartbeat.rs` / `heartbeat_agent.rs` | inventory | `POST /v1/heartbeats` ingest + host-local heartbeat agent |
| `notifications/` | core | Apprise dispatcher, rule evaluators (incl. `ingest_silence`), daily digest |
| `compose/`, `setup/`, `deploy.rs`, `doctor.rs` | deployment | Compose owner resolution, idempotent setup/repair, drift diagnostics |
| `cli/` | all | Direct CLI with full MCP parity; routes via `/api/*` when `CORTEX_USE_HTTP=true` |

## Background tasks

Spawned by `RuntimeCore::spawn_maintenance_tasks` (`src/runtime.rs`) and
supervised listeners:

| Task | Cadence | Knob |
| --- | --- | --- |
| Retention purge (global + AdGuard 7d tags + heartbeats 14d) | hourly (fixed) | `CORTEX_RETENTION_DAYS` (0 disables the global age purge) |
| Storage budget enforcement (DB-size delete / free-disk write-block) | every 60s | `CORTEX_CLEANUP_INTERVAL_SECS`, `CORTEX_MAX_DB_SIZE_MB`, `CORTEX_MIN_FREE_DISK_MB` |
| Error-signature scan | every 3600s | `CORTEX_ERROR_DETECTION_ENABLED`, `CORTEX_ERROR_DETECTION_SCAN_INTERVAL_SECS` |
| Notification dispatcher | every 30s | `[notifications] dispatcher_interval_secs` |
| Notification evaluator (oom_kill, ingest_silence, ...) | every 300s | `[notifications.evaluators] evaluator_interval_secs` |
| Notification daily digest | cron `0 8 * * *` (local) | `[notifications] digest_cron_local` |
| Inventory refresh (+ graph projection) | every 300s + file watchers | `CORTEX_INVENTORY_REFRESH_INTERVAL_SECS` (0 disables), `CORTEX_INVENTORY_WATCH_ENABLED` |
| Inventory graph backfill | one-shot at startup (skipped once complete) | — |
| AI session rollup refresh | every 300s (eager first run) | fixed (`SESSION_ROLLUP_REFRESH_SECS`) |
| Timeline hourly rollup (incremental) | every 60s | fixed (`TIMELINE_ROLLUP_REFRESH_SECS`) |
| `PRAGMA optimize` (planner stats) | every 6h | fixed (`OPTIMIZE_INTERVAL_SECS`) |
| Host-local agent Docker streams | continuous on deployed agents | agent deployment config + local Docker socket |
| Legacy central pull Docker streams | continuous, reconnect with backoff | `CORTEX_DOCKER_INGEST_ENABLED`, `CORTEX_DOCKER_RECONNECT_INITIAL_MS` / `_MAX_MS` |
| Syslog UDP/TCP listeners | continuous, supervised restart + backoff | `CORTEX_RECEIVER_HOST` / `_PORT` |

A dead syslog listener fails `/health` with 503; per-listener liveness
(`not_started` / `alive` / `down`) is reported in the `/health/full` ingest
snapshot as `syslog_udp_listener_state` / `syslog_tcp_listener_state`.

## Caller → database paths (post v0.26)

This captures how callers reach the SQLite database after the v0.26
CLI-over-HTTP cutover (epic `cortex-0p8r`). It complements the endpoint
matrix in [`docs/api.md`](api.md).

```text
AI clients ──▶ /mcp (rmcp streamable HTTP)        ─┐
                                                   │
CLI default ──▶ /api/* (REST)                      ├──▶ container SyslogService ──▶ SQLite (/data)
   [CORTEX_USE_HTTP=true since v0.26]              │       (db_permits pool + MAINTENANCE_PERMIT)
                                                   │
CLI explicit "unset CORTEX_USE_HTTP"  ─────────────┘
   ──▶ direct SQLite (RuntimeCore::load_query_only, read-only)

cortex sessions watch (systemd) ────────────────────────────▶ direct SQLite
   (service.add_ai_file; long-running daemon on the host)

cortex mcp stdio (spawned by AI clients) ─────────────▶ direct SQLite
   (one-shot stdio session bound to the host's DB path)
```

## Ownership

The container is the **canonical query-path owner**: every `/api/*`
caller — REST CLI, AI client over `/mcp`, anything routed through
SWAG — funnels through one `SyslogService` instance with shared
`db_permits` and `MAINTENANCE_PERMIT` gates. Direct-SQLite access
remains for two consumers that cannot reasonably go through HTTP — one
write-path and one read-path:

- `cortex sessions watch` (write-path) — a host-side systemd daemon that
  streams local AI transcript files into SQLite. Going through HTTP
  would mean uploading every JSONL chunk over loopback for no value, so
  this writer keeps direct `service.add_ai_file` access against the
  same DB file the container reads.
- `cortex mcp` stdio (read/query-path only) — spawned by AI clients
  (Claude Desktop, Codex) that don't speak HTTP-MCP. The stdio process
  opens the same DB path read-only via `RuntimeCore::load_query_only`,
  so it never participates in the write path.

Both direct-write consumers are detected by `cortex compose doctor`
(always-on) and optionally surfaced through `cortex db status --check-coord`.
See [`docs/api.md`](api.md) "Local-only commands" for the per-command
breakdown and the operational `systemd` timer recipe.
