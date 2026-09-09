---
title: "Runtime Lifecycle Contract (V1)"
created: 2026-05-16
updated: 2026-08-24
---

# Runtime Lifecycle Contract (V1)

## 1. Purpose & status

Contract derived from `src/main.rs` (CLI mode dispatch, `serve_mcp`, `shutdown_signal`), `src/runtime.rs` (`RuntimeCore`, `MaintenanceHandles`, `build_auth_policy`), `src/mcp/routes.rs::health`, and `src/observability.rs::RuntimeObservabilitySnapshot`. It pins the operator-visible process contract: which CLI mode does what, which signals are honored, how the server shuts down, the shape of `/health`, and the exit-code matrix.

Anyone wiring `cortex` into `systemd`, Docker, Kubernetes, or a Compose-managed deployment should be able to write correct probes, restart policies, and graceful-stop timeouts from this document alone.

Companion contracts: `docs/contracts/config-schema.md` (knobs that drive these modes), `docs/contracts/data-layout.md` (filesystem state the process owns).

## 2. Process modes (from `Mode::parse` in `src/main.rs`)

| Invocation | Mode | Starts | Skips | Use when |
|---|---|---|---|---|
| `cortex` (no args) or `cortex serve mcp` | **ServeMcp** | UDP+TCP syslog listeners, batch writer, retention task, storage-budget task, docker-ingest tasks (when enabled), HTTP MCP server on `[mcp].port`, OTLP `/v1/logs` mount, optional non-MCP `/api` mount | — | Production daemon — the one host per fleet that ingests and stores logs. |
| `cortex mcp` | **StdioMcp** | RMCP stdio transport bound to the same SQLite store (read-mostly query path) | All listeners; no HTTP port is bound; auth policy is forced to `LoopbackDev` (process isolation is the trust boundary) | Wiring `cortex` into an MCP client (Claude Code plugin, Codex) on a query-only client host. |
| `cortex setup [check\|repair\|doctor\|ai-index-timer …]` | **Setup** | One-shot setup phases (write `~/.cortex/.env`, render compose, install systemd timers, etc.) | Never binds listeners; never starts maintenance tasks | First-run install, plugin hook reruns, dev-mode rewires. |
| `cortex doctor [binary] [--json]` | **Doctor** | One-shot health audit (setup, compose, binary, AI transcripts) | Never binds listeners | Diagnostics / smoke checks. |
| `cortex search\|tail\|errors\|hosts\|sessions\|ai\|correlate\|stats\|db\|compose` | **Cli** | Single query or maintenance operation against the SQLite store via `RuntimeCore::load_query_only` | Never binds the syslog/HTTP listeners; never spawns maintenance tasks | Operator queries on the box; scripting. |
| `cortex --version` / `--help` | Version/Help | Print and exit | Everything | Banner. |

Default tracing filter per mode is set by `Mode::default_log_filter`: `info` for `ServeMcp`, `warn` for stdio/setup/doctor, `error` for one-shot CLI queries. `RUST_LOG` overrides.

**ServeMcp startup ordering** (`src/main.rs::serve_mcp`):

1. `RuntimeCore::load()` → `Config::load()` runs all §6 validations; on failure: `anyhow::bail!` → exit 1.
2. `db::init_pool` → opens SQLite, applies schema, enables WAL; on failure: exit 2 (anyhow bubble).
3. Initial storage-budget enforcement (when configured).
4. `start_writer_from_syslog_config` → spawns the batch writer.
5. `build_auth_policy` → fails fast on OAuth-init errors; tightens auth file perms to 0600.
6. `start_syslog().await` → binds UDP + TCP listeners (`SO_REUSEADDR` per Tokio defaults).
7. `spawn_maintenance_tasks()` → retention + storage + docker-ingest tasks.
8. Merge `mcp::router`, optional `/api`, and `runtime.otlp_router()` → final `axum::Router`.
9. `TcpListener::bind(mcp_bind)` → bind the MCP HTTP port; on failure: exit 3 (bind error).
10. `axum::serve(...).with_graceful_shutdown(shutdown_signal())` → run until SIGINT/SIGTERM.

Any failure before step 9 prevents the HTTP port from opening, so health probes can rely on `/health` being a strong "all listeners are up" indicator.

## 3. Signal handling

Signal handler installed by `src/main.rs::shutdown_signal`. Unix-only signals are guarded by `#[cfg(unix)]`.

| Signal | Number | V1 behavior | Notes |
|---|---|---|---|
| `SIGINT`  | 2  | Graceful shutdown | `ctrl_c` future in `shutdown_signal`. Exits **0** — `tokio::main` returns `Ok(())` after the graceful shutdown sequence. (Unix convention `128+2=130` does not apply here because the Rust runtime catches the signal internally rather than re-raising it.) |
| `SIGTERM` | 15 | Graceful shutdown | `SignalKind::terminate()` future. Identical handling to SIGINT. Exits **0**. |
| `SIGHUP`  | 1  | **No-op (not installed).** The default-disposition `SIGHUP` terminates the process. There is no config-reload semantics. | Unix daemon convention says SIGHUP reloads config; we **do not** support that. Adding it later is a feature, not an expectation. |
| `SIGUSR1` | 10 | Unused | Default disposition (terminate). Reserved; do not rely on. |
| `SIGUSR2` | 12 | Unused | Same. |
| `SIGPIPE` | 13 | Handled by Tokio/axum | We do not crash on broken-pipe writes. |
| `SIGQUIT` | 3  | Default (core dump) | Use SIGINT/SIGTERM for clean stops. |
| `SIGKILL` | 9  | Unblockable | Operator-of-last-resort; will leave WAL files behind (recovered on next start). |

Windows: only `ctrl_c` is wired; `terminate` is `pending::<()>()`.

## 4. Graceful shutdown sequence (normative)

Triggered by SIGINT or SIGTERM. Order is explicit in `main::serve_mcp`, `MaintenanceHandles::shutdown`, `IngestTx::shutdown`, and `RuntimeCore::shutdown`.

1. **Stop accepting new HTTP connections.** axum's graceful-shutdown future flips; new TCP accepts on `mcp.port` are refused. In-flight HTTP requests are allowed to finish.
2. **Drain in-flight requests.** axum waits for outstanding handlers to return.
3. **Cancel and drain maintenance.** `MaintenanceHandles::shutdown` cancels its shared token and awaits every owned task for 10 seconds. If the cooperative deadline expires, it explicitly aborts and joins unfinished async tasks; it never detaches them. Already-running `spawn_blocking` work cannot be force-cancelled by Tokio and must finish before its wrapper can settle.
4. **UDP/TCP syslog listeners stop.** Their supervisor handles are owned by the maintenance set. Packets still in kernel buffers and partial TCP lines have no receiver-side replay guarantee.
5. **Writer drain.** `IngestTx::shutdown` closes the channel and awaits the batch writer for 5 seconds so accepted entries can flush. On timeout it aborts the writer; senders must retry TCP when end-to-end delivery guarantees are required.
6. **WAL checkpoint.** `RuntimeCore::shutdown` attempts `wal_checkpoint(TRUNCATE)` after writer drain. Failure is logged as non-fatal because committed WAL content remains recoverable on next open.
7. **DB pool close and process exit.** The remaining pool owners drop and `tokio::main` returns.

**Shutdown deadline.** The current code uses a 10-second maintenance deadline followed by a 5-second ingest deadline. These constants are not configuration fields. Operators should allow at least 30 seconds before escalating SIGTERM to SIGKILL so HTTP drain and final checkpoint also have room to complete.

**WAL safety.** Because SQLite is configured with WAL mode (`storage.wal_mode = true`), abrupt SIGKILL or power loss does **not** corrupt the database. On next start SQLite replays WAL automatically. The only loss is the in-memory batch since the most recent transaction commit (≤ `batch_size` rows).

## 5. Healthcheck contract: `GET /health`

Implemented in `src/mcp/routes.rs::health`. Mounted on the MCP HTTP port outside the auth-gated router so Docker / SWAG / Prometheus can hit it unauthenticated.

### Status semantics (V1)

| HTTP status | Meaning | Operator action |
|---|---|---|
| `200 OK` | Process is up, listeners are bound, DB connectivity verified by `service.health_check().await`. | None. |
| `5xx` (currently `500 Internal Server Error`) | DB connectivity failed. The container/unit should be restarted. | Restart and inspect logs. |

V1 **does not** distinguish liveness from readiness: there is no `503` "still warming up" state. The HTTP server only binds (`TcpListener::bind`) after listener bring-up and maintenance-task spawn, so by the time `/health` is reachable, the process is fully live and ready. Adding a readiness probe shape is deferred to V2.

### Body shape (downstream-stable contract)

Body is JSON. **Field additions are always allowed** (additive minor change); renames or removals are a contract break and require a major version bump. The exact field set comes from `src/observability.rs::RuntimeObservabilitySnapshot` (plus the `status` envelope and OTLP counters).

```jsonc
{
  "status": "ok" | "error",
  "otlp_logs_received": <u64>,
  "otlp_decode_errors": <u64>,
  "ingest": {
    // Ingest counters
    "syslog_udp_packets_received":            <u64>,
    "syslog_udp_bytes_received":              <u64>,
    "syslog_tcp_connections_accepted":        <u64>,
    "syslog_tcp_connections_active":          <u64>,
    "syslog_tcp_connections_closed":          <u64>,
    "syslog_tcp_connections_rejected":        <u64>,
    "syslog_tcp_lines_received":              <u64>,
    "syslog_tcp_bytes_received":              <u64>,
    "syslog_tcp_lines_dropped_oversize":      <u64>,
    // Docker ingest counters
    "docker_ingest_events_received":          <u64>,
    "docker_ingest_log_entries_received":     <u64>,
    "docker_ingest_parse_errors":             <u64>,
    "docker_ingest_stream_reconnects":        <u64>,
    "docker_ingest_stream_failures":          <u64>,
    "docker_ingest_tasks_spawned":            <u64>,
    "docker_ingest_host_streams_active":      <u64>,
    "docker_ingest_container_streams_active": <u64>,
    // Internal queue state
    "ingest_entries_enqueued":      <u64>,
    "ingest_enqueue_errors":        <u64>,
    "ingest_queue_depth":           <usize>,
    "ingest_queue_capacity":        <usize>,
    "ingest_queue_utilization_pct": "<f64 as string, 2 decimals>",
    // Writer state
    "writer_batches_flushed": <u64>,
    "writer_logs_written":    <u64>,
    "writer_flush_failures":  <u64>,
    "writer_logs_retained":         <u64>,
    "writer_logs_retained_current": <usize>,
    "writer_logs_discarded":        <u64>,
    "writer_storage_blocked": <bool>,
    // Last-event timestamps (RFC3339 millis UTC, nullable)
    "last_ingest_at":               "YYYY-MM-DDTHH:MM:SS.sssZ" | null,
    "last_write_at":                "YYYY-MM-DDTHH:MM:SS.sssZ" | null,
    "last_error_at":                "YYYY-MM-DDTHH:MM:SS.sssZ" | null,
    "last_docker_ingest_event_at":  "YYYY-MM-DDTHH:MM:SS.sssZ" | null,
    "last_docker_ingest_log_at":    "YYYY-MM-DDTHH:MM:SS.sssZ" | null,
    "last_docker_ingest_error_at":  "YYYY-MM-DDTHH:MM:SS.sssZ" | null
  }
  // Future (planned, not in V1):
  //   "agents": { "total": ..., "active": ..., "revoked": ... }   // Epic A
  //   "pollers": { "<name>": { "last_poll_at": ..., "errors": ... } }  // Epic C
  //   "notifications": { "rules_active": ..., "deliveries": ... }  // Epic E
}
```

Field groupings (Prometheus / Grafana consumers may rely on these prefixes):

- `syslog_udp_*`, `syslog_tcp_*` — listener counters.
- `docker_ingest_*` — legacy central pull Docker ingestion. Current deployed
  agents stream Docker logs from each host's local Docker socket.
- `ingest_*` — channel/queue state between listeners and writer.
- `writer_*` — batch writer + storage-budget interaction.
- `otlp_*` — OTLP `/v1/logs` receiver counters (top-level, not under `ingest`).

**Compatibility rule.** Removing or renaming any field listed above is a major-version break. Adding new fields under `ingest`, adding top-level keys (e.g. `agents`, `pollers`), or extending grouped counters is additive and minor.

### Docker compose example

The bundled `docker-compose.yml` already wires this:

```yaml
healthcheck:
  test: ["CMD-SHELL", "curl -sf http://localhost:3100/health || exit 1"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s
```

`start_period: 10s` covers the gap between container start and `axum::serve` accepting connections; tune up if your host is slow to start SQLite under contention.

## 6. Exit codes

| Code | Cause | Reachable from |
|---|---|---|
| `0`   | Graceful shutdown (SIGINT or SIGTERM) — `tokio::main` returns `Ok(())` after the graceful shutdown sequence. Also emitted by any one-shot CLI/setup/doctor command that completed successfully. Note: Unix convention `128+N` does **not** apply because the signal is caught by `tokio::signal` rather than re-raised. | All modes. |
| `1`   | Config error: any `validate_*` failure in `src/config.rs`, missing required OAuth fields, blank tokens, parent-of-`CORTEX_DB_PATH` missing, unknown CLI flag, unknown setup subcommand. | `anyhow::bail!` from `Config::load` or `Mode::parse`. |
| `2`   | DB initialization failure: `db::init_pool` cannot open the SQLite file, cannot apply schema migrations, or cannot enable WAL. | `serve_mcp`, `RuntimeCore::load*`. |
| `3`   | Bind error: `TcpListener::bind(mcp_bind)` failed (port in use, address not configured). Also covers UDP/TCP syslog bind failures via `start_syslog`. | `serve_mcp`. |
| other (typically `101`) | Uncaught panic. Treat as crash; container/unit should restart. | Any mode. |

**Note**: V1 does not currently `std::process::exit(N)` to distinguish (1)/(2)/(3) — they all surface as `Err` from `tokio::main`, which Rust maps to a generic non-zero exit (commonly `1`). The matrix above is the **intended** semantics and the target for a planned `ExitCode` cleanup. Operators writing systemd `Restart=` policies should treat any non-zero exit code (except panic) as a fatal startup error for now.

## 7. Startup invariants (operator preconditions)

Operators must satisfy these before launching `cortex serve mcp`. Failing any produces a startup error per §6.

1. **DB path is writable by the runtime UID.** Default `/data/cortex.db` requires `/data` to be a bind-mounted dir owned by `CORTEX_UID:CORTEX_GID` (default `1000:1000` per `docker-compose.yml`). See `docs/contracts/data-layout.md` §3.
2. **Listener ports are free.** Default `1514/udp`, `1514/tcp`, `3100/tcp`. The container may need `cap_add: NET_BIND_SERVICE` only if binding port `< 1024` *inside* the container; the published bundle keeps `CORTEX_RECEIVER_PORT=1514` and remaps via Compose.
3. **Non-loopback bind ⇒ auth configured.** Per `src/config.rs::validate_auth_config`: at least one of `mcp.api_token`, `auth.mode = oauth`+token combo (see config-schema §6.1), or `mcp.no_auth = true` plus `mcp.trusted_gateway_no_auth = true` (only when an upstream gateway enforces).
4. **OAuth env triple and admin email set** when `auth.mode = oauth`: `CORTEX_PUBLIC_URL`, `CORTEX_GOOGLE_CLIENT_ID`, `CORTEX_GOOGLE_CLIENT_SECRET`, plus `CORTEX_AUTH_ADMIN_EMAIL` or `mcp.auth.admin_email`. Non-empty `mcp.auth.allowed_emails` is rejected until cortex can pass or enforce that config list. `mcp.no_auth=true` bypasses this because auth config is ignored under `LoopbackDev` or `TrustedGatewayUnscoped`.
5. **Auth file paths writable.** `auth.db` and `auth-jwt.pem` are created and chmodded to `0600` at startup; the parent dir (default: parent of `storage.db_path`) must be writable.
6. **Docker network exists** (Compose deployments only). `docker-compose.yml` references the external network named by `DOCKER_NETWORK` (default `cortex`) — must be created before `docker compose up`.

## 8. Restart safety

- **WAL mode is mandatory in practice.** `storage.wal_mode` defaults to `true` and there is no documented support for the rollback-journal mode. WAL guarantees that abrupt restart (SIGKILL, host crash, power loss) loses only **uncommitted** writes — anything that landed in a transaction is durable.
- **Loss window.** On any non-graceful stop, the in-memory batch since the most recent commit may be lost. Upper bound: `[syslog].batch_size` rows or `[syslog].flush_interval` ms of accumulation, whichever comes first (defaults: 100 rows / 500 ms).
- **WAL/SHM sidecar files** (`cortex.db-wal`, `cortex.db-shm`) are auto-rebuilt on first SQL connection if missing. They are transient — see `docs/contracts/data-layout.md`.
- **OAuth state persistence.** Refresh tokens issued before restart remain valid until their TTL (default 8 h) as long as `auth.db` and `auth-jwt.pem` are preserved across the restart. Losing `auth-jwt.pem` invalidates **all** issued tokens; see data-layout §5.
- **No replay log for syslog ingestion.** If the listener loses a packet during shutdown, there is no resend protocol; senders that need delivery guarantees must use TCP transport with retry on the sender side (rsyslog `omfwd` with `queue.type` is the common pattern).

## 9. Unresolved questions

- **Configurable shutdown deadline.** The 10-second maintenance and 5-second ingest deadlines are currently code constants rather than `[server]` configuration.
- **Blocking maintenance cancellation.** Tokio cannot abort work already running inside `spawn_blocking`; admitted integrity checks are single-flight and their lifecycle is recorded, but a hard process deadline can still terminate the process before such a check finishes.
- **Exit-code surface.** As noted in §6, the (1)/(2)/(3)/(other) split is the intended semantics but not yet implemented as distinct `ExitCode` values. Until that ships, systemd `RestartPreventExitStatus=1` will catch all startup misconfigs but cannot distinguish DB-init from bind-error from config-error.
- **SIGHUP as reload.** Some operators ask whether SIGHUP triggers `Config::load` re-evaluation. **It does not in V1**, and there is no plan to add it before V2 — restart-only is the contract.
