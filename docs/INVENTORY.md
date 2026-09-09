---
title: "Component Inventory -- cortex"
created: 2026-04-04
updated: 2026-07-30
---

# Component Inventory -- cortex

Complete listing of all plugin components.

MCP, REST, and CLI are transport surfaces over the shared service layer. The
runtime MCP action schema is derived from `src/mcp/actions.rs::ACTION_SPECS`
through `src/mcp/schemas.rs::tool_definitions()` and exposed as
`cortex://schema/mcp-tool`; maintained Markdown docs are drift-checked rather
than automatically generated.

## Agent Observatory design package

The following files preserve the Agent Observatory design, contract, and proof
history. They are reference material rather than a generated runtime inventory;
the implemented runtime surfaces remain governed by the registry and route
contracts below.

| Artifact | Scope |
| --- | --- |
| `research/2026-07-31-agent-observatory.md` | July 2026 source, version, dependency, and gap ledger |
| `design/agent-observatory-architecture.md` | Projector, Git observer, OTLP, stream, storage, and embedding architecture |
| `design/agent-observatory-ui.md` | Complete static Next.js and Aurora registry UI design |
| `specs/agent-observatory.md` | Normative product and production requirements |
| `contracts/agent-observatory.md` | Identity, API, streaming, OTLP, configuration, storage, and security contract |
| `contracts/agent-observatory.sql` | Planned additive schema versions 44-47 |
| `contracts/agent-observatory.schema.json` | JSON Schema definitions |
| `contracts/agent-observatory.openapi.json` | Proposed REST/OpenAPI surface |
| `contracts/agent-observatory-types.rs` | Rust contract declarations; intended to be compile-checked once wired into CI (not currently referenced by any Cargo target, build.rs, or CI step) |
| `contracts/agent-observatory-types.ts` | Type-checked TypeScript declarations |
| `contracts/agent-observatory-aurora-lock.example.json` | Pinned Aurora source and generated-file lock contract |
| `plans/2026-07-31-agent-observatory-implementation.md` | 116-task TDD implementation index and phase gates, including the transcript-forward env compatibility track |

Runtime MCP actions, routes, commands, variables, ports, and dependencies below
are the authoritative current inventory.

## Palette session contract

The runtime now exposes authenticated `GET /api/capabilities`,
`GET /api/sessions/rendered`, `GET /api/streams/logs`, and
`GET /api/streams/sessions`. Rendered session pages normalize semantic event
kinds, redaction annotations, and parse warnings over a durable ascending
`logs.id` cursor. Polls are bounded to 200 events and 256 KiB with an explicit
2-second retry hint. Native log and session streams use principal- and
filter-bound durable row-ID cursors, `Last-Event-ID` resume, typed retention
gap/expiry/overload termination, and bounded replay batches;
durable resumable SSE is owned by the separate streaming delivery slice.

## MCP tools

cortex exposes one MCP tool named `cortex`. The required `action`
argument selects the operation. The authoritative action registry lives in
`src/mcp/actions.rs::ACTION_SPECS`; the runtime schema enum is derived from
that registry by `src/mcp/schemas.rs::tool_definitions()`.

| Action | Description | Destructive |
| --- | --- | --- |
| `search` | Full-text search across syslog messages with FTS5 syntax, host/source_ip/severity/app/time filters | no |
| `filter` | Structured filter-only log retrieval for indexed fields and source aliases | no |
| `tail` | Get N most recent log entries, optionally filtered by host, source_ip, and/or application | no |
| `errors` | Error/warning summary grouped by hostname and severity level with counts | no |
| `hosts` | List all hosts with first/last seen timestamps and total log counts | no |
| `map` | Cached homelab inventory plus graph-backed topology answers | no |
| `host_state` | Latest bounded heartbeat state for one host | no |
| `fleet_state` | Fleet-wide heartbeat snapshot with pressure flags and summary counts | no |
| `correlate` | Cross-host event correlation within a time window around a reference timestamp, or one derived from query via AI-session search | no |
| `correlate_state` | Correlate logs with heartbeat window summaries around a reference time | no |
| `stats` | Database statistics: total logs, hosts, time range, DB size, free disk, write-block status | no |
| `status` | Lightweight runtime status: DB health, queue/backpressure state, listener/writer counters, OTLP counters | no |
| `sessions` | AI transcript sessions grouped by project/tool/session/host | no |
| `search_sessions` | Ranked grouped session search | no |
| `abuse` | Abuse-term detector with same-session context | no |
| `abuse_incidents` | Groups abuse hits into scored incident candidates | no |
| `abuse_investigate` | Expands incidents into deterministic evidence bundles | no |
| `ai_correlate` | AI transcript anchors cross-referenced against nearby non-AI logs | no |
| `topic_correlate` | Resolve a topic to graph entities and correlate all related logs into a unified timeline | no |
| `usage_blocks` | AI transcript activity grouped into deterministic 5-hour UTC blocks | no |
| `project_context` | Summary and recent entries for one AI project path | no |
| `list_ai_tools` | Distinct AI tools with counts | no |
| `list_ai_projects` | Distinct AI projects with counts | no |
| `apps` | Distinct application names with log and host counts | no |
| `source_ips` | Distinct source identifiers with hostname breakdown | no |
| `timeline` | Bucketed log counts over time | no |
| `patterns` | Near-duplicate message template clusters | no |
| `context` | Surrounding logs around a log id or timestamp | no |
| `get` | One log entry by id, including raw frame | no |
| `ingest_rate` | Recent ingest throughput and write-block state | no |
| `silent_hosts` | Hosts whose last_seen is older than a threshold | no |
| `clock_skew` | Per-host received_at minus timestamp distribution | no |
| `anomalies` | Recent vs baseline volume/error comparison | no |
| `compare` | Side-by-side comparison of two time ranges | no |
| `compose_status` | Redacted Docker Compose runtime projection | no |
| `compose_doctor` | Strict redacted Docker Compose health diagnostics | no |
| `unaddressed_errors` | Repeating unacknowledged error signatures | no |
| `notifications_recent` | Recent notification firings | no |
| `similar_incidents` | FTS5 historical incident clusters with overlapping AI sessions | no |
| `recurring_error_comparison` | Compare recurring error signatures with redacted deterministic evidence bundles | no |
| `incident_context` | Window bundle of non-AI log aggregates/errors and active AI sessions | no |
| `graph` | Resolve graph entities, neighborhoods, and evidence-backed explanations | no |
| `artifact_evidence` | Query bounded source-attributed artifact ecosystem evidence | no |
| `artifact_evidence_record` | Append one bounded artifact ecosystem evidence event | yes |
| `skill_events` | List extracted AI skill-invocation events | no |
| `skill_incidents` | Groups negative-signal transcript hits following a skill invocation into scored incident candidates | no |
| `skill_investigate` | Expands skill-usage incidents into deterministic evidence bundles, skill-first | no |
| `mcp_events` | List extracted AI MCP tool-call events | no |
| `mcp_incidents` | Groups negative-signal transcript hits following an MCP tool call into scored incident candidates | no |
| `mcp_investigate` | Expands MCP-usage incidents into deterministic evidence bundles, server/tool-first | no |
| `hook_events` | List extracted/collected AI hook events (runtime execution and config inventory) | no |
| `hook_incidents` | Groups hook failures/timeouts and other negative signals into scored incident candidates | no |
| `hook_investigate` | Expands hook-usage incidents into deterministic evidence bundles, hook-first | no |
| `ack_error` | Acknowledge an error signature | yes |
| `unack_error` | Revoke an error acknowledgement | yes |
| `file_tails` | Manage Cortex-owned file-tail ingest sources | yes |
| `notifications_test` | Send a test Apprise notification | yes |
| `llm_invocations` | Recent LLM invocation audit records (concurrency/rate-limit/circuit-breaker denials included) | no |
| `help` | Returns markdown documentation for all actions | no |

Most MCP actions are read-only. `ack_error`, `unack_error`, `file_tails`,
`notifications_test`, `artifact_evidence_record`, and `llm_invocations` require
`cortex:admin`. Artifact-evidence writes append only bounded source-attributed
evidence through the canonical log transaction path; they do not grant artifact,
license, publication, policy, or deployment authority. `llm_invocations` is
read-only but admin-scoped because it exposes operational kill-switch/circuit-breaker
state, not log content.

## Direct CLI commands

The `cortex` binary also exposes direct local commands backed by the same service
methods as the MCP actions.

| Command | Matches MCP action | Description |
| --- | --- | --- |
| `cortex search` | `search` | Full-text search with filters |
| `cortex tail` | `tail` | Recent log entries |
| `cortex analysis errors` | `errors` | Error/warning summary |
| `cortex hosts` | `hosts` | Known host list |
| `cortex hosts sources` | `source_ips` | Source identifiers with hostname breakdown |
| `cortex hosts silent` | `silent_hosts` | Hosts older than a staleness threshold |
| `cortex ingest inventory refresh` | -- | Native refresh into `~/.cortex/inventory` |
| `cortex ingest inventory status` | -- | Cache freshness, collector status, warnings, and artifact paths |
| `cortex filter` | `filter` | Structured filter-only log retrieval |
| `cortex correlate events` | `correlate` | Cross-host event correlation |
| `cortex state host` | `host_state` | Latest bounded heartbeat state for one host |
| `cortex state fleet` | `fleet_state` | Fleet-wide heartbeat snapshot with pressure flags |
| `cortex correlate state` | `correlate_state` | Logs plus heartbeat summaries around a reference time |
| `cortex entity` | `graph` | Resolve a graph entity by canonical key or alias |
| `cortex graph status` | `graph` | Inspect graph projection status, freshness, counts, and rebuild progress |
| `cortex graph rebuild` | `graph` | Explicitly rebuild the derived graph projection from current source tables |
| `cortex graph around` | `graph` | One-hop graph neighborhood with typed relationships and evidence |
| `cortex graph explain` | `graph` | Evidence-backed deterministic incident explanation over graph chains |
| `cortex graph evidence` | `graph` | Inspect one evidence id with relationship endpoints and bounded source proof |
| `cortex artifactevents` | `artifact_evidence` | Query bounded artifact ecosystem evidence by artifact/revision/digest/correlation/target/source/time |
| `cortex sessions correlate` | `ai_correlate` | AI transcript anchors cross-referenced against nearby non-AI logs |
| `cortex sessions incidents` | `abuse_incidents` | Grouped abuse incident candidates |
| `cortex sessions investigate` | `abuse_investigate` | Abuse incident evidence bundles |
| `cortex sessions similar` | `similar_incidents` | Historical incident clusters |
| `cortex sessions incidentcontext` | `incident_context` | Full context bundle for a time window |
| `cortex stats` | `stats` | Database and storage metrics |
| `cortex stats ingestrate` | `ingest_rate` | Recent ingest throughput and write-block state |

## MCP resources

| URI | Description | MIME type |
| --- | --- | --- |
| `cortex://schema/mcp-tool` | JSON schema for the `cortex` MCP tool and action-based parameters | `application/json` |

## Environment variables

| Variable | Required | Default | Sensitive |
| --- | --- | --- | --- |
| `CORTEX_RECEIVER_HOST` | no | `0.0.0.0` | no |
| `CORTEX_RECEIVER_PORT` | no | `1514` | no |
| `CORTEX_MAX_MESSAGE_SIZE` | no | `8192` | no |
| `CORTEX_BATCH_SIZE` | no | `100` | no |
| `CORTEX_FLUSH_INTERVAL` | no | `500` | no |
| `CORTEX_HOST` | no | `127.0.0.1` | no |
| `CORTEX_PORT` | no | `3100` | no |
| `CORTEX_TOKEN` | no | (none) | yes |
| `CORTEX_ALLOWED_HOSTS` | no | (none) | no |
| `CORTEX_ALLOWED_ORIGINS` | no | (none) | no |
| `CORTEX_API_TOKEN` | yes (always-on `/api/*`) | (none) | yes |
| `CORTEX_DB_PATH` | no | `/data/cortex.db` | no |
| `CORTEX_POOL_SIZE` | no | `8` | no |
| `CORTEX_SQLITE_PAGE_CACHE_MB` | no | `128` | no |
| `CORTEX_SQLITE_MMAP_MB` | no | `256` | no |
| `CORTEX_HEAVY_READ_CONCURRENCY` | no | `1` | no |
| `CORTEX_WAL_CHECKPOINT_MB` | no | `256` | no |
| `CORTEX_RETENTION_DAYS` | no | `90` | no |
| `CORTEX_MAX_DB_SIZE_MB` | no | `1024` | no |
| `CORTEX_RECOVERY_DB_SIZE_MB` | no | `900` | no |
| `CORTEX_MIN_FREE_DISK_MB` | no | `0` (disabled; breach blocks writes) | no |
| `CORTEX_RECOVERY_FREE_DISK_MB` | no | `0` | no |
| `CORTEX_CLEANUP_INTERVAL_SECS` | no | `60` | no |
| `CORTEX_CLEANUP_CHUNK_SIZE` | no | `2000` | no |
| `RUST_LOG` | no | `info` | no |
| `CORTEX_INVENTORY_DIR` | no | `~/.cortex/inventory` | no |
| `CORTEX_INVENTORY_COMPOSE_PATHS` | no | `~/.cortex/compose/docker-compose.yml` | no |
| `CORTEX_INVENTORY_PROXY_PATHS` | no | (none) | no |
| `CORTEX_INVENTORY_ADGUARD_PATHS` | no | common AdGuard Home config paths | no |
| `CORTEX_INVENTORY_SSH_CONFIG` | no | `~/.ssh/config` | no |
| `CORTEX_INVENTORY_SSH_HOSTS` | no | all concrete `Host` aliases in SSH config except wildcard patterns and `github.com` | no |
| `CORTEX_INVENTORY_PROJECT_ROOTS` | no | `~/workspace` | no |
| `CORTEX_INVENTORY_REFRESH_INTERVAL_SECS` | no | `300` (`0` disables server-side periodic refresh) | no |
| `CORTEX_INVENTORY_WATCH_ENABLED` | no | `true` | no |
| `CORTEX_INVENTORY_REMOTE_DOCKER_EVENTS` | no | `false` | no |
| `CORTEX_UNRAID_URL` | no | (none) | no |
| `CORTEX_UNRAID_API_KEY` | no | (none) | yes |
| `CORTEX_UNIFI_URL` | no | (none) | no |
| `CORTEX_UNIFI_API_KEY` | no | (none) | yes |
| `CORTEX_<MEDIA>_URL` | no | (none) | no |
| `CORTEX_<MEDIA>_API_KEY` / `TOKEN` / `USERNAME` / `PASSWORD` | no | (none) | yes |

## Homelab inventory refresh

`cortex ingest inventory refresh` writes the private cache consumed by MCP
`action=map` under `~/.cortex/inventory`. The server also refreshes that cache
automatically: one refresh runs shortly after startup, then every
`CORTEX_INVENTORY_REFRESH_INTERVAL_SECS` seconds. Set the interval to `0` to
disable background refresh.

When background refresh is enabled, Cortex also watches local configured
Compose/proxy config paths and refreshes after a short debounce when they
change. AdGuard Home paths are collected during each refresh; configure them
with `CORTEX_INVENTORY_ADGUARD_PATHS` when the defaults do not match. Set
`CORTEX_INVENTORY_WATCH_ENABLED=false` to disable local file
watching. To use container events as refresh triggers, explicitly set
`CORTEX_INVENTORY_REMOTE_DOCKER_EVENTS=true`; Cortex then opens `docker events`
streams over SSH for selected hosts.

Remote collection is SSH-backed and uses concrete aliases from `~/.ssh/config`
unless `CORTEX_INVENTORY_SSH_HOSTS` is set. It collects host facts, listener
ports, storage summaries, Compose YAML artifacts, reverse proxy conf artifacts,
redacted AdGuard Home configuration, and compact Docker inspect data including
container status/health, image, published ports, networks, mounts, compose/route
labels, and environment key names only. One bounded config sweep runs per host.
A slow or unreachable host is reported without discarding completed host results.
Cortex does not store Docker environment values.

SSH targets are validated before invoking OpenSSH, option-like hosts are
rejected, and the command builder inserts `--` before the host argument.
Inventory collectors and remote Docker event streams share strict host-key
defaults, a fleet-wide concurrency budget, and retry backoff. Deploy helpers
share host validation, the `--` delimiter, and the host-key argument policy, but
they do not use the inventory retry/concurrency context. The default is
`StrictHostKeyChecking=yes`; bootstrap TOFU is available only when explicitly
opted in with `CORTEX_INVENTORY_SSH_TRUST_ON_FIRST_USE=true`. Set
`CORTEX_INVENTORY_SSH_KNOWN_HOSTS` when automation should use a managed
known-hosts file.

Optional provider collectors are activated only when their URL/credential env
vars are present. The UniFi collector includes sites, devices, network settings,
and normalized DHCP assignments such as gateway, pool, lease time, and DNS
servers. Supported media prefixes are `SONARR`, `RADARR`, `PROWLARR`, `SABNZBD`,
`QBITTORRENT`, `PLEX`, `TAUTULLI`, and `OVERSEERR`.

Safe provider configuration is exposed in typed `services[].details` and
`networks[].details` objects. Raw artifact bodies remain private and redacted.

The MCP `map` action defaults to the bounded snapshot. Set `mode` to ask
topology questions backed by the graph projection:

```json
{"action":"map","mode":"host_services","host":"edgehost"}
{"action":"map","mode":"domain_routes","domain":"adguard.example.invalid"}
{"action":"map","mode":"service_dependencies","host":"edgehost","service":"swag"}
{"action":"map","mode":"findings","finding_limit":25}
```

Non-snapshot responses include `graph_answer.answer_status`, bounded `rows`,
safe evidence samples, map-native `next_queries`, and graph `proof_queries`.
`mode=findings` instead fills `graph_answer.findings` with supported topology
findings: `potential_public_route`, `risky_mounts`, and `collector_health`.
These findings use relationship-specific graph proof for configured routes and
mounts, normalized inventory for mount source/target/read-only detail, and
cache/collector state for degraded-confidence context. Evidence is intentionally
safe: no raw config bodies, raw cache paths, credential-bearing upstream URLs,
raw collector warnings, raw frames, or `metadata_json` are returned.

## Plugin surfaces

| Surface | Present | Path |
| --- | --- | --- |
| Skills | yes | `plugins/cortex/skills/` |
| Agents | no | -- |
| Commands | no | -- |
| Hooks | yes | `plugins/cortex/hooks/` |
| Channels | no | -- |
| Output styles | no | -- |
| Schedules | no | -- |

## Network ports

| Port | Protocol | Purpose |
| --- | --- | --- |
| 1514 | UDP + TCP | Syslog receiver (RFC 3164/5424) |
| 3100 | TCP | RMCP Streamable HTTP endpoint |

## HTTP endpoints

| Endpoint | Method | Auth required | Description |
| --- | --- | --- | --- |
| `/mcp` | POST | yes (when token set) | RMCP stateless Streamable HTTP endpoint |
| `/mcp` | GET, DELETE | yes (when token set) | 401 first if token auth is enabled and the bearer token is missing/invalid; otherwise 405 in stateless mode |
| `/health` | GET | no | Health check -- verifies DB connectivity |
| `/api/search` | GET | yes when API enabled | Plain JSON log search |
| `/api/tail` | GET | yes when API enabled | Plain JSON recent logs |
| `/api/errors` | GET | yes when API enabled | Plain JSON error summary |
| `/api/hosts` | GET | yes when API enabled | Plain JSON host list |
| `/api/correlate` | GET | yes when API enabled | Plain JSON event correlation |
| `/api/stats` | GET | yes when API enabled | Plain JSON database stats |
| `/api/filter` | GET | yes when API enabled | Plain JSON structured log filtering |
| `/api/timeline` | GET | yes when API enabled | Plain JSON bucketed timeline |
| `/api/patterns` | GET | yes when API enabled | Plain JSON message pattern clusters |
| `/api/notifications/recent` | GET | yes when API enabled | Recent notification firings |

## Docker

| Component | Value |
| --- | --- |
| Image | `ghcr.io/dinglebear-ai/cortex:latest` |
| Syslog port | `1514/udp`, `1514/tcp` |
| MCP port | `3100/tcp` |
| Health endpoint | `GET /health` (unauthenticated) |
| Compose file | `docker-compose.yml` |
| Entrypoint | `cortex` binary |
| User | `1000:1000` |
| Data volume | `/data` (SQLite database) |

## CI/CD workflows

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `ci.yml` | push, PR | Lint (clippy), check, test |
| `docker-publish.yml` | tag push | Build and publish Docker image to GHCR |
| `publish-crates.yml` | tag push | Publish to crates.io |
| `codex-plugin-scanner.yml` | PR | Validate Codex plugin manifest |

## Scripts

| Script | Purpose |
| --- | --- |
| `scripts/smoke-test.sh` | Compatibility wrapper for the canonical live smoke profile |
| `scripts/backup.sh` | WAL-safe SQLite backup (checkpoint + `.backup` method) |
| `scripts/reset-db.sh` | WAL-safe backup + destructive DB reset for dev recovery |





## Dependencies

### Runtime

| Crate | Purpose |
| --- | --- |
| `tokio` | Async runtime (full features) |
| `axum` | HTTP framework for MCP server |
| `tower-http` | CORS and tracing middleware |
| `rusqlite` | SQLite driver (bundled, with FTS5) |
| `r2d2` / `r2d2_sqlite` | Connection pooling |
| `syslog_loose` | RFC 3164/5424 syslog parsing |
| `serde` / `serde_json` | Serialization |
| `chrono` | Timestamps |
| `toml` | Config file parsing |
| `tracing` / `tracing-subscriber` | Structured logging |
| `anyhow` | Error handling |
| `subtle` | Constant-time token comparison |
| `rustix` | Filesystem stats (free disk space) |

### Development

| Crate | Purpose |
| --- | --- |
| `tempfile` | Temporary directories for test databases |
| `serial_test` | Serialized test execution for env var tests |
| `tower` | HTTP testing utilities |
