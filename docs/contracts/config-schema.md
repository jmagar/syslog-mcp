---
title: "Configuration Schema Contract (V1)"
created: 2026-05-16
updated: 2026-07-30
---

# Configuration Schema Contract (V1)

## 1. Purpose & status

Contract derived from `src/config.rs` (the source-of-truth `Config`/`ConfigSchema` types and their `load` / `validate_*` functions). It also consolidates plugin-exposed knobs from `.claude-plugin/plugin.json::userConfig` and pins the operator-visible TOML schema currently scattered across `docs/CONFIG.md` and `docs/SETUP.md`.

This document is normative for every config knob the V1 server respects. Any change to a TOML key name, env var, default, or validation rule MUST be made in `src/config.rs` first; this contract is then re-derived. Specs that add new config blocks (`docs/superpowers/specs/2026-05-16-agent-mode-design.md`, `…-api-pollers-design.md`, `…-digest-notifications-design.md`, `…-probe-registry-design.md`, `…-rag-incidents-design.md`) are pinned in §5 as **planned** rows — none of these blocks are honored by the V1 loader yet. Unknown top-level keys in `config.toml` are silently ignored (the `Config` struct uses `#[serde(default)]` without `deny_unknown_fields`), so operators can include planned blocks for forward compatibility without causing startup errors. They are listed here so operators can write forward-compatible configs.

Companion contracts: `docs/contracts/runtime-lifecycle.md` (process behavior), `docs/contracts/data-layout.md` (filesystem layout for the values referenced here).

## 2. Precedence (normative)

Highest priority wins. The loader applies layers in this order; later layers overwrite earlier ones:

1. **Compile-time defaults** — every field has a `default = "default_*"` serde annotation in `src/config.rs` (see §4 default columns).
2. **`config.toml`** — read from the process working directory. Missing keys keep their defaults (partial configs are supported via `#[serde(default)]`). Missing file is not an error.
3. **`~/.cortex/.env`** — written by `cortex setup`. Lines of the form `KEY=VALUE` are loaded **only when the matching process env var is not already set**. Loader rules (`load_setup_env_file` in `src/config.rs`):
   - Symlinked `.env` files are refused (printed warning, file ignored).
   - Comments (`#`) and blank lines are skipped.
   - Only keys starting with `CORTEX_`, `CORTEX_`, `CORTEX_API_`, `CORTEX_DOCKER_`, plus the bare `NO_AUTH`, are honored. Other keys are silently dropped.
   - `CORTEX_DB_PATH` values starting with `/data/` are rewritten to `<CORTEX_DATA_VOLUME>/<suffix>` when `CORTEX_DATA_VOLUME` is also present in the same file.
4. **Process environment** — `std::env::var(...)`. Takes precedence over `.env`. Empty-string values are treated as absent (the loader does not blank an already-set field with `KEY=`).

**v0.1.9 flat-prefix rule.** Environment variables use a single underscore between `CORTEX` and the field name (e.g. `CORTEX_MAX_DB_SIZE_MB`). The pre-v0.1.9 nested form (`CORTEX_STORAGE__MAX_DB_SIZE_MB`) is **not** parsed. There is no auto-translation; the old form silently no-ops.

**Boolean parsing.** `env_override_bool` accepts `true|false|1|0|yes|no|y|n|on|off` (case-insensitive). Anything else is a startup error.

## 3. Sensitivity & reload taxonomy

For every row in §4:

- **Sensitivity** — `public` (safe to print/log/check into git), `tuning` (operationally tweakable, no secrecy risk), `secret` (never log; field is marked `sensitive: true` in plugin.json or carries a credential).
- **Reload** — `restart-only` (must restart `cortex serve mcp` to pick up; nothing in V1 watches `config.toml`), `hot-reload` (changes via a runtime mechanism — **none in V1**), `runtime-configurable` (mutated through an MCP tool action while the server runs — V1 has none for these fields; deferred to V2). **V1 is uniformly `restart-only` for every row below.** The probe registry epic plans `runtime-configurable` for probe schedules only; see §5.

## 4. Schema — current loader (`src/config.rs`)

### Top-level integration identity and cursor security

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | plugin.json | Notes |
|---|---|---|---|---|---|---|---|---|
| `server_id` | `CORTEX_SERVER_ID` | string | `None` | public | restart-only | non-empty values are hashed unless already a `cortex_` identity | — | Stable per-instance identity seed; OAuth `public_url`, then loopback bind + DB path are fallbacks |
| `cursor_signing_key` | `CORTEX_CURSOR_SIGNING_KEY` | string | random only on loopback | **secret** | restart-only | required and non-empty on non-loopback binds | — | Current HMAC key for durable stream cursors |
| `cursor_previous_keys` | `CORTEX_CURSOR_PREVIOUS_KEYS` | string[] / CSV | `[]` | **secret** | restart-only | empty entries ignored | — | Verification-only rotation keys; new cursors always use the current key |

### `[syslog]` — listener + ingest writer

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | plugin.json | Notes |
|---|---|---|---|---|---|---|---|---|
| `host` | `CORTEX_RECEIVER_HOST` | string | `"0.0.0.0"` | public | restart-only | no `:` in value | `syslog_host` | UDP+TCP bind iface |
| `port` | `CORTEX_RECEIVER_PORT` | u16 | `1514` | public | restart-only | parse u16 | `syslog_port` | UDP+TCP shared port |
| `max_message_size` | `CORTEX_MAX_MESSAGE_SIZE` | usize bytes | `8192` | tuning | restart-only | `> 0` | — | |
| `max_tcp_connections` | `CORTEX_MAX_TCP_CONNECTIONS` | usize | `512` | tuning | restart-only | `> 0` | — | Semaphore cap |
| `tcp_idle_timeout_secs` | `CORTEX_TCP_IDLE_TIMEOUT_SECS` | u64 | `300` | tuning | restart-only | `> 0` | — | Per-read deadline |
| `batch_size` | `CORTEX_BATCH_SIZE` | usize | `100` | tuning | restart-only | `> 0` | `batch_size` | Writer flush size |
| `flush_interval` | `CORTEX_FLUSH_INTERVAL` | u64 ms | `500` | tuning | restart-only | `> 0` | — | Writer flush deadline |
| `write_channel_capacity` | `CORTEX_WRITE_CHANNEL_CAPACITY` | usize | `10_000` | tuning | restart-only | `> 0` | `write_channel_capacity` | Listener→writer mpsc cap |

### `[storage]` — SQLite + retention + storage budget

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | plugin.json | Notes |
|---|---|---|---|---|---|---|---|---|
| `db_path` | `CORTEX_DB_PATH` | path | `/data/cortex.db` | public | restart-only | parent dir must exist when env is set | `data_dir` (parent) | See §2 for `/data/` rewrite rule |
| `pool_size` | `CORTEX_POOL_SIZE` | u32 | `8` | tuning | restart-only | `>= 6` | — | r2d2 pool size. `config::PoolBudget` splits it: 4 connections are reserved for the resident lanes in `UNPERMITTED_CONNECTION_LANES` (ingest batch writer, maintenance permit, notification dispatcher permit, Agent Observatory projector), and reads get the remaining `pool_size - 4` permits |
| `sqlite_page_cache_mb` | `CORTEX_SQLITE_PAGE_CACHE_MB` | u64 | `128` | tuning | restart-only | `> 0`; derived KiB per connection must fit `i64` | — | Total SQLite page-cache budget across the pool; divided by `pool_size` before `PRAGMA cache_size` |
| `sqlite_mmap_mb` | `CORTEX_SQLITE_MMAP_MB` | u64 | `256` | tuning | restart-only | derived bytes must fit `i64` | — | Bounded SQLite mmap size; resident pages may still count toward cgroup memory |
| `heavy_read_concurrency` | `CORTEX_HEAVY_READ_CONCURRENCY` | usize | `1` | tuning | restart-only | `> 0` | — | Shared service-layer limiter for SQLite-heavy reads |
| `wal_checkpoint_mb` | `CORTEX_WAL_CHECKPOINT_MB` | u64 | `256` | tuning | restart-only | `> 0` | — | WAL size threshold for bounded PASSIVE checkpoint attempts |
| `retention_days` | `CORTEX_RETENTION_DAYS` | u32 | `90` | tuning | restart-only | `0` disables age purge | `retention_days` | Hourly purge task |
| `wal_mode` | — | bool | `true` | tuning | restart-only | — | — | WAL is effectively mandatory |
| `max_db_size_mb` | `CORTEX_MAX_DB_SIZE_MB` | u64 | `1024` | tuning | restart-only | see §6 | `max_db_size_mb` | `0` disables soft cap |
| `recovery_db_size_mb` | `CORTEX_RECOVERY_DB_SIZE_MB` | u64 | `900` | tuning | restart-only | see §6 | — | Target after eviction |
| `min_free_disk_mb` | `CORTEX_MIN_FREE_DISK_MB` | u64 | `0` | tuning | restart-only | see §6 | — | `0` disables disk guard; breach blocks writes instead of deleting data |
| `recovery_free_disk_mb` | `CORTEX_RECOVERY_FREE_DISK_MB` | u64 | `0` | tuning | restart-only | see §6 | — | Hysteresis target before writes resume |
| `cleanup_interval_secs` | `CORTEX_CLEANUP_INTERVAL_SECS` | u64 | `60` | tuning | restart-only | `>= 5` | — | Storage task tick |
| `cleanup_chunk_size` | `CORTEX_CLEANUP_CHUNK_SIZE` | usize | `2_000` | tuning | restart-only | `> 0` and `<= 1_000_000` | — | Rows-per-chunk during eviction |

### `[mcp]` — HTTP MCP server

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | plugin.json | Notes |
|---|---|---|---|---|---|---|---|---|
| `host` | `CORTEX_HOST` | string | `"0.0.0.0"` | public | restart-only | no `:` | `mcp_host` | |
| `port` | `CORTEX_PORT` | u16 | `3100` | public | restart-only | parse u16 | `mcp_port` | |
| `server_name` | — | string | `"cortex"` | public | restart-only | — | — | Reported in MCP capabilities |
| `no_auth` | `NO_AUTH` or `CORTEX_NO_AUTH` | bool | `false` | public | restart-only | see §6 | `no_auth` | Disables service-local MCP auth; non-loopback binds also require `trusted_gateway_no_auth` |
| `trusted_gateway_no_auth` | `CORTEX_TRUSTED_GATEWAY_NO_AUTH` | bool | `false` | public | restart-only | see §6 | — | Allows `no_auth` on non-loopback binds only when an upstream gateway enforces auth |
| `api_token` | `CORTEX_TOKEN` (preferred), `CORTEX_API_TOKEN` (deprecated) | string | `None` | **secret** | restart-only | non-empty if set | `api_token` | Static Bearer token; deprecated env var logs a warning |
| `allowed_hosts` | `CORTEX_ALLOWED_HOSTS` | csv list | `[]` | public | restart-only | — | — | Extra Host headers RMCP accepts. Compose prepends `cortex,cortex:3100` and appends this operator value. |
| `allowed_origins` | `CORTEX_ALLOWED_ORIGINS` | csv list | `[]` | public | restart-only | — | — | Extra browser Origins |

### `[mcp.auth]` — OAuth / JWT policy

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | plugin.json | Notes |
|---|---|---|---|---|---|---|---|---|
| `mode` | `CORTEX_AUTH_MODE` | `bearer`\|`oauth` | `bearer` | public | restart-only | enum | `auth_mode` | |
| `public_url` | `CORTEX_PUBLIC_URL` | string | `None` | public | restart-only | required when `oauth` | `public_url` | |
| `google_client_id` | `CORTEX_GOOGLE_CLIENT_ID` | string | `None` | public | restart-only | required when `oauth` | `google_client_id` | |
| `google_client_secret` | `CORTEX_GOOGLE_CLIENT_SECRET` | string | `None` | **secret** | restart-only | required when `oauth` | `google_client_secret` | |
| `admin_email` | `CORTEX_AUTH_ADMIN_EMAIL` | string | `""` | public | restart-only | non-empty when `oauth` | `auth_admin_email` | Only config-backed OAuth email gate cortex passes into lab-auth in V1 |
| `allowed_emails` | — (TOML only) | string[] | `[]` | public | restart-only | must be empty when `oauth` unless `no_auth=true` | — | Reserved for future config-backed multi-user enforcement; rejected in OAuth mode today |
| `sqlite_path` | — | path | `auth.db` | **secret** | restart-only | relative resolved against `db_path` parent | — | See `docs/contracts/data-layout.md` |
| `key_path` | — | path | `auth-jwt.pem` | **secret** | restart-only | relative resolved against `db_path` parent | — | JWT signing PEM; chmod 0600 enforced |
| `access_token_ttl_secs` | — | u64 | `3600` | tuning | restart-only | — | — | 1 h |
| `refresh_token_ttl_secs` | — | u64 | `28800` | tuning | restart-only | — | — | 8 h (deliberately tighter than lab-auth's 30 d default) |
| `auth_code_ttl_secs` | — | u64 | `300` | tuning | restart-only | — | — | 5 m |
| `register_rpm` | — | u32 | `20` | tuning | restart-only | — | — | Parity with lab-auth; unused in V1 |
| `authorize_rpm` | — | u32 | `60` | tuning | restart-only | — | — | |
| `disable_static_token_with_oauth` | `CORTEX_AUTH_DISABLE_STATIC_TOKEN_WITH_OAUTH` | bool | `true` | public | restart-only | — | — | When `false`, keeps static `CORTEX_TOKEN` as break-glass under OAuth |
| `allowed_client_redirect_uris` | `CORTEX_AUTH_ALLOWED_REDIRECT_URIS` | csv list | `[]` | public | restart-only | — | `auth_allowed_redirect_uris` | Loopback URIs are implicit |

### `[api]` — non-MCP JSON API

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | plugin.json | Notes |
|---|---|---|---|---|---|---|---|---|
| `enabled` | `CORTEX_API_ENABLED` | bool | `false` | public | restart-only | — | — | |
| `api_token` | `CORTEX_API_TOKEN` | string | `None` | **secret** | restart-only | required & non-empty when `enabled` | — | |

CORS for this API is allowed at the MCP port (`config.mcp.port`); there is no separate `[api.cors]` block today.

### `[docker_ingest]` — legacy central Docker pull ingestion

Current deployments use the host-local cortex agent for Docker logs. This block
is retained as compatibility mode for explicit remote Docker Engine HTTP
endpoints.

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | plugin.json | Notes |
|---|---|---|---|---|---|---|---|---|
| `enabled` | `CORTEX_DOCKER_INGEST_ENABLED` | bool | `false` | public | restart-only | — | `docker_ingest_enabled` | |
| `hosts` | `CORTEX_DOCKER_HOSTS` (csv shorthand) or `CORTEX_DOCKER_HOSTS_FILE` (TOML path) | `DockerHostConfig[]` | `[]` | public | restart-only | non-empty if `enabled`; unique names; `http://` or `https://`; `http://` requires per-host `allow_insecure_http=true` | `fleet_hosts` | shorthand env yields `http://<name>:2375` with `allow_insecure_http=true` (logs warning) |
| `reconnect_initial_ms` | `CORTEX_DOCKER_RECONNECT_INITIAL_MS` | u64 | `1_000` | tuning | restart-only | `> 0` | — | |
| `reconnect_max_ms` | `CORTEX_DOCKER_RECONNECT_MAX_MS` | u64 | `30_000` | tuning | restart-only | `>= reconnect_initial_ms` | — | |

Per-host (`DockerHostConfig`): `name`, `base_url`, `allow_insecure_http` (default `false`).

### `[enrichment]` — parser/scrubbing knobs

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | plugin.json | Notes |
|---|---|---|---|---|---|---|---|---|
| `authelia_source_ip` | `CORTEX_AUTHELIA_SOURCE_IP` | string | `None` | public | restart-only | — | — | IP prefix gate for Authelia severity reclassification |
| `adguard_source_ip` | `CORTEX_ADGUARD_SOURCE_IP` | string | `None` | public | restart-only | — | — | IP prefix gate for AdGuard JSON tag classification |
| `scrub_prompts` | `CORTEX_SCRUB_PROMPTS` | bool | `true` | tuning | restart-only | — | — | AI-source credential scrub |
| `mcp.forwarding_agents.<principal>` | — | secret string | none | secret | restart-only | non-empty values enabled | `[mcp.forwarding_agents]` map of server-authoritative principals to bearer credentials accepted only by evidence-forwarding endpoints; values are redacted from Debug and serialization |
| `fts_merge_pages` | `CORTEX_FTS_MERGE_PAGES` | u32 | `0` | tuning | restart-only | `0..=10_000` | — | `0` = force merge after every purge |

### `[agent_observatory]` — durable agent, Git, and telemetry projection

This block is parsed strictly with `deny_unknown_fields`. The entire subsystem is
disabled unless `enabled=true`; when disabled, nested safety limits are retained as
defaults but do not start projector, Git, stream, or retention work.

| TOML key | Env var | Type | Default | Validation |
|---|---|---|---|---|
| `enabled` | `CORTEX_AGENT_OBSERVATORY_ENABLED` | bool | `false` | dedicated rollout switch |
| `projector_poll_ms` | `CORTEX_AGENT_OBSERVATORY_PROJECTOR_POLL_MS` | u64 | `500` | `> 0` when enabled |
| `projector_page_rows` | `CORTEX_AGENT_OBSERVATORY_PROJECTOR_PAGE_ROWS` | usize | `500` | `> 0` when enabled |
| `projector_page_bytes` | `CORTEX_AGENT_OBSERVATORY_PROJECTOR_PAGE_BYTES` | usize bytes | `4_194_304` | `> 0` when enabled |
| `active_window_secs` | `CORTEX_AGENT_OBSERVATORY_ACTIVE_WINDOW_SECS` | u64 | `15` | `> 0` |
| `stale_after_secs` | `CORTEX_AGENT_OBSERVATORY_STALE_AFTER_SECS` | u64 | `300` | `> active_window_secs` |
| `abandoned_after_secs` | `CORTEX_AGENT_OBSERVATORY_ABANDONED_AFTER_SECS` | u64 | `86_400` | `> stale_after_secs` |

#### `[agent_observatory.git]`

| TOML key | Env var | Type | Default | Validation |
|---|---|---|---|---|
| `enabled` | `CORTEX_AGENT_OBSERVATORY_GIT_ENABLED` | bool | `true` | — |
| `roots` | `CORTEX_AGENT_OBSERVATORY_GIT_ROOTS` | csv/string[] | `["~/workspace"]` | non-empty, no blank entries when Git observer enabled |
| `max_depth` | `CORTEX_AGENT_OBSERVATORY_GIT_MAX_DEPTH` | usize | `3` | `> 0` |
| `max_repositories` | `CORTEX_AGENT_OBSERVATORY_GIT_MAX_REPOSITORIES` | usize | `120` | `> 0` |
| `reconcile_interval_secs` | `CORTEX_AGENT_OBSERVATORY_GIT_RECONCILE_INTERVAL_SECS` | u64 | `60` | `> 0` |
| `debounce_ms` | `CORTEX_AGENT_OBSERVATORY_GIT_DEBOUNCE_MS` | u64 | `500` | `> 0` |
| `command_timeout_ms` | `CORTEX_AGENT_OBSERVATORY_GIT_COMMAND_TIMEOUT_MS` | u64 | `5_000` | `> 0` |
| `max_commits_per_transition` | `CORTEX_AGENT_OBSERVATORY_GIT_MAX_COMMITS_PER_TRANSITION` | usize | `500` | `> 0` |
| `store_changed_paths` | `CORTEX_AGENT_OBSERVATORY_GIT_STORE_CHANGED_PATHS` | bool | `true` | privacy switch |
| `store_author_name` | `CORTEX_AGENT_OBSERVATORY_GIT_STORE_AUTHOR_NAME` | bool | `true` | privacy switch |
| `store_author_email_hash` | `CORTEX_AGENT_OBSERVATORY_GIT_STORE_AUTHOR_EMAIL_HASH` | bool | `false` | never stores plaintext email |

#### `[agent_observatory.stream]`

| TOML key | Env var | Type | Default | Validation |
|---|---|---|---|---|
| `outbox_retention_secs` | `CORTEX_AGENT_OBSERVATORY_STREAM_OUTBOX_RETENTION_SECS` | u64 | `86_400` | `> 0` |
| `replay_limit` | `CORTEX_AGENT_OBSERVATORY_STREAM_REPLAY_LIMIT` | usize | `1_000` | `> 0` |
| `client_queue` | `CORTEX_AGENT_OBSERVATORY_STREAM_CLIENT_QUEUE` | usize | `256` | `> 0` |
| `max_clients` | `CORTEX_AGENT_OBSERVATORY_STREAM_MAX_CLIENTS` | usize | `256` | `> 0` |
| `keepalive_secs` | `CORTEX_AGENT_OBSERVATORY_STREAM_KEEPALIVE_SECS` | u64 | `15` | `> 0` |
| `max_event_bytes` | `CORTEX_AGENT_OBSERVATORY_STREAM_MAX_EVENT_BYTES` | usize bytes | `65_536` | `1..=1_048_576` |

#### `[agent_observatory.privacy]`

| TOML key | Env var | Type | Default |
|---|---|---|---|
| `include_prompt_content` | `CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_PROMPT_CONTENT` | bool | `false` |
| `include_tool_content` | `CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_TOOL_CONTENT` | bool | `false` |
| `include_command_content` | `CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_COMMAND_CONTENT` | bool | `true` |
| `include_paths` | `CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_PATHS` | bool | `true` |
| `include_user_identity` | `CORTEX_AGENT_OBSERVATORY_PRIVACY_INCLUDE_USER_IDENTITY` | bool | `false` |
| `hash_email` | `CORTEX_AGENT_OBSERVATORY_PRIVACY_HASH_EMAIL` | bool | `true` |

#### `[agent_observatory.retention]`

| TOML key | Env var | Type | Default | Validation |
|---|---|---|---|---|
| `events_days` | `CORTEX_AGENT_OBSERVATORY_RETENTION_EVENTS_DAYS` | u64 | `90` | `> 0` |
| `spans_days` | `CORTEX_AGENT_OBSERVATORY_RETENTION_SPANS_DAYS` | u64 | `30` | `> 0` |
| `metrics_days` | `CORTEX_AGENT_OBSERVATORY_RETENTION_METRICS_DAYS` | u64 | `30` | `> 0` |
| `repository_observations_days` | `CORTEX_AGENT_OBSERVATORY_RETENTION_REPOSITORY_OBSERVATIONS_DAYS` | u64 | `90` | `> 0` |
| `removed_worktrees_days` | `CORTEX_AGENT_OBSERVATORY_RETENTION_REMOVED_WORKTREES_DAYS` | u64 | `365` | `> 0` |

All fields are `restart-only`. Environment values take precedence over TOML.

## 5. Schema — planned blocks (not in V1 loader)

These rows are sourced from the design specs under `docs/superpowers/specs/`. They are **not** yet defined in `src/config.rs`; the current `serde(deny_unknown_fields)` behavior is *off* (the top-level `Config` uses `#[serde(default)]` without deny), so unknown top-level tables in `config.toml` are silently ignored. Operators writing forward-compatible config can include these sections, but the V1 server will not act on them. Each row carries an epic pointer.

### `[agent_server]` — server-side WebSocket bridge (Epic A — `…-agent-mode-design.md`)

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | Notes |
|---|---|---|---|---|---|---|---|
| `enabled` | `CORTEX_AGENT_SERVER_ENABLED` | bool | `false` | public | restart-only | — | Mounts `/ws/agent` on the MCP router |
| `ws_path` | — | string | `"/ws/agent"` | public | restart-only | leading `/` | |
| `max_connections` | — | usize | `256` | tuning | restart-only | `> 0` | Semaphore cap on concurrent agents |
| `min_agent_version` | — | semver | `"0.1.0"` | public | restart-only | semver parse | `agent.hello` rejection bound |
| `allow_insecure` | — | bool | `false` | public | restart-only | refused on non-loopback bind when `enabled` | Allows `ws://` for local dev |
| `handshake_timeout_secs` | — | u64 | `5` | tuning | restart-only | `> 0` | |

### `[agent]` — agent host (client-side, on every fleet host running the agent binary)

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | Notes |
|---|---|---|---|---|---|---|---|
| `server_url` | `CORTEX_AGENT_SERVER_URL` | string | — | public | restart-only | `ws://` or `wss://` | Where the agent dials |
| `token_path` | — | path | `~/.config/cortex/agent-token` | **secret** | restart-only | file mode 0600 | Long-lived token file |
| `host_id` | — | string | autoderived | public | restart-only | UUIDv4 | First-run generated |
| `buffer_path` | — | path | `~/.local/state/cortex/agent-buffer.redb` | tuning | restart-only | parent writable | Local replay buffer |
| `allow_insecure` | — | bool | `false` | public | restart-only | refused if `server_url` is non-loopback `ws://` | |

### `[pollers.unifi]`, `[pollers.adguard]` — API pollers (Epic C — `…-api-pollers-design.md`)

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | Notes |
|---|---|---|---|---|---|---|---|
| `enabled` | `CORTEX_POLLERS_UNIFI_ENABLED` etc. | bool | `false` | public | restart-only | — | |
| `base_url` | — | string | — | public | restart-only | `http(s)://` | |
| `api_key` | — | string | — | **secret** | restart-only | non-empty when `enabled` | |
| `poll_interval_secs` | — | u64 | `30` (unifi) / `15` (adguard) | tuning | restart-only | `>= 5` | |
| `verify_tls` | — | bool | `true` | public | restart-only | — | |

### `[notifications]`

Current Cortex uses a fixed set of built-in notification evaluators. Operator-defined
`[[notifications.rules]]`, nested `[notifications.apprise]`, and nested
`[notifications.digest]` blocks from the 2026-05-16 design are **not implemented**.

| TOML key | Env var | Type | Default | Sens. | Reload | Validation | Notes |
|---|---|---|---|---|---|---|---|
| `enabled` | `CORTEX_NOTIFICATIONS_ENABLED` | bool | `false` | public | restart-only | when true, both Apprise fields below must be non-empty | Master switch |
| `apprise_url` | `CORTEX_NOTIFICATIONS_APPRISE_URL` | string | `""` | public | restart-only | required when enabled | Apprise API base URL |
| `apprise_urls` | `CORTEX_NOTIFICATIONS_APPRISE_URLS` | string[] | `[]` | **secret** | restart-only | at least one nonblank target when enabled | Delivery URLs may embed credentials/tokens |
| `dispatcher_interval_secs` | — | u64 | `30` | tuning | restart-only | `> 0` | Outbox dispatcher interval |
| `dedup_window_secs` | — | u64 | `900` | tuning | restart-only | — | Duplicate suppression window |
| `digest_cron_local` | — | string | `"0 8 * * *"` | tuning | restart-only | parsed by digest scheduler | Daily digest schedule |
| `max_retry_attempts` | — | u8 | `8` | tuning | restart-only | — | Dead-letter threshold |

#### `[notifications.evaluators]`

| TOML key | Env var | Type | Default | Validation / notes |
|---|---|---|---|---|
| `oom_kill` | — | bool | `true` | Built-in kernel OOM evaluator |
| `container_die_nonzero` | — | bool | `true` | Built-in Docker exit evaluator |
| `fail2ban_ban` | — | bool | `true` | Built-in fail2ban evaluator |
| `authelia_mfa_fail` | — | bool | `true` | Built-in Authelia evaluator |
| `disk_fill` | — | bool | `true` | Storage guardrail evaluator |
| `ingest_queue_pressure` | — | bool | `true` | Ingest queue pressure evaluator |
| `ingest_silence` | — | bool | `true` | Threshold below must be `> 0` when enabled |
| `ingest_silence_threshold_secs` | — | u64 | `900` | Ingest silence threshold |
| `heartbeat_silence` | `CORTEX_NOTIFICATIONS_HEARTBEAT_SILENCE` | bool | `true` | Threshold below must be `> 0` when enabled |
| `heartbeat_silence_threshold_secs` | `CORTEX_NOTIFICATIONS_HEARTBEAT_SILENCE_SECS` | u64 | `600` | Heartbeat silence threshold |
| `stream_silence` | `CORTEX_NOTIFICATIONS_STREAM_SILENCE` | bool | `true` | Threshold and source-kind list must be non-empty when enabled |
| `stream_silence_threshold_secs` | `CORTEX_NOTIFICATIONS_STREAM_SILENCE_SECS` | u64 | `3600` | Stream silence threshold |
| `stream_silence_kinds` | `CORTEX_NOTIFICATIONS_STREAM_SILENCE_KINDS` | string[] | continuous source kinds | Must contain a nonblank value when stream silence is enabled |
| `silence_forget_secs` | `CORTEX_NOTIFICATIONS_SILENCE_FORGET_SECS` | u64 | `604800` | Must exceed the heartbeat/stream silence thresholds |
| `evaluator_interval_secs` | — | u64 | `300` | `> 0` |

#### Planned notification policy surfaces — **not implemented**

The rule schema in `notification-rules.schema.json`, configurable
`[[notifications.rules]]`, and quiet-hours behavior document the earlier design only.
Current Cortex does not parse operator-defined notification rules. `Config::load`
explicitly rejects `[notifications.quiet_hours]`, `[notifications.apprise]`,
`[notifications.digest]`, and `[[notifications.rules]]` so operators cannot mistake
silently ignored legacy/design configuration for active behavior. The current digest
schedule is the flat `notifications.digest_cron_local` field above.

### `[rag]` (Epic F — `…-rag-incidents-design.md`)

| TOML key | Env var | Type | Default | Sens. | Reload | Notes |
|---|---|---|---|---|---|---|
| `enabled` | — | bool | `false` | public | restart-only | |
| `axon_collection` | — | string | `"incidents"` | public | restart-only | Locked in spec §13 |
| `llm_endpoint` | — | string | — | public | restart-only | Optional; for `suggest_fix` synthesis |
| `llm_api_key_env` | — | string | — | public | restart-only | **Name** of the env var holding the key (the key itself is **secret** and read at runtime from `std::env`) |
| `incidents_dir` | — | path | `<db_dir>/incidents` | tuning | restart-only | Card staging path |

### Probe registry (Epic D — `…-probe-registry-design.md`)

Probe schedules are **agent-side** config, stored on each agent host and queried over the WebSocket RPC. They are the **only** planned `runtime-configurable` surface in V1 — operators push schedule changes from the server CLI without restarting the agent.

## 6. Safety invariants (normative)

These are checked in `src/config.rs::validate_*` and `src/runtime.rs::reject_unsafe_otlp_oauth_only_exposure`. Violations are **startup errors** (exit code 1; see `docs/contracts/runtime-lifecycle.md`).

1. **Non-loopback bind requires auth.** When `serve mcp` is the active mode (i.e. an HTTP port is bound), the server refuses to start if:
   - `mcp.host` does not resolve to a loopback `IpAddr`, AND
   - `mcp.no_auth == false` or `mcp.trusted_gateway_no_auth == false`, AND
   - Neither a static token (`mcp.api_token`) nor `auth.mode == OAuth` is configured.
   - **OAuth-only on a non-loopback bind also requires `mcp.api_token`** because OTLP `/v1/logs` honors only the static bearer gate in V1. This is enforced once in `validate_auth_config` and again as defense-in-depth in `runtime.rs::reject_unsafe_otlp_oauth_only_exposure`.
2. **Storage budget shape.** When `storage.max_db_size_mb > 0`: `storage.recovery_db_size_mb > 0` AND `storage.recovery_db_size_mb < storage.max_db_size_mb`. When `storage.max_db_size_mb == 0`: `storage.recovery_db_size_mb` MUST also be `0`. Symmetric rule for `min_free_disk_mb` / `recovery_free_disk_mb` (recovery must be **greater than** min).
3. **OAuth admin email required.** With `auth.mode == oauth`, `admin_email` must be non-empty because it is the only config-backed email gate cortex passes into lab-auth today. Non-empty `allowed_emails` is rejected in OAuth mode until cortex can pass or enforce that config list. `mcp.no_auth=true` short-circuits auth validation because auth config is ignored under `LoopbackDev` or `TrustedGatewayUnscoped`.
4. **OAuth prerequisite triple.** `public_url`, `google_client_id`, `google_client_secret` are all required when `auth.mode == oauth`.
5. **OTLP non-loopback gate.** Already captured by (1) — restated because it is the most-common operator misconfig: setting `mcp.host = 0.0.0.0` with neither token nor OAuth+token combo is rejected.
6. **`CORTEX_DB_PATH` parent must exist** when explicitly set via env. Catches the Docker misconfig where the variable is pointed at an unmounted host path.
7. **Docker ingest hosts.** When `docker_ingest.enabled = true`: at least one host; unique `name`; `base_url` starts with `http://` or `https://`; `http://` only allowed when the per-host `allow_insecure_http = true` (`CORTEX_DOCKER_HOSTS` env shorthand sets this automatically and logs a warning).
8. **Token fields not blank.** A `mcp.api_token` / `api.api_token` set to an all-whitespace value is rejected even if technically present.
9. **`cleanup_interval_secs >= 5`** and **`cleanup_chunk_size <= 1_000_000`** — guards against pathological maintenance loops.

The `cortex mcp` (stdio) entrypoint **bypasses** invariant (1) only, via `Config::load_for_stdio`. Stdio binds no TCP port so the gate is irrelevant; setting `mcp.host = 0.0.0.0` in stdio mode is harmless and accepted.

## 7. Hot-reload status (V1)

**Nothing in this contract is hot-reloadable in V1.** All knobs above are `restart-only`. Operators must `cortex compose restart` (or equivalent systemd action) for any change to take effect. The probe-registry epic plans the first `runtime-configurable` surface — probe schedules pushed from `cortex agent probes set …` over the WS RPC — but that lives in agent-side config, not this loader. `SIGHUP` is a no-op in V1 (see `docs/contracts/runtime-lifecycle.md` §3).

## 8. Cross-references

- `src/config.rs::Config::load` — actual schema + validation; source of truth.
- `src/config.rs::load_setup_env_file` — `.env` loader (called only outside `cfg(test)`).
- `src/setup/` — code that writes `~/.cortex/.env` and `~/.cortex/config.toml` during `cortex setup`.
- `~/.cortex/.env` — operator-editable env file written by setup; loader rules in §2.
- `~/.cortex/config.toml` — operator-editable TOML file (overlaid before env).
- `.claude-plugin/plugin.json::userConfig` — plugin-managed subset that maps to env vars at setup time. The `plugin.json` column in §4 names the userConfig field that drives each row.
- `docker-compose.yml` — references `CORTEX_UID`, `CORTEX_GID`, `CORTEX_FILE_TAIL_GROUP`, `CORTEX_RECEIVER_HOST_PORT`, `CORTEX_RECEIVER_PORT`, `CORTEX_PORT`, `CORTEX_DATA_VOLUME`, `CORTEX_BACKUP_DIR`, `CORTEX_VERSION`, `DOCKER_NETWORK` — these are **compose-level** vars, not server config; they shape the container, not the process inside it.
- `docs/CONFIG.md` — narrative operator guide; should link **here** for the canonical table.
- `docs/SETUP.md` — first-run procedure; references the secret files in `docs/contracts/data-layout.md`.
- `docs/contracts/runtime-lifecycle.md` — what happens when validations above fail (exit codes).

## 9. Unresolved questions

- `allowed_emails` is parsed into `AuthConfig` for schema compatibility, but cortex does not pass this TOML list into lab-auth today. OAuth startup rejects non-empty `allowed_emails` until the runtime can pass or enforce the full config list. This does not disable lab-auth-managed `allowed_users` rows in `auth.db`.
- The `[pollers.*]`, `[notifications.*]`, `[rag]`, `[agent_server]`, `[agent]` blocks above are **not** defined in `Config`. The exact field names listed in §5 may shift when the implementing epic lands — this contract will be revised against the merged code.
- There is no schema-versioning header in `config.toml` today. Operators upgrading across major versions must consult release notes; adding a `schema_version` key is deferred to V2.
