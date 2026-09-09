---
title: "Configuration Reference -- cortex"
created: 2026-04-04
updated: 2026-07-30
---

# Configuration Reference -- cortex

Complete configuration reference. cortex uses compiled defaults, optional
TOML config, the shared setup env file, and process environment overrides.

## Configuration precedence

Precedence (highest to lowest):
1. Environment variables (always win)
2. `~/.cortex/.env` (or `$CORTEX_HOME/.env`) when present
3. `config.toml` in the working directory (partial configs supported -- missing fields keep defaults)
4. Compiled defaults in `src/config.rs`

The setup env file is created and repaired by `cortex setup`. It is loaded
automatically by installed CLI commands so `cortex stats`, `cortex mcp`, and
`cortex serve mcp` see the same database path and runtime settings as the
Docker Compose container. Explicit process environment variables still win.

## config.toml

The TOML config file at the repo root is used for local development. It is **not** copied into the Docker image -- container deployments use defaults + env vars exclusively.

```toml
[syslog]
host = "0.0.0.0"
port = 1514
max_message_size = 8192

[storage]
db_path = "/data/cortex.db"
pool_size = 8
sqlite_page_cache_mb = 128
sqlite_mmap_mb = 256
heavy_read_concurrency = 1
wal_checkpoint_mb = 256
retention_days = 90
wal_mode = true
max_db_size_mb = 1024
recovery_db_size_mb = 900
min_free_disk_mb = 0      # 0 = free-disk guard disabled (default)
recovery_free_disk_mb = 0
cleanup_interval_secs = 60

[mcp]
host = "127.0.0.1"
port = 3100
server_name = "cortex"
allowed_hosts = ["cortex.example.com", "cortex.example.com:443"]
allowed_origins = ["https://cortex.example.com"]

[api]
# Always-on REST API token — required at server startup.
# api_token = "your-api-token"

[docker_ingest]
enabled = false
reconnect_initial_ms = 1000
reconnect_max_ms = 30000

[[docker_ingest.hosts]]
name = "edge-host-a"
base_url = "http://edge-host-a:2375"
allow_insecure_http = true

[llm]
enabled = true
max_concurrent = 1
max_per_action_concurrent = 1
max_invocations_per_minute = 3
max_invocations_per_hour = 30
failure_threshold = 3
cooldown_secs = 300
timeout_secs = 120
max_prompt_bytes = 1048576
max_output_bytes = 262144
background_enrichment_enabled = false

[llm.actions.ai_assess]
enabled = true
```

Bind host fields (`CORTEX_RECEIVER_HOST` and `CORTEX_HOST`) must be hostnames or IP
addresses without `:` because their ports are configured separately.
`allowed_hosts` / `CORTEX_ALLOWED_HOSTS` are RMCP Host-header allow-list
entries and may include `host:port` values such as `cortex.example.com:443`.
`allowed_origins` / `CORTEX_ALLOWED_ORIGINS` remain full browser origin URLs
such as `https://cortex.example.com`.

## Environment variables

### Syslog listener (`CORTEX_*`)

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `CORTEX_RECEIVER_HOST` | no | `0.0.0.0` | no | Listen host for UDP+TCP syslog (no port -- use separate setting) |
| `CORTEX_RECEIVER_PORT` | no | `1514` | no | Listen port shared by UDP and TCP syslog listeners |
| `CORTEX_MAX_MESSAGE_SIZE` | no | `8192` | no | Max bytes per UDP datagram or newline-delimited TCP frame. Oversized frames are dropped. |
| `CORTEX_MAX_TCP_CONNECTIONS` | no | `512` | no | Maximum simultaneous TCP syslog connections |
| `CORTEX_TCP_IDLE_TIMEOUT_SECS` | no | `300` | no | Idle timeout per TCP read before closing inactive connections |
| `CORTEX_BATCH_SIZE` | no | `100` | no | Entries per batch flush to SQLite |
| `CORTEX_FLUSH_INTERVAL` | no | `500` | no | Batch flush interval in milliseconds |
| `CORTEX_WRITE_CHANNEL_CAPACITY` | no | `10000` | no | Internal parsed-message queue capacity |

TCP forwarders can keep a connection open and send multiple newline-delimited syslog frames. The size limit applies to each frame, not to the full TCP connection lifetime. An oversized newline-delimited frame is dropped and later bounded frames on the same connection can still be ingested. An oversized unterminated frame is dropped and the connection is closed because the listener cannot safely find the next frame boundary.

### Docker log ingest (`CORTEX_DOCKER_*`)

Current deployments use the host-local cortex agent: each deployed agent reads Docker logs from `unix:///var/run/docker.sock` on its own host and forwards normalized rows into cortex. That is the recommended path because it does not expose a Docker API endpoint on the network.

`CORTEX_DOCKER_*` is the legacy central pull compatibility mode. It lets the cortex server pull stdout/stderr logs from explicit remote Docker Engine HTTP endpoints. Older deployments commonly placed `docker-socket-proxy` in front of those endpoints, but that is no longer the default homelab path.

Set `CORTEX_DOCKER_HOSTS` to a comma-separated list of hostnames. Each hostname becomes `http://<host>:2375` with insecure HTTP allowed — use only on trusted private networks.

```env
CORTEX_DOCKER_HOSTS=edgehost,nashost,devhost
```

`CORTEX_DOCKER_HOSTS_FILE` (path to a legacy `[[hosts]]` TOML file) is still accepted as a fallback when `CORTEX_DOCKER_HOSTS` is not set.

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `CORTEX_DOCKER_INGEST_ENABLED` | no | `false` | no | Enable legacy central pull Docker log ingestion |
| `CORTEX_DOCKER_HOSTS` | yes, if Docker ingest is enabled | (none) | no | Comma-separated hostnames — each becomes `http://<host>:2375` |
| `CORTEX_DOCKER_RECONNECT_INITIAL_MS` | no | `1000` | no | Initial reconnect delay after host stream failure |
| `CORTEX_DOCKER_RECONNECT_MAX_MS` | no | `30000` | no | Maximum reconnect delay after repeated failures |

If the legacy central pull endpoint is a docker-socket-proxy, minimum recommended permissions are:

```env
CONTAINERS=1
EVENTS=1
PING=1
VERSION=1
POST=0
```

`CONTAINERS=1` exposes the broader read-only Docker container API to every client that can reach that endpoint. Bind it on a trusted private network, firewall it so only cortex can connect, or put it behind authenticated TLS. Hosts using plain `http://` must set `allow_insecure_http = true` in the hosts file; otherwise config validation rejects them.

Docker log ingest is tested by path: host-local agent parity tests cover deployed-agent Docker streaming, while the legacy central pull path has a mocked Docker HTTP fixture. For a full legacy integration run, set `CORTEX_DOCKER_INGEST_ENABLED=true` against a disposable Docker-compatible HTTP fixture, emit a unique container stdout/stderr line, and verify it with `search` or `tail`. Container stream rows identify their source as `docker://<host>/<container>/<stream>`. Container lifecycle events such as `create`, `start`, `restart`, `die`, `stop`, `destroy`, `rename`, and `oom` identify their source as `docker-event://<host>/<container>/<action>` and use `facility=docker`.

## Managed File-Tail Sources

Cortex can tail local log files directly and ingest appended lines through the
same writer/enrichment path as syslog, Docker, and OTLP. Sources are stored in
`<data-dir>/file-tails.json`, where `<data-dir>` is the parent directory of
`CORTEX_DB_PATH`.

Use this for logs that do not naturally reach journald or container stdout,
such as SWAG nginx access/error logs, SWAG fail2ban logs, Authelia file logs,
and AdGuard query logs.

In Docker, mount a host log tree read-only at `/file-tail-root`:

```bash
CORTEX_FILE_TAIL_LOG_VOLUME=/mnt/user/appdata
```

Registered paths must be absolute, existing, non-symlink regular files under
`CORTEX_FILE_TAIL_ALLOWED_ROOTS`. The documented safe default is the dedicated
`/file-tail-root` mount. To opt into broader roots, mount those directories
read-only and set an explicit comma-separated allowlist, for example
`CORTEX_FILE_TAIL_ALLOWED_ROOTS=/file-tail-root,/var/log,/logs`. Sensitive
Cortex mounts such as `/data`, `/cortex-home`, `/home/cortex/.ssh`, and
`/home/cortex/workspace` are always rejected. REST management requires both the
normal API bearer and `X-Cortex-Admin-Token: $CORTEX_API_ADMIN_TOKEN`; MCP
management requires `cortex:admin`.

```bash
cortex ingest filetail add /file-tail-root/swag/log/nginx/access.log \
  --facility local4

cortex ingest filetail add /file-tail-root/swag/log/nginx/error.log \
  --id swag-error \
  --facility local4 \
  --severity warning

cortex ingest filetail add /file-tail-root/swag/log/fail2ban/fail2ban.log \
  --facility local5

cortex ingest filetail add /file-tail-root/authelia/logs/authelia.log \
  --facility local5

cortex ingest filetail add /file-tail-root/adguard/var/data/querylog.json \
  --id adguard-query \
  --facility local6
```

The source id and tag derive from the lowercased file name. With no `--host`,
the source gets the stable synthetic owner `file-tail-<id>`; Cortex never uses
the server or container hostname for mounted files. Pass `--host` when the path
belongs to a real host that should participate in host filters and correlation.
`--from-start` ingests existing file contents on first open. The default starts
at EOF so adding a source does not backfill a large historic log unexpectedly.
After a source is running, Cortex checkpoints `dev`/`inode`/offset in
`file-tails.json`, resumes from that cursor on restart, reopens on
rename/create rotation, seeks back to 0 after truncation, and bounds each line
by `CORTEX_MAX_MESSAGE_SIZE`. Per-row metadata stores `file_tail_id`, `tag`,
and `path_basename`; full paths are visible only through the admin management
surface. The runtime reconciles enabled sources periodically and after
CLI/REST/MCP mutations.

### MCP server (`CORTEX_*`)

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `CORTEX_HOST` | no | `127.0.0.1` | no | HTTP listen host for MCP endpoint (loopback by default; non-loopback binds require `CORTEX_TOKEN`, OAuth, or the trusted-gateway pair) |
| `CORTEX_PORT` | no | `3100` | no | HTTP listen port for MCP endpoint |
| `CORTEX_TOKEN` | no | (none) | **yes** | Bearer token for `/mcp` auth. Generate: `openssl rand -hex 32`. When unset, auth is disabled. |
| `CORTEX_ALLOWED_HOSTS` | no | (none) | no | Extra comma-separated Host header values for RMCP Host validation |
| `CORTEX_ALLOWED_ORIGINS` | no | (none) | no | Extra comma-separated browser origins for RMCP Origin validation |

### Non-MCP API (`CORTEX_API_*`)

The plain JSON API is **always on**: it is mounted under `/api/*` on the same HTTP listener and requires its own bearer token. The server fails to start (on the `serve mcp` path) when no token is configured; `cortex setup repair` generates one if missing.

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `CORTEX_API_TOKEN` | yes | (none) | **yes** | Bearer token for `/api/*` routes — required at startup |
| `CORTEX_API_ADMIN_TOKEN` | for REST admin mutations | (none) | **yes** | Extra token sent as `X-Cortex-Admin-Token` for admin REST mutations, including `/api/file-tails`, `/api/sessions/prune-checkpoints`, `/api/db/integrity/background`, `/api/db/checkpoint`, `/api/db/vacuum`, and `/api/db/backup`. The normal API bearer is still required. |

### Shared LLM selection (`CORTEX_LLM`)

Every skill, MCP, hook and abuse assessment uses the same `CORTEX_LLM`
selector, including dry-run metadata. The selector and provider installation
settings are captured during configuration loading, so values in the managed
`~/.cortex/.env` work without exporting them. Process environment values override
managed-file values. Set it to `codex` (the default, using
Codex app-server) or `gemini` (Gemini CLI). Pin a model for all operations
with `provider/MODEL`, for example `codex/gpt-5.5` or
`gemini/gemini-3.1-flash-lite-preview`.

A model in `CORTEX_LLM` takes precedence over `--model`. With a provider-only
selector, the existing `--model` flag remains available; otherwise Codex uses
its server default and Gemini uses `gemini-3.1-flash-lite-preview`.
Empty, malformed or unsupported selectors fail without switching providers.
`--no-llm` bypasses provider selection and needs no provider credentials.
The old `CORTEX_CODEX_MODEL` and `CORTEX_HEADLESS_GEMINI_MODEL` variables
are ignored; move model selection into `CORTEX_LLM`.

Both providers run locally with isolated temporary homes. Codex links only the
authoritative `auth.json` into its isolated home, so the provider persists OAuth
refreshes directly rather than losing them in a disposable copy. Cortex never
copies credentials back over a newer login. On Windows this requires Developer
Mode or permission to create file symlinks. Codex starts an ephemeral app-server
task with no environments or dynamic tools, disables shell and web tools, and
rejects unexpected tool activity. This requires an app-server version supporting
`thread/start.environments`; use a compatible Codex installation. Gemini copies
its auth files, disables MCP servers, hooks and
context-file loading, and parses streamed assistant text. Installation and
authentication locations can still be configured separately:

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `CORTEX_LLM` | no | `codex` | no | Shared provider and optional model: `codex[/MODEL]` or `gemini[/MODEL]` |
| `CORTEX_CODEX_CMD` | no | `codex` | no | Codex executable path or command name |
| `CORTEX_CODEX_HOME` | no | `$CODEX_HOME` or `$HOME/.codex` | maybe | Absolute source directory containing Codex `auth.json` |
| `CORTEX_HEADLESS_GEMINI_CMD` | no | `gemini` | no | Gemini CLI executable path or command name |
| `CORTEX_HEADLESS_GEMINI_HOME` | no | `$HOME` | maybe | Absolute source home containing `.gemini` auth files |
| `CORTEX_LLM_COMPLETION_TIMEOUT_SECS` | no | — | no | **Deprecated, ignored.** Use `[llm].timeout_secs` for the shared invocation timeout. |

### LLM invocation guard (`CORTEX_LLM_*`, `[llm]`)

Shared by every LLM-backed assessment feature (`ai_assess`, `skill_assess`,
`mcp_assess` and `hook_assess`). `LlmRunner`
(`src/app/llm_runner.rs`) enforces global/per-action concurrency limits,
per-action rate limits, a consecutive-failure circuit breaker, a per-invocation
timeout, prompt/output byte caps (enforced before streaming provider output), a global + per-action kill switch, and writes
every invocation attempt — including denials — to the `llm_invocations` audit
table (see the `llm_invocations` MCP action / `GET /api/sessions/llm-invocations`
/ `cortex sessions llminvocations`).

> **Behavior change:** prior to this release, `cortex sessions assess` had no
> concurrency guard — multiple overlapping invocations ran in parallel. As of
> this release it routes through `LlmRunner`, whose defaults
> (`max_concurrent=1`, `max_per_action_concurrent=1`) mean a second concurrent
> `assess` call is now REJECTED with a concurrency-limited error instead of
> running alongside the first. Raise `[llm].max_concurrent` /
> `[llm].max_per_action_concurrent` if your workflow depends on concurrent
> assessments.

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `CORTEX_LLM_ENABLED` | no | `true` | no | Global kill switch — `false` denies every LLM invocation immediately (still audited with status `disabled`) |

Fields without a dedicated env override (`max_concurrent`,
`max_per_action_concurrent`, `max_invocations_per_minute`,
`max_invocations_per_hour`, `failure_threshold`, `cooldown_secs`,
`timeout_secs`, `max_prompt_bytes`, `max_output_bytes`,
`background_enrichment_enabled`, `[llm.actions.<name>].enabled`) are set via
`config.toml`'s `[llm]` section — see the sample above. Defaults match the
sample TOML block; per-action tables (e.g. `[llm.actions.ai_assess]`) default
to `enabled = true` when omitted, except `background_enrich`, which is gated
separately by `background_enrichment_enabled` (default `false`) regardless of
its own table.

### Storage (`CORTEX_*`)

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `CORTEX_DB_PATH` | no | `/data/cortex.db` | no | Path to SQLite database file |
| `CORTEX_POOL_SIZE` | no | `8` | no | SQLite connection pool size (must be >= 6); reads get `pool_size - 4` permits, the other 4 being reserved for the writer lanes that bypass the read semaphore |
| `CORTEX_SQLITE_PAGE_CACHE_MB` | no | `128` | no | Total SQLite page-cache budget across the pool; divided by `pool_size` before `PRAGMA cache_size` |
| `CORTEX_SQLITE_MMAP_MB` | no | `256` | no | Bounded SQLite mmap size; resident mapped pages may still count toward cgroup memory |
| `CORTEX_HEAVY_READ_CONCURRENCY` | no | `1` | no | Shared service-layer limiter for SQLite-heavy reads |
| `CORTEX_WAL_CHECKPOINT_MB` | no | `256` | no | WAL size threshold for bounded PASSIVE checkpoint attempts |
| `CORTEX_RETENTION_DAYS` | no | `90` | no | Days to retain logs and `llm_invocations` audit rows before automatic hourly purge (0 = keep forever for both) |

### Storage budget (`CORTEX_*`)

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `CORTEX_MAX_DB_SIZE_MB` | no | `1024` | no | Soft limit for logical DB size in MB; breach deletes oldest logs (0 = disable) |
| `CORTEX_RECOVERY_DB_SIZE_MB` | no | `900` | no | Cleanup target after DB-size breach (must be < max) |
| `CORTEX_MIN_FREE_DISK_MB` | no | `0` | no | Minimum free disk space in MB — **disabled by default**. A breach blocks writes; it does not delete data. |
| `CORTEX_RECOVERY_FREE_DISK_MB` | no | `0` | no | Hysteresis target before writes resume after a free-disk breach (must be > min when enabled) |
| `CORTEX_CLEANUP_INTERVAL_SECS` | no | `60` | no | Storage budget enforcement interval in seconds (minimum 5) |
| `CORTEX_CLEANUP_CHUNK_SIZE` | no | `2000` | no | Rows deleted per chunk during enforcement (1 to 1,000,000) |
| `CORTEX_ERR_FLOOR_WINDOW_HOURS` | no | `24` | no | err+ rows received within this window are protected from disk-pressure deletion (0 = disable floor) |
| `CORTEX_ERR_FLOOR_PER_SOURCE_CAP` | no | `10000` | no | Max protected err+ rows per source IP within the floor window (0 = disable floor) |

### Logging

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `RUST_LOG` | no | `info` | no | Rust tracing filter directive. Examples: `debug`, `cortex=debug,tower_http=info`, `trace` |

### Docker / container

| Variable | Required | Default | Sensitive | Description |
| --- | --- | --- | --- | --- |
| `CORTEX_UID` | no | `1000` | no | Container user ID |
| `CORTEX_GID` | no | `1000` | no | Container group ID |
| `CORTEX_FILE_TAIL_GROUP` | no | `adm` | no | Extra container group added by Compose so the non-root cortex user can read group-owned log files mounted at `/file-tail-root`; set a numeric gid if your host log-reader group differs |
| `CORTEX_RECEIVER_PORT` | no | `1514` | no | Host-side syslog port mapping |
| `CORTEX_PORT` | no | `3100` | no | Host-side MCP port mapping |
| `CORTEX_MCP_BIND` | no | `127.0.0.1` | no | Host interface the MCP port is published on (loopback by default; set `0.0.0.0` only with `CORTEX_TOKEN`) |
| `CORTEX_DATA_VOLUME` | no | `cortex-data` | no | Named Docker volume for `/data` |
| `CORTEX_HOME_VOLUME` | no | `~/.cortex` | no | Shared cortex home (inventory cache, setup env) mounted at `/cortex-home` |
| `CORTEX_SSH_VOLUME` | no | `~/.cortex/ssh` | no | Dedicated SSH key dir mounted read-only at `/home/cortex/.ssh` for inventory collection. Never point at `~/.ssh` — see `docs/SECURITY.md` |
| `CORTEX_VERSION` | no | current release | no | Image tag pulled by `docker-compose.prod.yml` (kept in version canon) |
| `DOCKER_NETWORK` | no | `cortex` | no | External Docker network name |

## Storage budget behavior

The two guards behave differently:

1. **DB-size guard** (enabled by default): when logical DB size exceeds `max_db_size_mb`, the oldest logs are deleted in chunks until size drops below `recovery_db_size_mb`. err+ rows inside the floor (`err_floor_window_hours` × `err_floor_per_source_cap`) are excluded from the deletable set.
2. **Free-disk guard** (disabled by default): low free disk is an external condition cortex cannot fix by deleting its own data, so a breach **blocks new writes** instead of self-trimming. Writes resume once free disk rises above `recovery_free_disk_mb` (hysteresis prevents oscillation).
3. **Write blocking**: if DB-size cleanup cannot recover enough space (e.g. no more deletable logs), the batch writer also blocks new writes until storage becomes healthy.
4. **Enforcement interval**: checked every `cleanup_interval_secs` seconds (default 60). The age-based retention purge is separate and runs hourly.

Set both `max_db_size_mb` and `min_free_disk_mb` to 0 (with their recovery targets at 0) to disable all storage enforcement.

## SQLite migration upgrades

Startup creates missing schema objects automatically. Small migrations are expected to complete quickly, but heavyweight migrations on a populated database can hold SQLite's write lock before syslog listeners and `/health` are ready. The server logs an operator-visible `Migration N: starting ...` message before such work and a completion message with elapsed time.

**One-time `auto_vacuum` conversion VACUUM:** the first startup against a database that is not yet `auto_vacuum=INCREMENTAL` runs a full `VACUUM` to convert it. This is logged loudly at startup and can take minutes on large databases — treat it like a heavy migration (backup first, expect `/health` and the listeners to be unavailable until it completes). It runs once; subsequent startups skip it.

For populated databases, treat heavy migrations as a planned upgrade step:

1. Stop or quiet high-volume senders if packet loss is unacceptable.
2. Take a WAL-safe backup with `scripts/backup.sh` or `sqlite3 /data/cortex.db ".backup /data/syslog-pre-upgrade.db"`.
3. Start the upgraded container or binary and watch `docker compose logs -f cortex` or the relevant service log for migration start/completion lines.
4. Wait for `curl -sf http://localhost:3100/health` to succeed.
5. Run `cortex stats --json` or `mcporter call ... action=stats` and confirm `total_logs`, storage metrics, and `write_blocked` match expectations.

If a migration must be abandoned, stop the new process before changing files, restore the WAL-safe backup, and restart the previous image or binary. See [RELEASE.md](RELEASE.md) for the current deploy gate checklist.

## Validation rules

- `CORTEX_POOL_SIZE` must be > 0
- `CORTEX_SQLITE_PAGE_CACHE_MB` must be > 0 and its derived KiB-per-connection value must fit SQLite's signed PRAGMA range
- `CORTEX_SQLITE_MMAP_MB` derived bytes must fit SQLite's signed PRAGMA range
- `CORTEX_HEAVY_READ_CONCURRENCY` must be > 0
- `CORTEX_WAL_CHECKPOINT_MB` must be > 0
- `recovery_db_size_mb` must be > 0 and < `max_db_size_mb` when DB size guard is enabled
- `recovery_free_disk_mb` must be > 0 and > `min_free_disk_mb` when free-disk guard is enabled
- `cleanup_interval_secs` must be >= 5
- `cleanup_chunk_size` must be between 1 and 1,000,000
- `err_floor_per_source_cap` must be > 0 when `err_floor_window_hours` is set
- `CORTEX_API_TOKEN` is required for the server to start (`/api/*` is always mounted)
- Bind host fields (`CORTEX_RECEIVER_HOST`, `CORTEX_HOST`) must not contain a colon (port is a separate setting)
- `CORTEX_ALLOWED_HOSTS` values may include `host:port` to match reverse-proxy Host headers
- `CORTEX_DOCKER_HOSTS` must contain at least one hostname when Docker ingest is enabled
- Docker ingest host names must be unique

## Plugin deployment

`cortex serve mcp` runs as a daemon (syslog listener + HTTP MCP server), so the plugin connects via HTTP -- not stdio.

When installed as a Claude Code plugin, users are prompted for:

| Field | Sensitive | Description |
| --- | --- | --- |
| `server_url` | no | Base server URL (e.g. `https://cortex.example.com`) |
| `api_token` | yes | Bearer token used by the plugin MCP client; enforced by the server unless `no_auth=true` |
| `no_auth` | no | Explicit no-auth mode; non-loopback server binds also require `CORTEX_TRUSTED_GATEWAY_NO_AUTH=true` |
| `is_server` | no | Whether this host owns the Docker Compose deployment |

These values are interpolated into `plugins/cortex/mcp.json` via `${user_config.*}` syntax. See [plugin/CONFIG.md](plugin/CONFIG.md) for details.

## .env.example conventions

- Group variables by section with comment headers
- Required variables first within each group
- No actual secrets -- use descriptive placeholders
- See `.env.example` at the repo root for the full template
