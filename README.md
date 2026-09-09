# Cortex

[![CI](https://github.com/dinglebear-ai/cortex/actions/workflows/ci.yml/badge.svg)](https://github.com/dinglebear-ai/cortex/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dinglebear-ai/cortex)](https://github.com/dinglebear-ai/cortex/releases)
[![npm](https://img.shields.io/npm/v/cortex-rmcp)](https://www.npmjs.com/package/cortex-rmcp)
[![crates.io](https://img.shields.io/crates/v/cortex)](https://crates.io/crates/cortex)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Self-hosted homelab log intelligence over MCP, CLI, and REST with SQLite/FTS.

It collects logs and operational evidence, stores them in SQLite with FTS5 search, and exposes one shared intelligence layer through CLI, REST, MCP, and a bundled browser workspace.

Cortex began as a syslog receiver. It now covers network logs, Docker, managed files, OpenTelemetry logs, host heartbeats, fleet inventory, shell and agent activity, and Claude, Codex, Gemini CLI, and Antigravity transcripts. It correlates those sources into timelines, incidents, and an evidence-backed topology graph without making the graph a second source of truth.

## At a glance

| Area | What Cortex provides |
| --- | --- |
| Ingest | UDP/TCP syslog, OTLP/HTTP logs, Docker logs and events, managed file tails, host heartbeats, AI transcripts, shell history, agent command records, and fleet inventory |
| Storage | SQLite in WAL mode, FTS5 full-text search, bounded metadata, retention, storage budgets, maintenance jobs, checkpoints, and 58 sequential schema migrations |
| Investigation | Search, filtering, context, timelines, patterns, anomaly comparison, cross-source correlation, recurring error signatures, deterministic incident bundles, and graph explanations |
| Fleet intelligence | SSH and API inventory collectors, host state, service topology, container and route relationships, redacted evidence, and rebuildable graph projections |
| AI operations | Claude, Codex, Gemini CLI, and Antigravity session indexing; skill, MCP, and hook event extraction where each provider exposes them; incident clustering; and guarded local LLM assessments |
| Interfaces | Native CLI, one action-dispatched MCP tool, authenticated REST APIs, MCP prompts and resources, an MCP Apps search widget, and a bundled investigation workspace |
| Operations | Setup and repair, diagnostics, Compose control, backup, integrity checks, WAL checkpoints, vacuum, update workflows, agents, and health endpoints |

> [!IMPORTANT]
> Cortex is designed for a trusted homelab or small private fleet. It is not a clustered log warehouse, a general-purpose SIEM, or a safe place to expose unauthenticated administrative surfaces to the public internet.

## Contents

- [Quick start](#quick-start)
- [How Cortex is built](#how-cortex-is-built)
- [Ingestion](#ingestion)
- [Investigation and intelligence](#investigation-and-intelligence)
- [Fleet inventory and graph](#fleet-inventory-and-graph)
- [AI session intelligence](#ai-session-intelligence)
- [Alerts and notifications](#alerts-and-notifications)
- [Interfaces](#interfaces)
- [Configuration](#configuration)
- [Authentication and trust boundaries](#authentication-and-trust-boundaries)
- [Storage and maintenance](#storage-and-maintenance)
- [Deployment and distribution](#deployment-and-distribution)
- [Operations](#operations)
- [Development and verification](#development-and-verification)
- [Documentation](#documentation)
- [Current boundaries](#current-boundaries)
- [License](#license)

## Quick start

### Install the CLI

The npm launcher is the fastest path for local CLI and stdio MCP use:

```bash
npx -y @dinglebear/cortex --help
npx -y @dinglebear/cortex mcp
```

Install it permanently with:

```bash
npm install --global @dinglebear/cortex
cortex --version
```

The launcher requires Node.js 18 or newer. It downloads a checksum-verified native release binary and currently supports Linux x64 and Windows x64.

Build from source with the current stable Rust toolchain:

```bash
git clone https://github.com/dinglebear-ai/cortex.git
cd cortex
mise install       # optional, but pins the repository tools
just build
./.cache/cargo/debug/cortex --version
```

### Start a local server

The full daemon starts UDP and TCP syslog receivers plus the shared HTTP server. Use separate MCP and REST tokens:

```bash
mkdir -p "$HOME/.cortex/data"
export CORTEX_DB_PATH="$HOME/.cortex/data/cortex.db"
export CORTEX_TOKEN="$(openssl rand -hex 32)"
export CORTEX_API_TOKEN="$(openssl rand -hex 32)"

cortex serve mcp
```

Defaults:

- Syslog: `0.0.0.0:1514` over UDP and TCP
- HTTP: `127.0.0.1:3100`
- MCP: `http://127.0.0.1:3100/mcp`
- REST: `http://127.0.0.1:3100/api/*`
- Investigation workspace: `http://127.0.0.1:3100/app`

Verify it from another terminal:

```bash
curl -fsS http://127.0.0.1:3100/health
logger -n 127.0.0.1 -P 1514 --tcp "cortex quickstart from $(hostname)"

export CORTEX_API_TOKEN="the-same-api-token"
cortex tail --limit 10
```

For a managed local deployment, `cortex setup repair` creates or repairs the Cortex home, Compose assets, data paths, and missing 64-character MCP and REST tokens without replacing existing token values.

### Connect an MCP client

Query-only stdio mode reads the configured local database and starts no network listeners:

```json
{
  "mcpServers": {
    "cortex": {
      "command": "npx",
      "args": ["-y", "cortex-rmcp", "mcp"],
      "env": {
        "CORTEX_DB_PATH": "/absolute/path/to/cortex.db"
      }
    }
  }
}
```

Streamable HTTP mode connects to the persistent daemon:

```json
{
  "mcpServers": {
    "cortex": {
      "url": "http://127.0.0.1:3100/mcp",
      "headers": {
        "Authorization": "Bearer your-cortex-token"
      }
    }
  }
}
```

A useful first call is:

```json
{"action":"status"}
```

Then narrow the investigation with `tail`, `errors`, `search`, `timeline`, or `context` before using broader analysis operations.

## How Cortex is built

Cortex is one Rust binary with multiple operating modes. The same application and service layer backs the CLI, REST handlers, and MCP handlers, so validation, limits, identity resolution, redaction, and business rules do not belong to one transport alone.

```text
                         INGESTION

  Syslog UDP/TCP       OTLP logs          Docker agent / pull
  Managed file tails  Heartbeats         Claude / Codex / Gemini / Antigravity
  Shell history       Agent commands     Fleet inventory
          \               |                    /
           \              |                   /
            +---- bounded parsing and enrichment ----+
                              |
                    scrub, normalize, batch
                              |
                    SQLite WAL + FTS5
                              |
             +----------------+----------------+
             |                                 |
    authoritative records             derived accelerators
    logs, heartbeats,                 rollups, signatures,
    inventory, sessions              graph projections
             |                                 |
             +----------------+----------------+
                              |
                     shared service layer
                              |
          CLI       REST       MCP       Web workspace
```

The daemon supervises its receivers and background services with cooperative cancellation. Shutdown drains HTTP requests, gives maintenance tasks 10 seconds to finish before abort-and-join, gives ingest 5 seconds to flush, and then attempts a WAL checkpoint. Already-running blocking SQLite calls cannot be cancelled by Tokio.

Background services include:

- Retention and storage-budget enforcement
- WAL and FTS maintenance
- Docker ingest supervision
- File-tail supervision
- Error-signature scanning
- Notification evaluation, dispatch, and digest scheduling
- Inventory refresh and backfill
- Graph projection refresh
- AI-session and timeline rollups
- Database optimization and maintenance jobs

Heavy analytical reads and maintenance jobs have separate concurrency controls so one expensive investigation cannot starve the ingest path.

## Ingestion

All log-like sources are normalized into the same durable log model, enriched where safe, scrubbed where configured, and written through bounded batch paths.

### Syslog over UDP and TCP

Cortex listens on the same configurable port for UDP and TCP syslog. It parses common RFC 3164 and RFC 5424 shapes, preserves the raw frame, records sender identity, normalizes severity and facility, and enriches known application formats.

Relevant defaults:

- Bind: `0.0.0.0:1514`
- Maximum message: 8 KiB
- Maximum concurrent TCP connections: 512
- TCP idle timeout: 300 seconds
- Writer batch: 100 records or 500 ms
- Write queue capacity: 10,000 records

Syslog has no application-layer authentication. Restrict senders with network controls and `CORTEX_ALLOWED_SOURCE_CIDRS` when the listener is reachable beyond a trusted network.

Built-in enrichment recognizes useful signals from AdGuard, Authelia, Docker lifecycle events, fail2ban, Linux kernel and OOM events, SWAG, reverse-proxy logs, and host-local Cortex Docker agent metadata. Source gates can restrict enrichment that would otherwise trust a marker inside an unauthenticated syslog body.

### OpenTelemetry logs

Cortex accepts OTLP/HTTP log export requests at `POST /v1/logs` on the shared HTTP listener. Requests are bounded to 4 MiB and flow into the normal Cortex writer.

Current OTLP scope is intentionally narrow:

- Logs over HTTP are supported.
- OTLP traces are not accepted.
- OTLP metrics are not accepted.
- OTLP/gRPC is not implemented.

`POST /v1/logs` authenticates with **`CORTEX_TOKEN`** — the same static MCP bearer token that guards `POST /mcp`, read from the managed `~/.cortex/.env` on a deployed host. It is **not** `CORTEX_API_TOKEN` (REST `/api/*`) and **not** `CORTEX_API_ADMIN_TOKEN`. Loopback and trusted-gateway policies skip the check. An OAuth-only deployment with no static token denies OTLP outright, because machine exporters have no OAuth flow — so a non-loopback OAuth-only `/v1/logs` exposure is rejected at startup unless `CORTEX_TOKEN` is set.

### Docker logs and events

Cortex supports two Docker collection paths:

1. **Host-local agent**, the preferred multi-host path. The host-local cortex agent reads the local Docker socket, converts logs and lifecycle events into bounded records, and forwards them to the server without changing Docker's daemon logging driver.
2. **Central pull compatibility mode**, an optional server-side collector for explicitly configured Docker Engine or docker-socket-proxy HTTP endpoints. It records per-container checkpoints and reconnects with bounded exponential backoff.

Central pull is disabled by default. The `CORTEX_DOCKER_HOSTS` shorthand expands hosts into insecure `http://host:2375` endpoints and should only be used on a tightly controlled private network. A hosts file supports explicit base URLs and safer endpoint configuration.

### Managed file tails

Managed file-tail sources are persisted in a registry and supervised by the daemon. Add, remove, list, and inspect sources through the CLI, REST, or the `file_tails` MCP admin action.

The path policy rejects unsafe targets, including paths outside configured roots, symlink escapes, non-regular files, and sensitive mounts. Container deployments expose an explicit read-only file-tail root rather than the entire host filesystem.

### Host heartbeats

The host agent can post bounded JSON snapshots to `POST /v1/heartbeats`. Heartbeats include host state such as load, memory, disks, networking, processes, and container summaries. They power `host_state`, `fleet_state`, and `correlate_state`.

Heartbeat request bodies are capped at 256 KiB. Heartbeat data has short operational retention separate from the main log-retention policy.

### AI transcripts

Cortex indexes local and forwarded transcript data from:

- Claude Code projects under `~/.claude/projects`
- Codex sessions and worktrees under `~/.codex/sessions` and `~/.codex/worktrees`
- Gemini CLI chat data under `~/.gemini/tmp`
- Antigravity desktop's redacted transcript projections under `~/.gemini/antigravity/brain/<session>/.system_generated/logs/transcript.jsonl`
- Antigravity CLI's redacted transcript projections under `~/.gemini/antigravity-cli/brain/<session>/.system_generated/logs/transcript.jsonl`

The Antigravity adapter reads only the narrow redacted JSONL projections above; it does not scan conversation databases or other brain artifacts. The scanner supports incremental checkpoints, parse-error records, bounded chunks, broad-path rejection, and safe recovery from changed files. It extracts normalized transcript rows plus dedicated skill, MCP tool-call, and hook events where those lanes are represented by the provider schema, and reports unsupported lanes honestly.

A satellite agent can send already-parsed records to `POST /v1/ai-transcripts`, which prevents transcript collection from depending on the database living on the same host as the AI client.

### Shell and agent activity

Satellite agents can forward additional operational evidence to the shared server:

- `POST /v1/agent-commands` for deduplicated agent command-spool records
- `POST /v1/shell-history` for parsed Bash, Zsh extended-history, and Atuin records

These records use the same storage and correlation model as the rest of Cortex, which makes an agent change or shell command visible beside the service failure that followed it.

### Fleet inventory

Inventory collection builds a redacted fleet snapshot from local files, SSH probes, Docker endpoints, and optional service APIs, then projects safe relationships into the investigation graph.

## Investigation and intelligence

Cortex exposes bounded workflows rather than a raw SQL console.

### Search and context

- FTS5 full-text search with host, app, severity, source, project, session, and time filters
- Structured filter-only retrieval for indexed fields
- Recent tails and single-row retrieval with raw-frame evidence
- Surrounding context around a log ID or timestamp
- Host, app, and source-IP inventories
- Clock-skew measurement using event and receive timestamps

### Time and volume analysis

- Bucketed timelines
- Ingest-rate and queue-pressure state
- Near-duplicate message pattern clustering
- Recent-versus-baseline anomaly detection
- Side-by-side time-range comparison
- Silent-host and silent-stream detection
- Database, storage, and runtime statistics

### Correlation

- Cross-host correlation around a timestamp
- AI-session anchor correlation against infrastructure logs
- Topic resolution through the entity graph before timeline construction
- Host-state correlation across logs, heartbeats, and inventory
- Historical incident similarity using FTS5
- Deterministic incident context bundles with bounded evidence

### Recurring errors

An optional background scanner groups repeating error signatures into durable records. Operators can inspect unaddressed signatures, acknowledge them, revoke acknowledgements, and correlate a signature with logs and graph evidence.

Error detection is disabled by default. When enabled, it scans bounded batches, records lower-severity recurrences without paging, and can notify only above a configured severity floor.

## Fleet inventory and graph

### Inventory collectors

The native inventory subsystem can collect and normalize evidence from:

- Local and remote Compose, reverse-proxy, and AdGuard Home configuration
- Local process, storage, project, and raw configuration inventories
- SSH sessions to remote fleet hosts
- Local and remote Docker endpoints
- Tailscale
- UniFi
- Unraid
- Media-stack services and related APIs

SSH collection uses strict host-key verification, bounded concurrency, timeouts, and retry backoff. Sensitive fields are redacted before persistence.

The cache lives under `~/.cortex/inventory` by default and includes:

- `normalized/homelab.json`: the typed normalized fleet snapshot
- `collection-state.json`: collector health, timing, and warning state
- `raw/<run-id>/...`: raw-but-redacted supporting artifacts

The `map` action reads the normalized cache. It does not trigger a collection run and does not return raw config bodies or credential-bearing URLs.

### Derived investigation graph

The graph connects canonical entities such as:

- Hosts and source identities
- Logical services and concrete service instances
- Applications and containers
- Domains, routes, and endpoints
- AI projects and sessions
- Error signatures and operational findings

Relationships carry confidence, trust, reason codes, timestamps, and bounded evidence references. The graph supports entity resolution, neighborhoods, topology questions, evidence lookup, and explanation paths.

The graph is a rebuildable projection. Raw logs, heartbeats, inventory records, error signatures, and AI session data remain authoritative. Projection rebuilds use staging tables and a short serialized swap, record watermarks and metrics, and preserve explicit degraded state when refresh fails.

## AI session intelligence

Cortex treats AI transcripts as operational evidence, not merely chat archives.

### Deterministic session analysis

The shared service layer can:

- List and search sessions by project
- Measure activity in five-hour usage blocks
- Summarize project context
- List observed tools and projects
- Detect frustration or abuse signals
- Group those signals into scored incidents
- Correlate AI activity with non-AI infrastructure logs
- Extract skill invocations
- Extract MCP server and tool-call events
- Extract hook configuration and runtime events
- Build skill-first, MCP-first, and hook-first investigation bundles

The deterministic query and incident workflows are available through CLI, REST, and MCP.

### Guarded local assessments

LLM-backed assessments are deliberately local-only. They run through `cortex assess` and are not exposed as MCP actions or REST routes because they spawn a local Gemini subprocess.

The shared LLM runner enforces:

- A global kill switch
- Global and per-action concurrency limits
- Per-minute and per-hour rate limits
- Per-action circuit breakers and cooldowns
- Invocation timeouts
- Prompt and output byte caps
- An explicit background-enrichment gate, disabled by default
- Durable audit records for successes, failures, timeouts, and policy denials

Default guard values allow one concurrent invocation, three per minute and thirty per hour per action, a 120-second timeout, a 1 MiB prompt cap, and a 256 KiB output cap.

Prompt scrubbing is enabled by default. Skill, MCP, and hook event extraction happens before scrubbed transcript text is persisted, so structured operational signals are retained without requiring raw prompt storage.

## Alerts and notifications

Notifications are optional and disabled by default. When enabled, Cortex uses Apprise as the delivery bridge and a durable SQLite outbox for retry, deduplication, and dead-letter handling.

Built-in evaluators cover:

- OOM kills
- Containers exiting nonzero
- fail2ban bans
- Authelia MFA failures
- Disk-fill and storage guardrail pressure
- Ingest queue pressure
- Complete ingest silence
- Heartbeat silence
- Silence from previously active continuous streams

The notification subsystem includes:

- Configurable evaluator cadence
- Per-rule toggles and thresholds
- Deduplication windows
- Outage-scoped silence keys
- Bounded retry with dead-letter state
- Recent-firing history
- Test notifications
- A scheduled daily digest

By default, continuous stream-silence tracking covers UDP/TCP syslog, agent Docker, Docker stream and event records, and managed file tails. Sporadic sources such as transcripts and shell history are intentionally excluded.

## Interfaces

### CLI

Run `cortex --help` and command-specific `--help` for the generated command tree.

| Group | Purpose |
| --- | --- |
| `search`, `filter`, `tail` | Log retrieval |
| `hosts`, `apps`, `entity`, `graph` | Discovery and topology |
| `analysis`, `correlate`, `state`, `stats`, `timeline` | Investigation and analytics |
| `sessions`, `assess` | AI-session queries and local guarded assessments |
| `alerts` | Error signatures, acknowledgements, and notification history |
| `ingest`, `heartbeat` | Collectors, agents, file tails, inventory, and heartbeats |
| `serve`, `mcp` | Full daemon and query-only stdio MCP modes |
| `doctor`, `status`, `db`, `compose` | Diagnostics and maintenance |
| `setup`, `update`, `config`, `completions` | Lifecycle and operator tooling |

Examples:

```bash
cortex search "oom killer" --host devhost --since 1h
cortex filter --severity err --since 6h
cortex timeline --since 24h
cortex sessions search "migration failure"
cortex graph explain --help
cortex alerts errors list
cortex ingest inventory refresh --json
cortex ingest filetail list
cortex status
cortex doctor
```

The CLI supports direct/local operation and HTTP operation. REST-backed mode is the normal remote path and uses `CORTEX_URL` plus `CORTEX_API_TOKEN`.

### MCP

Cortex exposes one MCP tool named `cortex`. Its required `action` field selects an action from a single authoritative Rust registry. The mechanically generated current count is published in [the live coverage inventory](tests/TEST_COVERAGE.md).

The current scope split is:

- 52 read actions requiring `cortex:read`
- 6 admin actions requiring `cortex:admin`: `artifact_evidence_record`, `ack_error`, `unack_error`, `file_tails`, `notifications_test`, and `llm_invocations`
- 1 informational action, `help`, which requires an authenticated context when authentication is mounted but no read/admin scope

#### Complete MCP action catalog

| Domain | Actions |
| --- | --- |
| Log retrieval | `search`, `filter`, `tail`, `errors`, `get`, `context` |
| Discovery and health | `hosts`, `apps`, `source_ips`, `status`, `stats`, `ingest_rate`, `silent_hosts`, `clock_skew` |
| Analytics and correlation | `timeline`, `patterns`, `anomalies`, `compare`, `correlate`, `topic_correlate`, `similar_incidents`, `recurring_error_comparison`, `incident_context` |
| Fleet and topology | `map`, `host_state`, `fleet_state`, `correlate_state`, `graph`, `compose_status`, `compose_doctor` |
| AI sessions | `sessions`, `search_sessions`, `abuse`, `abuse_incidents`, `abuse_investigate`, `ai_correlate`, `usage_blocks`, `project_context`, `list_ai_tools`, `list_ai_projects` |
| AI operational events | `skill_events`, `skill_incidents`, `skill_investigate`, `mcp_events`, `mcp_incidents`, `mcp_investigate`, `hook_events`, `hook_incidents`, `hook_investigate` |
| Errors and administration | `unaddressed_errors`, `ack_error`, `unack_error`, `notifications_recent`, `notifications_test`, `file_tails`, `llm_invocations`, `artifact_evidence_record` |
| Reference | `help` |

The runtime schema contains per-action flags, defaults, examples, relative cost metadata, and validation. See [docs/mcp/SCHEMA.md](docs/mcp/SCHEMA.md) for the parameter reference.

#### MCP prompts

Cortex ships twelve reusable infrastructure prompts:

- `infra.incident-triage`
- `infra.host-health`
- `infra.service-outage`
- `infra.security-auth-review`
- `infra.noise-reduction`
- `infra.agent-change-correlation`
- `infra.docker-container-regression`
- `infra.network-dns-failure`
- `infra.storage-pressure`
- `infra.auth-bruteforce`
- `infra.syslog-forwarding-gap`
- `infra.after-deploy-check`

See [docs/mcp/PROMPTS.md](docs/mcp/PROMPTS.md) for arguments and output expectations.

#### MCP resources and UI

The MCP server exposes:

| URI | Purpose |
| --- | --- |
| `cortex://schema/mcp-tool` | Live JSON schema for the action-dispatched tool |
| `cortex://schema/prompt-output` | Schema for structured incident-style prompt output |
| `ui://cortex/query-widget` | Self-contained MCP Apps search widget |

The query widget is progressive enhancement. UI-capable MCP hosts can render it; ordinary MCP clients continue receiving the normal text and structured JSON result.

### REST

Authenticated JSON routes live under `/api/*` on the shared HTTP listener. They cover the same major query domains as MCP and add operator workflows for session checkpoints, parse errors, database integrity jobs, backup, checkpoint, and vacuum.

The versioned investigation API lives under `/api/v1/*` and provides Ask Cortex plus graph entity, neighborhood, explanation, and evidence endpoints for the bundled browser workspace.

REST requires `CORTEX_API_TOKEN`. Privileged maintenance and file-tail workflows can also require `CORTEX_API_ADMIN_TOKEN`.

See [docs/api.md](docs/api.md) for the route and response reference.

### Browser investigation workspace

The daemon serves a bundled workspace at `/app` and `/app/investigate`. It includes:

- Runtime and schema status
- Fleet and ingest summaries
- Ask Cortex investigation requests
- An interactive Cytoscape graph canvas
- Evidence inspection
- A recent-log timeline

The app is embedded into the Rust binary, has no external runtime dependency, uses a restrictive Content Security Policy, and keeps the entered REST bearer token in memory only. The current UI identifies itself as an investigation preview rather than a full general-purpose dashboard.

### Claude Code plugin

`.claude-plugin/plugin.json` packages Cortex as a Claude Code plugin. It declares exactly three surfaces plus configuration:

| Key | Points at |
| --- | --- |
| `mcpServers` | `plugins/cortex/mcp.json` — HTTP transport to `${user_config.server_url}/mcp` with a `Bearer ${user_config.api_token}` header |
| `skills` | `plugins/cortex/skills/` — twelve skills |
| `userConfig` | Server-vs-client mode, `server_url`, `api_token`, auth mode and OAuth fields, syslog/MCP bind host and port, retention and storage budgets, Docker ingest, and fleet hosts |

The twelve skills are `cortex`, `frustration-assessment`, `hook-friction-assessment`, `incidents`, `logs`, `mcp-friction-assessment`, `report`, `searching-sessions`, `skill-improvement-assessment`, `topology`, `troubleshoot`, and `version-check`.

The plugin registers **no Claude Code lifecycle hooks** — there is no `hooks` key and no `hooks.json`. Setup is explicit: run `cortex setup pluginhook` (or the `plugins/cortex/scripts/plugin-setup.sh` adapter) after installing, upgrading, or reconfiguring. `just validate-plugin` and `scripts/validate-marketplace.sh` assert the `hooks` key stays absent, and `cargo xtask check-version-sync` asserts the manifest carries no top-level `version`.

See [docs/plugin/HOOKS.md](docs/plugin/HOOKS.md) for the setup lifecycle and [docs/plugin/PLUGINS.md](docs/plugin/PLUGINS.md) for the manifest reference.

### Health endpoints

- `GET /health`: minimal unauthenticated liveness response for containers and proxies
- `GET /health/full`: authenticated detailed health and ingest observability

## Configuration

Cortex loads configuration in this order, with later layers winning:

1. Built-in defaults
2. A partial `config.toml` in the current working directory
3. The managed `$CORTEX_HOME/.env` file, normally `~/.cortex/.env`
4. Process environment variables

### Important defaults

| Setting | Default |
| --- | ---: |
| Syslog bind | `0.0.0.0:1514` UDP and TCP |
| HTTP bind | `127.0.0.1:3100` |
| Database path | `/data/cortex.db` unless setup or environment overrides it |
| SQLite pool size | 8 connections |
| SQLite page cache budget | 128 MiB total |
| SQLite mmap target | 256 MiB |
| Heavy-read concurrency | 1 |
| WAL checkpoint threshold | 256 MiB |
| Log retention | 90 days |
| Logical database limit | 1,024 MiB |
| Recovery threshold | 900 MiB, auto-adjusted when the limit is raised substantially |
| Cleanup cadence | 60 seconds |
| Notifications | Disabled |
| Recurring-error scanner | Disabled |
| Central Docker pull | Disabled |
| Prompt scrubbing | Enabled |
| Background LLM enrichment | Disabled |

Useful environment variables include:

| Variable | Purpose |
| --- | --- |
| `CORTEX_HOME` | Managed configuration and operational home |
| `CORTEX_DB_PATH` | SQLite database path |
| `CORTEX_RECEIVER_HOST`, `CORTEX_RECEIVER_PORT` | Syslog listener |
| `CORTEX_ALLOWED_SOURCE_CIDRS` | Optional syslog sender allowlist |
| `CORTEX_HOST`, `CORTEX_PORT` | Shared HTTP listener |
| `CORTEX_TOKEN` | Static MCP, OTLP, heartbeat, and forwarding bearer token |
| `CORTEX_API_TOKEN` | REST bearer token |
| `CORTEX_API_ADMIN_TOKEN` | Additional REST admin token where required |
| `CORTEX_AUTH_MODE` | Static-token or OAuth authentication mode |
| `CORTEX_PUBLIC_URL` | Public URL used for OAuth and exposure validation |
| `CORTEX_ALLOWED_HOSTS`, `CORTEX_ALLOWED_ORIGINS` | Host-header and CORS policy |
| `CORTEX_RETENTION_DAYS` | Log retention |
| `CORTEX_MAX_DB_SIZE_MB` | Logical database storage budget |
| `CORTEX_MIN_FREE_DISK_MB` | Optional external free-space write guard |
| `CORTEX_FILE_TAIL_ALLOWED_ROOTS` | Managed file-tail root allowlist |
| `CORTEX_DOCKER_INGEST_ENABLED` | Enable central Docker pull compatibility mode |
| `CORTEX_SCRUB_PROMPTS` | Best-effort AI prompt credential scrubbing |
| `CORTEX_NOTIFICATIONS_ENABLED` | Enable notification services |
| `CORTEX_LLM_ENABLED` | Global local-assessment kill switch |
| `RUST_LOG` | Tracing filter |

See [docs/CONFIG.md](docs/CONFIG.md) for the complete reference and validation rules.

## Authentication and trust boundaries

Cortex intentionally separates transport credentials and capabilities.

### MCP

- `CORTEX_TOKEN` authenticates static-token HTTP MCP calls.
- Static-token callers receive `cortex:read` by default.
- Set `CORTEX_STATIC_TOKEN_ADMIN=true` only when the token should also receive `cortex:admin`.
- OAuth mode supports explicit read and admin scopes through the shared authentication layer.
- Non-loopback unauthenticated binds are rejected unless an explicit trusted-gateway mode is configured.

### REST

- `CORTEX_API_TOKEN` is separate from `CORTEX_TOKEN`.
- REST refuses to mount without an API token.
- Sensitive maintenance and file-tail operations can require `CORTEX_API_ADMIN_TOKEN` in addition to the normal REST bearer token.

### Ingest endpoints

- Syslog itself is unauthenticated. Use CIDR and network controls.
- OTLP logs, heartbeats, AI transcripts, shell history, and agent-command forwarding use the Cortex bearer-token policy when configured.
- Unauthenticated forwarding endpoints are loopback-only unless the operator explicitly establishes another trusted boundary.

### Data handling

- AI prompt scrubbing is enabled by default.
- Inventory is redacted before it reaches the normalized cache.
- MCP and REST return bounded evidence instead of raw credential-bearing config artifacts.
- File tails are constrained to configured roots and reject path escapes.
- Docker endpoints and SSH keys are treated as privileged infrastructure access.
- Container examples mount a dedicated least-privilege SSH directory rather than a user's complete `~/.ssh`.

Read [docs/SECURITY.md](docs/SECURITY.md), [docs/GUARDRAILS.md](docs/GUARDRAILS.md), and [docs/OAUTH.md](docs/OAUTH.md) before exposing Cortex beyond loopback or a trusted gateway.

## Storage and maintenance

### SQLite model

Cortex uses SQLite with:

- WAL mode
- A bounded r2d2 connection pool
- FTS5 external-content indexing for log messages
- Covering and composite indexes for common filters and timelines
- Transactional batch writes
- Durable source checkpoints and parse errors
- Maintenance job tracking
- Online backup support
- Integrity checks, checkpoints, and vacuum workflows

The current schema history contains 58 sequential migrations. CI derives this denominator from `KNOWN_SCHEMA_VERSION` and the migration registry. Forwarding receipts have a seven-day replay horizon and are removed when their canonical evidence is deleted. Senders retain unacknowledged spool records; retries beyond the horizon are new ingestion attempts.

### Authoritative and derived data

Authoritative records include:

- Normalized logs and raw frames
- Hosts and source identities
- Transcript source, checkpoint, import, and parse-error records
- Heartbeats and component snapshots
- Inventory snapshots and collector state
- Error signatures and acknowledgement events
- Skill, MCP, and hook events
- Notification outbox and firing history
- LLM invocation audit records

Derived accelerators include:

- AI session rollups
- Hourly timeline rollups
- Inventory statistics
- Stream-last-seen state
- Entity graph tables and evidence relationships

Derived data can be refreshed or rebuilt from authoritative evidence.

### Storage guardrails

The daemon enforces retention and a logical database budget in chunks. It can enter a write-block state before uncontrolled growth damages the host, then resume after recovery thresholds are met. An optional minimum-free-disk guard protects against pressure caused by data outside the Cortex database without deleting Cortex data merely because another application filled the filesystem.

Operational commands:

```bash
cortex db status
cortex db integrity
cortex db checkpoint
cortex db backup --help
cortex db vacuum --help
```

Maintenance operations, including synchronous and background integrity checks, share one process-wide single-flight gate and are separately limited from heavy read queries. Concurrent attempts return a retryable busy response.

## Deployment and distribution

### Current identities

| Artifact | Current identity |
| --- | --- |
| Canonical source repository | `dinglebear-ai/cortex` |
| Native binary and CLI | `cortex` |
| npm launcher | `@dinglebear/cortex` |
| MCP Registry server name | `ai.dinglebear/cortex` |
| Published OCI image | `ghcr.io/dinglebear-ai/cortex:v<version>` |

The source repository and its published artifacts both live under the `dinglebear-ai` organization. The legacy `jmagar` namespace is retired: `scripts/check-public-identity.sh` fails the build on any tracked file that reintroduces it, and the release workflow derives the MCP Registry OCI identifier from the same `REGISTRY`/`IMAGE_NAME` it pushes to, so the two cannot drift apart again.

Container images published before the move remain readable under the legacy namespace for older pinned deployments, but nothing new is pushed there.

### Native and npm

- The repository ships Linux x86_64 and Windows x86_64 release installers.
- The npm launcher supports `linux/x64` and `win32/x64` and verifies release checksums.
- Source builds use Rust edition 2024 and the current stable toolchain in CI.

### Docker Compose

The repository includes:

- `docker-compose.yml` for a local build from the checkout
- `docker-compose.prod.yml` for the published image
- `config/Dockerfile` for a non-root Debian runtime image

Manual Compose deployment expects an external Docker network named `cortex` unless `DOCKER_NETWORK` overrides it:

```bash
docker network inspect cortex >/dev/null 2>&1 || docker network create cortex
cp .env.example .env
bash scripts/prepare-compose-dirs.sh
docker compose up -d
curl -fsS http://127.0.0.1:3100/health
```

The preflight resolves the `/backups` bind with Docker Compose's own parser and
creates the default or `CORTEX_BACKUP_DIR` override at mode `0700`. Compose is
configured not to create this host path implicitly, preventing root-owned or
overly permissive backup directories.

The Compose files:

- Publish syslog on UDP/TCP 1514
- Publish HTTP to host loopback by default
- Persist the database in a stable named volume or configured bind mount
- Run as a non-root UID/GID
- Mount inventory SSH credentials and workspace data read-only
- Mount a dedicated file-tail root read-only
- Use a 2 GiB default memory limit, configurable per host
- Include a health check and bounded container logs

For managed installation and repair:

```bash
cortex setup check
cortex setup repair
```

### Host agents

Cortex includes setup and runtime support for satellite collection, including:

- Heartbeat agents
- Docker stream agents
- AI-session watch services and timers
- Shell-history forwarding
- Agent-command forwarding
- Completion and debug wrappers

Use `cortex setup --help`, `cortex ingest --help`, and `cortex heartbeat --help` for the exact platform-specific command tree.

## Operations

Common operator commands:

```bash
# Health and diagnostics
cortex status
cortex doctor
cortex doctor binary

# Managed setup
cortex setup check
cortex setup repair

# Database operations
cortex db status
cortex db integrity
cortex db checkpoint
cortex db backup --help
cortex db vacuum --help

# Compose lifecycle
cortex compose status
cortex compose doctor
cortex compose pull
cortex compose up
cortex compose restart
cortex compose logs

# Collection and inventory
cortex ingest inventory status --json
cortex ingest inventory refresh --json
cortex ingest filetail list
cortex sessions doctor

# Updates and configuration
cortex update --help
cortex config list
cortex completions zsh
```

The daemon exposes minimal and full health responses, records database maintenance jobs, reports projection and collector degradation, and surfaces ingest queue and write-block state through CLI, REST, and MCP.

## Development and verification

### Tooling

The repository uses:

- Rust edition 2024
- `mise` for pinned development tools
- `just` for common workflows
- `cargo-nextest` for the hermetic Rust suite
- `cargo-llvm-cov` for coverage
- `cargo-deny` for dependency policy
- Lefthook and `cargo xtask` for local release and pre-push checks
- A custom soldr-backed Rust compiler wrapper for fast local and CI builds

### Common commands

```bash
mise install
just dev
just build
just check
just lint
just fmt
just test
just test-doc
just coverage
just coverage-html
just test-live
just validate-plugin
cargo xtask pre-push
```

`just test-live` (also `just live-smoke`) is the canonical fail-closed pull-request subset. It exercises real HTTP JSON-RPC, UDP and TCP syslog ingest, CLI/REST behavior, browser routes, and managed file-tail behavior in a run-owned topology. Run `just live-mcp` for every registered MCP action; the scheduled aggregate combines all authoritative owner profiles. Specialist profiles are documented in [the live qualification guide](docs/LIVE_QUALIFICATION.md). Docker collection has separate agent-deployment tests and a mocked Docker HTTP fixture for central pull.

CI gates include:

- Formatting
- Clippy with warnings denied
- Nextest and doctests
- Version and distribution identity synchronization
- MCP integration
- npm launcher checks
- Secret scanning
- `cargo-deny`
- Coverage generation
- Repository module-size policy

See [tests/TEST_COVERAGE.md](tests/TEST_COVERAGE.md) and [docs/RELEASE.md](docs/RELEASE.md) for the split between hermetic CI and live-fleet verification.

## Documentation

The code-owned registries and runtime schemas are authoritative for command names, actions, routes, scopes, defaults, and validation. Human documentation explains how to operate those surfaces.

| Document | Purpose |
| --- | --- |
| [docs/README.md](docs/README.md) | Documentation index and authority map |
| [docs/SETUP.md](docs/SETUP.md) | Installation and deployment walkthrough |
| [docs/CONFIG.md](docs/CONFIG.md) | Complete configuration reference |
| [docs/CLI.md](docs/CLI.md) | CLI reference |
| [docs/api.md](docs/api.md) | REST API reference |
| [docs/architecture.md](docs/architecture.md) | Runtime and data-flow architecture |
| [docs/mcp/SCHEMA.md](docs/mcp/SCHEMA.md) | MCP action and parameter schema |
| [docs/mcp/PROMPTS.md](docs/mcp/PROMPTS.md) | Prompt catalog |
| [docs/SECURITY.md](docs/SECURITY.md) | Consolidated trust model |
| [docs/OAUTH.md](docs/OAUTH.md) | OAuth configuration |
| [docs/INVENTORY.md](docs/INVENTORY.md) | Component and surface inventory |
| [docs/RELEASE.md](docs/RELEASE.md) | Release and verification gates |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

Design plans, runbooks, and session logs under `docs/plans`, `docs/runbooks`, and `docs/sessions` are valuable engineering history, but they are not the source of truth for the current public interface.

## Current boundaries

Cortex is intentionally opinionated:

- It is a single-node SQLite service, not a distributed ingestion cluster.
- OTLP support is logs-over-HTTP only. Traces, metrics, and OTLP/gRPC are outside the current implementation.
- Syslog does not authenticate senders. Network and CIDR controls matter.
- The graph is derived evidence, not authoritative configuration state.
- MCP and REST expose bounded operations, not arbitrary SQL or unaudited log mutation.
- LLM-backed assessments are local-only and require an operator-controlled Gemini environment.
- Central Docker pull requires privileged read access to Docker endpoints and is disabled by default.
- Inventory quality depends on collector access, SSH trust, optional API credentials, and cache freshness.
- The bundled browser app is an investigation workspace preview, not a full monitoring dashboard.
- Cortex is built for a homelab or small trusted fleet. Internet-facing or multi-tenant deployment requires additional isolation and policy outside the binary.

## License

Original Dinglebear-authored portions of this project are licensed under [AGPL-3.0-only](LICENSE). Separate commercial licensing is available for organizations that need terms outside the AGPL. Third-party material remains under its original license. See [LICENSING.md](https://github.com/dinglebear-ai/cortex/blob/main/LICENSING.md).
