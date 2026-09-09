---
title: "`source_kind` Enumeration & `source_ip` URI Scheme Contract"
created: 2026-05-16
updated: 2026-07-30
---

# `source_kind` Enumeration & `source_ip` URI Scheme Contract

**Status:** Contract — source of truth
**Date:** 2026-05-16
**Pinning header:**

> Contract derived from cross-cutting audit; supersedes scattered enumerations
> in `docs/superpowers/specs/2026-05-16-agent-mode-design.md` §12,
> `docs/contracts/log-row-shape.md` §3, and `docs/contracts/parser-trait.rs::SourceKind`.
> Changing this requires updating all dependents.

**Current implementation note:** The `filter`/`search` alias layer currently
supports `source_kind=docker-stream`, `docker-event`, `agent-command`,
`shell-history`, `transcript`, `claude`, `codex`, and `gemini`. It rejects
`source_kind=syslog-udp`, `syslog-tcp`, and `otlp` because transport protocol
is not indexed separately today. It does not currently support `agent`,
`unifi-api`, or `adguard-api` as query aliases.

---

## 1. Background — the casing drift

Three different spellings of `source_kind` are in flight across the corpus:

| Surface | Spelling family | Example values |
|---|---|---|
| `docs/contracts/log-row-shape.md` §3 (lines 60–69) | **kebab-case** | `syslog-udp`, `syslog-tcp`, `agent`, `docker-stream`, `docker-event`, `otlp`, `unifi-api`, `adguard-api` |
| `docs/contracts/parser-trait.rs::SourceKind` (lines 51–61, `#[serde(rename_all = "snake_case")]`) | **snake_case** | `cortex`, `docker_stream`, `docker_event`, `otlp`, `adguard_api`, `unifi_api`, `agent` |
| `docs/superpowers/specs/2026-05-16-agent-mode-design.md` §12 (line 587–593) | kebab-case but uses `docker-ingest` instead of `docker-stream` | `syslog-udp`, `syslog-tcp`, `agent`, `docker-ingest`, `otlp` |
| `docs/superpowers/specs/2026-05-16-enrichment-framework-design.md` §3 / §4 (lines 78, 128–134) | snake_case, **no UDP/TCP distinction** | `cortex`, `docker_stream`, `docker_event`, `otlp`, `adguard_api` |
| `docs/superpowers/specs/2026-05-16-api-pollers-design.md` §2 / §4 (lines 44, 51, 202) | kebab-case | `adguard-api`, `unifi-api` |

This contract reconciles all five.

---

## 2. Locked decision — kebab-case for the wire

`source_kind` values are written **kebab-case** everywhere they appear at the
"wire" boundary: in `metadata_json.source_kind`, in `source_ip` URI schemes
(by encoding the transport in the scheme), in any persisted DB column, in
notification rule matchers, and in incident-card payloads.

**Why kebab-case wins:**

1. `docs/contracts/log-row-shape.md` (the canonical row contract) already
   defines kebab-case, and 4.9M existing production rows already carry
   kebab-case strings in `metadata_json` and Docker-derived `source_ip`
   paths (`docker://host/container/stream`).
2. URI scheme tokens (`syslog-udp://`, `docker-event://`, `adguard://`) are
   naturally kebab-case — `_` is uncommon in URI schemes (RFC 3986 allows
   it but real-world deployments do not).
3. Aligning Rust enum serde to kebab-case is a one-line change; renaming
   4.9M rows is not.

**Required follow-up:** `docs/contracts/parser-trait.rs::SourceKind` MUST
change from `#[serde(rename_all = "snake_case")]` to
`#[serde(rename_all = "kebab-case")]`. This is a contract change for
`parser-trait.rs`; flagged in §6 below as a downstream update required to
land this contract.

---

## 3. Closed enumeration

The value set is **closed**. Adding a new ingest source requires registering
a new row here AND a new URI scheme in §4 — pick a name that does not
collide. Adding a variant is additive (rule engines treat unknown values as
no-match, §7). Renaming an existing value is a major version bump.

| `source_kind` | Producer | Description |
|---|---|---|
| `syslog-udp` | `src/syslog/listener.rs` UDP path | RFC 3164/5424 over UDP `:1514` |
| `syslog-tcp` | `src/syslog/listener.rs` TCP path | RFC 3164/5424 over TCP `:1514` |
| `agent` | `src/mcp/ws_agent/*` (epic A) | JSON-RPC 2.0 over WSS from the `cortex agent` binary on each host |
| `docker-stream` | `src/docker_ingest/parser.rs::log_output_to_entry` | Container stdout/stderr via Docker socket proxy |
| `docker-event` | `src/docker_ingest/parser.rs::docker_event_to_entry` | Docker lifecycle events from the `/events` stream |
| `otlp` | `src/otlp.rs` | OpenTelemetry logs received on `/v1/logs` |
| `unifi-api` | UniFi poller (epic C `cortex-awvr`) | UniFi controller events + alarms poller |
| `adguard-api` | AdGuard poller (epic C `cortex-awvr`) | AdGuard Home `/control/querylog` poller |
| `shell-history` | `src/command_log.rs` | Local shell history backfill, currently zsh extended history |
| `agent-command` | `src/command_log.rs` | AI agent-launched shell commands imported from a private JSONL spool |
| `file-tail` | `src/file_tail/supervisor.rs` | Cortex-managed local file tails configured in `file-tails.json` |
| `agent-file-tail` | `src/agent/file_tail.rs` | Authenticated file tails forwarded by a fleet agent |

**Removed / renamed during reconciliation:**

- `docker-ingest` (used in agent-mode spec §12 line 593) is **not a member**.
  The two Docker producers split cleanly into `docker-stream` (per-container
  stdout/stderr) and `docker-event` (lifecycle events). Replace any
  `docker-ingest` reference with one of those two.
- Bare `cortex` (used in parser-trait.rs and enrichment-framework spec) is
  **not a member**. It always splits into `syslog-udp` and `syslog-tcp`.
  The UDP/TCP distinction is operationally meaningful (TCP is reliable,
  UDP is fire-and-forget) and the listener already knows which one it is
  by the time it produces a row — there is no cost to keeping them apart.

---

## 4. `source_ip` URI scheme table

`source_ip` is the URI-style source identity for each row (see
`log-row-shape.md` §4). The **scheme** of the URI determines the
`source_kind` uniquely — this is how `source_kind` is reconstructed when
needed (it is not stored as a column on `logs`; see `log-row-shape.md` §3).

Every value MUST parse with `url::Url::parse`; path segments are
percent-encoded as required.

| `source_kind` | URI shape | Example |
|---|---|---|
| `syslog-udp` | `udp://<sender_ip>:<sender_port>` | `udp://203.0.113.7:48132` |
| `syslog-tcp` | `tcp://<sender_ip>:<sender_port>` | `tcp://203.0.113.7:51422` |
| `agent` | `agent://<host_id>/` | `agent://550e8400-e29b-41d4-a716-446655440000/` |
| `docker-stream` | `docker://<docker_host>/<container_name>/<stream>` where `stream ∈ {stdout, stderr}` | `docker://rkx/postgres/stdout` |
| `docker-event` | `docker-event://<docker_host>/<container_name>/<action>` | `docker-event://rkx/postgres/die` |
| `otlp` | `otlp://<peer_ip>` (no port; one exporter, many records) | `otlp://10.0.0.5/plex` (optional path: `service.name`) |
| `unifi-api` | `unifi://<controller_host>/` (single-site v1; per spec C §14 open question 1) | `unifi://udm-pro.lan/` |
| `adguard-api` | `adguard://<adguard_host>/` | `adguard://adguard.lan/` |
| `shell-history` | `shell-history://<hostname>/<user>/<shell>` | `shell-history://devhost/jmagar/zsh` |
| `agent-command` | `agent-command://<hostname>/<agent>/<session_id>` | `agent-command://devhost/claude-code/019e588f` |
| `file-tail` | `file-tail://<hostname>/<source_id>` | `file-tail://edgehost/swag-access` |
| `agent-file-tail` | `agent-file-tail://<hostname>/<source_id>` | `agent-file-tail://devhost/app-log` |

### Notes on the `agent://` authority

The authority portion of `agent://` is the agent's **`host_id`** — the
UUIDv4 the agent generates on first run and persists to
`/var/lib/syslog-agent/host_id` (per agent-mode spec §5 / §6.2). It is
**not** the same as the `hostname` field on the `logs` row; the hostname
is operator-visible and can change without re-registration, the `host_id`
cannot.

### `unifi-api` site-id path

Earlier drafts proposed `unifi://<controller_host>/site/<site_id>`
(`log-row-shape.md` §4) to support per-site filtering. The locked v1 of
the UniFi poller is **single-site** (spec C §14 resolved open question
1), so the path is dropped to `unifi://<controller_host>/`. If multi-site
ever ships, the migration is additive: the resolver in §7 already accepts
a longer path and ignores trailing segments.

### `adguard-api` client-IP path

Earlier drafts proposed `adguard://<host>/<client_ip_or_name>` to let
fleet-wide AdGuard views filter per-client. The poller emits one row per
DNS query and the `client` is already stored in
`metadata_json.adguard.client` (per metadata-json-shape.md §3). The path
is dropped from the URI to keep the scheme stable across all adguard rows
(easier to dedupe; lets the retention selector match the prefix without
a path component) and to avoid leaking the client IP into a column that
flows through every log surface. Per-client filters use
`metadata_json.adguard.client` via the rule-engine field resolver
(metadata-json-shape.md §6).

---

## 5. Dispatch implications — where `source_kind` is consulted

Code paths that key off `source_kind` (directly or via `source_ip`
scheme reconstruction):

1. **Parser dispatch** (enrichment-framework spec §4, lines 124–138).
   The dispatcher branches on `source_kind` first:
   - `docker-stream` → parser chosen by container_name → app_name →
     compose_service (Docker is authoritative; operators rename
     containers).
   - `docker-event` → always the `docker-event` parser.
   - `syslog-udp` / `syslog-tcp` → `app_name` exact match,
     case-insensitive.
   - `adguard-api` → always the `adguard` parser (poller writes
     `app_name="adguard-query"`).
   - `unifi-api` → no parser in V1 (poller writes structured rows
     directly under `metadata_json.unifi`).
   - `file-tail` → parser chosen by `app_name`/tag; metadata includes
     `file_tail_id`, `tag`, and `path_basename` (full paths stay on the
     admin-only management surface).
   - `otlp` → `app_name` (= OTLP `service.name`).
   - `agent` → `app_name` exact match, same path as syslog.
   - `shell-history` / `agent-command` → no parser in V1; the importer
     writes scrubbed command rows and structured metadata directly.

2. **Retention selector** (`runtime.rs` line 58 / spec C §5 storage
   projection). AdGuard rows tagged via the `adguard-*` prefix get a
   hardcoded 7-day retention floor; the prefix is recognised from
   `app_name` today but the dispatcher SHOULD also accept rows where
   `source_kind == "adguard-api"` once the poller lands.

3. **Agent vs non-agent silent-host logic** (agent-mode spec §7.3,
   §12). The MCP `silent_hosts` action excludes hosts whose latest row
   has `source_kind == "agent"` — those hosts have their own connection
   liveness signal (`agents.connection_state == 'Active'`) and should
   not be flagged as silent based on log volume.

4. **Dedup considerations** (agent-mode spec §12, "Dedup"). A host
   running both `rsyslog → :1514` and the agent will produce two rows
   per event with different `source_kind` values
   (`syslog-udp`/`syslog-tcp` vs `agent`). V1 ships with no dedup; the
   deploy-time guidance is to disable rsyslog forwarding on
   agent-installed hosts. Downstream searches that want a canonical
   stream filter `source_kind = 'agent'`.

5. **Rule-engine matchers** (notification-rules.schema.json `match`
   clause). A rule can match on `source_kind` via the `field_eq`
   operator: `field_eq = { source_kind = "docker-event" }`. The value
   on the row's side comes from `metadata_json.source_kind` (always
   written per metadata-json-shape.md §3); the kebab-case spelling
   here matches.

6. **Incident-card payload** (incident-card.md §5). The Qdrant payload
   field `source` is the Epic-B source tag (e.g. `kernel.oom`), NOT
   `source_kind`. They are distinct: `source_kind` describes how the
   row entered the system, `source` describes what kind of incident
   it is. Don't conflate them.

---

## 6. Stability rules & required downstream updates

**Stability rules:**

- **Additive** (backwards-compatible): introducing a new variant. Rule
  engines and dispatchers MUST treat unknown values as the equivalent
  of "no match" rather than erroring. Existing data with the new
  variant stays valid.
- **Breaking** (major version bump): renaming an existing variant (e.g.
  `docker-stream` → `docker-container`), removing a variant, or changing
  a variant's URI scheme (e.g. swapping `agent://` for `wss://`).
  Requires a migration plan and a compatibility-window where the rule
  engine accepts both names.

**Downstream contract files that need updating to match this contract:**

| File | Drift | Status |
|---|---|---|
| `docs/contracts/parser-trait.rs` line 52 | `#[serde(rename_all = "snake_case")]` on `SourceKind` | ✅ **RESOLVED** (bead `cortex-s6et`) — `rename_all = "kebab-case"` |
| `docs/contracts/parser-trait.rs` lines 40–60 | Comment lists snake_case forms | ✅ **RESOLVED** (bead `cortex-s6et`) — doc comments updated to kebab-case |
| `docs/contracts/parser-trait.rs` line 53 | Enum variant `Syslog` (no UDP/TCP distinction) | ✅ **RESOLVED** (bead `cortex-s6et`) — split into `SyslogUdp` and `SyslogTcp` + `is_syslog()` helper + `as_str()` method |
| `docs/superpowers/specs/2026-05-16-agent-mode-design.md` §12 | Lists `docker-ingest` as a member | ✅ **RESOLVED** (bead `cortex-s6et`) — replaced with `docker-stream` + `docker-event`; `unifi-api` and `adguard-api` added |
| `docs/superpowers/specs/2026-05-16-enrichment-framework-design.md` §3 / §4 | Uses bare `cortex` and `_`-style names | ✅ **RESOLVED** (bead `cortex-s6et`) — dispatch matrix rewritten in kebab-case with UDP/TCP rows merged via `app_name`-only dispatch (transport tag lives in `source_kind`/`source_ip`) |
| `docs/contracts/log-row-shape.md` §4 line 88 | `unifi://<controller_host>/site/<site_id>` | ✅ **RESOLVED** (bead `cortex-s6et`) — path dropped; v1 single-site |
| `docs/contracts/log-row-shape.md` §4 line 89 | `adguard://<adguard_host>/<client_ip_or_name>` | ✅ **RESOLVED** (bead `cortex-s6et`) — path dropped; per-client filtering uses `metadata_json.adguard.client` |
| `docs/contracts/metadata-json-shape.md` §3 line 46 | Used `docker_stream` (snake_case) for ingest envelope | ✅ **RESOLVED** (bead `cortex-s6et`) — rewritten to `docker-stream` / `docker-event` kebab forms |
| `src/syslog/listener.rs` | Today's UDP/TCP listener may not yet write the kebab-case `source_kind` to `metadata_json` | ⏳ **DEFERRED** — implementation work for epic B (`cortex-1wjr`). When migration 10 lands, listener populates `metadata_json.source_kind` to `"syslog-udp"` or `"syslog-tcp"` based on transport. |
| `src/db/models.rs` | `LogBatchEntry` doc comment lists URI patterns | ✅ No change needed — already kebab. |

Per agent-mode spec §12, a `source_kind` column on `logs` is proposed
(`source_kind TEXT NOT NULL DEFAULT 'syslog-udp'`) — but `log-row-shape.md`
locks this OUT (`source_kind` lives in `metadata_json` only, reconstructed
from `source_ip` scheme). This contract sides with `log-row-shape.md`.
The agent-mode spec §12 column proposal SHOULD be dropped during
implementation; the index `idx_logs_source_kind_received_at` from that
section becomes an expression index on
`json_extract(metadata_json, '$.source_kind')` if a fast filter on
source_kind is ever needed.

---

## 7. Resolver semantics for unknown values

The rule engine and any other consumer that switches on `source_kind`
MUST tolerate unknown values:

- A `field_eq = { source_kind = "future-source" }` predicate against a
  row with no matching value evaluates **false** (not error). Same
  semantics as metadata-json-shape.md §6.
- A `field_in = { source_kind = ["syslog-udp", "syslog-tcp"] }`
  predicate against a row whose `source_kind` is `"agent"` evaluates
  **false**.
- Unknown variants are logged at `trace` level by the dispatcher, not
  warned — a future variant arriving in production rows from a
  newer-version agent must not spam the server log.

---

## 8. Self-check — every reference in the corpus is covered

Cross-checked against:

- agent-mode spec §12 source_kind enum (line 587–593): all 5 values
  covered (`syslog-udp`, `syslog-tcp`, `agent`, `docker-ingest` →
  remapped to `docker-stream` + `docker-event`, `otlp`).
- enrichment-framework spec §3, §4: bare `cortex` rewritten to
  `syslog-udp`/`syslog-tcp` (functionally the same for parser
  dispatch); `docker_stream`, `docker_event`, `otlp`, `adguard_api`
  all map to kebab-case equivalents.
- api-pollers spec §2, §4, §5: `unifi-api`, `adguard-api` covered;
  `source_kind` already in kebab-case.
- log-row-shape.md §3: all 8 values match this contract verbatim.
- parser-trait.rs `SourceKind` enum: 7 variants covered after the
  required `Syslog → SyslogUdp/SyslogTcp` split.
- notification-rules.schema.json: rules match on `source_kind` via
  `field_eq` / `field_in`; the operator-side value set is what this
  contract defines.
- mcp-actions.md: no direct `source_kind` enumeration; filters flow
  through `field_eq` like any other field.
- incident-card.md: uses `source` (Epic-B source tag), not
  `source_kind`. Separation preserved.

## Agent Docker identity source (`agent-docker`)

Agent-forwarded Docker container lines arrive over syslog TCP, so their
row-level `source_kind` (derived from `source_ip`) stays `syslog-tcp`. The
Docker identity itself is carried by the host-local agent as structured
metadata:

```text
Agent Docker identity source: agent-docker.
Structured metadata path: metadata_json.agent_docker.
Required fields: host, container_id, container_name, stream.
Optional fields: compose_project, compose_service, image.
```

The agent emits the metadata as an internal message prefix
(`[cortex-agent-docker-meta:{json}] `), which receiver enrichment extracts
into `metadata_json` (setting the denormalised `metadata_json.source_kind`
to `agent-docker`) and strips from `message`.

**Trust boundary:** the marker rides the unauthenticated syslog message
body, so the payload is sender-controlled — without a source gate, any
port-1514 sender can forge agent-docker identity (same spoofing class as
the CEF `UNIFIdeviceName` gotcha; `source_ip` is the only network-verified
identity). Mitigations in receiver enrichment
(`src/receiver/enrichment.rs`):

- The merge is scoped: only the `agent_docker` object is accepted, it never
  overwrites keys already present in `metadata_json`, and
  `metadata_json.source_kind` is set from the receiver's constant, never
  from the payload.
- Operators MUST set `agent_docker_source_prefixes` (config.toml
  `[enrichment]`, env `CORTEX_AGENT_DOCKER_SOURCE_PREFIXES`, comma-separated
  exact IPs or `10.0.0.`-style subnet prefixes) to the hosts that actually
  run the cortex agent. **The gate is fail-closed:** when the list is empty
  the marker is rejected from every sender and no agent-docker identity is
  extracted at all. Startup logs this at `ERROR`. Deployments that trust
  every sender on the syslog port can opt back in to extract-from-anywhere
  with `agent_docker_trust_any_source` / `CORTEX_AGENT_DOCKER_TRUST_ANY_SOURCE`,
  which is also reported at `ERROR` on startup.
- Each prefix entry must be a **full IP literal** (`198.51.100.7` or
  `2001:db8::1`, exact-host match) or a **dot-terminated partial IPv4
  quad** (`100.64.0.`, subnet-prefix match). A partial quad without its
  trailing dot (`100.64.0`) is treated as an exact-host literal that
  matches nothing — the failure mode silently disables all agent-docker
  extraction. Config load warns about entries with any other shape.
- IPv6 sources are supported for **exact-host entries only**: the source
  address (including bracketed `[2001:db8::1]:514` forms) is parsed and
  compared as an address, so non-canonical spellings still match. There
  is no IPv6 subnet-prefix form — the dot-terminated prefix syntax is
  IPv4-only.

Canonical resolver proof must use `agent-docker` structured metadata.
`docker://` and `docker-event://` central-pull rows are not proof for the
resolver-backed graph contract.
