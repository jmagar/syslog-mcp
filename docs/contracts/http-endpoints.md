---
title: "HTTP Endpoint Catalog (V1)"
created: 2026-05-16
updated: 2026-08-24
---

# HTTP Endpoint Catalog (V1)

## 1. Purpose & status

This document is the canonical catalog of every HTTP and WebSocket route the
`cortex` axum server exposes, the auth/CORS/body-limit policy attached to
each, and the rules under which the surface evolves. It is **normative** for
any consumer (clients, reverse proxies, monitoring, integration tests).

The contract is **V1**. It is derived from the route mounting in
`src/main.rs::serve_mcp`, the routers in `src/mcp/routes.rs`, `src/api.rs`,
`src/otlp.rs`, and the auth wiring in `src/runtime.rs::build_auth_policy` /
`src/config.rs::validate_auth_config`. Any change to a route name, method,
auth requirement, body limit, or stability tier MUST update this file in the
same PR as the code change. Route **renames** at `stable` tier require a major
version bump plus a deprecation window (see §10).

Cross-references:

- WebSocket `/ws/agent` JSON-RPC envelopes, methods, and error codes are
  defined in [`agent-protocol.md`](agent-protocol.md). This document covers
  only the HTTP-layer wrapping (upgrade, subprotocol, body cap).
- Forwarder configuration (which endpoints to point what at) is in
  [`forwarder-dropins.md`](forwarder-dropins.md).

## 2. Stability tiers

Every route in §4 carries one of these tiers. The tier dictates how the route
may evolve and what compatibility guarantee operators get.

| Tier           | Guarantee                                                                                                                                                                                              |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `stable`       | Committed surface. Method+path is fixed for the major version. Renames or removals require a major version bump on the prefix (e.g. `/v1/logs` → `/v2/logs`) and an overlap window of ≥1 minor release. |
| `experimental` | May change with one minor release of warning in `CHANGELOG.md`. Consumers should pin server version. Used for routes that exist for operator/diagnostic convenience.                                   |
| `internal`     | For `cortex`'s own components (agents, sibling services). External consumers MUST NOT depend on the shape. May change in any release with a CHANGELOG entry.                                       |
| `deferred`     | Currently returns `404` but the path is **reserved**. Promise: `cortex` will never repurpose a `deferred` path for unrelated semantics. When the feature lands the route is promoted to `stable` or `experimental` without changing path. |

## 3. Auth flow matrix

Every authenticated route uses exactly one of four policies, summarised here
and explained in detail in `runtime.rs::build_auth_policy`. The matrix below
mirrors the decision table embedded in that function (locked by the OAuth
epic, post eng-review):

| `auth.mode`            | `mcp.api_token` | bind          | Resolved policy                                  | `/mcp`, `/api/*` accept                                                                                                                                              |
| ---------------------- | --------------- | ------------- | ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OAuth`                | set             | any           | `Mounted { auth_state: Some(_) }`                | OAuth JWT *and* (unless `disable_static_token_with_oauth = true`) the static Bearer token. The static token is the **break-glass path**.                              |
| `OAuth`                | unset           | any           | `Mounted { auth_state: Some(_) }`                | OAuth JWT only.                                                                                                                                                       |
| `Bearer`               | set             | any           | `Mounted { auth_state: None }`                   | Static Bearer token only (`Authorization: Bearer <token>` or `X-Mcp-Token: <token>`, compared constant-time via lab-auth's `tokens_equal`).                            |
| `Bearer`               | unset           | loopback      | `LoopbackDev`                                    | Unauthenticated — the loopback bind *is* the trust boundary. Scope checks are bypassed.                                                                               |
| `Bearer`               | unset           | non-loopback  | **rejected at startup** (see §9)                 | n/a — process exits.                                                                                                                                                  |
| any                    | any             | loopback      | `LoopbackDev` when `mcp.no_auth = true`           | Unauthenticated — local development only.                                                                                                                            |
| any                    | any             | non-loopback  | `TrustedGatewayUnscoped` when `mcp.no_auth = true` and `mcp.trusted_gateway_no_auth = true` | Unauthenticated by cortex. The operator is asserting that an upstream gateway enforces access.                                                                    |

Notes:

- "Bearer" header forms accepted: `Authorization: Bearer <token>` and the
  legacy `X-Mcp-Token: <token>` header. Constant-time compared.
- OAuth flow: discovery via `/.well-known/oauth-authorization-server` and
  `/.well-known/oauth-protected-resource`, authorization via `/authorize` +
  Google callback at `/auth/google/callback`, token exchange at `/token`,
  dynamic client registration at `/register`, JWKS at `/jwks`. Once a JWT is
  issued, protected routes accept it as `Authorization: Bearer <jwt>`.
- `disable_static_token_with_oauth` (default `true`) decides whether the
  static token coexists with OAuth on protected routes. Setting it to `false`
  is the "OAuth + break-glass" mode for the homelab.

## 4. Route catalog

The table below is exhaustive — every route mounted by `src/main.rs::serve_mcp`
appears here, plus every deferred-by-design 404 (which is part of the
contract, not an accident). "Auth" abbreviations: **none** = no auth check;
**bearer** = static Bearer token only; **oauth** = OAuth JWT only (when
`disable_static_token_with_oauth = true`); **bearer-or-oauth** = either,
mixed mode; **optional-bearer** = check enforced only when
`CORTEX_TOKEN` is set, otherwise the route is unauthenticated **but**
the non-loopback safety gate (§9) bars this combo at startup.

| Method+Path                                              | Tier           | Auth                  | Body limit | CORS                       | Rate limit          | Introduced | Source                          | Purpose                                                                                          |
| -------------------------------------------------------- | -------------- | --------------------- | ---------- | -------------------------- | ------------------- | ---------- | ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `POST /mcp`                                              | `stable`       | bearer-or-oauth †     | 64 KiB     | configured allowlist       | —                   | 0.1.x      | `mcp/routes.rs::router`         | RMCP Streamable HTTP JSON-RPC ingress; the MCP tool surface.                                     |
| `GET /mcp`                                               | `stable`       | bearer-or-oauth †     | n/a        | configured allowlist       | —                   | 0.1.x      | `mcp/routes.rs`                 | RMCP requires `405 Method Not Allowed`; if auth is mounted, `401` is returned **first**.         |
| `DELETE /mcp`                                            | `stable`       | bearer-or-oauth †     | n/a        | configured allowlist       | —                   | 0.1.x      | `mcp/routes.rs`                 | Same as `GET /mcp` — RMCP is stateless. `401` precedes `405` when auth is on.                    |
| `GET /health`                                            | `stable`       | none                  | n/a        | configured allowlist       | —                   | 0.1.x      | `mcp/routes.rs::health`         | Lightweight DB ping + OTLP/ingest counters. Used by Docker `HEALTHCHECK`, compose, SWAG.         |
| `POST /v1/logs`                                          | `experimental` | optional-bearer ‡     | 4 MiB      | (no CORS)                  | —                   | 0.11.x     | `otlp.rs::logs_handler`         | OTLP/HTTP log ingest (`ExportLogsServiceRequest` protobuf). Returns `200` on accept, `413+Retry-After: 86400` on oversize, `503 channel_full` on backpressure (§13). |
| `POST /v1/file-tails`                                    | `experimental` | optional-bearer ‡     | 2 MiB      | (no CORS)                  | —                   | 3.15.x     | `agent_file_tail_ingest.rs`     | Authenticated fleet-agent file-tail batches with identity distinct from network syslog and server-managed tails. |
| `POST /v1/metrics`                                       | `experimental` | optional-bearer ‡     | 8 MiB      | (no CORS)                  | —                   | 3.14.x     | `otlp/metric_http.rs`           | OTLP/HTTP metric ingest with bounded normalization, idempotent persistence, and protobuf partial-success responses. Three distinct `503` backpressure/unavailable codes — see §13. |
| `POST /v1/traces`                                        | `experimental` | optional-bearer ‡     | 8 MiB      | (no CORS)                  | —                   | 3.14.x     | `otlp/trace_http.rs`            | OTLP/HTTP trace ingest with bounded normalization, idempotent persistence, and protobuf partial-success responses. Two distinct `503` codes — see §13. |
| `GET /.well-known/oauth-authorization-server`            | `stable`       | none                  | n/a        | configured allowlist       | —                   | OAuth GA   | `mcp/routes.rs` (lab-auth)      | OAuth 2.1 authorization-server metadata. Mounted **only** when `auth.mode = OAuth`.              |
| `GET /.well-known/oauth-protected-resource`              | `stable`       | none                  | n/a        | configured allowlist       | —                   | OAuth GA   | `mcp/routes.rs` (lab-auth)      | OAuth 2.1 protected-resource metadata. Same condition.                                            |
| `GET /mcp/.well-known/oauth-authorization-server`        | `stable`       | none                  | n/a        | configured allowlist       | —                   | OAuth GA   | `mcp/routes.rs`                 | Path-prefixed mirror of the AS discovery doc for clients that probe under `/mcp/`.               |
| `GET /mcp/.well-known/oauth-protected-resource`          | `stable`       | none                  | n/a        | configured allowlist       | —                   | OAuth GA   | `mcp/routes.rs`                 | Path-prefixed mirror of the protected-resource discovery doc.                                    |
| `GET /mcp/.well-known/openid-configuration`              | `stable`       | none                  | n/a        | configured allowlist       | —                   | OAuth GA   | `mcp/routes.rs`                 | OpenID Connect discovery alias for the AS metadata document.                                     |
| `GET /jwks`                                              | `stable`       | none                  | n/a        | configured allowlist       | —                   | OAuth GA   | `mcp/routes.rs` (lab-auth)      | JSON Web Key Set used to verify JWTs issued by cortex. Same condition as discovery.          |
| `GET /authorize`                                         | `stable`       | none                  | n/a        | configured allowlist       | `authorize_rpm` (default 60/min, per process) | OAuth GA   | `mcp/routes.rs` (lab-auth)      | OAuth authorization-request endpoint. Rate-limited.                                              |
| `GET /auth/google/callback`                              | `stable`       | none                  | n/a        | configured allowlist       | —                   | OAuth GA   | `mcp/routes.rs` (lab-auth)      | Google OIDC redirect URI.                                                                         |
| `POST /token`                                            | `stable`       | none                  | small §    | configured allowlist       | —                   | OAuth GA   | `mcp/routes.rs` (lab-auth)      | OAuth token-exchange endpoint.                                                                    |
| `POST /register`                                         | `stable`       | none                  | small §    | configured allowlist       | `register_rpm` (default 20/min, per process) | OAuth GA   | `mcp/routes.rs` (lab-auth)      | OAuth 2.0 Dynamic Client Registration. Enabled because MCP clients require DCR.                  |
| `GET /api/search`                                        | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.1.x      | `api.rs::search`                | Mounted **only** when `CORTEX_API_ENABLED=true`. Mirrors the `search` MCP action via querystring. |
| `GET /api/tail`                                          | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.1.x      | `api.rs::tail`                  | Same condition. Tail-latest-N rows.                                                              |
| `GET /api/errors`                                        | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.1.x      | `api.rs::errors`                | Same condition. Error rollup.                                                                    |
| `GET /api/hosts`                                         | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.1.x      | `api.rs::hosts`                 | Same condition. Known-hosts list.                                                                |
| `GET /api/correlate`                                     | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.1.x      | `api.rs::correlate`             | Same condition. Window-based event correlation.                                                  |
| `GET /api/stats`                                         | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.1.x      | `api.rs::stats`                 | Same condition. Aggregate counts.                                                                |
| `GET /api/source-ips`                                    | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.27.x     | `api.rs::source_ips`            | Distinct verified source IPs with log and host counts.                                           |
| `GET /api/timeline`                                      | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.27.x     | `api.rs::timeline`              | Bucketed log counts over a time range.                                                           |
| `GET /api/patterns`                                      | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.27.x     | `api.rs::patterns`              | Recurring message templates with frequency counts.                                               |
| `GET /api/ingest-rate`                                   | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.27.x     | `api.rs::ingest_rate`           | Current ingest throughput (1m/5m/15m buckets), optionally broken down by host.                   |
| `GET /api/get`                                           | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.27.x     | `api.rs::get_log`               | Fetch a single log entry by `id`.                                                                |
| `GET /api/errors/unaddressed`                            | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.27.x     | `api.rs::unaddressed_errors`    | List error signatures not yet acknowledged.                                                      |
| `POST /api/errors/ack`                                   | `experimental` | bearer-or-oauth †     | 64 KiB     | localhost-only             | —                   | 0.27.x     | `api.rs::ack_error`             | Acknowledge an error signature; suppresses it from future alerts. Actor set to `"api"`.          |
| `POST /api/errors/unack`                                 | `experimental` | bearer-or-oauth †     | 64 KiB     | localhost-only             | —                   | 0.27.x     | `api.rs::unack_error`           | Revoke an acknowledgement so the signature resurfaces. Actor set to `"api"`.                     |
| `GET /api/notifications/recent`                          | `experimental` | bearer-or-oauth †     | n/a        | localhost-only             | —                   | 0.27.x     | `api.rs::notifications_recent`  | Recent notification firings from `notification_firings` table.                                   |
| `POST /api/notifications/test`                           | `experimental` | bearer-or-oauth †     | 64 KiB     | localhost-only             | 10/min per actor    | 0.27.x     | `api.rs::notifications_test`    | Send a test notification via the configured Apprise endpoint (SSRF-safe: URLs from server config only). |
| `WS /ws/agent` (Upgrade)                                 | `deferred`     | first-message token ¶ | 1 KiB pre-hello / 1 MiB per frame post-hello | n/a (subprotocol-gated) | per-agent leaky bucket (`-32030 QuotaExceeded`) | Epic A (`cortex-qgnx`) | `mcp/ws_agent.rs` (planned — **not yet mounted**) | Path reserved. Currently returns `404`. Will carry JSON-RPC 2.0 over WebSocket (`agent.hello`, `logs.push`, `metrics.push`, `agent.heartbeat`, `probe.request/response`, `config.update`, `agent.shutdown`) when Epic A lands. See `agent-protocol.md` for envelopes, methods, error codes. |
| `* /*` (fallback)                                        | `stable`       | none                  | 64 KiB     | configured allowlist       | —                   | 0.1.x      | `mcp/routes.rs::router` (fallback) | Returns `404 {"error":"not_found"}` for any unmatched path. The 64 KiB body limit applies to the merged MCP router. |

Footnotes:

- **†** "bearer-or-oauth" resolves to one of the four policies in §3 depending
  on env. On `LoopbackDev` the route is effectively `none`. The `/api/*` and
  `/mcp` surfaces share the same `AuthLayer` construction via
  `mcp::build_auth_layer`.
- **‡** "optional-bearer": `OtlpState::api_token` is the `mcp.api_token`
  (with `CORTEX_API_TOKEN` accepted as a deprecated alias). When unset
  the route is unauthenticated, but the non-loopback safety gate (§9)
  prevents that state from coexisting with a non-loopback bind without
  the operator explicitly setting both no-auth gateway flags.
- **§** OAuth token/register payloads are small JSON envelopes; the 64 KiB
  MCP body cap applies (`/token` and `/register` are merged into the MCP
  router before the `RequestBodyLimitLayer`).
- **¶** `/ws/agent` has no HTTP-layer auth. The first JSON-RPC frame on the
  socket MUST be `agent.hello` containing the agent's token; mismatch closes
  with WS code `4001`. A 5-second pre-handshake timer and 1 KiB byte cap
  apply. See `agent-protocol.md` §3.

## 5. Body limits

Body limits are enforced by `tower_http::limit::RequestBodyLimitLayer` mounted
on each router. Oversize requests get HTTP `413 Payload Too Large`. The OTLP
router additionally attaches `Retry-After: 86400` to any 413 so misconfigured
OTel exporters back off for a day instead of retrying immediately.

| Surface                                                | Limit  | Source                                       | On overflow                                   |
| ------------------------------------------------------ | ------ | -------------------------------------------- | --------------------------------------------- |
| Merged MCP router (`/mcp`, `/health`, OAuth, fallback) | 64 KiB | `mcp/routes.rs::MCP_BODY_LIMIT_BYTES`         | `413` (no `Retry-After`)                       |
| Non-MCP API (`/api/*`) — `GET` routes                 | n/a    | All GET endpoints use querystring only.       | n/a                                            |
| Non-MCP API (`/api/*`) — `POST` routes                | 64 KiB | `POST /api/errors/ack`, `POST /api/errors/unack`, `POST /api/notifications/test` | `413` (no `Retry-After`) |
| OTLP logs (`/v1/logs`)                                  | 4 MiB  | `otlp.rs::OTLP_BODY_LIMIT_BYTES`              | `413 + Retry-After: 86400`                     |
| OTLP traces/metrics (`/v1/traces`, `/v1/metrics`)       | 8 MiB  | `otlp.rs::OTLP_SIGNAL_BODY_LIMIT_BYTES`       | `413 + Retry-After: 86400`                     |
| `/ws/agent` pre-handshake                              | 1 KiB  | `agent-protocol.md` §2                        | WS close `4000` (handshake timeout)            |
| `/ws/agent` post-handshake per frame                   | 1 MiB  | `agent-protocol.md` §2                        | WS close `1009 Message Too Big`                |

## 6. CORS

Two CORS regimes coexist, applied at the router boundary:

1. **Configured allowlist (`/mcp` + `/health` + OAuth + fallback).**
   Built by `mcp::rmcp_server::allowed_origins(config)` from
   `[mcp].allowed_origins` (env: `CORTEX_ALLOWED_ORIGINS`). Methods:
   `GET, POST`. Headers: `Any`. Invalid entries log a warning and are
   dropped. If no origins are configured, browser clients cannot call
   `/mcp` from a different origin.
2. **Localhost-only (`/api/*`).** Hardcoded to
   `http://localhost:<mcp_port>` and `http://127.0.0.1:<mcp_port>` where
   `<mcp_port>` is `mcp.port`. Methods: `GET, POST`. Headers: `Any`.

OTLP and `/ws/agent` are server-to-server channels and have **no** CORS
layer; browsers should never hit them.

## 7. Rate limits

V1 status: there is **no rate limit on `/mcp` itself**. The only rate
limits enforced today are inside the OAuth path:

| Knob              | Default       | Scope        | Applies to                | Source                             |
| ----------------- | ------------- | ------------ | ------------------------- | ---------------------------------- |
| `authorize_rpm`   | 60 req/min    | per process  | `GET /authorize`          | `config.rs::default_authorize_rpm` |
| `register_rpm`    | 20 req/min    | per process  | `POST /register` (DCR)    | `config.rs::default_register_rpm`  |

Gap, tracked as deferred: per-token / per-IP rate limiting on `POST /mcp`
and `POST /v1/logs`. Until that lands, treat these as **upstream-rate-limited**
(SWAG limit_req zones) when exposed to the internet. The agent channel
carries its own per-agent leaky-bucket budget (`-32030 QuotaExceeded`) inside
`/ws/agent`, defined in `agent-protocol.md` §5.

## 8. Versioning policy

- `/mcp` is **unversioned at the path**. The MCP protocol itself carries
  versioning via its JSON-RPC envelopes. A future incompatible MCP transport
  would land at `/mcp/v2` as a **sibling** route — never gated by request
  header — so old clients keep working until the deprecation window closes.
- `/v1/logs` is **path-versioned**. A future `/v2/logs` is a sibling, never a
  drop-in replacement. `v1` remains accepted for ≥1 minor release after
  `v2` is GA.
- `/api/*` is implicitly v1. A future `/api/v2/*` is a sibling and the
  existing `/api/*` remains as the v1 surface for one minor release. The
  `experimental` tier means consumers should already be prepared for this.
- `/ws/agent` is gated by the WebSocket subprotocol `cortex.v1`. A v2
  protocol bumps the subprotocol to `cortex.v2` and the `protocol_version`
  integer in `agent.hello`. See `agent-protocol.md` §9.
- `.well-known` and OAuth routes follow OAuth 2.1 / OIDC versioning at the
  spec level; the path names themselves are fixed by those specs.

## 9. Safety gate (non-loopback bind)

`config.rs::validate_auth_config` enforces this at process start. The exact
failure mode is **`anyhow::bail!` from `Config::load()` → process exits before
binding the listener**. The HTTP server never comes up.

Three blocked combinations:

1. `auth.mode = OAuth` **and** `api_token` unset **and** bind is non-loopback
   — rejected because OTLP `/v1/logs` only supports the static Bearer token
   today, so allowing it would expose unauthenticated OTLP writes on a
   public address.
2. `auth.mode = Bearer` **and** `api_token` unset **and** bind is non-loopback
   — rejected because no auth is configured and the bind is publicly
   reachable.
3. Either of the above can be overridden by `CORTEX_NO_AUTH=true` plus
   `CORTEX_TRUSTED_GATEWAY_NO_AUTH=true`. The operator is asserting that
   an upstream gateway (typically SWAG with Authelia) enforces access for all
   mounted routes.

Additionally, when `/v1/logs` is mounted **without** a token on a non-loopback
bind (which is only reachable via the trusted-gateway no-auth path), `main.rs`
logs a `WARN` with the exact bind address and a pointer to set
`CORTEX_TOKEN`. The server still starts.

## 10. Reverse proxy guidance

Production deployments terminate TLS at SWAG (`syslog.example.invalid`) and forward
to cortex on its plaintext bind. SWAG MUST:

- Preserve `Host` so `[mcp.auth].public_url` matches.
- Forward `X-Forwarded-For` and `X-Forwarded-Proto: https` so logs record
  the real peer and OAuth redirects build `https://` URLs.
- Forward the `Authorization`, `X-Mcp-Token`, and `Sec-WebSocket-Protocol`
  headers verbatim. **Do not strip** `Authorization` on the OAuth callback
  paths.
- Honour WebSocket upgrade on `/ws/agent`: `proxy_set_header Upgrade`,
  `proxy_set_header Connection "upgrade"`, `proxy_read_timeout 7200s`
  (matches the 1h+ idle agent connections under low log volume).
- Apply `client_max_body_size 8M` so the 4 MiB OTLP cap is reachable end-to-
  end without SWAG truncating first.
- Optionally apply a `limit_req` zone keyed by client IP on `/mcp` and
  `/v1/logs` to compensate for the absent app-layer rate limit (§7).

The agent talks `wss://syslog.example.invalid/ws/agent`. Loopback `ws://` is only
permitted when `agent.allow_insecure = true` (refused if bind is
non-loopback) — see `agent-protocol.md` §2.

## 11. Self-check

- Every route mounted by `main.rs::serve_mcp` is in §4, including the OTLP
  signal handlers and the fallback handler.
- Every authenticated route's auth column references the policy matrix
  in §3 — no route exposes a one-off auth scheme.
- Every body limit visible in code (`MCP_BODY_LIMIT_BYTES`,
  `OTLP_BODY_LIMIT_BYTES`, `OTLP_SIGNAL_BODY_LIMIT_BYTES`, agent pre-hello /
  per-frame caps) appears in §5.
- The non-loopback safety gate in §9 matches the three branches in
  `validate_auth_config`.
- `/ws/agent` is listed with a pointer to the wire-level contract in
  `agent-protocol.md` — this file does not duplicate that contract.
- Every `503` an OTLP handler can return appears in §13 with its `error`
  code, its `retryable` value, and its `Retry-After` header (or the explicit
  absence of one).

## 12. Surprise audit

Notes for operators on auth requirements that may not be obvious from a
quick read:

- `GET /mcp` and `DELETE /mcp` exist only because RMCP's stateless transport
  requires `405 Method Not Allowed`. **The 401-before-405 ordering is
  intentional** — clients probing for the right HTTP verb without credentials
  must learn auth is required before they learn the verb is wrong.
- `/v1/logs` accepts payloads even when `api_token` is unset, but the
  non-loopback safety gate (§9) makes that combination impossible on a
  public bind without both no-auth gateway flags. The combination
  "unauthenticated `/v1/logs` on `0.0.0.0`" is therefore an explicit operator
  choice, not an oversight.
- `/api/*` uses a **separate** bearer token from `/mcp`. The `/api/*` gate
  is `CORTEX_API_TOKEN` (env var for `[api].api_token`), which is distinct
  from `CORTEX_TOKEN` (the MCP + OTLP token). Operators setting up
  monitoring against `/api/stats` must provision `CORTEX_API_TOKEN`; the
  MCP token alone is not sufficient. Both tokens pass through the same
  `AuthLayer` construction mechanism, but they are distinct secrets.
- `/register` is a public, unauthenticated endpoint **by design** — OAuth
  2.0 Dynamic Client Registration is how MCP clients self-onboard. The
  `register_rpm` knob is the mitigation against abuse.

## 13. Backpressure responses (`503`)

The OTLP handlers answer `503 Service Unavailable` for six distinct
conditions. All six carry a JSON body of the shape:

```json
{"error": "<code>", "retryable": <bool>}
```

`retryable` is present on **every** `503` this surface emits, and it — not the
status code, and not the presence of `Retry-After` — is the discriminator a
client should branch on. The codes are stable identifiers; the enum backing
them is `otlp::error::OtlpError` in `src/otlp/error.rs`.

| Route | `error` | `retryable` | `Retry-After` | Condition |
| --- | --- | --- | --- | --- |
| `POST /v1/logs` | `channel_full` | `true` | `1` | The ingest channel cannot accept the batch. Pre-flight capacity check, so the whole request is rejected — nothing was partially queued. |
| `POST /v1/metrics` | `metric_ingest_unavailable` | `false` | — | Agent Observatory metric ingest is not configured on this process. Fixed for the process lifetime; retrying cannot help. |
| `POST /v1/metrics` | `metric_storage_blocked` | `true` | `1` | The storage budget has write-blocked persistence (`storage.max_db_size_mb` / `min_free_disk_mb`). Clears when retention or the disk guardrail recovers space. |
| `POST /v1/metrics` | `metric_storage_unavailable` | `true` | `1` | The DB connection pool did not yield a connection before its timeout; the points never reached SQLite. |
| `POST /v1/traces` | `trace_ingest_unavailable` | `false` | — | Agent Observatory trace ingest is not configured on this process. Fixed for the process lifetime. |
| `POST /v1/traces` | `trace_storage_unavailable` | `true` | `1` | The DB connection pool did not yield a connection before its timeout; the spans never reached SQLite. |

Rules this table encodes:

- **`Retry-After` is present exactly when `retryable` is `true`.** The two
  never disagree. A `503` with no `Retry-After` is a permanent-for-this-process
  condition and an exporter that keeps retrying it will never succeed.
- **`retryable: false` is not an error in the request.** The payload was
  well-formed; the receiver is simply not configured for that signal. It is a
  `503` rather than a `404` because the route is mounted and would accept the
  same payload on a process that has the signal enabled.
- **Storage-budget write-block is reported differently per signal.**
  `/v1/metrics` returns the `metric_storage_blocked` `503` above.
  `/v1/traces` instead returns `200` with `rejected_spans` set in the OTLP
  `ExportTracePartialSuccess` — a *permanent* rejection in OTLP terms, so the
  exporter drops rather than retries. Only the pool-timeout case on
  `/v1/traces` asks the exporter to retry.
- **OTLP/HTTP exporters only retry `429`, `502`, `503`, and `504`.** That is
  why a pool-acquisition timeout must not surface as `500`: a conforming
  exporter would drop the batch permanently.

The `/api/agent/heartbeat` surface has its own `503 storage_unavailable`,
documented in [`heartbeat-telemetry.md`](heartbeat-telemetry.md) §10. It
carries `Retry-After` for the same reason but is not part of the OTLP
`retryable` contract above.

## Surface Parity Additions (2026-05-21)

These routes mirror existing MCP actions through the REST surface — pure
plumbing, no new behaviour. All require the standard bearer token.

| Method | Path | Body / Query | Service method |
|---|---|---|---|
| GET | `/api/source-ips` | `?limit=N&offset=N` | `list_source_ips` |
| GET | `/api/timeline` | `?bucket=...&group_by=...&since=...&until=...&host=...&app=...&severity_min=...` | `timeline` |
| GET | `/api/patterns` | filter + `&scan_limit=N&top_n=N` | `patterns` |
| GET | `/api/ingest-rate` | `?by_host=true` | `ingest_rate` |
| GET | `/api/get` | `?id=N` | `get_log` |
| GET | `/api/errors/unaddressed` | `?limit=N&include_acknowledged=true` | `unaddressed_errors` |
| POST | `/api/errors/ack` | `{"signature_hash":"...","notes":"..."}` | `ack_error` (actor=`api`) |
| POST | `/api/errors/unack` | `{"signature_hash":"...","reason":"..."}` | `unack_error` (actor=`api`) |
| GET | `/api/notifications/recent` | `?limit=N&rule_id=...&since=...` | `notifications_recent` |
| POST | `/api/notifications/test` | `{"body":"..."}` | `notifications_test` (apprise URLs server-side) |

The `/api/notifications/test` route uses the server's configured apprise URLs
(`config.notifications.apprise_url` / `apprise_urls`); callers cannot override
them on the wire. Rate-limited to 10 test notifications per minute per
`actor`, where actor is hard-coded to `"api"` for REST requests.
