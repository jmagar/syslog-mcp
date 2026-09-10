---
title: Palette integration profile
created: 2026-08-29
updated: 2026-09-10
---

# Palette integration profile

Cortex owns this conservative version/schema contract. Its canonical source is `contracts/integration-profile.schema.json`, its generated snapshot is `docs/contracts/generated/integration-profile.schema.json`, and `python3 scripts/check-integration-contracts.py` checks drift and fail-closed fixtures.

The root advertises stable identity, API compatibility, auth binding, current route support, and stream support. It does not claim full capability discovery and does not define session-page or stream-event DTOs; those land with their Cortex slices. Route support is therefore conservative. Stream transport remains `none` until the streaming slice adds Cortex-owned event schemas and cursor behavior.

Credentials are pinned to profile, canonical origin, `server_id`, issuer, audience, token endpoint origin, principal cache scope, and credential generation. Any change requires explicit re-trust. API/SSE redirects are rejected. `auth.credential_generation` is 16 lowercase hex characters of HMAC-SHA256 over a fixed purpose label and `CORTEX_API_TOKEN`, keyed by the server-held `<DATA_DIR>/integration-credential.key` (see `data-layout.md`), so it changes when the token changes, and the token cannot be brute-forced from the published value without that server-held key; it is `none` when no API token is configured. Upgrade note: the first start of a release with the keyed format publishes a new `auth.credential_generation` even though `CORTEX_API_TOKEN` is unchanged, so every pinned integration must re-trust Cortex once. Back up the key with `cortex.db`; losing it has the same one-time re-trust effect. Discovery is credential-free and any future final discovery origin must be pinned before auth.

Cache keys include stable server identity, API major, principal/auth snapshot, credential generation, route/capability generation, object revision, query digest, and cursor lineage. Each cache declares owner, TTL, byte/item cap, stale policy, and synchronous invalidation. Performance traces cover session/log pages, stream connect/resume, correlation, IPC, and render commit with bounded labels; payloads, principals, queries, schemas, and session content are never labels or logs.
