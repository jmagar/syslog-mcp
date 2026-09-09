---
title: "Release Checklist"
created: 2026-06-07
updated: 2026-07-30
---

# Release Checklist

Use this checklist before merging release-bound work. CI covers hermetic gates;
live fleet gates require a running cortex deployment and explicit operator
intent.

## Hermetic Gates

Run from the repo root:

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo xtask check-version-sync
bash scripts/check-agent-memory-symlinks.sh
bash scripts/check-public-identity.sh
git diff --check
```

For release commits, also require:

```bash
cargo xtask check-release-versions
```

Version-bearing files are declared in `release/components.toml`: `Cargo.toml`
(canonical), `Cargo.lock`, `server.json` (version + `cortex:vX.Y.Z` image tag),
`mcpb/manifest.json`, `docker-compose.prod.yml` (`${CORTEX_VERSION:-X.Y.Z}`),
and `CHANGELOG.md`. Plugin manifests are intentionally unversioned —
`check-version-sync` rejects a top-level `version` key in
`.claude-plugin/plugin.json`. Bump everything at once with
`cargo xtask bump-version patch|minor|major`.

## Live Gates

Run the release-blocking isolated profiles against run-owned services:

```bash
just live-full
just live-auth
just live-stateful
just live-notifications
just live-artifact
just live-upgrade
just live-security
just live-mutation
```

Fleet/provider qualification is a separate explicit opt-in with immutable
target manifests and operation-specific grants. See `docs/LIVE_QUALIFICATION.md`.

Live Docker ingest validation now follows two paths: host-local cortex agent
parity for deployed agents, and the legacy central pull fixture with
`CORTEX_DOCKER_INGEST_ENABLED=true` plus `CORTEX_DOCKER_HOSTS` set to an
explicit Docker-compatible HTTP endpoint.

Live SSH inventory validation requires configured SSH aliases or
`CORTEX_INVENTORY_SSH_HOSTS`, strict known-hosts coverage, and any intentional
TOFU bootstrap set explicitly with `CORTEX_INVENTORY_SSH_TRUST_ON_FIRST_USE=true`.

Fleet drop-in deployment is intentionally outside hermetic CI. Validate first
with:

```bash
cortex compose doctor
cortex ingest inventory refresh --json
```

Then push rsyslog drop-ins per [forwarder-dropins.md](contracts/forwarder-dropins.md)
only when the target `fleet_hosts` list is correct and reachable.

## Commit Policy

Every feature branch push bumps the version according to the repo policy in
`CLAUDE.md`. Patch bumps are appropriate for fixes, docs, CI, test, and policy
work. `CHANGELOG.md` must describe the operator-visible behavior, not just the
file list.
