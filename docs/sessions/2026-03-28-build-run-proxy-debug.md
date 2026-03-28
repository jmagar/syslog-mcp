# Session: Build, Run, and Proxy Debug
**Date:** 2026-03-28
**Branch:** `chore/add-lavra-project-config`
**Working Directory:** `/home/jmagar/workspace/syslog-mcp`

---

## Session Overview

Built and ran the syslog-mcp binary directly (outside Docker), fixed two bugs:
1. MCP OAuth discovery returned an empty 404 body causing client JSON parse errors
2. SWAG nginx proxy pointed to wrong IP (`10.1.0.8`) and wrong port (`8005`) instead of `10.1.0.6:3100`

Both fixes resulted in a working authenticated connection from claude.ai to `https://syslog.tootie.tv/mcp`.

---

## Timeline

1. **Build** — `cargo build` succeeded clean; `cargo build --release` succeeded in ~21s
2. **Run attempt** — Default config uses `/data/syslog.db` (Docker path); fails with `Permission denied`
3. **DB ownership fix** — `sudo chown $USER data/syslog.db*` to allow writes from binary running as user
4. **Binary running** — `SYSLOG_MCP_STORAGE__DB_PATH=$(pwd)/data/syslog.db ./target/release/syslog-mcp` → healthy on `:3100`, 13k→213k logs ingested
5. **OAuth 404 bug** — Client (claude.ai) hits `/.well-known/oauth-authorization-server`, gets `404` with empty body, JSON parser throws "Unexpected EOF"
6. **OAuth fix** — Added axum `.fallback()` handler returning `{"error":"not_found"}` JSON on all unmatched routes
7. **Proxy diagnosis** — SWAG nginx config had `10.1.0.8:8005` for both `$upstream` and `$mcp_upstream`; actual server is `10.1.0.6:3100`
8. **Proxy fix** — Used SWAG MCP tool to update config; also removed `authelia-server.conf` / `authelia-location.conf` includes that conflict with OAuth gateway pattern
9. **Verified working** — Health check `200`, user confirmed connection success

---

## Key Findings

- `mcp.rs:82-87` — Router had no fallback; axum default 404 returns `content-length: 0` which breaks MCP client JSON parser
- `syslog-mcp.subdomain.conf` — `$mcp_upstream_app`/`$mcp_upstream_port` are the variables used by `location /mcp`, NOT `$upstream_app`/`$upstream_port` — updating only the main upstream left `/mcp` still broken
- `syslog-mcp.subdomain.conf` — Had `include /config/nginx/authelia-server.conf` and `authelia-location.conf` in `location /`; `unifi.subdomain.conf` (working reference) uses `auth_request /_oauth_verify` directly — Authelia redirects to login page on 401 instead of returning JSON, which breaks OAuth clients
- Local machine LAN IP is `10.1.0.6`, not `10.1.0.8` as hardcoded in the proxy config
- syslog-mcp default config uses `/data/syslog.db` which is the Docker container path; running locally requires `SYSLOG_MCP_STORAGE__DB_PATH` override

---

## Technical Decisions

- **Fallback returns 404 with JSON body** — MCP spec (2025-03-26) says clients MUST handle 404 on `/.well-known/oauth-authorization-server` by proceeding without auth; the client bug is that it tries to JSON-parse the 404 body and crashes on empty string. Returning `{"error":"not_found"}` lets it parse successfully and proceed.
- **Removed Authelia from syslog proxy** — Authelia and the mcp-oauth gateway are mutually exclusive for MCP endpoints. Authelia issues HTML redirects; OAuth clients expect 401 JSON. Unifi (working) uses only OAuth gateway.
- **Did not implement full OAuth 2.0** — Server is localhost homelab; full OAuth would be overkill. The fallback JSON 404 satisfies the client's parser requirement without implementing auth.
- **Did not downgrade protocol version** — Server claims `2025-03-26`; kept it. Downgrading to `2024-11-05` was considered as an alternative but the JSON fallback is the correct minimal fix.

---

## Files Modified

| File | Change |
|------|--------|
| `src/mcp.rs:82-91` | Added `.fallback()` handler returning `(404, JSON {"error":"not_found"})` |
| `squirts:/mnt/appdata/swag/nginx/proxy-confs/syslog-mcp.subdomain.conf` | Fixed IP `10.1.0.8→10.1.0.6`, port `8005→3100` for both `$upstream` and `$mcp_upstream`; removed Authelia includes; `location /` now uses `auth_request /_oauth_verify` |

---

## Commands Executed

```bash
# Build
cargo build
cargo build --release

# Fix DB ownership
sudo chown $USER data/syslog.db data/syslog.db-shm data/syslog.db-wal

# Run binary directly (Docker stack down)
docker compose down
SYSLOG_MCP_STORAGE__DB_PATH=$(pwd)/data/syslog.db ./target/release/syslog-mcp &

# Health check
curl -s http://localhost:3100/health

# Verify OAuth fallback
curl -s http://localhost:3100/.well-known/oauth-authorization-server
# → {"error":"not_found"}

# Check listening ports
ss -tlnp | grep -E '3100|1514'
# → 0.0.0.0:1514 and 0.0.0.0:3100 confirmed
```

---

## Behavior Changes (Before/After)

| Endpoint | Before | After |
|----------|--------|-------|
| `/.well-known/oauth-authorization-server` | `404` empty body → client parse error | `404` `{"error":"not_found"}` → client proceeds without auth |
| Any unknown path | `404` empty body | `404` `{"error":"not_found"}` |
| `https://syslog.tootie.tv/mcp` | Proxied to `10.1.0.8:8005` (wrong host/port) | Proxied to `10.1.0.6:3100` (correct) |
| `https://syslog.tootie.tv/` | Authelia auth → HTML redirect on 401 | OAuth gateway auth → JSON 401 |

---

## Verification Evidence

| Command | Expected | Actual | Status |
|---------|----------|--------|--------|
| `curl http://localhost:3100/health` | `{"status":"ok",...}` | `{"status":"ok","stats":{"total_logs":213778,...}}` | ✅ |
| `curl http://localhost:3100/.well-known/oauth-authorization-server` | JSON body | `{"error":"not_found"}` | ✅ |
| `ss -tlnp \| grep 3100` | `0.0.0.0:3100` | `0.0.0.0:3100` bound | ✅ |
| SWAG health_check `syslog.tootie.tv` | `200` | `200` (436ms) | ✅ |
| claude.ai `/mcp` reconnect | Connected | User confirmed working | ✅ |

---

## Risks and Rollback

- **Proxy change rollback**: SWAG MCP created backup `syslog-mcp.subdomain.conf.backup.20260328_105537_590486_44fdcea5` on squirts — restore with SWAG MCP `edit` action using backup content
- **Binary is running detached**: PID 777298; not managed by systemd/Docker. Will not survive reboot. Run `docker compose up -d` to return to managed deployment.
- **DB file ownership**: `data/syslog.db` is now owned by `jmagar` (not `root`). If Docker is restarted, the container (running as root) will still have write access since it's the owner. No risk.

---

## Decisions Not Taken

- **Full OAuth 2.0 implementation** — Would require `/authorize`, `/token` endpoints backed by real auth. Overkill for homelab; OAuth gateway on squirts handles this externally.
- **Downgrade to protocol `2024-11-05`** — Would sidestep OAuth discovery entirely. Rejected: the server correctly claims 2025-03-26; the fix should be at the right layer (valid JSON 404).
- **Keep Authelia on syslog proxy** — Would work for browser-based access but breaks programmatic MCP clients that expect JSON 401.
- **Run via `docker compose`** — User explicitly brought the stack down to run the latest binary directly. Docker image not rebuilt this session.

---

## Open Questions

- Is there a systemd unit or startup script for the binary, or is Docker the intended production deployment?
- Should `10.1.0.6` be replaced with the container/service name (e.g., `syslog-mcp`) if the binary moves back to Docker on the same network as SWAG?
- The `authelia-server.conf` include was removed — if Authelia is desired for the web UI at `/`, a separate non-MCP vhost or location block may be needed.

---

## Next Steps

- Rebuild Docker image with the `mcp.rs` fallback fix: `docker compose build && docker compose up -d`
- Update `docker-compose.yml` or add a `.env` to ensure `SYSLOG_MCP_STORAGE__DB_PATH` is correct if the binary path changes
- Consider pinning `10.1.0.6` as a named constant or using Docker DNS name once back on compose
