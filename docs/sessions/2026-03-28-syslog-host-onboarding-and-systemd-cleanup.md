# Session: Syslog Host Onboarding and Systemd Cleanup
**Date:** 2026-03-28
**Branch:** chore/add-lavra-project-config
**Commit:** 800d7f8

---

## Session Overview

Verified the running syslog-mcp server, onboarded 5 homelab hosts to forward syslog (tootie, dookie, squirts, steamy-wsl, vivobook-wsl), identified and cleaned up failed/crashed systemd services across all machines.

---

## Timeline

1. **Verified server running** — ports 1514 (UDP+TCP) and 3100 (MCP) already bound; 19 logs across 4 hosts in DB
2. **Confirmed tootie connected** — rsyslog startup messages already received (rc.rsyslogd + rsyslogd start)
3. **Onboarded 4 more hosts** — dookie (localhost), squirts, steamy-wsl via SSH; vivobook-wsl required manual sudo
4. **Discovered SHART host** — new host connected mid-session with rsyslog startup events
5. **Spotted clawdbot crash loop** — vivobook restart counter at 40,483+; disabled user service
6. **Systemd audit** — found failed units across dookie, squirts, steamy-wsl; cleaned all

---

## Key Findings

- `clawdbot-node.service` on vivobook-wsl was a user-level unit (`~/.config/systemd/user/`), not system-level — required `systemctl --user` to manage
- `zclean.service` binary (`~/.local/bin/zclean`) missing on dookie, squirts, steamy-wsl — service driven by a timer (`zclean.timer`); disabling service alone left timer active
- `ubuntu-insights-collect.timer` on squirts is system-scoped (global enablement) — user-level disable was insufficient; required `sudo systemctl mask`
- `xdg-desktop-portal*.service` failures on steamy-wsl are expected (no display server in WSL) — masked rather than disabled
- vivobook-wsl requires interactive sudo password — automated SSH config failed; manual steps provided in `vivobook-wsl-setup.md`
- dookie uses `127.0.0.1:1514` (localhost); all remote hosts use Tailscale IP `100.88.16.79:1514`

---

## Technical Decisions

- **TCP over UDP for rsyslog forwarding** (`@@` prefix) — reliable delivery preferred for log aggregation; UDP is faster but lossy
- **Tailscale IPs for WSL hosts** — WSL2 has its own network namespace; Tailscale provides stable cross-namespace routing
- **Mask xdg-desktop-portal on WSL** — masking (`→ /dev/null`) prevents systemd from ever attempting to start it, cleaner than disable for permanently-inapplicable services
- **Reset-failed on stale user@NNNNN.service entries on squirts** — these were ghost entries from old session UIDs, not real failures

---

## Files Modified

| File | Purpose |
|------|---------|
| `/etc/rsyslog.d/99-remote.conf` (dookie) | Forward all logs → `127.0.0.1:1514` TCP |
| `/etc/rsyslog.d/99-remote.conf` (squirts) | Forward all logs → `100.88.16.79:1514` TCP |
| `/etc/rsyslog.d/99-remote.conf` (steamy-wsl) | Forward all logs → `100.88.16.79:1514` TCP |
| `/etc/rsyslog.d/99-remote.conf` (vivobook-wsl) | Manually applied by user |
| `~/.config/systemd/user/clawdbot-node.service` (vivobook) | Disabled (crash-looping, 40k+ restarts) |
| `Cargo.toml` | Bumped version 0.1.3 → 0.1.4 |
| `CHANGELOG.md` | Added 0.1.4 entry + fixed version links |
| `docs/sessions/2026-03-28-syslog-host-onboarding-and-systemd-cleanup.md` | This file |

---

## Commands Executed

```bash
# Verify server running
curl http://localhost:3100/health
curl -s -X POST http://localhost:3100/mcp -d '{"method":"tools/call","params":{"name":"get_stats",...}}'

# Discover Tailscale IP
tailscale ip -4   # → 100.88.16.79

# Configure rsyslog on dookie
echo '*.* @@127.0.0.1:1514' | sudo tee /etc/rsyslog.d/99-remote.conf
sudo systemctl restart rsyslog

# Configure remote hosts (parallel)
ssh squirts "echo '*.* @@100.88.16.79:1514' | sudo tee /etc/rsyslog.d/99-remote.conf && sudo systemctl restart rsyslog"
ssh steamy-wsl "..."
ssh vivobook-wsl "..."   # failed — needs interactive sudo

# Verify test messages
logger -n 127.0.0.1 -P 1514 --tcp "test from dookie"
ssh squirts "logger -n 100.88.16.79 -P 1514 --tcp 'test from squirts'"
ssh steamy-wsl "logger -n 100.88.16.79 -P 1514 --tcp 'test from steamy-wsl'"

# Disable clawdbot (vivobook)
ssh vivobook-wsl "systemctl --user stop clawdbot-node && systemctl --user disable clawdbot-node"

# Systemd cleanup — zclean timer (all machines)
systemctl --user disable --now zclean.timer
ssh squirts "systemctl --user disable --now zclean.timer ubuntu-insights-collect.timer"
ssh steamy-wsl "systemctl --user disable --now zclean.timer && systemctl --user mask xdg-desktop-portal.service xdg-desktop-portal-gtk.service"

# Mask ubuntu-insights system-level on squirts
ssh squirts "sudo systemctl mask ubuntu-insights-collect.timer ubuntu-insights-collect.service"
```

---

## Behavior Changes (Before/After)

| Area | Before | After |
|------|--------|-------|
| Syslog sources | tootie only (2 logs) | 5 hosts: tootie, dookie, squirts, steamy-wsl, vivobook-wsl |
| clawdbot-node (vivobook) | Crash-looping at 40,483+ restarts | Stopped and disabled |
| zclean.service (dookie, squirts, steamy-wsl) | Failing (binary missing) | Disabled + timer removed |
| ubuntu-insights (squirts) | Telemetry running | Masked at system level |
| xdg-desktop-portal (steamy-wsl) | Failing (no display) | Masked |
| Failed systemd units | 5 across 3 machines | 0 across all machines |

---

## Verification Evidence

| Command | Expected | Actual | Status |
|---------|----------|--------|--------|
| `curl http://localhost:3100/health` | `{"status":"ok",...}` | `{"status":"ok","db_size_mb":"0.06","total_logs":19}` | PASS |
| `tail_logs hostname=dookie` | dookie logs | 3 dookie entries | PASS |
| `tail_logs hostname=squirts` | squirts logs | squirts logs received | PASS |
| `tail_logs hostname=vivobook` | vivobook logs | 3500+ logs received | PASS |
| logger test — dookie | log appears in DB | `"hostname":"dookie","message":"test from dookie"` | PASS |
| logger test — squirts | log appears in DB | `"hostname":"squirts","message":"test from squirts"` | PASS |
| logger test — steamy-wsl | log appears in DB | `"hostname":"STEAMY","message":"test from steamy-wsl"` | PASS |
| `systemctl --user list-units --state=failed` (all hosts) | 0 failed | 0 failed across dookie, squirts, steamy-wsl, vivobook-wsl | PASS |

---

## Source IDs + Collections Touched

Axon embedding attempted post-session (see embed step below).

---

## Risks and Rollback

- **rsyslog forwarding**: Low risk. To rollback: `sudo rm /etc/rsyslog.d/99-remote.conf && sudo systemctl restart rsyslog` on each host
- **clawdbot disabled**: Re-enable with `systemctl --user enable --now clawdbot-node` on vivobook-wsl. Note: service will crash-loop again until underlying 502 gateway issue is fixed
- **Masked services**: Unmask with `systemctl --user unmask <service>` (xdg-desktop-portal on steamy-wsl) or `sudo systemctl unmask` (ubuntu-insights on squirts)

---

## Decisions Not Taken

- **UDP forwarding** — faster but lossy; TCP chosen for reliability
- **Port 514 with iptables redirect** — avoided root requirement by using 1514 directly
- **Fixing clawdbot** — out of scope; service disabled pending separate investigation of 502 gateway error

---

## Open Questions

- What is `SHART`? A new host that connected mid-session with rsyslog startup messages — not explicitly configured by user
- Why does steamy-wsl report hostname as `STEAMY` (uppercase) rather than `steamy-wsl`?
- What is the clawdbot 502 gateway error caused by? `node host gateway connect failed: Unexpected server response: 502`
- vivobook-wsl sudo password required interactively — is passwordless sudo available for specific commands?

---

## Next Steps

- Investigate clawdbot 502 error on vivobook if service needs to be restored
- Add tootie, SHART to SETUP.md as documented hosts
- Consider adding more hosts (SHART appears to be another Unraid machine)
- Monitor log volume — vivobook generates very high volume (tailscale keepalives, clawdbot restarts)
