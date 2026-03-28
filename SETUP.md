# Syslog-MCP Host Configuration Guide

Replace `SYSLOG_SERVER` below with the IP/hostname of whichever host runs the container (e.g., `dookie.willynet`, `10.x.x.x`).

---

## Linux Hosts (Tootie, Dookie, Squirts, Shart)

### Option A: rsyslog (most distros)

Create `/etc/rsyslog.d/99-remote.conf`:

```conf
# Forward all logs to syslog-mcp via TCP (reliable)
*.* @@SYSLOG_SERVER:1514

# Or UDP (faster, less reliable):
# *.* @SYSLOG_SERVER:1514
```

Restart: `sudo systemctl restart rsyslog`

### Option B: systemd-journal-upload

If running pure journald without rsyslog:

```bash
sudo apt install systemd-journal-remote  # if not installed
```

For rsyslog forwarding from journald, ensure `/etc/systemd/journald.conf`:
```ini
[Journal]
ForwardToSyslog=yes
```

Then use rsyslog Option A above.

---

## WSL Hosts (vivobook-wsl, steamy-wsl)

WSL2 with systemd enabled:

1. Ensure systemd is enabled in `/etc/wsl.conf`:
   ```ini
   [boot]
   systemd=true
   ```

2. Install and configure rsyslog:
   ```bash
   sudo apt install rsyslog
   ```

3. Create `/etc/rsyslog.d/99-remote.conf` (same as Linux above).

4. **Important**: WSL networking — use the Tailscale IP of SYSLOG_SERVER
   since WSL has its own network namespace.

5. Restart: `sudo systemctl restart rsyslog`

---

## UniFi Cloud Gateway Max

1. SSH into the gateway: `ssh admin@<gateway-ip>`

2. Edit `/etc/rsyslog.d/remote.conf` (persists across firmware updates on newer firmware):
   ```conf
   *.* @SYSLOG_SERVER:1514
   ```

   **OR** use the UniFi Network UI:
   - Settings → System → Advanced → Remote Syslog Server
   - Set host: `SYSLOG_SERVER`
   - Set port: `1514`

3. The UI method is preferred as it survives firmware updates.

---

## ATT BGW-320 Router

1. Access the gateway admin panel: `http://192.168.1.254` (default)
2. Navigate to: **Diagnostics → Syslog**
3. Enable Remote Syslog
4. Set server address: `SYSLOG_SERVER`
5. Set port: `1514`
6. Protocol: **UDP** (BGW-320 only supports UDP syslog)

**Note**: The BGW-320 has limited syslog categories. You'll primarily get
WAN link events, DHCP, firewall, and connection state changes.

---

## Port Forwarding (if using privileged port 514)

If any device can't be configured to use port 1514 (looking at you, BGW-320),
set up a port redirect on the Docker host:

```bash
# iptables redirect 514 -> 1514
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-port 1514
sudo iptables -t nat -A PREROUTING -p tcp --dport 514 -j REDIRECT --to-port 1514

# Make persistent (Debian/Ubuntu)
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

**Unraid alternative**: Use the container port mapping `514:1514/udp` and `514:1514/tcp`
directly in the Docker template — Unraid handles the host-side binding.

---

## Verification

After configuring each host, verify logs are arriving:

```bash
# Send a test message from any Linux host
logger -n SYSLOG_SERVER -P 1514 --tcp "test from $(hostname)"

# Check the MCP health endpoint
curl http://SYSLOG_SERVER:3100/health

# Search for the test message via MCP
curl -X POST http://SYSLOG_SERVER:3100/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "tail_logs",
      "arguments": {"n": 10}
    }
  }'
```

---

## SWAG Reverse Proxy

Add to your SWAG proxy-confs for MCP access over HTTPS:

```nginx
# /config/nginx/proxy-confs/syslog-mcp.subdomain.conf
server {
    listen 443 ssl;
    server_name syslog-mcp.*;

    include /config/nginx/ssl.conf;

    location / {
        include /config/nginx/proxy.conf;
        include /config/nginx/resolver.conf;

        # SSE support
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
        proxy_buffering off;
        proxy_cache off;

        set $upstream_app syslog-mcp;
        set $upstream_port 3100;
        set $upstream_proto http;
        proxy_pass $upstream_proto://$upstream_app:$upstream_port;
    }
}
```

Then your MCP endpoint becomes: `https://syslog-mcp.tootie.tv/mcp`
