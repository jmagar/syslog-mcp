# Syslog MCP Server

> **Unified homelab log aggregation and AI-powered correlation via the Model Context Protocol.**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](CHANGELOG.md)
[![Rust Version](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![FastMCP](https://img.shields.io/badge/FastMCP-Enabled-brightgreen.svg)](https://github.com/jlowin/fastmcp)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

---

## ✨ Overview
Syslog MCP is a high-performance log receiver and search engine built in Rust. It aggregates syslog data (UDP/TCP) from all your homelab hosts into a central SQLite database, providing AI assistants with full-text search, real-time tailing, and cross-host event correlation.

### 🎯 Key Features
| Feature | Description |
|---------|-------------|
| **Log Aggregator** | Supports RFC 3164/5424 via UDP and TCP on port 1514 |
| **FTS5 Search** | Blazing fast full-text search across all aggregated logs |
| **Event Correlation** | Analyze related events across multiple hosts in specific time windows |
| **Storage Budget** | Automatic retention policies and emergency disk-space guards |

---

## 🎯 Claude Code Integration
The easiest way to use this plugin is through the Claude Code marketplace:

```bash
# Add the marketplace
/plugin marketplace add jmagar/claude-homelab

# Install the plugin
/plugin install syslog-mcp @jmagar-claude-homelab
```

---

## ⚙️ Configuration & Credentials
Credentials follow the standardized `homelab-core` pattern.

**Location:** `~/.syslog-mcp/.env`

### Required Variables
```bash
SYSLOG_PORT=1514
SYSLOG_MCP_PORT=3100
SYSLOG_MCP_API_TOKEN="your-secret-token"
SYSLOG_MCP_RETENTION_DAYS=90
```

> **Security Note:** Set `SYSLOG_MCP_API_TOKEN` to enable Bearer authentication. Without it, the search endpoint is unauthenticated within your LAN.

---

## 🛠️ Available Tools & Resources

### 🔧 Primary Tools
| Tool | Parameters | Description |
|------|------------|-------------|
| **`search_logs`** | `query`, `host`, `limit` | Full-text search with FTS5 syntax |
| **`tail_logs`** | `host`, `n` | Recent entries across hosts (distributed tail) |
| **`get_errors`** | `none` | Aggregated error summary by host and severity |
| **`correlate_events`**| `window_secs` | Cross-host event mapping in a time window |
| **`get_stats`** | `none` | Database size, log counts, and retention status |

---

## 🏗️ Architecture & Design
Built as a single Rust binary for maximum efficiency:
- **Batch Writer:** Uses `mpsc` channels for non-blocking SQLite persistence.
- **Axum Web Server:** Provides the MCP interface over high-speed HTTP.
- **Storage Guard:** Hourly cleanup tasks enforce retention and disk quotas.

---

## 🔧 Development
### Prerequisites
- Rust 1.75+
- Docker (optional)

### Setup
```bash
cargo build --release
./target/release/syslog-mcp
```

### Docker Deployment
```bash
docker compose up -d
```

---

## 🐛 Troubleshooting
| Issue | Cause | Solution |
|-------|-------|----------|
| **No Logs Found** | Firewall Block | Allow port 1514 (UDP/TCP) on host |
| **Disk Full** | DB Growth | Adjust `SYSLOG_MCP_MAX_DB_SIZE_MB` |
| **401 Unauthorized** | Token Mismatch | Verify `SYSLOG_MCP_API_TOKEN` |

---

## 📄 License
MIT © jmagar
