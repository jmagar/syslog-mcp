# Syslog MCP Server

A comprehensive Model Context Protocol (MCP) server for advanced syslog analysis and monitoring using Elasticsearch. Built with ultra-focused modular architecture for maintainability and scalability.

## 🚀 Features

### Core Analysis Tools

- **Device Health Monitoring** - Comprehensive device status and activity analysis
- **Security Analysis** - Failed authentication detection, suspicious activity monitoring, and timeline analysis
- **System Error Analysis** - Error pattern detection and troubleshooting recommendations
- **Authentication Timeline** - Track authentication events and patterns over time

### Advanced Search & Correlation

- **Multi-field Search** - Advanced search with time ranges, device filters, and log levels
- **Full-text Search** - Intelligent search with highlighting and relevance scoring
- **Correlation Analysis** - Discover relationships between log events across multiple fields
- **Pattern Detection** - Identify recurring patterns and anomalies

### Productivity Features

- **Saved Searches** - Save and reuse frequent search queries
- **Daily Reports** - Automated comprehensive system health reports
- **Log Export** - Export filtered logs in multiple formats (JSON, CSV)
- **Alert Rules** - Create monitoring rules with thresholds and severity levels

### Data Management

- **Real-time Analysis** - Fast async Elasticsearch integration
- **Smart Aggregations** - Device, program, and time-based groupings
- **Performance Optimization** - Efficient query execution and caching

## 🏗️ Architecture

Built with **ultra-focused modular architecture**:

```text
├── Data Access Layer     # Pure Elasticsearch queries (~300 lines each)
│   ├── security_queries.py    # Authentication & security data
│   ├── device_queries.py      # Device health & activity data  
│   ├── search_queries.py      # General search & correlation
│   └── storage_queries.py     # Saved searches & alert rules
├── Analysis Layer        # Pure business logic (~300 lines each)  
│   ├── auth_analyzer.py       # Authentication analysis
│   ├── ip_analyzer.py         # IP reputation analysis
│   ├── suspicious_analyzer.py # Suspicious activity detection
│   ├── device_analyzer.py     # Device health analysis
│   ├── correlation_analyzer.py# Event correlation analysis
│   ├── timeline_analyzer.py   # Timeline pattern analysis
│   └── report_analyzer.py     # Report generation logic
├── Presentation Layer    # Pure formatting (~200 lines each)
│   └── summary_formatters.py  # Markdown report generation
├── Interface Layer       # Thin orchestration (~150 lines each)
│   ├── security_tools.py      # Security tool interfaces
│   ├── device_tools.py        # Device tool interfaces  
│   ├── search_tools.py        # Search tool interfaces
│   └── utility_tools.py       # Utility tool interfaces
└── Registry Layer        # MCP tool registration
    └── device_analysis.py     # Tool registration (227 lines vs original 3,621)
```

**Benefits:**

- **Single Responsibility** - Each module has one focused purpose
- **Easy Testing** - Pure functions with clear inputs/outputs
- **Simple Debugging** - Issues isolated to specific layers
- **Maintainable** - Changes contained to relevant modules
- **Extensible** - New tools follow established patterns

## 📋 Available MCP Tools (16 Total)

### 🛡️ Security Analysis (3 tools)

- `failed_auth_summary_tool` - Analyze failed authentication attempts
- `suspicious_activity_tool` - Detect suspicious system activities  
- `auth_timeline_tool` - Track authentication events over time

### 📱 Device Monitoring (2 tools)

- `get_device_summary_tool` - Comprehensive device health analysis
- `error_analysis_tool` - System error pattern analysis

### 🔍 Search & Analysis (4 tools)

- `search_logs` - General log search with filtering
- `search_by_timerange_tool` - Time-based log searches
- `full_text_search_tool` - Advanced full-text search with highlighting
- `search_correlate_tool` - **NEW** - Multi-field event correlation analysis

### 📊 Productivity Tools (4 tools)

- `saved_searches_tool` - **NEW** - View all saved search queries
- `add_saved_search_tool` - **NEW** - Save frequently used searches
- `generate_daily_report_tool` - **NEW** - Automated daily system reports
- `export_logs_tool` - **NEW** - Export logs with analysis summaries

### 🔔 Monitoring & Alerts (4 tools)

- `create_alert_rule_tool` - **NEW** - Create monitoring alert rules
- `alert_rules_tool` - **NEW** - View configured alert rules
- `check_alerts_tool` - **NEW** - Check all alerts now and send notifications
- `test_gotify_tool` - **NEW** - Test Gotify server connection

## 🛠️ Setup

### Prerequisites

- Python 3.11+
- uv (Python package manager)
- Elasticsearch cluster with syslog data

### Installation

1. **Install dependencies:**

```bash
uv sync
```

1. **Configure Elasticsearch connection:**

```bash
cp .env.example .env
# Edit .env with your Elasticsearch settings
```

1. **Run the MCP server:**

```bash
uv run python -m syslog_mcp
```

## 🐳 Infrastructure Deployment (Docker)

Deploy a complete syslog collection and analysis infrastructure using Docker Compose.

### Prerequisites

- Docker and Docker Compose installed
- Network connectivity on ports 514 (UDP/TCP), 601, 6514
- At least 2GB RAM for Elasticsearch
- Sufficient disk space for log storage

### Quick Start

1. **Create external network** (one-time setup):
   ```bash
   docker network create jakenet
   ```

2. **Start the infrastructure**:
   ```bash
   docker-compose up -d
   ```

3. **Verify services are running**:
   ```bash
   # Check container status
   docker-compose ps
   
   # Verify Elasticsearch health
   curl http://localhost:9200/_cluster/health
   
   # Check syslog-ng logs
   docker logs syslog-ng
   ```

### Directory Structure

The Docker setup creates the following structure:
```
syslog-mcp/
├── docker-compose.yml       # Docker services configuration
├── syslog-ng.conf          # Syslog-ng configuration
├── .env                    # Environment variables
└── /mnt/appdata/          # Data persistence (configurable)
    ├── syslog-ng/         # Syslog files by device
    └── syslog-ng_elasticsearch/  # Elasticsearch data
```

### Services Overview

| Service | Ports | Purpose |
|---------|-------|---------|
| syslog-ng | 514 (UDP/TCP), 601, 6514 | Receives and processes syslog messages |
| elasticsearch | 9200, 9300 | Stores and indexes log data |

### Custom Network Configuration

If you need to use a different network instead of `jakenet`:

1. Create your network:
   ```bash
   docker network create your-network-name
   ```

2. Update `docker-compose.yml`:
   ```yaml
   networks:
     your-network-name:
       external: true
   ```

## 📡 Configuring Devices to Send Logs

Configure your devices to send syslog messages to the syslog-ng server.

### Linux Servers (rsyslog)

Edit `/etc/rsyslog.conf` or `/etc/rsyslog.d/50-remote.conf`:

```bash
# Send all logs via TCP (recommended)
*.* @@your-syslog-server:514

# Or send via UDP (less reliable)
*.* @your-syslog-server:514

# Send only specific facilities
auth,authpriv.* @@your-syslog-server:514
kern.* @@your-syslog-server:514

# Restart rsyslog
sudo systemctl restart rsyslog
```

### Network Devices

#### Cisco IOS/IOS-XE
```cisco
logging host your-syslog-server transport tcp port 514
logging trap informational
logging origin-id hostname
logging source-interface GigabitEthernet0/0
```

#### Cisco NX-OS
```cisco
logging server your-syslog-server 5 port 514 use-vrf management
logging origin-id hostname
logging timestamp milliseconds
```

#### Ubiquiti UniFi
Via Controller UI:
1. Settings → System Settings → Remote Logging
2. Enable "Enable remote syslog server"
3. Host: `your-syslog-server`
4. Port: `514`
5. Protocol: TCP/UDP as preferred

Via SSH (EdgeRouter):
```bash
set system syslog host your-syslog-server facility all level info
set system syslog host your-syslog-server port 514
commit
save
```

#### MikroTik RouterOS
```mikrotik
/system logging action
add name=remote target=remote remote=your-syslog-server remote-port=514
/system logging
add action=remote topics=info,warning,error,critical
```

### Firewalls

#### pfSense
1. Status → System Logs → Settings
2. Enable "Send log messages to remote syslog server"
3. Remote Syslog Server: `your-syslog-server:514`
4. Select log types to forward

#### OPNsense
1. System → Settings → Logging / Targets
2. Add new target:
   - Transport: TCP4 or UDP4
   - Application: syslog
   - Program: `*`
   - Level: Info
   - Hostname: `your-syslog-server`
   - Port: `514`

#### FortiGate
```fortigate
config log syslogd setting
    set status enable
    set server "your-syslog-server"
    set port 514
    set facility local7
    set source-ip x.x.x.x
end
```

### Docker Containers

#### Using Docker logging driver
```bash
# For a single container
docker run --log-driver=syslog \
  --log-opt syslog-address=tcp://your-syslog-server:514 \
  --log-opt tag="{{.Name}}" \
  your-image

# In docker-compose.yml
services:
  app:
    image: your-image
    logging:
      driver: syslog
      options:
        syslog-address: "tcp://your-syslog-server:514"
        tag: "{{.Name}}/{{.ID}}"
```

### Windows Servers

#### Using nxlog (Recommended)

1. Install [nxlog](https://nxlog.co/products/nxlog-community-edition)
2. Configure `nxlog.conf`:

```xml
<Input eventlog>
    Module im_msvistalog
</Input>

<Output syslog>
    Module om_tcp
    Host your-syslog-server
    Port 514
    Exec to_syslog_ietf();
</Output>

<Route 1>
    Path eventlog => syslog
</Route>
```

#### Using Windows Event Forwarding
```powershell
# Configure Windows Event Collector
wecutil cs subscription.xml
# Where subscription.xml points to your syslog forwarder
```

### Application-Specific Logging

#### Python Applications
```python
import logging.handlers

syslog = logging.handlers.SysLogHandler(
    address=('your-syslog-server', 514),
    socktype=socket.SOCK_STREAM  # TCP
)
syslog.setFormatter(logging.Formatter(
    '%(name)s: %(levelname)s %(message)s'
))
logger.addHandler(syslog)
```

#### Node.js Applications
```javascript
const winston = require('winston');
require('winston-syslog').Syslog;

winston.add(new winston.transports.Syslog({
    host: 'your-syslog-server',
    port: 514,
    protocol: 'tcp4',
    app_name: 'node-app'
}));
```

## ✅ Verification & Troubleshooting

### Verify Logs are Being Received

1. **Check syslog-ng is receiving logs**:
   ```bash
   # Watch syslog-ng logs
   docker logs -f syslog-ng
   
   # Check local log files
   docker exec syslog-ng ls -la /var/log/
   ```

2. **Send a test message**:
   ```bash
   # Using logger (from any Linux host)
   logger -n your-syslog-server -P 514 "Test message from $(hostname)"
   
   # Using netcat
   echo "<14>Test syslog message" | nc your-syslog-server 514
   ```

3. **Verify Elasticsearch indexing**:
   ```bash
   # Check indices
   curl http://localhost:9200/_cat/indices/syslog-*
   
   # Search recent logs
   curl http://localhost:9200/syslog-*/_search?q=*&size=10
   ```

### Common Issues & Solutions

#### Logs Not Appearing in Elasticsearch

1. **Check syslog-ng to Elasticsearch connection**:
   ```bash
   docker logs syslog-ng | grep -i elasticsearch
   ```

2. **Verify Elasticsearch is accessible from syslog-ng**:
   ```bash
   docker exec syslog-ng curl http://elasticsearch:9200
   ```

3. **Check syslog-ng configuration syntax**:
   ```bash
   docker exec syslog-ng syslog-ng --syntax-only
   ```

#### Connection Refused Errors

1. **Verify firewall rules**:
   ```bash
   # Check if port is open
   sudo netstat -tulpn | grep 514
   
   # Test connectivity
   telnet your-syslog-server 514
   ```

2. **Check Docker port mapping**:
   ```bash
   docker port syslog-ng
   ```

#### Timezone Mismatches

1. **Set timezone in docker-compose.yml**:
   ```yaml
   environment:
     - TZ=America/New_York
   ```

2. **Verify timezone in containers**:
   ```bash
   docker exec syslog-ng date
   docker exec elasticsearch date
   ```

#### High Memory Usage

1. **Adjust Elasticsearch heap size** in `docker-compose.yml`:
   ```yaml
   environment:
     - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
   ```

2. **Monitor memory usage**:
   ```bash
   docker stats elasticsearch
   ```

### Performance Tuning

#### Syslog-ng Optimization
```conf
options {
    # Increase for high-volume environments
    log_fifo_size(10000);
    # Adjust based on CPU cores
    threaded(yes);
};
```

#### Elasticsearch Optimization
```bash
# Increase indices refresh interval for better ingestion
curl -X PUT "localhost:9200/syslog-*/_settings" -H 'Content-Type: application/json' -d'{
  "index": {
    "refresh_interval": "30s"
  }
}'
```

## ⚙️ Configuration

### Environment Variables (`.env`)

```bash
# Elasticsearch Configuration
# Use localhost:9200 when MCP server runs on host (Docker infrastructure)
# Use elasticsearch:9200 when MCP server runs in Docker network
# Use actual hostname/IP for external Elasticsearch (e.g., squirts:9200)
ELASTICSEARCH_HOST=localhost:9200
ELASTICSEARCH_USER=your-username
ELASTICSEARCH_PASSWORD=your-password
ELASTICSEARCH_USE_SSL=false
ELASTICSEARCH_VERIFY_CERTS=false

# Index Configuration  
ELASTICSEARCH_INDEX=syslog-*
ELASTICSEARCH_TIMEOUT=30

# Optional: Security
ELASTICSEARCH_API_KEY=your-api-key

# Gotify Configuration (Alert Notifications)
GOTIFY_URL=https://gotify-server:443
GOTIFY_TOKEN=your_gotify_app_token_here
```

### MCP Client Configuration

#### For MCP Server on Host (with Docker Infrastructure)

Configure Claude Desktop or your MCP client (`.mcp.json` or `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "syslog": {
      "command": "uv",
      "args": ["run", "python", "-m", "syslog_mcp"],
      "cwd": "/path/to/syslog-mcp",
      "env": {
        "ELASTICSEARCH_HOST": "localhost:9200",
        "ELASTICSEARCH_USE_SSL": "false"
      }
    }
  }
}
```

#### For Everything in Docker

If running the MCP server as a Docker container alongside the infrastructure:

```json
{
  "mcpServers": {
    "syslog": {
      "command": "docker",
      "args": ["run", "--rm", "--network", "jakenet", 
               "-e", "ELASTICSEARCH_HOST=elasticsearch:9200",
               "syslog-mcp:latest"],
      "env": {
        "DOCKER_HOST": "unix:///var/run/docker.sock"
      }
    }
  }
}
```

#### For External Elasticsearch

If using an existing Elasticsearch cluster:

```json
{
  "mcpServers": {
    "syslog": {
      "command": "uv",
      "args": ["run", "python", "-m", "syslog_mcp"],
      "cwd": "/path/to/syslog-mcp",
      "env": {
        "ELASTICSEARCH_HOST": "your-elasticsearch-host:9200",
        "ELASTICSEARCH_USER": "your-username",
        "ELASTICSEARCH_PASSWORD": "your-password",
        "ELASTICSEARCH_USE_SSL": "true",
        "ELASTICSEARCH_VERIFY_CERTS": "true"
      }
    }
  }
}
```

## 📚 Usage Examples

### Basic Device Analysis

```python
# Get comprehensive device health summary
await get_device_summary_tool(device="web-server-01", hours=24)

# Analyze system errors
await error_analysis_tool(device="web-server-01", hours=24, severity="error")
```

### Security Monitoring

```python
# Check for failed authentication attempts
await failed_auth_summary_tool(hours=24, top_ips=10)

# Detect suspicious activities  
await suspicious_activity_tool(hours=24, sensitivity="high")

# Analyze IP reputation
await ip_reputation_tool(hours=24, min_attempts=5)
```

### Advanced Search & Correlation

```python
# Correlate events across multiple fields
await search_correlate_tool(
    primary_query="error database",
    correlation_fields="device,program,level", 
    time_window=300,
    hours=12
)

# Full-text search with highlighting
await full_text_search_tool(
    query="connection timeout",
    search_type="fuzzy",
    hours=6
)
```

### Productivity Features

```python
# Save frequently used searches
await add_saved_search_tool(
    name="Database Errors",
    query="database AND (error OR timeout)",
    description="Monitor database-related issues"
)

# Generate daily system report
await generate_daily_report_tool(target_date="2025-01-15")

# Export logs with analysis
await export_logs_tool(
    query="level:error", 
    format_type="json",
    start_time="2025-01-15T00:00:00Z",
    limit=1000
)
```

### Alert Management

```python
# Create monitoring alert rules
await create_alert_rule_tool(
    name="High Error Rate",
    query="level:error",
    threshold=100,
    time_window=60,
    severity="high"
)

# View all configured alerts
await alert_rules_tool()

# Check alerts now and send notifications
await check_alerts_tool()

# Test Gotify notification system
await test_gotify_tool()
```

### Alert Notifications with Gotify

The Syslog MCP server supports **real-time alert notifications** via [Gotify](https://gotify.net/), an open-source push notification service.

#### Gotify Setup

1. **Install Gotify server** (Docker recommended):

   ```bash
   docker run -d --name gotify-server \
     -p 80:80 \
     -v gotify-data:/app/data \
     gotify/server
   ```

1. **Create application token** in Gotify admin interface

1. **Configure environment variables**:

   ```bash
   GOTIFY_URL=http://gotify-server:80
   GOTIFY_TOKEN=your_gotify_app_token_here
   ```

#### Alert Features

- **Automatic notifications** when thresholds are exceeded
- **Severity-based priorities** (Low=3, Medium=5, High=8, Critical=10)
- **Cooldown periods** prevent notification spam (30-minute default)
- **Rich messages** with detailed alert context
- **Manual testing** with `test_gotify_tool()`

#### Alert Flow

1. **Create alert rules** with `create_alert_rule_tool()`
1. **Monitor continuously** (or manually with `check_alerts_tool()`)
1. **Receive notifications** via Gotify when thresholds exceeded
1. **Review alert history** and manage rules

## 🚀 Performance Features

- **Async Operations** - Non-blocking Elasticsearch queries
- **Smart Caching** - Optimized query performance
- **Batch Processing** - Efficient bulk operations  
- **Connection Pooling** - Reusable database connections
- **Query Optimization** - Elasticsearch best practices
- **Memory Efficient** - Streaming large datasets

## 🔧 Development

### Project Structure

```text
src/syslog_mcp/
├── services/              # Core services
│   └── elasticsearch_client.py
├── tools/                 # MCP tools (ultra-focused modules)
│   ├── data_access/      # Pure Elasticsearch queries
│   ├── analysis/         # Pure business logic  
│   ├── presentation/     # Pure formatting
│   ├── interface/        # Thin orchestration
│   └── device_analysis.py # Tool registry
├── utils/                # Utilities
│   ├── logging.py
│   └── retry.py
└── main.py               # MCP server entry point
```

### Development Commands

```bash
# Run with hot reload
uv run python main.py

# Run tests  
uv run pytest

# Type checking
uv run mypy src/

# Code formatting
uv run black src/
uv run ruff check --fix src/
```

### Adding New Tools

Follow the ultra-focused modular pattern:

1. **Data Access** - Add pure Elasticsearch queries in `data_access/`
1. **Analysis** - Add business logic in `analysis/`  
1. **Presentation** - Add formatters in `presentation/`
1. **Interface** - Add orchestration in `interface/`
1. **Registry** - Register MCP tool in `device_analysis.py`

## 📊 Monitoring & Observability

- **Request Logging** - All MCP requests logged with parameters
- **Performance Metrics** - Query execution times and success rates
- **Error Tracking** - Detailed error logging with context
- **Health Checks** - Elasticsearch connectivity monitoring

## 🔒 Security

- **Parameter Validation** - Pydantic models for input validation
- **Query Sanitization** - Safe Elasticsearch query construction
- **Rate Limiting** - Configurable request throttling
- **SSL Support** - Encrypted Elasticsearch connections
- **Audit Logging** - Track all search operations

## 🤝 Contributing

1. Fork the repository
1. Create feature branch (`git checkout -b feature/amazing-feature`)
1. Follow the ultra-focused modular architecture
1. Add tests for new functionality
1. Commit changes (`git commit -m 'Add amazing feature'`)
1. Push to branch (`git push origin feature/amazing-feature`)
1. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Community support via GitHub Discussions  
- **Documentation**: Comprehensive guides in `/docs/`

---

**Built with ❤️ using FastMCP, Elasticsearch, and ultra-focused modular architecture**
