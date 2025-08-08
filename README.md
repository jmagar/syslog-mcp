# Syslog MCP Server

A comprehensive Model Context Protocol (MCP) server for advanced syslog analysis and monitoring using Elasticsearch. Built with ultra-focused modular architecture for maintainability and scalability.

## 🚀 Features

### Core Analysis Tools
- **Device Health Monitoring** - Comprehensive device status and activity analysis
- **Security Analysis** - Failed authentication detection, suspicious activity monitoring, IP reputation analysis
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

```
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

## 📋 Available MCP Tools (18 Total)

### 🛡️ Security Analysis (4 tools)
- `failed_auth_summary_tool` - Analyze failed authentication attempts
- `suspicious_activity_tool` - Detect suspicious system activities  
- `ip_reputation_tool` - Analyze IP addresses and attack patterns
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

2. **Configure Elasticsearch connection:**
```bash
cp .env.example .env
# Edit .env with your Elasticsearch settings
```

3. **Run the MCP server:**
```bash
uv run python main.py
```

## ⚙️ Configuration

### Environment Variables (`.env`)
```bash
# Elasticsearch Configuration
ELASTICSEARCH_HOST=your-elasticsearch-host:9200
ELASTICSEARCH_USER=your-username
ELASTICSEARCH_PASSWORD=your-password
ELASTICSEARCH_USE_SSL=true
ELASTICSEARCH_VERIFY_CERTS=true

# Index Configuration  
ELASTICSEARCH_INDEX=syslog-*
ELASTICSEARCH_TIMEOUT=30

# Optional: Security
ELASTICSEARCH_API_KEY=your-api-key
```

### MCP Client Configuration (`.mcp.json`)
```json
{
  "mcpServers": {
    "syslog": {
      "command": "uv",
      "args": ["run", "python", "/path/to/syslog-mcp/main.py"],
      "env": {
        "ELASTICSEARCH_HOST": "your-host:9200"
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

2. **Create application token** in Gotify admin interface
3. **Configure environment variables**:
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
2. **Monitor continuously** (or manually with `check_alerts_tool()`)
3. **Receive notifications** via Gotify when thresholds exceeded
4. **Review alert history** and manage rules

## 🚀 Performance Features

- **Async Operations** - Non-blocking Elasticsearch queries
- **Smart Caching** - Optimized query performance
- **Batch Processing** - Efficient bulk operations  
- **Connection Pooling** - Reusable database connections
- **Query Optimization** - Elasticsearch best practices
- **Memory Efficient** - Streaming large datasets

## 🔧 Development

### Project Structure
```
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
2. **Analysis** - Add business logic in `analysis/`  
3. **Presentation** - Add formatters in `presentation/`
4. **Interface** - Add orchestration in `interface/`
5. **Registry** - Register MCP tool in `device_analysis.py`

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
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Follow the ultra-focused modular architecture
4. Add tests for new functionality
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Community support via GitHub Discussions  
- **Documentation**: Comprehensive guides in `/docs/`

---

**Built with ❤️ using FastMCP, Elasticsearch, and ultra-focused modular architecture**