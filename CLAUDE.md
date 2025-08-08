# Claude Code Instructions - Syslog MCP Server

## Project Overview
**Syslog MCP Server** - A comprehensive Model Context Protocol (MCP) server for advanced syslog analysis and monitoring using Elasticsearch. Built with **ultra-focused modular architecture** for maintainability and scalability.

### Key Capabilities
- **15 MCP Tools** for security analysis, device monitoring, search/correlation, productivity, and alert management
- **Real-time syslog analysis** with advanced Elasticsearch queries
- **Ultra-focused modular architecture** with separated layers (Data → Analysis → Presentation → Interface → Registry)
- **Production-ready** with async operations, error handling, and comprehensive logging

## 🏗️ Ultra-Focused Modular Architecture

**CRITICAL**: This project follows a strict **ultra-focused modular architecture** pattern. Each module has a **single responsibility** and **~300 lines max**.

```
src/syslog_mcp/tools/
├── 📁 data_access/           # Pure Elasticsearch queries (~300 lines each)
│   ├── security_queries.py     # Authentication & security data queries
│   ├── device_queries.py       # Device health & activity queries  
│   ├── search_queries.py       # General search & correlation queries
│   └── storage_queries.py      # Saved searches & alert rules storage
├── 🧠 analysis/              # Pure business logic (~300 lines each)  
│   ├── auth_analyzer.py        # Authentication analysis logic
│   ├── ip_analyzer.py          # IP reputation analysis logic
│   ├── suspicious_analyzer.py  # Suspicious activity detection logic
│   ├── device_analyzer.py      # Device health analysis logic
│   ├── correlation_analyzer.py # Event correlation analysis logic
│   ├── timeline_analyzer.py    # Timeline pattern analysis logic
│   └── report_analyzer.py      # Report generation logic
├── 🎨 presentation/          # Pure formatting (~200 lines each)
│   └── summary_formatters.py   # All Markdown report formatters
├── 🔗 interface/             # Thin orchestration (~150 lines each)
│   ├── security_tools.py       # Security tool interfaces
│   ├── device_tools.py         # Device tool interfaces  
│   ├── search_tools.py         # Search tool interfaces
│   └── utility_tools.py        # Utility tool interfaces
└── 📋 device_analysis.py      # Tool registry (227 lines vs original 3,621)
```

### Architecture Rules
1. **Data Access Layer**: ONLY Elasticsearch queries, NO business logic
2. **Analysis Layer**: ONLY business logic, NO data access or formatting
3. **Presentation Layer**: ONLY formatting, NO business logic
4. **Interface Layer**: ONLY orchestration, calls Data → Analysis → Presentation
5. **Registry Layer**: ONLY MCP tool registration

### Benefits
- **Single Responsibility**: Each module has one focused purpose
- **Easy Testing**: Pure functions with clear inputs/outputs
- **Simple Debugging**: Issues isolated to specific layers
- **Maintainable**: Changes contained to relevant modules
- **Extensible**: New tools follow established patterns

## 📋 Available MCP Tools (15 Total)

### 🛡️ Security Analysis Tools (4 tools)
- `failed_auth_summary_tool` - Analyze failed authentication attempts with IP analysis
- `suspicious_activity_tool` - Detect suspicious activities with sensitivity controls  
- `ip_reputation_tool` - Analyze IP addresses with threat assessment
- `auth_timeline_tool` - Track authentication events with timeline visualization

### 📱 Device Monitoring Tools (2 tools)
- `get_device_summary_tool` - Comprehensive device health with recommendations
- `error_analysis_tool` - System error analysis with troubleshooting insights

### 🔍 Search & Analysis Tools (4 tools)  
- `search_logs` - General log search with advanced filtering (raw JSON format)
- `search_by_timerange_tool` - Time-based searches with aggregations
- `full_text_search_tool` - Advanced full-text search with highlighting and relevance
- `search_correlate_tool` - **Multi-field event correlation** with pattern detection

### 📊 Productivity Tools (4 tools)
- `saved_searches_tool` - View and manage saved search queries with usage stats
- `add_saved_search_tool` - Save frequently used searches for quick access
- `generate_daily_report_tool` - Automated comprehensive daily system reports
- `export_logs_tool` - Export filtered logs with analysis summaries

### 🔔 Monitoring & Alert Tools (2 tools)
- `create_alert_rule_tool` - Create monitoring alert rules with thresholds
- `alert_rules_tool` - View and manage configured alert rules

## Python Environment & Dependencies

### Core Dependencies
- **Python 3.11+** (required for modern async features)
- **uv** for Python environment management (fast, reliable)
- **FastMCP 2.11.1** for MCP server implementation
- **elasticsearch-py** for async Elasticsearch client
- **pydantic** for data validation and serialization

### Development Dependencies  
- **pytest** for comprehensive testing
- **mypy** for static type checking
- **black** for code formatting
- **ruff** for fast linting

## Development Workflow

### Key Principles
- **Async/await patterns** throughout (never blocking operations)
- **Comprehensive error handling** with specific exception types
- **Detailed logging** with structured context
- **Type hints everywhere** for better IDE support and catching errors
- **Unit tests** for all MCP tools and critical functions

### Code Quality Standards
- **Max 300 lines per module** (ultra-focused principle)
- **Single responsibility** per function and class
- **Pure functions** where possible (no side effects)
- **Descriptive naming** (no abbreviations)
- **Comprehensive docstrings** for all public functions

## Key Files Structure

```
src/syslog_mcp/
├── main.py                      # MCP server entry point with FastMCP setup
├── services/
│   └── elasticsearch_client.py # Async ES client with connection management
├── tools/                       # MCP tools (ultra-focused modules)
│   ├── data_access/            # Pure Elasticsearch queries
│   ├── analysis/               # Pure business logic  
│   ├── presentation/           # Pure formatting
│   ├── interface/              # Thin orchestration
│   └── device_analysis.py      # Tool registry (all @mcp.tool() decorators)
├── utils/                      # Utilities
│   ├── logging.py              # Structured logging with context
│   ├── retry.py               # Retry logic with exponential backoff
│   └── exceptions.py          # Custom exception classes
├── tests/                      # Comprehensive test suite
│   ├── unit/                  # Unit tests for individual modules
│   ├── integration/           # Integration tests with Elasticsearch
│   └── fixtures/              # Test data and fixtures
└── config/
    └── elasticsearch.py       # ES configuration and validation
```

## Development Commands

```bash
# Environment setup
uv sync                          # Install all dependencies
uv add package-name             # Add new dependency

# Development server
uv run python main.py           # Run MCP server (hot reload enabled)

# Testing
uv run pytest                   # Run all tests
uv run pytest tests/unit/       # Run only unit tests  
uv run pytest -v               # Verbose test output
uv run pytest --cov            # Test coverage report

# Code quality
uv run mypy src/                # Static type checking
uv run black src/               # Format code
uv run ruff check --fix src/    # Lint and auto-fix
uv run ruff check src/          # Lint only (no auto-fix)

# Performance testing
uv run python -m cProfile main.py  # Profile performance
```

## Infrastructure & Configuration

### Elasticsearch Setup
- **Production**: Elasticsearch cluster at `squirts:9200`
- **Index Pattern**: `syslog-*` (time-based indices)
- **Required Fields**: `timestamp`, `device`, `message`, `program`, `level`, `facility`

### Environment Configuration (`.env`)
```bash
# Elasticsearch connection
ELASTICSEARCH_HOST=squirts:9200
ELASTICSEARCH_USER=your-username
ELASTICSEARCH_PASSWORD=your-password
ELASTICSEARCH_USE_SSL=false
ELASTICSEARCH_VERIFY_CERTS=false

# Index configuration
ELASTICSEARCH_INDEX=syslog-*
ELASTICSEARCH_TIMEOUT=30

# Logging configuration
LOG_LEVEL=INFO
LOG_FORMAT=json

# Performance tuning
ELASTICSEARCH_MAX_RETRIES=3
ELASTICSEARCH_RETRY_TIMEOUT=60
```

### MCP Client Configuration (`.mcp.json`)
```json
{
  "mcpServers": {
    "syslog": {
      "command": "uv",
      "args": ["run", "python", "/path/to/syslog-mcp/main.py"],
      "env": {
        "ELASTICSEARCH_HOST": "squirts:9200"
      }
    }
  }
}
```

## Adding New MCP Tools

Follow the **ultra-focused modular pattern** for all new tools:

### Step 1: Data Access Layer
```python
# Add to appropriate data_access/*.py file
async def query_new_feature(
    es_client: ElasticsearchClient,
    param1: str,
    param2: int = 100
) -> Dict[str, Any]:
    """Pure Elasticsearch query - NO business logic."""
    # Build and execute ES query
    # Return raw ES response
```

### Step 2: Analysis Layer  
```python
# Add to appropriate analysis/*.py file
def analyze_new_feature_data(
    es_response: Dict[str, Any],
    param1: str
) -> Dict[str, Any]:
    """Pure business logic - NO data access or formatting."""
    # Process ES response
    # Apply business rules
    # Return structured analysis data
```

### Step 3: Presentation Layer
```python
# Add to presentation/summary_formatters.py
def format_new_feature_summary(analysis_data: Dict[str, Any]) -> str:
    """Pure formatting - NO business logic."""
    # Convert analysis data to markdown
    # Return formatted string
```

### Step 4: Interface Layer
```python
# Add to appropriate interface/*.py file  
async def new_feature_interface(
    client,
    param1: str,
    param2: int = 100
) -> str:
    """Thin orchestration layer."""
    try:
        # Data Access Layer
        es_response = await query_new_feature(client, param1, param2)
        
        # Analysis Layer  
        analysis_data = analyze_new_feature_data(es_response, param1)
        
        # Presentation Layer
        return format_new_feature_summary(analysis_data)
        
    except Exception as e:
        logger.error(f"New feature error: {e}")
        return f"Error: {str(e)}"
```

### Step 5: Registry Layer
```python
# Add to tools/device_analysis.py in register_device_analysis_tools()
@mcp.tool()
async def new_feature_tool(param1: str, param2: int = 100) -> str:
    """Description for the MCP tool."""
    log_mcp_request("new_feature", {"param1": param1, "param2": param2})
    
    es_client = ElasticsearchClient()
    try:
        await es_client.connect()
        result = await new_feature_interface(es_client, param1, param2)
        log_mcp_response("new_feature", True)
        return result
    except Exception as e:
        log_mcp_response("new_feature", False, error=str(e))
        return f"Error: {str(e)}"
    finally:
        await es_client.disconnect()
```

## Testing Strategy

### Unit Tests
- **Data Access**: Mock Elasticsearch responses, test query building
- **Analysis**: Test business logic with known inputs/outputs
- **Presentation**: Test formatting with sample analysis data
- **Interface**: Test orchestration flow with mocked layers

### Integration Tests  
- **End-to-end**: Test complete MCP tool flows with real Elasticsearch
- **Performance**: Measure query execution times and memory usage
- **Error Handling**: Test error scenarios and recovery

### Test Structure
```python
# tests/unit/test_new_feature.py
import pytest
from syslog_mcp.tools.analysis.new_analyzer import analyze_new_feature_data

def test_analyze_new_feature_with_valid_data():
    # Given
    sample_es_response = {...}
    
    # When  
    result = analyze_new_feature_data(sample_es_response, "test_param")
    
    # Then
    assert result["status"] == "success"
    assert len(result["insights"]) > 0
```

## Performance & Monitoring

### Performance Guidelines
- **Async everywhere**: Never block the event loop
- **Connection pooling**: Reuse Elasticsearch connections
- **Query optimization**: Use specific indices and field filters
- **Memory efficiency**: Stream large result sets
- **Caching**: Cache expensive computations (when appropriate)

### Monitoring & Observability
- **Request logging**: All MCP requests with parameters and timing
- **Performance metrics**: Query execution times and success rates
- **Error tracking**: Structured error logging with full context
- **Health checks**: Elasticsearch connectivity and index status

### Production Considerations
- **Rate limiting**: Prevent abuse of expensive queries
- **Timeouts**: All ES queries have reasonable timeouts
- **Retries**: Exponential backoff for transient failures
- **Security**: Input validation and query sanitization

## Common Patterns & Best Practices

### Error Handling
```python
try:
    result = await risky_operation()
    log_mcp_response("operation", True)
    return result
except ElasticsearchConnectionError as e:
    logger.error(f"ES connection failed: {e}")
    return "Elasticsearch unavailable - please try again later"
except ElasticsearchQueryError as e:
    logger.error(f"Invalid query: {e}")
    return f"Query error: {str(e)}"
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    log_mcp_response("operation", False, error=str(e))
    return f"System error: {str(e)}"
```

### Logging
```python
from ...utils.logging import get_logger, log_mcp_request, log_mcp_response

logger = get_logger(__name__)

# MCP request logging
log_mcp_request("tool_name", {"param1": value1, "param2": value2})

# Operation logging
logger.info("Starting analysis", extra={"device": device, "hours": hours})

# MCP response logging  
log_mcp_response("tool_name", success=True, metrics={"execution_time": 1.23})
```

### Type Annotations
```python
from typing import Any, Dict, List, Optional

async def query_function(
    es_client: ElasticsearchClient,
    required_param: str,
    optional_param: Optional[int] = None,
    limit: int = 100
) -> Dict[str, Any]:
    """Function with complete type annotations."""
    pass
```

## Debugging & Troubleshooting

### Common Issues
1. **Elasticsearch connection failures**: Check `.env` configuration
2. **Query timeout errors**: Optimize queries or increase timeout
3. **Memory issues**: Stream large datasets instead of loading all at once
4. **Type errors**: Run `mypy` regularly during development

### Debug Commands
```bash
# Enable debug logging
LOG_LEVEL=DEBUG uv run python main.py

# Test Elasticsearch connection
uv run python -c "from src.syslog_mcp.services.elasticsearch_client import ElasticsearchClient; import asyncio; asyncio.run(ElasticsearchClient().test_connection())"

# Validate configuration
uv run python -c "from src.syslog_mcp.config.elasticsearch import validate_config; validate_config()"
```

## Task Master AI Instructions
**Import Task Master's development workflow commands and guidelines, treat as if import is in the main CLAUDE.md file.**
@./.taskmaster/CLAUDE.md

---

## Important Reminders

1. **Architecture First**: Always follow the ultra-focused modular architecture
2. **Pure Functions**: Keep layers separate with pure functions where possible  
3. **Async Throughout**: Never block the event loop
4. **Comprehensive Testing**: Test all new functionality
5. **Type Safety**: Use type hints everywhere
6. **Error Handling**: Handle all error scenarios gracefully
7. **Performance**: Monitor and optimize query performance
8. **Documentation**: Update documentation for new features