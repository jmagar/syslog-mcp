# Syslog-MCP Testing Strategy

This document outlines the comprehensive testing strategy for the syslog-mcp project, following FastMCP testing patterns with minimal mocking and realistic test scenarios.

## 🎯 Testing Philosophy

Our testing approach prioritizes:

1. **Realistic Testing**: Use real Elasticsearch instances via testcontainers when possible
2. **Minimal Mocking**: Only mock external dependencies, not business logic
3. **FastMCP Patterns**: Follow FastMCP's in-memory testing recommendations
4. **Bug Detection**: Tests designed to actually uncover bugs, not just pass
5. **High Coverage**: Comprehensive coverage of code paths and edge cases

## 📁 Test Structure

```
tests/
├── conftest.py                 # Central fixture configuration
├── factories.py               # Realistic data generation with Faker
├── README.md                  # This file
├── unit/                      # Fast unit tests with minimal dependencies
│   ├── test_search_logs.py    # Search functionality tests
│   └── test_device_analysis_tools.py  # Device analysis tool tests
├── integration/               # Integration tests with real Elasticsearch
│   └── test_elasticsearch_integration.py  # Full E2E tests
└── test_error_handling.py     # Error scenarios and edge cases
```

## 🧪 Test Types

### Unit Tests (`tests/unit/`)
- **Speed**: Fast execution (< 1 second per test)
- **Dependencies**: Minimal mocking of Elasticsearch only
- **Focus**: Business logic, parameter validation, tool behavior
- **Pattern**: FastMCP in-memory testing with `Client(server)` 
- **Markers**: `@pytest.mark.unit`

### Integration Tests (`tests/integration/`)
- **Speed**: Slower (5-30 seconds per test)
- **Dependencies**: Real Elasticsearch via testcontainers
- **Focus**: End-to-end functionality, real data scenarios
- **Pattern**: FastMCP in-memory testing with real ES backend
- **Markers**: `@pytest.mark.integration`, `@pytest.mark.elasticsearch`, `@pytest.mark.slow`

### Error Handling Tests (`tests/test_error_handling.py`)
- **Speed**: Fast to medium
- **Dependencies**: Mix of mocked and real scenarios
- **Focus**: Error conditions, edge cases, security
- **Markers**: `@pytest.mark.error_handling`, `@pytest.mark.security`

## 🔧 Test Fixtures

### Core Fixtures (conftest.py)

#### Unit Test Fixtures
- `mock_elasticsearch_client`: Lightweight ES mock for unit tests
- `mock_elasticsearch_server`: MCP server with mocked ES
- `fastmcp_client_mock`: FastMCP client for unit tests

#### Integration Test Fixtures  
- `elasticsearch_container`: Real ES container via testcontainers
- `elasticsearch_client`: Async ES client connected to test container
- `elasticsearch_with_data`: ES with pre-loaded realistic test data
- `real_elasticsearch_server`: MCP server with real ES connection
- `fastmcp_client_real`: FastMCP client for integration tests

#### Data Fixtures
- `sample_log_data`: Generated realistic log entries
- `security_scenario_data`: Security attack patterns
- `device_health_scenario_data`: Device health degradation scenarios

## 📊 Realistic Test Data

### Data Factories (`tests/factories.py`)

Our test data generation uses Faker and Factory Boy to create authentic scenarios:

#### SyslogProvider
Custom Faker provider generating realistic:
- Device names (`server-01`, `router-02`, `firewall-03`)
- Security messages (SSH failures, sudo attempts, brute force)
- System messages (service starts/stops, resource alerts)
- Programs (`sshd`, `sudo`, `kernel`, `systemd`, etc.)

#### Log Entry Factories
- `LogEntryFactory`: General log entries
- `SecurityLogFactory`: Security-focused entries
- `SystemLogFactory`: System health entries
- `BruteForceAttackFactory`: Generates attack scenarios
- `DeviceHealthScenarioFactory`: Device degradation patterns

#### Scenario Generators
- `create_elasticsearch_bulk_data()`: Large realistic datasets
- `create_security_scenario()`: Complex attack patterns
- `create_device_health_scenario()`: System health issues

## 🚀 Running Tests

### Quick Commands

```bash
# Fast unit tests only
python scripts/run_tests.py --mode unit

# Unit tests with coverage
python scripts/run_tests.py --mode unit --coverage

# Integration tests (requires Docker)
python scripts/run_tests.py --mode integration

# All tests with coverage
python scripts/run_tests.py --mode all --coverage

# Error handling tests
python scripts/run_tests.py --mode error

# Security tests
python scripts/run_tests.py --mode security

# Performance tests  
python scripts/run_tests.py --mode performance
```

### Direct Pytest Commands

```bash
# Unit tests only
uv run pytest -m unit

# Integration tests only  
uv run pytest -m integration

# Skip integration tests if no Docker
uv run pytest -m "not integration"

# Error handling tests
uv run pytest -m error_handling

# Security tests
uv run pytest -m security

# Specific test file
uv run pytest tests/unit/test_search_logs.py -v

# With coverage
uv run pytest --cov=syslog_mcp --cov-report=html
```

## 📈 Coverage Goals

- **Overall Coverage**: ≥ 90% for business logic, ≥ 80% total
- **Unit Test Coverage**: ≥ 95% of tool interfaces and core logic
- **Integration Coverage**: ≥ 80% of end-to-end scenarios  
- **Error Handling**: 100% of error conditions and edge cases

### Coverage Reports

Coverage reports are generated in `.cache/coverage/`:
- HTML report: `.cache/coverage/htmlcov/index.html`
- XML report: `.cache/coverage/coverage.xml`
- Terminal output during test runs

## 🐳 Docker Requirements

### For Integration Tests

Integration tests require Docker to spin up real Elasticsearch:

```yaml
# docker-compose.test.yml
services:
  elasticsearch-test:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.15.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
```

### Alternative: Skip Integration Tests

```bash
# Skip integration tests if Docker unavailable
export SKIP_INTEGRATION_TESTS=1
uv run pytest
```

## 🎭 Test Markers

Use pytest markers to run specific test categories:

- `unit`: Fast unit tests with minimal dependencies
- `integration`: Integration tests requiring Elasticsearch  
- `slow`: Slow-running tests (usually integration tests)
- `elasticsearch`: Tests requiring Elasticsearch connection
- `performance`: Performance benchmarking tests
- `error_handling`: Error scenario tests
- `security`: Security-focused tests

## 🔍 Property-Based Testing

We use Hypothesis for property-based testing to uncover edge cases:

```python
@given(
    query_text=st.one_of(st.none(), st.text(min_size=1, max_size=100)),
    limit=st.integers(min_value=1, max_value=1000),
    offset=st.integers(min_value=0, max_value=10000)
)
async def test_search_logs_property_based(fastmcp_client_mock, query_text, limit, offset):
    # Test with generated inputs
    result = await fastmcp_client_mock.call_tool("search_logs", {
        "query": query_text,
        "limit": limit,
        "offset": offset
    })
    
    # Verify invariants hold for all valid inputs
    assert result.is_error is False
    assert result.data["limit"] == limit
    assert result.data["offset"] == offset
```

## 🧬 Mutation Testing

Verify test quality with mutation testing:

```bash
# Run mutation tests
python scripts/run_tests.py --mode mutation

# Or directly
uv run mutmut run
uv run mutmut results
```

Mutation testing changes your code and verifies that tests fail, ensuring tests actually detect bugs.

## 🐛 Debugging Tests

### Verbose Output
```bash
# Detailed test output
uv run pytest -v -s

# Show local variables on failure
uv run pytest --tb=long --locals

# Drop into debugger on failure
uv run pytest --pdb
```

### Elasticsearch Debugging
```bash
# Check ES container logs (integration tests)
docker logs elasticsearch-test

# Connect to test ES directly
curl http://localhost:9200/_cluster/health
```

## 📝 Test Writing Guidelines

### Unit Test Pattern
```python
@pytest.mark.unit
async def test_search_functionality(fastmcp_client_mock):
    """Test search with meaningful description."""
    result = await fastmcp_client_mock.call_tool("search_logs", {
        "query": "authentication failed",
        "limit": 10
    })
    
    assert result.is_error is False
    data = result.data
    
    # Verify response structure
    assert "status" in data
    assert "total_hits" in data
    assert data["status"] == "success"
    
    # Verify business logic
    assert isinstance(data["logs"], list)
    assert len(data["logs"]) <= 10
```

### Integration Test Pattern
```python
@pytest.mark.integration
@pytest.mark.elasticsearch
async def test_real_search_functionality(fastmcp_client_real):
    """Test search with real Elasticsearch and data."""
    result = await fastmcp_client_real.call_tool("search_logs", {
        "query": "ssh",
        "level": "warning"
    })
    
    assert result.is_error is False
    data = result.data
    
    # Verify with real data
    assert data["status"] == "success"
    
    # If we have results, verify they match filters
    for log in data["logs"]:
        if "message" in log:
            assert "ssh" in log["message"].lower()
        if "level" in log:
            assert log["level"].lower() in ["warning", "error", "critical"]
```

### Error Test Pattern  
```python
@pytest.mark.error_handling
async def test_connection_error_handling(fastmcp_client_mock, monkeypatch):
    """Test graceful handling of ES connection errors."""
    # Mock connection error
    mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
    mock_es_client.search.side_effect = ElasticsearchConnectionError("Connection failed")
    
    result = await fastmcp_client_mock.call_tool("search_logs", {"query": "test"})
    
    assert result.is_error is True
    assert "connection" in result.error_data.get("message", "").lower()
```

## 🎨 Best Practices

1. **Test Behavior, Not Implementation**: Focus on what tools do, not how
2. **Use Realistic Data**: Generate authentic syslog entries and scenarios
3. **Test Edge Cases**: Empty results, large datasets, malformed input
4. **Verify Error Messages**: Ensure errors are user-friendly and actionable
5. **Test Concurrency**: Verify tools work under concurrent access
6. **Performance Awareness**: Monitor test execution times
7. **Security Mindset**: Test injection attempts and DoS scenarios

## 🔧 Troubleshooting

### Common Issues

#### Docker Not Available
```bash
# Skip integration tests
export SKIP_INTEGRATION_TESTS=1
uv run pytest -m "not integration"
```

#### ES Container Fails to Start
```bash
# Check Docker logs
docker logs elasticsearch-test

# Increase wait timeout
# Edit conftest.py: wait_timeout=300
```

#### Tests Hang
```bash
# Run with timeout
timeout 300 uv run pytest

# Debug hanging tests
uv run pytest --timeout=60
```

#### Memory Issues
```bash
# Reduce ES memory
# Edit docker-compose.test.yml: ES_JAVA_OPTS=-Xms256m -Xmx256m

# Run tests sequentially
uv run pytest -x --maxfail=1
```

## 📚 Additional Resources

- [FastMCP Testing Documentation](https://gofastmcp.com/deployment/testing.md)
- [Pytest Documentation](https://docs.pytest.org/)  
- [Testcontainers Python](https://testcontainers-python.readthedocs.io/)
- [Hypothesis Documentation](https://hypothesis.readthedocs.io/)
- [Faker Documentation](https://faker.readthedocs.io/)

## 🤝 Contributing

When adding new tests:

1. Follow existing patterns and naming conventions
2. Add realistic test data using factories
3. Include both positive and negative test cases  
4. Test error conditions and edge cases
5. Update this README if adding new test categories
6. Ensure tests are properly marked with pytest markers
7. Verify tests actually fail when they should (mutation testing mindset)