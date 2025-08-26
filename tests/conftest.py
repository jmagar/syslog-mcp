"""
Test fixtures and configuration for syslog-mcp tests.

This module provides fixtures for both unit tests (with minimal mocking) and
integration tests (with real Elasticsearch via testcontainers).

Following FastMCP testing patterns with in-memory server testing.
"""

import asyncio
import os
import time
from typing import AsyncGenerator, Dict, Generator, List, Any
from unittest.mock import AsyncMock

import pytest
from elasticsearch import AsyncElasticsearch
from fastmcp import Client
from testcontainers.elasticsearch import ElasticSearchContainer

from syslog_mcp.server import create_server
from syslog_mcp.services.elasticsearch_client import ElasticsearchClient, ElasticsearchConfig
from tests.factories import (
    create_elasticsearch_bulk_data,
    create_security_scenario,
    create_device_health_scenario,
)


# Test configuration
TEST_ELASTICSEARCH_IMAGE = "docker.elastic.co/elasticsearch/elasticsearch:7.15.0"
TEST_INDEX_NAME = "syslog-test-*"


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for the entire test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def elasticsearch_container() -> Generator[ElasticSearchContainer, None, None]:
    """
    Fixture that provides a real Elasticsearch container for integration tests.
    
    Uses testcontainers to spin up an actual ES instance. This is slower but
    provides the most realistic testing environment.
    """
    with ElasticSearchContainer(
        image=TEST_ELASTICSEARCH_IMAGE,
        environment={
            "discovery.type": "single-node",
            "ES_JAVA_OPTS": "-Xms512m -Xmx512m",
            "xpack.security.enabled": "false",
        },
        wait_timeout=120,
    ) as es_container:
        # Wait for container to be ready
        time.sleep(5)
        yield es_container


@pytest.fixture(scope="session")
async def elasticsearch_client(elasticsearch_container) -> AsyncGenerator[AsyncElasticsearch, None]:
    """Create an async Elasticsearch client connected to the test container."""
    connection_string = elasticsearch_container.get_connection_url()
    
    client = AsyncElasticsearch(
        [connection_string],
        timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )
    
    # Wait for the cluster to be ready
    for attempt in range(30):
        try:
            health = await client.cluster.health(wait_for_status="yellow", timeout="30s")
            if health["status"] in ["green", "yellow"]:
                break
        except Exception:
            if attempt == 29:
                raise
            await asyncio.sleep(1)
    
    yield client
    
    await client.close()


@pytest.fixture
async def elasticsearch_with_data(elasticsearch_client) -> AsyncElasticsearch:
    """
    Elasticsearch client with realistic test data pre-loaded.
    
    This fixture creates indices and loads them with comprehensive test data
    including security events, system logs, and device health scenarios.
    """
    # Create test index
    index_name = "syslog-test-2025.01.15"
    
    # Create index with proper mapping
    mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "device": {"type": "keyword"},
                "message": {"type": "text", "analyzer": "standard"},
                "program": {"type": "keyword"},
                "level": {"type": "keyword"},
                "facility": {"type": "keyword"},
                "host": {"type": "keyword"},
                "severity": {"type": "integer"}
            }
        }
    }
    
    await elasticsearch_client.indices.create(index=index_name, body=mapping, ignore=400)
    
    # Load bulk test data
    bulk_data = create_elasticsearch_bulk_data(1000)
    security_data = create_security_scenario()
    health_data = create_device_health_scenario()
    
    all_data = bulk_data + security_data + health_data
    
    # Prepare for bulk indexing
    bulk_body = []
    for doc in all_data:
        action = {"index": {"_index": index_name}}
        bulk_body.extend([action, doc])
    
    # Bulk index the data
    if bulk_body:
        await elasticsearch_client.bulk(body=bulk_body, refresh="wait_for")
    
    yield elasticsearch_client
    
    # Cleanup
    await elasticsearch_client.indices.delete(index=index_name, ignore=404)


@pytest.fixture
def mock_elasticsearch_client():
    """
    Lightweight mock for unit tests that need speed over realism.
    
    This provides basic mocking for tests that focus on business logic
    rather than Elasticsearch integration.
    """
    mock_client = AsyncMock()
    
    # Mock basic connection methods
    mock_client.connect.return_value = None
    mock_client.disconnect.return_value = None
    mock_client.is_connected.return_value = True
    
    # Create a simple mock that just returns the expected data structure
    # This will be overridden by the actual mock when needed
    mock_client.search.return_value = {
        "took": 5,
        "timed_out": False,
        "hits": {
            "total": {"value": 42, "relation": "eq"},
            "hits": []
        },
        "aggregations": {}
    }
    
    # Mock cluster health
    mock_client.cluster.health.return_value = {
        "cluster_name": "test-cluster",
        "status": "green",
        "number_of_nodes": 1,
        "active_shards": 5
    }
    
    return mock_client


@pytest.fixture
async def real_elasticsearch_server(elasticsearch_with_data, monkeypatch):
    """
    MCP server with real Elasticsearch connection for integration tests.
    
    This fixture creates a real server connected to a test Elasticsearch instance
    with realistic data. Use this for integration tests.
    """
    # Get the connection URL from the container
    es_config = ElasticsearchConfig(
        hosts=elasticsearch_with_data._transport.hosts[0],
        default_index=TEST_INDEX_NAME,
        timeout=30,
    )
    
    # Patch the config to use test settings
    monkeypatch.setattr("syslog_mcp.services.elasticsearch_client.ElasticsearchConfig", lambda: es_config)
    
    return create_server()


@pytest.fixture
async def mock_elasticsearch_server(mock_elasticsearch_client, monkeypatch):
    """
    MCP server with mocked Elasticsearch for fast unit tests.
    
    This fixture uses the minimal mock client for tests that focus on
    business logic and tool behavior rather than ES integration.
    """
    # Mock the ElasticsearchClient class entirely
    class MockElasticsearchClient:
        def __init__(self):
            self.mock_client = mock_elasticsearch_client
        
        async def connect(self):
            return None
        
        async def disconnect(self):
            return None
        
        def is_connected(self):
            return True
        
        async def search(self, **kwargs):
            # Return the mock response
            return self.mock_client.search.return_value
        
        @property
        def cluster(self):
            return self.mock_client.cluster
    
    monkeypatch.setattr(
        "syslog_mcp.services.elasticsearch_client.ElasticsearchClient",
        MockElasticsearchClient
    )
    
    return create_server()


@pytest.fixture
async def fastmcp_client_real(real_elasticsearch_server):
    """
    FastMCP client connected to server with real Elasticsearch (integration tests).
    
    This fixture follows FastMCP's in-memory testing pattern by passing
    the server instance directly to the client for zero-overhead testing.
    """
    async with Client(real_elasticsearch_server) as client:
        yield client


@pytest.fixture
async def fastmcp_client_mock(mock_elasticsearch_server):
    """
    FastMCP client connected to server with mocked Elasticsearch (unit tests).
    
    This fixture provides fast testing for business logic without the
    overhead of real Elasticsearch operations.
    """
    async with Client(mock_elasticsearch_server) as client:
        yield client


@pytest.fixture
def sample_log_data() -> List[Dict[str, Any]]:
    """Generate sample log data for tests."""
    return create_elasticsearch_bulk_data(50)


@pytest.fixture
def security_scenario_data() -> List[Dict[str, Any]]:
    """Generate a security scenario with attack patterns."""
    return create_security_scenario()


@pytest.fixture
def device_health_scenario_data() -> List[Dict[str, Any]]:
    """Generate device health degradation scenario."""
    return create_device_health_scenario()


# Pytest configuration for different test types
def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line("markers", "unit: Fast unit tests with minimal dependencies")
    config.addinivalue_line("markers", "integration: Integration tests requiring Elasticsearch")
    config.addinivalue_line("markers", "slow: Slow-running tests")
    config.addinivalue_line("markers", "elasticsearch: Tests requiring Elasticsearch connection")
    config.addinivalue_line("markers", "performance: Performance benchmarking tests")
    config.addinivalue_line("markers", "error_handling: Error scenario tests")
    config.addinivalue_line("markers", "security: Security-focused tests")


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their location and dependencies."""
    for item in items:
        # Mark integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
            item.add_marker(pytest.mark.elasticsearch)
        
        # Mark unit tests
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        
        # Mark tests using real elasticsearch fixtures as slow
        if any(fixture in item.fixturenames for fixture in [
            "elasticsearch_container", "elasticsearch_client", 
            "elasticsearch_with_data", "real_elasticsearch_server"
        ]):
            item.add_marker(pytest.mark.slow)
            item.add_marker(pytest.mark.elasticsearch)


@pytest.fixture(autouse=True)
def skip_integration_tests_if_no_docker():
    """Skip integration tests if Docker is not available."""
    if "SKIP_INTEGRATION_TESTS" in os.environ:
        pytest.skip("Integration tests disabled")


# Performance testing utilities
@pytest.fixture
def benchmark_settings():
    """Configuration for performance benchmarks."""
    return {
        "min_rounds": 5,
        "max_time": 30.0,
        "warmup": True,
        "warmup_iterations": 2,
    }