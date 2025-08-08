"""
Pytest configuration and shared fixtures.

This module contains pytest configuration and fixtures that are shared
across multiple test modules.
"""

from unittest.mock import AsyncMock

import pytest


@pytest.fixture
def mcp_server():
    """Create a test FastMCP server."""
    from syslog_mcp.server import create_server

    return create_server()


@pytest.fixture
def mock_elasticsearch():
    """Mock Elasticsearch client for testing."""
    return AsyncMock()


# Additional fixtures will be added as needed
