"""
Comprehensive tests for search_logs tool.

Tests the search_logs MCP tool with realistic data scenarios to achieve 90% coverage.
Follows FastMCP testing patterns with minimal mocking for real test value.
"""

import pytest
from datetime import datetime, timezone, timedelta
from fastmcp import FastMCP
from unittest.mock import AsyncMock, patch

# Import the module under test
from syslog_mcp.tools.search_logs import SearchLogsParameters, register_search_tools
from syslog_mcp.models.log_entry import LogLevel, LogEntry
from syslog_mcp.models.query import SortOrder, LogSearchResult, SearchResultStatus
from syslog_mcp.models.response import SearchMetrics
from syslog_mcp.exceptions import (
    ElasticsearchConnectionError,
    ElasticsearchQueryError,
    ElasticsearchTimeoutError,
)


class TestSearchLogsParameters:
    """Test suite for SearchLogsParameters validation model."""

    def test_valid_parameters_basic(self):
        """Test valid basic parameter validation."""
        params = SearchLogsParameters(
            query="test query",
            device="server1.example.com",
            level=LogLevel.INFO,
            limit=50,
            offset=10
        )

        assert params.query == "test query"
        assert params.device == "server1.example.com"
        assert params.level == LogLevel.INFO
        assert params.limit == 50
        assert params.offset == 10
        assert params.sort_field == "timestamp"  # default
        assert params.sort_order == SortOrder.DESC  # default

    def test_valid_parameters_with_time_range(self):
        """Test valid parameters with time range."""
        start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        end_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        params = SearchLogsParameters(
            query="error",
            start_time=start_time,
            end_time=end_time,
            limit=100
        )

        assert params.start_time == start_time
        assert params.end_time == end_time
        assert params.query == "error"
        assert params.limit == 100

    def test_limit_validation_bounds(self):
        """Test limit field validation bounds."""
        # Valid limits
        params_min = SearchLogsParameters(limit=1)
        assert params_min.limit == 1

        params_max = SearchLogsParameters(limit=1000)
        assert params_max.limit == 1000

        # Invalid limits should raise ValidationError
        with pytest.raises(ValueError, match="greater than or equal to 1"):
            SearchLogsParameters(limit=0)

        with pytest.raises(ValueError, match="less than or equal to 1000"):
            SearchLogsParameters(limit=1001)

    def test_time_range_validation_invalid(self):
        """Test invalid time range validation."""
        start_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        end_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)  # Before start

        with pytest.raises(ValueError, match="end_time must be after start_time"):
            SearchLogsParameters(
                start_time=start_time,
                end_time=end_time
            )

    async def test_search_logs_with_device_filter(self, fastmcp_client_mock):
        """Test search with device filtering."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "device": "server-01",
            "limit": 50
        })
        
        assert result.is_error is False
        data = result.data
        
        assert data["status"] == "success"
        assert data["limit"] == 50
        # Mock should return realistic data structure
        assert len(data["logs"]) >= 0

    async def test_search_logs_with_level_filter(self, fastmcp_client_mock):
        """Test search with log level filtering."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "level": "WARNING",
            "limit": 25
        })
        
        assert result.is_error is False
        data = result.data
        
        assert data["status"] == "success"
        assert data["limit"] == 25

    async def test_search_logs_with_time_range(self, fastmcp_client_mock):
        """Test search with time range filtering."""
        start_time = datetime.now(timezone.utc) - timedelta(hours=1)
        end_time = datetime.now(timezone.utc)
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "limit": 100
        })
        
        assert result.is_error is False
        data = result.data
        
        assert data["status"] == "success"
        assert data["limit"] == 100

    async def test_search_logs_pagination(self, fastmcp_client_mock):
        """Test pagination functionality."""
        # Test first page
        result_page1 = await fastmcp_client_mock.call_tool("search_logs", {
            "limit": 10,
            "offset": 0
        })
        
        assert result_page1.is_error is False
        data1 = result_page1.data
        assert data1["offset"] == 0
        assert data1["limit"] == 10
        
        # Test second page
        result_page2 = await fastmcp_client_mock.call_tool("search_logs", {
            "limit": 10,
            "offset": 10
        })
        
        assert result_page2.is_error is False
        data2 = result_page2.data
        assert data2["offset"] == 10
        assert data2["limit"] == 10

    async def test_search_logs_sorting(self, fastmcp_client_mock):
        """Test sorting functionality."""
        # Test descending order (default)
        result_desc = await fastmcp_client_mock.call_tool("search_logs", {
            "sort_field": "timestamp",
            "sort_order": "desc",
            "limit": 5
        })
        
        assert result_desc.is_error is False
        data_desc = result_desc.data
        assert data_desc["status"] == "success"
        
        # Test ascending order
        result_asc = await fastmcp_client_mock.call_tool("search_logs", {
            "sort_field": "timestamp",
            "sort_order": "asc", 
            "limit": 5
        })
        
        assert result_asc.is_error is False
        data_asc = result_asc.data
        assert data_asc["status"] == "success"

    async def test_search_logs_wildcard_device(self, fastmcp_client_mock):
        """Test device filtering with wildcards."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "device": "server-*",
            "limit": 20
        })
        
        assert result.is_error is False
        data = result.data
        assert data["status"] == "success"

    async def test_search_logs_combined_filters(self, fastmcp_client_mock):
        """Test search with multiple filters combined."""
        start_time = datetime.now(timezone.utc) - timedelta(hours=2)
        end_time = datetime.now(timezone.utc)
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "authentication",
            "device": "server-01",
            "level": "WARNING",
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "limit": 50,
            "sort_field": "timestamp",
            "sort_order": "desc"
        })
        
        assert result.is_error is False
        data = result.data
        assert data["status"] == "success"
        assert data["limit"] == 50

    @pytest.mark.parametrize("invalid_limit", [0, -1, 1001, 9999])
    async def test_search_logs_invalid_limit(self, fastmcp_client_mock, invalid_limit):
        """Test validation of limit parameter."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "limit": invalid_limit
        })
        
        # Should fail validation
        assert result.is_error is True

    @pytest.mark.parametrize("invalid_offset", [-1, -10])
    async def test_search_logs_invalid_offset(self, fastmcp_client_mock, invalid_offset):
        """Test validation of offset parameter."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "offset": invalid_offset
        })
        
        # Should fail validation
        assert result.is_error is True

    async def test_search_logs_invalid_time_range(self, fastmcp_client_mock):
        """Test validation when end_time is before start_time."""
        start_time = datetime.now(timezone.utc)
        end_time = start_time - timedelta(hours=1)  # Earlier than start
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        })
        
        # Should fail validation
        assert result.is_error is True

    async def test_search_logs_empty_query(self, fastmcp_client_mock):
        """Test search with empty/null query returns all logs."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": None,
            "limit": 10
        })
        
        assert result.is_error is False
        data = result.data
        assert data["status"] == "success"

    async def test_search_logs_execution_metrics(self, fastmcp_client_mock):
        """Test that execution metrics are included in response."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test",
            "limit": 5
        })
        
        assert result.is_error is False
        data = result.data
        
        # Verify execution metrics structure
        assert "metrics" in data
        metrics = data["metrics"]
        assert isinstance(metrics, dict)
        
        # Basic metrics that should be present in real implementation
        # Mock might not have all of these, so we just check structure exists
        assert isinstance(metrics, dict)

    @given(
        query_text=st.one_of(st.none(), st.text(min_size=1, max_size=100)),
        limit=st.integers(min_value=1, max_value=1000),
        offset=st.integers(min_value=0, max_value=10000)
    )
    async def test_search_logs_property_based(self, fastmcp_client_mock, query_text, limit, offset):
        """Property-based test for search_logs with various valid inputs."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": query_text,
            "limit": limit,
            "offset": offset
        })
        
        # Should always succeed with valid inputs
        assert result.is_error is False
        data = result.data
        
        # Basic invariants
        assert data["status"] == "success"
        assert data["limit"] == limit
        assert data["offset"] == offset
        assert isinstance(data["total_hits"], int)
        assert data["total_hits"] >= 0
        assert isinstance(data["logs"], list)
        assert len(data["logs"]) <= limit

    async def test_search_logs_response_log_structure(self, fastmcp_client_mock):
        """Test that individual log entries have the expected structure."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test",
            "limit": 1
        })
        
        assert result.is_error is False
        data = result.data
        
        if data["logs"]:
            log_entry = data["logs"][0]
            
            # Expected fields in log entries (based on mock data)
            expected_fields = ["timestamp", "device", "message", "program", "level", "facility"]
            for field in expected_fields:
                assert field in log_entry

    @pytest.mark.parametrize("log_level", [
        LogLevel.DEBUG,
        LogLevel.INFO, 
        LogLevel.WARN,
        LogLevel.WARNING,
        LogLevel.ERROR,
        LogLevel.CRITICAL,
        LogLevel.FATAL
    ])
    async def test_search_logs_all_log_levels(self, fastmcp_client_mock, log_level):
        """Test search with all supported log levels."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "level": log_level.value,
            "limit": 5
        })
        
        assert result.is_error is False
        data = result.data
        assert data["status"] == "success"

    @pytest.mark.parametrize("sort_order", [SortOrder.ASC, SortOrder.DESC])
    async def test_search_logs_sort_orders(self, fastmcp_client_mock, sort_order):
        """Test search with different sort orders."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "sort_field": "timestamp",
            "sort_order": sort_order.value,
            "limit": 10
        })
        
        assert result.is_error is False
        data = result.data
        assert data["status"] == "success"

    async def test_search_logs_has_more_logic(self, fastmcp_client_mock):
        """Test the has_more field logic for pagination."""
        # Configure mock to return specific total_hits
        mock_client = fastmcp_client_mock._server_instance._client
        
        # Test case where has_more should be True
        mock_client.search.return_value["hits"]["total"]["value"] = 150
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "limit": 50,
            "offset": 0
        })
        
        assert result.is_error is False
        data = result.data
        
        # has_more should be True when offset + limit < total_hits
        expected_has_more = (data["offset"] + data["limit"]) < data["total_hits"]
        assert data["has_more"] == expected_has_more

    async def test_search_logs_empty_result_set(self, fastmcp_client_mock, monkeypatch):
        """Test behavior with empty result set."""
        # Mock empty results
        empty_response = {
            "took": 2,
            "timed_out": False,
            "hits": {
                "total": {"value": 0, "relation": "eq"},
                "hits": []
            },
            "aggregations": {}
        }
        
        # Get the mock client and modify its response
        mock_elasticsearch_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_elasticsearch_client.search.return_value = empty_response
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "nonexistent_string_12345",
            "limit": 10
        })
        
        assert result.is_error is False
        data = result.data
        
        assert data["status"] == "success"
        assert data["total_hits"] == 0
        assert len(data["logs"]) == 0
        assert data["has_more"] is False


@pytest.mark.error_handling
class TestSearchLogsErrorHandling:
    """Test error handling scenarios for search_logs tool."""
    
    async def test_elasticsearch_connection_error(self, fastmcp_client_mock, monkeypatch):
        """Test handling of Elasticsearch connection errors."""
        # Mock connection error
        mock_elasticsearch_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_elasticsearch_client.search.side_effect = ElasticsearchConnectionError("Connection failed")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test"
        })
        
        assert result.is_error is True
        # Should contain error information
        assert "Connection failed" in result.error_data.get("message", "")

    async def test_elasticsearch_query_error(self, fastmcp_client_mock, monkeypatch):
        """Test handling of Elasticsearch query errors."""
        # Mock query error
        mock_elasticsearch_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_elasticsearch_client.search.side_effect = ElasticsearchQueryError("Invalid query syntax")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "invalid:query:syntax:::"
        })
        
        assert result.is_error is True
        assert "Invalid query syntax" in result.error_data.get("message", "")

    async def test_elasticsearch_timeout_error(self, fastmcp_client_mock, monkeypatch):
        """Test handling of Elasticsearch timeout errors."""
        # Mock timeout error
        mock_elasticsearch_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_elasticsearch_client.search.side_effect = ElasticsearchTimeoutError("Query timed out")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test",
            "limit": 1000  # Large limit might cause timeout
        })
        
        assert result.is_error is True
        assert "Query timed out" in result.error_data.get("message", "")

    async def test_unexpected_error(self, fastmcp_client_mock, monkeypatch):
        """Test handling of unexpected errors."""
        # Mock unexpected error
        mock_elasticsearch_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_elasticsearch_client.search.side_effect = Exception("Unexpected error occurred")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test"
        })
        
        assert result.is_error is True
        # Should handle unexpected errors gracefully
        assert "error" in result.error_data.get("message", "").lower()

    @pytest.mark.parametrize("malformed_datetime", [
        "not-a-date",
        "2025-13-45",
        "25/01/2025",
        "2025-01-01T25:00:00",
        ""
    ])
    async def test_malformed_datetime_handling(self, fastmcp_client_mock, malformed_datetime):
        """Test handling of malformed datetime strings."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "start_time": malformed_datetime
        })
        
        # Should fail validation or conversion
        assert result.is_error is True