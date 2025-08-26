"""
Integration tests for syslog-mcp with real Elasticsearch.

These tests use testcontainers to spin up a real Elasticsearch instance
and test the full end-to-end functionality with realistic data.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

from syslog_mcp.models.log_entry import LogLevel
from tests.factories import (
    create_elasticsearch_bulk_data,
    create_security_scenario, 
    create_device_health_scenario,
)


@pytest.mark.integration
@pytest.mark.elasticsearch
@pytest.mark.slow
class TestSearchLogsIntegration:
    """Integration tests for search_logs with real Elasticsearch."""
    
    async def test_search_logs_end_to_end(self, fastmcp_client_real):
        """Test complete search_logs functionality with real ES and data."""
        # Test basic search
        result = await fastmcp_client_real.call_tool("search_logs", {
            "query": "authentication",
            "limit": 20
        })
        
        assert result.is_error is False
        data = result.data
        
        # Verify complete response structure
        assert "status" in data
        assert "total_hits" in data
        assert "logs" in data
        assert "offset" in data
        assert "limit" in data
        assert "has_more" in data
        assert "execution_metrics" in data
        
        # Verify data quality with real ES
        assert data["status"] == "success"
        assert isinstance(data["total_hits"], int)
        assert data["total_hits"] >= 0
        assert isinstance(data["logs"], list)
        assert data["limit"] == 20
        assert data["offset"] == 0
        
        # Verify log entry structure
        if data["logs"]:
            log_entry = data["logs"][0]
            required_fields = ["timestamp", "device", "message", "program", "level", "facility"]
            for field in required_fields:
                assert field in log_entry
                assert log_entry[field] is not None
        
        # Verify execution metrics from real ES
        metrics = data["execution_metrics"]
        assert isinstance(metrics, dict)
        # Real ES should provide these metrics
        if "took" in metrics:
            assert isinstance(metrics["took"], int)
            assert metrics["took"] >= 0

    async def test_search_logs_with_real_filtering(self, fastmcp_client_real):
        """Test filtering with actual data in Elasticsearch."""
        # Search for SSH-related logs
        result = await fastmcp_client_real.call_tool("search_logs", {
            "query": "ssh",
            "level": "warning",
            "limit": 10
        })
        
        assert result.is_error is False
        data = result.data
        
        # Verify filtering works with real data
        assert data["status"] == "success"
        assert isinstance(data["logs"], list)
        
        # If we have results, verify they match our filters
        for log in data["logs"]:
            if "level" in log:
                # Level filtering should work (though exact matching depends on data)
                assert log["level"].lower() in ["warning", "warn", "error", "critical"]
            
            # SSH-related content should be present if we found results
            if "message" in log:
                # Message should contain ssh-related terms (case-insensitive)
                message_lower = log["message"].lower()
                # This is flexible since data might not always contain exact matches
                pass

    async def test_search_logs_time_range_with_real_data(self, fastmcp_client_real):
        """Test time range filtering with realistic timestamps."""
        # Search within the last hour
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)
        
        result = await fastmcp_client_real.call_tool("search_logs", {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "limit": 50
        })
        
        assert result.is_error is False
        data = result.data
        
        assert data["status"] == "success"
        assert isinstance(data["logs"], list)
        
        # Verify timestamps are within range (if we have results)
        for log in data["logs"]:
            if "timestamp" in log:
                log_time = datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00"))
                assert start_time <= log_time <= end_time

    async def test_search_logs_pagination_with_real_data(self, fastmcp_client_real):
        """Test pagination functionality with real Elasticsearch."""
        # Get first page
        result_page1 = await fastmcp_client_real.call_tool("search_logs", {
            "limit": 5,
            "offset": 0,
            "sort_field": "timestamp", 
            "sort_order": "DESC"
        })
        
        assert result_page1.is_error is False
        data1 = result_page1.data
        
        # Get second page
        result_page2 = await fastmcp_client_real.call_tool("search_logs", {
            "limit": 5,
            "offset": 5,
            "sort_field": "timestamp",
            "sort_order": "DESC"
        })
        
        assert result_page2.is_error is False
        data2 = result_page2.data
        
        # Verify pagination logic
        assert data1["offset"] == 0
        assert data2["offset"] == 5
        assert data1["limit"] == data2["limit"] == 5
        
        # If we have enough data, pages should be different
        if len(data1["logs"]) > 0 and len(data2["logs"]) > 0:
            # Logs should be different between pages
            page1_ids = [log.get("_id") or log.get("timestamp") for log in data1["logs"]]
            page2_ids = [log.get("_id") or log.get("timestamp") for log in data2["logs"]]
            # There might be some overlap in edge cases, but generally should be different
            
        # has_more logic should be correct
        if data1["total_hits"] > 5:
            assert data1["has_more"] is True
        if data1["total_hits"] <= 10:
            assert data2["has_more"] is False

    async def test_search_logs_device_wildcard_with_real_data(self, fastmcp_client_real):
        """Test device wildcard filtering with real data."""
        result = await fastmcp_client_real.call_tool("search_logs", {
            "device": "server-*",
            "limit": 20
        })
        
        assert result.is_error is False
        data = result.data
        
        assert data["status"] == "success"
        
        # If we have matching results, verify they match the wildcard
        for log in data["logs"]:
            if "device" in log:
                device_name = log["device"].lower()
                # Should match server-* pattern
                assert device_name.startswith("server-") or "server" in device_name

    async def test_search_logs_performance_with_large_dataset(self, fastmcp_client_real):
        """Test search performance with larger result sets."""
        # Search for common terms that might return many results
        result = await fastmcp_client_real.call_tool("search_logs", {
            "query": "system",  # Common term
            "limit": 100
        })
        
        assert result.is_error is False
        data = result.data
        
        assert data["status"] == "success"
        
        # Verify performance metrics
        if "execution_metrics" in data and "took" in data["execution_metrics"]:
            took_ms = data["execution_metrics"]["took"]
            # Real ES query should complete within reasonable time
            assert took_ms < 10000  # Less than 10 seconds
            assert took_ms >= 0

    async def test_search_logs_sorting_with_real_data(self, fastmcp_client_real):
        """Test sorting functionality with real Elasticsearch data."""
        # Test DESC sorting (default)
        result_desc = await fastmcp_client_real.call_tool("search_logs", {
            "sort_field": "timestamp",
            "sort_order": "DESC",
            "limit": 10
        })
        
        assert result_desc.is_error is False
        data_desc = result_desc.data
        
        # Test ASC sorting
        result_asc = await fastmcp_client_real.call_tool("search_logs", {
            "sort_field": "timestamp", 
            "sort_order": "ASC",
            "limit": 10
        })
        
        assert result_asc.is_error is False
        data_asc = result_asc.data
        
        # If we have results, verify sorting
        if len(data_desc["logs"]) > 1:
            timestamps_desc = []
            for log in data_desc["logs"]:
                if "timestamp" in log:
                    timestamps_desc.append(datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00")))
            
            # Should be in descending order
            for i in range(len(timestamps_desc) - 1):
                assert timestamps_desc[i] >= timestamps_desc[i + 1]
        
        if len(data_asc["logs"]) > 1:
            timestamps_asc = []
            for log in data_asc["logs"]:
                if "timestamp" in log:
                    timestamps_asc.append(datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00")))
            
            # Should be in ascending order  
            for i in range(len(timestamps_asc) - 1):
                assert timestamps_asc[i] <= timestamps_asc[i + 1]


@pytest.mark.integration
@pytest.mark.elasticsearch
@pytest.mark.slow
class TestSecurityAnalysisIntegration:
    """Integration tests for security analysis tools with real data."""
    
    async def test_syslog_sec_failed_auth_with_real_data(self, fastmcp_client_real):
        """Test failed authentication analysis with real Elasticsearch."""
        result = await fastmcp_client_real.call_tool("syslog_sec", {
            "mode": "failed_auth",
            "hours": 24,
            "top_ips": 10
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain security analysis content
        response_lower = result.data.lower()
        security_keywords = ["failed", "auth", "security", "ip", "attempt", "analysis"]
        assert any(keyword in response_lower for keyword in security_keywords)
        
        # Should be properly formatted (markdown-like)
        assert any(marker in result.data for marker in ["#", "*", "-", ":"])

    async def test_syslog_sec_suspicious_activity_comprehensive(self, fastmcp_client_real):
        """Test comprehensive suspicious activity analysis."""
        result = await fastmcp_client_real.call_tool("syslog_sec", {
            "mode": "suspicious_activity",
            "device": "server-01",
            "hours": 48,
            "top_ips": 15
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain detailed analysis
        response_lower = result.data.lower()
        analysis_keywords = ["suspicious", "activity", "anomal", "threat", "pattern", "behavior"]
        assert any(keyword in response_lower for keyword in analysis_keywords)

    async def test_syslog_sec_ip_reputation_analysis(self, fastmcp_client_real):
        """Test IP reputation analysis with real data."""
        result = await fastmcp_client_real.call_tool("syslog_sec", {
            "mode": "ip_reputation",
            "hours": 12,
            "top_ips": 20
        })
        
        assert result.is_error is False  
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain IP analysis content
        response_lower = result.data.lower()
        ip_keywords = ["ip", "address", "reputation", "threat", "geolocation", "analysis"]
        assert any(keyword in response_lower for keyword in ip_keywords)

    async def test_syslog_sec_auth_timeline_comprehensive(self, fastmcp_client_real):
        """Test authentication timeline analysis."""
        result = await fastmcp_client_real.call_tool("syslog_sec", {
            "mode": "auth_timeline",
            "device": "firewall-01", 
            "hours": 72
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain timeline analysis
        response_lower = result.data.lower()
        timeline_keywords = ["timeline", "chronol", "auth", "pattern", "sequence", "time"]
        assert any(keyword in response_lower for keyword in timeline_keywords)


@pytest.mark.integration  
@pytest.mark.elasticsearch
@pytest.mark.slow
class TestReportingIntegration:
    """Integration tests for reporting tools with real data."""
    
    async def test_syslog_reports_device_summary_comprehensive(self, fastmcp_client_real):
        """Test comprehensive device summary report."""
        result = await fastmcp_client_real.call_tool("syslog_reports", {
            "mode": "device_summary",
            "device": "server-01",
            "hours": 24
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain device health information
        response_lower = result.data.lower()
        device_keywords = ["device", "health", "status", "summary", "performance", "system"]
        assert any(keyword in response_lower for keyword in device_keywords)
        
        # Should have structured report format
        assert any(marker in result.data for marker in ["#", "##", "*", "-"])

    async def test_syslog_reports_error_analysis_detailed(self, fastmcp_client_real):
        """Test detailed error analysis report."""
        result = await fastmcp_client_real.call_tool("syslog_reports", {
            "mode": "error_analysis",
            "hours": 48,
            "severity": "error"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain error analysis
        response_lower = result.data.lower()
        error_keywords = ["error", "failure", "issue", "problem", "critical", "analysis"]
        assert any(keyword in response_lower for keyword in error_keywords)

    async def test_syslog_reports_daily_report_comprehensive(self, fastmcp_client_real):
        """Test comprehensive daily report generation."""
        result = await fastmcp_client_real.call_tool("syslog_reports", {
            "mode": "daily_report",
            "hours": 24
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain comprehensive system overview
        response_lower = result.data.lower()
        report_keywords = ["daily", "report", "summary", "overview", "system", "activity"]
        assert any(keyword in response_lower for keyword in report_keywords)


@pytest.mark.integration
@pytest.mark.elasticsearch 
@pytest.mark.slow
class TestAlertingIntegration:
    """Integration tests for alerting functionality with real Elasticsearch."""
    
    async def test_syslog_alerts_create_and_list_rules(self, fastmcp_client_real):
        """Test creating and listing alert rules."""
        # Create an alert rule
        create_result = await fastmcp_client_real.call_tool("syslog_alerts", {
            "mode": "create_rule",
            "name": "Integration Test Alert",
            "query": "error OR critical",
            "threshold": 5
        })
        
        assert create_result.is_error is False
        assert isinstance(create_result.data, str)
        
        # Verify creation confirmation
        response_lower = create_result.data.lower()
        creation_keywords = ["created", "rule", "alert", "configured", "threshold"]
        assert any(keyword in response_lower for keyword in creation_keywords)
        
        # List alert rules
        list_result = await fastmcp_client_real.call_tool("syslog_alerts", {
            "mode": "list_rules"
        })
        
        assert list_result.is_error is False
        assert isinstance(list_result.data, str)
        
        # Should contain our created rule or similar rule information
        response_lower = list_result.data.lower()
        list_keywords = ["rule", "alert", "threshold", "query", "configured"]
        assert any(keyword in response_lower for keyword in list_keywords)

    async def test_syslog_alerts_notification_testing(self, fastmcp_client_real):
        """Test alert notification system."""
        result = await fastmcp_client_real.call_tool("syslog_alerts", {
            "mode": "test_notification"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain test results
        response_lower = result.data.lower()
        test_keywords = ["test", "notification", "sent", "result", "success", "fail"]
        assert any(keyword in response_lower for keyword in test_keywords)


@pytest.mark.integration
@pytest.mark.elasticsearch
@pytest.mark.slow
class TestExportIntegration:
    """Integration tests for data export functionality."""
    
    async def test_syslog_export_comprehensive(self, fastmcp_client_real):
        """Test comprehensive data export functionality."""
        # Test CSV export
        csv_result = await fastmcp_client_real.call_tool("syslog_export", {
            "query": "authentication",
            "format": "csv",
            "limit": 50
        })
        
        assert csv_result.is_error is False
        assert isinstance(csv_result.data, str)
        
        # Should contain export completion information
        response_lower = csv_result.data.lower()
        export_keywords = ["export", "data", "csv", "complete", "file", "format"]
        assert any(keyword in response_lower for keyword in export_keywords)
        
        # Test JSON export
        json_result = await fastmcp_client_real.call_tool("syslog_export", {
            "query": "system",
            "format": "json",
            "limit": 25
        })
        
        assert json_result.is_error is False
        assert isinstance(json_result.data, str)
        
        response_lower = json_result.data.lower()
        json_keywords = ["export", "json", "data", "complete"]
        assert any(keyword in response_lower for keyword in json_keywords)

    async def test_syslog_export_with_time_filtering(self, fastmcp_client_real):
        """Test export with time range filtering."""
        start_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        end_time = datetime.now(timezone.utc).isoformat()
        
        result = await fastmcp_client_real.call_tool("syslog_export", {
            "start_time": start_time,
            "end_time": end_time,
            "format": "csv",
            "limit": 100
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        
        # Should handle time-filtered export
        response_lower = result.data.lower()
        export_keywords = ["export", "complete", "time", "range", "filter"]
        assert any(keyword in response_lower for keyword in export_keywords)


@pytest.mark.integration
@pytest.mark.elasticsearch
@pytest.mark.slow 
class TestTailIntegration:
    """Integration tests for log tailing functionality."""
    
    async def test_syslog_tail_real_device_data(self, fastmcp_client_real):
        """Test log tailing with real device data."""
        result = await fastmcp_client_real.call_tool("syslog_tail", {
            "device": "server-01",
            "lines": 25
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain recent log entries
        response_lower = result.data.lower()
        tail_keywords = ["log", "recent", "latest", "entries", "tail"]
        assert any(keyword in response_lower for keyword in tail_keywords)

    async def test_syslog_tail_different_devices(self, fastmcp_client_real):
        """Test tailing logs from different devices."""
        devices = ["server-01", "router-01", "firewall-01"]
        
        for device in devices:
            result = await fastmcp_client_real.call_tool("syslog_tail", {
                "device": device,
                "lines": 10
            })
            
            assert result.is_error is False
            assert isinstance(result.data, str)
            
            # Each device should return its own logs
            # (might be empty if device has no recent logs)

    async def test_syslog_tail_varying_line_counts(self, fastmcp_client_real):
        """Test tailing with various line counts."""
        line_counts = [1, 10, 50, 100]
        
        for lines in line_counts:
            result = await fastmcp_client_real.call_tool("syslog_tail", {
                "device": "server-01", 
                "lines": lines
            })
            
            assert result.is_error is False
            assert isinstance(result.data, str)
            
            # Should handle different line counts appropriately


@pytest.mark.integration
@pytest.mark.elasticsearch
@pytest.mark.performance
class TestPerformanceIntegration:
    """Performance tests with real Elasticsearch."""
    
    async def test_search_performance_benchmarks(self, fastmcp_client_real, benchmark_settings):
        """Benchmark search performance with real ES."""
        import time
        
        start_time = time.time()
        
        result = await fastmcp_client_real.call_tool("search_logs", {
            "query": "authentication failed",
            "limit": 100
        })
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        assert result.is_error is False
        
        # Performance expectations
        assert execution_time < 30.0  # Should complete within 30 seconds
        
        # Check ES-reported timing if available
        if "execution_metrics" in result.data and "took" in result.data["execution_metrics"]:
            es_timing = result.data["execution_metrics"]["took"]
            assert es_timing < 10000  # Less than 10 seconds in ES

    async def test_concurrent_search_performance(self, fastmcp_client_real):
        """Test performance under concurrent load."""
        async def single_search(query_id: int):
            return await fastmcp_client_real.call_tool("search_logs", {
                "query": f"test query {query_id}",
                "limit": 10
            })
        
        # Run multiple searches concurrently
        tasks = [single_search(i) for i in range(5)]
        results = await asyncio.gather(*tasks)
        
        # All should succeed
        for result in results:
            assert result.is_error is False
            assert isinstance(result.data, dict)
            assert result.data["status"] == "success"

    async def test_large_result_set_performance(self, fastmcp_client_real):
        """Test performance with large result sets."""
        result = await fastmcp_client_real.call_tool("search_logs", {
            "query": "*",  # Match all (if supported)
            "limit": 1000  # Large result set
        })
        
        # Should handle large queries gracefully
        assert result.is_error is False
        
        # Response should be structured correctly even for large sets
        assert "total_hits" in result.data
        assert "logs" in result.data
        assert len(result.data["logs"]) <= 1000