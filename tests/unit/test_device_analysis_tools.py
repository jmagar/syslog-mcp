"""
Unit tests for device analysis MCP tools.

These tests use FastMCP's in-memory testing pattern to test the device analysis
tools including security analysis, reporting, alerts, search, export, and tail.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock

from hypothesis import given, strategies as st


@pytest.mark.unit
class TestSyslogSecTool:
    """Unit tests for the syslog_sec security analysis tool."""
    
    async def test_syslog_sec_failed_auth_mode(self, fastmcp_client_mock):
        """Test syslog_sec with failed_auth mode."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "failed_auth",
            "device": "server-01",
            "hours": 24,
            "top_ips": 10
        })
        
        assert result.is_error is False
        # Response should be a formatted string (markdown report)
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain security analysis keywords
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "failed", "auth", "security", "analysis", "ip", "attempt"
        ])

    async def test_syslog_sec_suspicious_activity_mode(self, fastmcp_client_mock):
        """Test syslog_sec with suspicious_activity mode."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "suspicious_activity",
            "hours": 12,
            "top_ips": 5
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain suspicious activity analysis
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "suspicious", "activity", "anomal", "threat", "security"
        ])

    async def test_syslog_sec_ip_reputation_mode(self, fastmcp_client_mock):
        """Test syslog_sec with ip_reputation mode."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "ip_reputation",
            "hours": 6,
            "top_ips": 15
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain IP reputation analysis
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "ip", "reputation", "threat", "analysis", "address"
        ])

    async def test_syslog_sec_auth_timeline_mode(self, fastmcp_client_mock):
        """Test syslog_sec with auth_timeline mode.""" 
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "auth_timeline",
            "device": "router-01",
            "hours": 48
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain timeline analysis
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "timeline", "auth", "authentication", "chronol", "time"
        ])

    @pytest.mark.parametrize("hours", [1, 6, 12, 24, 48, 72, 168])
    async def test_syslog_sec_different_time_ranges(self, fastmcp_client_mock, hours):
        """Test syslog_sec with different time ranges."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "failed_auth",
            "hours": hours
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)

    @pytest.mark.parametrize("top_ips", [1, 5, 10, 20, 50])
    async def test_syslog_sec_different_top_ip_counts(self, fastmcp_client_mock, top_ips):
        """Test syslog_sec with different top IP counts."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "ip_reputation",
            "top_ips": top_ips
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)

    async def test_syslog_sec_invalid_mode(self, fastmcp_client_mock):
        """Test syslog_sec with invalid mode."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "invalid_mode_xyz"
        })
        
        # Should either fail validation or return error message
        # Exact behavior depends on implementation
        if not result.is_error:
            # If it doesn't fail, should contain error info in response
            assert "error" in result.data.lower() or "invalid" in result.data.lower()
        else:
            assert result.is_error is True

    async def test_syslog_sec_with_device_filter(self, fastmcp_client_mock):
        """Test syslog_sec with specific device filtering."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "failed_auth",
            "device": "firewall-01",
            "hours": 24
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        # Analysis should be scoped to the specific device
        assert len(result.data) > 0

    async def test_syslog_sec_without_device_filter(self, fastmcp_client_mock):
        """Test syslog_sec without device filtering (all devices)."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "suspicious_activity",
            "hours": 12
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        # Should analyze all devices
        assert len(result.data) > 0


@pytest.mark.unit  
class TestSyslogReportsTool:
    """Unit tests for the syslog_reports reporting tool."""
    
    async def test_syslog_reports_device_summary_mode(self, fastmcp_client_mock):
        """Test syslog_reports with device_summary mode."""
        result = await fastmcp_client_mock.call_tool("syslog_reports", {
            "mode": "device_summary",
            "device": "server-01", 
            "hours": 24
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain device summary information
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "device", "summary", "health", "status", "report"
        ])

    async def test_syslog_reports_error_analysis_mode(self, fastmcp_client_mock):
        """Test syslog_reports with error_analysis mode."""
        result = await fastmcp_client_mock.call_tool("syslog_reports", {
            "mode": "error_analysis",
            "hours": 12,
            "severity": "error"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain error analysis
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "error", "analysis", "issue", "problem", "failure"
        ])

    async def test_syslog_reports_daily_report_mode(self, fastmcp_client_mock):
        """Test syslog_reports with daily_report mode."""
        result = await fastmcp_client_mock.call_tool("syslog_reports", {
            "mode": "daily_report",
            "hours": 24
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain daily report content
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "daily", "report", "summary", "overview", "system"
        ])

    @pytest.mark.parametrize("severity", ["debug", "info", "notice", "warning", "error", "critical"])
    async def test_syslog_reports_different_severities(self, fastmcp_client_mock, severity):
        """Test syslog_reports with different severity filters."""
        result = await fastmcp_client_mock.call_tool("syslog_reports", {
            "mode": "error_analysis",
            "severity": severity,
            "hours": 24
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)

    async def test_syslog_reports_without_severity(self, fastmcp_client_mock):
        """Test syslog_reports without severity filter."""
        result = await fastmcp_client_mock.call_tool("syslog_reports", {
            "mode": "device_summary",
            "device": "server-01"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)


@pytest.mark.unit
class TestSyslogAlertsTool:
    """Unit tests for the syslog_alerts tool."""
    
    async def test_syslog_alerts_create_rule_mode(self, fastmcp_client_mock):
        """Test syslog_alerts with create_rule mode."""
        result = await fastmcp_client_mock.call_tool("syslog_alerts", {
            "mode": "create_rule",
            "name": "High CPU Alert",
            "query": "CPU usage > 90%", 
            "threshold": 5
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain alert rule creation confirmation
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "alert", "rule", "created", "threshold", "configured"
        ])

    async def test_syslog_alerts_list_rules_mode(self, fastmcp_client_mock):
        """Test syslog_alerts with list_rules mode."""
        result = await fastmcp_client_mock.call_tool("syslog_alerts", {
            "mode": "list_rules"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should list configured alert rules
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "rules", "alert", "configured", "list", "threshold"
        ])

    async def test_syslog_alerts_test_notification_mode(self, fastmcp_client_mock):
        """Test syslog_alerts with test_notification mode."""
        result = await fastmcp_client_mock.call_tool("syslog_alerts", {
            "mode": "test_notification"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain test notification results
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "test", "notification", "sent", "success", "alert"
        ])

    @pytest.mark.parametrize("threshold", [1, 5, 10, 50, 100])
    async def test_syslog_alerts_different_thresholds(self, fastmcp_client_mock, threshold):
        """Test syslog_alerts with different threshold values."""
        result = await fastmcp_client_mock.call_tool("syslog_alerts", {
            "mode": "create_rule",
            "name": f"Test Alert {threshold}",
            "query": "test query",
            "threshold": threshold
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)

    async def test_syslog_alerts_invalid_mode(self, fastmcp_client_mock):
        """Test syslog_alerts with invalid mode."""
        result = await fastmcp_client_mock.call_tool("syslog_alerts", {
            "mode": "invalid_alert_mode"
        })
        
        # Should handle invalid mode gracefully
        if not result.is_error:
            assert "error" in result.data.lower() or "invalid" in result.data.lower()
        else:
            assert result.is_error is True


@pytest.mark.unit
class TestSyslogSearchTool:
    """Unit tests for the syslog_search tool."""
    
    async def test_syslog_search_basic(self, fastmcp_client_mock):
        """Test basic syslog_search functionality."""
        result = await fastmcp_client_mock.call_tool("syslog_search", {
            "query": "authentication failed",
            "device": "server-01"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0

    async def test_syslog_search_with_mode(self, fastmcp_client_mock):
        """Test syslog_search with specific mode."""
        result = await fastmcp_client_mock.call_tool("syslog_search", {
            "query": "error",
            "mode": "correlation",
            "level": "error"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)

    async def test_syslog_search_time_range(self, fastmcp_client_mock):
        """Test syslog_search with time range."""
        start_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        end_time = datetime.now(timezone.utc).isoformat()
        
        result = await fastmcp_client_mock.call_tool("syslog_search", {
            "query": "test query",
            "start_time": start_time,
            "end_time": end_time,
            "limit": 50
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)

    @pytest.mark.parametrize("level", ["debug", "info", "warning", "error", "critical"])
    async def test_syslog_search_different_levels(self, fastmcp_client_mock, level):
        """Test syslog_search with different log levels."""
        result = await fastmcp_client_mock.call_tool("syslog_search", {
            "query": "test",
            "level": level
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)


@pytest.mark.unit
class TestSyslogExportTool:
    """Unit tests for the syslog_export tool."""
    
    async def test_syslog_export_basic(self, fastmcp_client_mock):
        """Test basic syslog export functionality."""
        result = await fastmcp_client_mock.call_tool("syslog_export", {
            "query": "authentication",
            "device": "server-01",
            "format": "csv"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain export information
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "export", "data", "file", "format", "complete"
        ])

    async def test_syslog_export_json_format(self, fastmcp_client_mock):
        """Test syslog export with JSON format."""
        result = await fastmcp_client_mock.call_tool("syslog_export", {
            "query": "error",
            "format": "json",
            "limit": 100
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)

    async def test_syslog_export_with_time_range(self, fastmcp_client_mock):
        """Test syslog export with time range."""
        start_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        end_time = datetime.now(timezone.utc).isoformat()
        
        result = await fastmcp_client_mock.call_tool("syslog_export", {
            "start_time": start_time,
            "end_time": end_time,
            "format": "csv"
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)

    @pytest.mark.parametrize("export_format", ["csv", "json", "xml"])
    async def test_syslog_export_different_formats(self, fastmcp_client_mock, export_format):
        """Test syslog export with different formats."""
        result = await fastmcp_client_mock.call_tool("syslog_export", {
            "query": "test",
            "format": export_format
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)


@pytest.mark.unit
class TestSyslogTailTool:
    """Unit tests for the syslog_tail tool."""
    
    async def test_syslog_tail_basic(self, fastmcp_client_mock):
        """Test basic syslog tail functionality."""
        result = await fastmcp_client_mock.call_tool("syslog_tail", {
            "device": "server-01",
            "lines": 20
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)
        assert len(result.data) > 0
        
        # Should contain recent log entries
        response_lower = result.data.lower()
        assert any(keyword in response_lower for keyword in [
            "log", "recent", "latest", "tail", "entries"
        ])

    @pytest.mark.parametrize("lines", [1, 10, 50, 100, 500])
    async def test_syslog_tail_different_line_counts(self, fastmcp_client_mock, lines):
        """Test syslog tail with different line counts."""
        result = await fastmcp_client_mock.call_tool("syslog_tail", {
            "device": "router-01",
            "lines": lines
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)

    async def test_syslog_tail_nonexistent_device(self, fastmcp_client_mock):
        """Test syslog tail with nonexistent device."""
        result = await fastmcp_client_mock.call_tool("syslog_tail", {
            "device": "nonexistent-device-999",
            "lines": 10
        })
        
        # Should either succeed with empty results or provide informative message
        assert result.is_error is False  # Assuming it handles gracefully
        assert isinstance(result.data, str)

    async def test_syslog_tail_default_lines(self, fastmcp_client_mock):
        """Test syslog tail with default line count."""
        result = await fastmcp_client_mock.call_tool("syslog_tail", {
            "device": "server-01"
            # lines parameter omitted, should use default (50)
        })
        
        assert result.is_error is False
        assert isinstance(result.data, str)


@pytest.mark.error_handling
class TestDeviceAnalysisErrorHandling:
    """Test error handling for device analysis tools."""
    
    async def test_missing_required_parameters(self, fastmcp_client_mock):
        """Test tools with missing required parameters."""
        # syslog_tail requires device parameter
        result = await fastmcp_client_mock.call_tool("syslog_tail", {
            "lines": 10
            # Missing required 'device' parameter
        })
        
        assert result.is_error is True

    async def test_invalid_parameter_types(self, fastmcp_client_mock):
        """Test tools with invalid parameter types."""
        # lines should be integer, not string
        result = await fastmcp_client_mock.call_tool("syslog_tail", {
            "device": "server-01",
            "lines": "not-a-number"
        })
        
        assert result.is_error is True

    async def test_negative_numeric_parameters(self, fastmcp_client_mock):
        """Test tools with negative numeric parameters."""
        result = await fastmcp_client_mock.call_tool("syslog_tail", {
            "device": "server-01", 
            "lines": -10
        })
        
        # Should fail validation
        assert result.is_error is True

    async def test_extremely_large_parameters(self, fastmcp_client_mock):
        """Test tools with extremely large parameters."""
        result = await fastmcp_client_mock.call_tool("syslog_sec", {
            "mode": "failed_auth",
            "hours": 999999,  # Extremely large value
            "top_ips": 999999
        })
        
        # Should either fail validation or handle gracefully
        # Exact behavior depends on implementation constraints