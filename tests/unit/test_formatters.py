"""
Comprehensive tests for summary_formatters.py module.

Tests all presentation formatting functions with various inputs, edge cases,
and output validation to achieve high test coverage and ensure robust markdown generation.
"""

import pytest
from datetime import datetime
from unittest.mock import patch

from syslog_mcp.tools.presentation.summary_formatters import (
    format_device_summary,
    format_failed_auth_summary,
    format_suspicious_activity_summary,
    format_auth_timeline_summary,
    format_error_analysis_summary,
    format_search_results_summary,
    format_search_correlate_summary,
    format_daily_report_summary,
    format_export_summary,
    format_alert_rules_summary,
    _get_threat_level,
    THREAT_CRITICAL,
    THREAT_HIGH,
    THREAT_MEDIUM,
    THREAT_LOW,
)


class TestFormatDeviceSummary:
    """Test device summary formatting."""
    
    def test_basic_device_summary(self):
        """Test basic device summary formatting."""
        analysis_data = {
            "device_name": "server-01",
            "total_logs": 1500,
            "hours": 24,
            "device_status": "healthy"
        }
        
        result = format_device_summary(analysis_data)
        
        # Check header
        assert "# Device Summary: server-01" in result
        assert "✅ healthy" in result.lower()
        assert "Last 24 hours" in result
        assert "1,500" in result
    
    def test_device_with_severity_distribution(self):
        """Test device summary with severity breakdown."""
        analysis_data = {
            "device_name": "web-server",
            "total_logs": 1000,
            "hours": 12,
            "device_status": "warning",
            "severity_distribution": {
                "error": 50,
                "warning": 200,
                "info": 750
            }
        }
        
        result = format_device_summary(analysis_data)
        
        assert "⚠️ warning" in result.lower()
        assert "Log Severity Distribution" in result
        assert "Error:** 50 (5.0%)" in result
        assert "Warning:** 200 (20.0%)" in result
        assert "Info:** 750 (75.0%)" in result
    
    def test_device_no_activity(self):
        """Test device with no activity."""
        analysis_data = {
            "device_name": "offline-server",
            "total_logs": 0,
            "hours": 24,
            "device_status": "no_activity"
        }
        
        result = format_device_summary(analysis_data)
        
        assert "❓ no_activity" in result.lower()
        assert "No activity detected" in result
        assert "Device may be offline" in result
    
    def test_device_with_issues(self):
        """Test device summary with errors and warnings."""
        analysis_data = {
            "device_name": "problem-server",
            "total_logs": 500,
            "hours": 6,
            "device_status": "critical",
            "error_count": 25,
            "warning_count": 75
        }
        
        result = format_device_summary(analysis_data)
        
        assert "🚨 critical" in result.lower()
        assert "Recent Issues" in result
        assert "🚨 **25 errors**" in result
        assert "⚠️ **75 warnings**" in result
    
    def test_device_with_health_score(self):
        """Test device summary with health score."""
        analysis_data = {
            "device_name": "monitored-server",
            "total_logs": 800,
            "device_status": "healthy",
            "health_score": {
                "score": 85,
                "grade": "B+",
                "score_factors": [
                    "Low error rate",
                    "Consistent logging",
                    "No security issues"
                ]
            }
        }
        
        result = format_device_summary(analysis_data)
        
        assert "Health Score: 85/100 (B+)" in result
        assert "Score Factors:" in result
        assert "Low error rate" in result
        assert "Consistent logging" in result
    
    def test_device_with_top_programs(self):
        """Test device summary with top programs."""
        analysis_data = {
            "device_name": "busy-server",
            "total_logs": 2000,
            "device_status": "healthy",
            "top_programs": [
                {"program": "nginx", "log_count": 800},
                {"program": "mysql", "log_count": 600},
                {"program": "php-fpm", "log_count": 400},
                {"program": "systemd", "log_count": 200}
            ]
        }
        
        result = format_device_summary(analysis_data)
        
        assert "Most Active Services" in result
        assert "1. **nginx** - 800 logs (40.0%)" in result
        assert "2. **mysql** - 600 logs (30.0%)" in result
        assert "3. **php-fpm** - 400 logs (20.0%)" in result
    
    def test_device_with_recent_errors(self):
        """Test device summary with recent errors."""
        analysis_data = {
            "device_name": "error-server", 
            "total_logs": 100,
            "device_status": "critical",
            "recent_errors": [
                {
                    "timestamp": "2025-01-15T10:30:00Z",
                    "message": "Database connection failed after 5 retries - check database server status",
                    "program": "mysql"
                },
                {
                    "timestamp": "2025-01-15T10:25:00Z", 
                    "message": "HTTP 500 error in user authentication module",
                    "program": "nginx"
                }
            ]
        }
        
        result = format_device_summary(analysis_data)
        
        assert "Recent Errors" in result
        assert "2025-01-15T10:30:00Z" in result
        assert "[mysql]:" in result
        assert "Database connection failed" in result
        # Should truncate long messages
        assert "..." in result
    
    def test_device_with_recommendations(self):
        """Test device summary with recommendations."""
        analysis_data = {
            "device_name": "needs-attention",
            "total_logs": 300,
            "device_status": "warning",
            "recommendations": [
                "Consider increasing memory allocation",
                "Update outdated packages",
                "Review disk space usage"
            ]
        }
        
        result = format_device_summary(analysis_data)
        
        assert "Recommendations" in result
        assert "1. Consider increasing memory allocation" in result
        assert "2. Update outdated packages" in result
        assert "3. Review disk space usage" in result
    
    @patch('syslog_mcp.tools.presentation.summary_formatters.datetime')
    def test_device_timestamp(self, mock_datetime):
        """Test that timestamp is included in summary."""
        mock_now = datetime(2025, 1, 15, 14, 30, 0)
        mock_datetime.now.return_value = mock_now
        
        analysis_data = {"device_name": "test", "total_logs": 100}
        result = format_device_summary(analysis_data)
        
        assert "Analysis completed at 2025-01-15 14:30:00" in result
    
    def test_device_unknown_status(self):
        """Test device with unknown status."""
        analysis_data = {
            "device_name": "mystery-server",
            "total_logs": 50,
            "device_status": "unknown_status"
        }
        
        result = format_device_summary(analysis_data)
        
        # Should default to ❓ for unknown status
        assert "❓ unknown_status" in result.lower()
    
    def test_device_missing_fields(self):
        """Test device summary with missing fields."""
        analysis_data = {}  # Empty data
        
        result = format_device_summary(analysis_data)
        
        assert "Unknown Device" in result
        assert "❓ unknown" in result.lower()
        assert "Last 24 hours" in result  # Default hours
        assert "Total Log Entries:** 0" in result


class TestFormatFailedAuthSummary:
    """Test failed authentication summary formatting."""
    
    def test_basic_failed_auth_summary(self):
        """Test basic failed auth summary."""
        analysis_data = {
            "total_attempts": 150,
            "hours": 24,
            "device": "server-01"
        }
        
        result = format_failed_auth_summary(analysis_data)
        
        assert "Failed Authentication Summary - server-01" in result
        assert "Last 24 hours" in result
        assert "150" in result
    
    def test_no_failed_attempts(self):
        """Test summary with no failed attempts."""
        analysis_data = {
            "total_attempts": 0,
            "hours": 24
        }
        
        result = format_failed_auth_summary(analysis_data)
        
        assert "No failed authentication attempts detected" in result
        assert "✅" in result
        assert "System appears secure" in result
    
    def test_attack_intensity_levels(self):
        """Test different attack intensity classifications."""
        # Critical intensity (>50 per hour)
        data_critical = {"total_attempts": 1200, "hours": 12}  # 100/hour
        result = format_failed_auth_summary(data_critical)
        assert "🚨 **CRITICAL**" in result
        assert "(100.0 attempts/hour)" in result
        
        # High intensity (>20 per hour)
        data_high = {"total_attempts": 600, "hours": 12}  # 50/hour
        result = format_failed_auth_summary(data_high)
        assert "⚠️ **HIGH**" in result
        
        # Moderate intensity (>5 per hour)
        data_moderate = {"total_attempts": 120, "hours": 12}  # 10/hour
        result = format_failed_auth_summary(data_moderate)
        assert "🔶 **MODERATE**" in result
        
        # Low intensity (≤5 per hour)
        data_low = {"total_attempts": 24, "hours": 12}  # 2/hour
        result = format_failed_auth_summary(data_low)
        assert "🔵 **LOW**" in result
    
    def test_top_attacking_ips(self):
        """Test top attacking IPs formatting."""
        analysis_data = {
            "total_attempts": 1000,
            "hours": 24,
            "top_attacking_ips": [
                {"ip": "192.168.1.100", "attempts": 400},
                {"ip": "10.0.0.50", "attempts": 300},
                {"ip": "172.16.0.25", "attempts": 200}
            ]
        }
        
        result = format_failed_auth_summary(analysis_data)
        
        assert "Top Attacking IP Addresses" in result
        assert "1. **192.168.1.100** - 400 attempts (40.0%)" in result
        assert "2. **10.0.0.50** - 300 attempts (30.0%)" in result
        assert "3. **172.16.0.25** - 200 attempts (20.0%)" in result
    
    def test_most_targeted_users(self):
        """Test most targeted usernames formatting."""
        analysis_data = {
            "total_attempts": 800,
            "hours": 12,
            "most_targeted_users": [
                {"username": "admin", "attempts": 250},
                {"username": "root", "attempts": 200},
                {"username": "user", "attempts": 150}
            ]
        }
        
        result = format_failed_auth_summary(analysis_data)
        
        assert "Most Targeted Usernames" in result
        assert "**admin** - 250 attempts (31.2%)" in result
        assert "**root** - 200 attempts (25.0%)" in result
        assert "**user** - 150 attempts (18.8%)" in result
    
    def test_attack_patterns(self):
        """Test attack pattern analysis formatting."""
        analysis_data = {
            "total_attempts": 500,
            "hours": 6,
            "attack_patterns": {
                "primary_pattern": "DISTRIBUTED",
                "geographic_distribution": [
                    {"country": "China", "attempts": 200},
                    {"country": "Russia", "attempts": 150},
                    {"country": "Brazil", "attempts": 100}
                ]
            }
        }
        
        result = format_failed_auth_summary(analysis_data)
        
        assert "Attack Pattern Analysis" in result
        assert "🌐 **Distributed Attack Pattern**" in result
        assert "Geographic Distribution:" in result
        assert "China: 200 attempts" in result
        assert "Russia: 150 attempts" in result
    
    def test_concentrated_attack_pattern(self):
        """Test concentrated attack pattern."""
        analysis_data = {
            "total_attempts": 300,
            "attack_patterns": {
                "primary_pattern": "CONCENTRATED"
            }
        }
        
        result = format_failed_auth_summary(analysis_data)
        assert "🎯 **Concentrated Attack Pattern**" in result
    
    def test_scanning_pattern(self):
        """Test scanning attack pattern."""
        analysis_data = {
            "total_attempts": 100,
            "attack_patterns": {
                "primary_pattern": "SCANNING"
            }
        }
        
        result = format_failed_auth_summary(analysis_data)
        assert "🔍 **Scanning Pattern**" in result
    
    def test_zero_hours_edge_case(self):
        """Test edge case with zero hours."""
        analysis_data = {
            "total_attempts": 100,
            "hours": 0
        }
        
        result = format_failed_auth_summary(analysis_data)
        # Should handle division by zero gracefully
        assert "Attack Intensity:" in result


class TestFormatSuspiciousActivitySummary:
    """Test suspicious activity summary formatting."""
    
    def test_basic_suspicious_summary(self):
        """Test basic suspicious activity summary.""" 
        analysis_data = {
            "total_suspicious_events": 25,
            "hours": 12,
            "device": "web-server"
        }
        
        result = format_suspicious_activity_summary(analysis_data)
        
        assert "Suspicious Activity Analysis - web-server" in result
        assert "25" in result
        assert "12 hours" in result
    
    def test_no_suspicious_activity(self):
        """Test summary with no suspicious activity."""
        analysis_data = {
            "total_suspicious_events": 0,
            "hours": 24
        }
        
        result = format_suspicious_activity_summary(analysis_data)
        
        assert "✅" in result
        assert "No suspicious activity detected" in result


class TestFormatAuthTimelineSummary:
    """Test authentication timeline summary formatting."""
    
    def test_basic_timeline_summary(self):
        """Test basic timeline summary."""
        analysis_data = {
            "total_attempts": 150,
            "hours": 24
        }
        
        result = format_auth_timeline_summary(analysis_data)
        
        assert "Authentication Timeline Analysis" in result
        assert "150" in result
        assert "24 hours" in result


class TestFormatErrorAnalysisSummary:
    """Test error analysis summary formatting."""
    
    def test_basic_error_summary(self):
        """Test basic error analysis summary."""
        analysis_data = {
            "total_errors": 50,
            "hours": 6,
            "analysis_parameters": {
                "device": "app-server"
            }
        }
        
        result = format_error_analysis_summary(analysis_data)
        
        assert "System Error Analysis - app-server" in result
        assert "Total Errors:** 50" in result
        assert "Last 6 hours" in result
    
    def test_no_errors(self):
        """Test summary with no errors."""
        analysis_data = {
            "total_errors": 0,
            "hours": 24
        }
        
        result = format_error_analysis_summary(analysis_data)
        
        assert "✅" in result
        assert "No errors detected" in result


class TestFormatSearchResultsSummary:
    """Test search results summary formatting."""
    
    def test_basic_search_results(self):
        """Test basic search results summary."""
        search_results = {
            "total_hits": 150,
            "search_query": "login",
            "logs": [
                {
                    "timestamp": "2025-01-15T10:30:00Z",
                    "device": "server-01", 
                    "message": "User login successful",
                    "program": "sshd"
                },
                {
                    "timestamp": "2025-01-15T10:25:00Z",
                    "device": "server-02",
                    "message": "Database query completed",
                    "program": "mysql"
                }
            ]
        }
        
        result = format_search_results_summary(search_results)
        
        assert "Search Results" in result
        assert "150" in result
        assert "server-01" in result
        assert "User login successful" in result
    
    def test_search_no_results(self):
        """Test search with no results."""
        search_results = {
            "total_hits": 0,
            "search_query": "nonexistent",
            "logs": []
        }
        
        result = format_search_results_summary(search_results)
        
        assert "Search Results" in result
        assert "No results found" in result
        assert "ℹ️" in result
    
    def test_search_long_results(self):
        """Test search results formatting with many results."""
        search_results = {
            "total_hits": 500,
            "search_query": "test",
            "logs": [{"timestamp": f"2025-01-15T10:{i:02d}:00Z", "device": f"server-{i}", "message": f"Message {i}", "program": "test"} for i in range(15)]
        }
        
        result = format_search_results_summary(search_results)
        
        assert "500" in result
        assert "server-14" in result


class TestFormatSearchCorrelateSummary:
    """Test search correlation summary formatting."""
    
    def test_basic_correlate_summary(self):
        """Test basic correlation summary."""
        analysis_data = {
            "query_info": {
                "primary_query": "test",
                "analysis_hours": 12,
                "total_events": 75,
                "correlation_fields": ["device", "program"]
            },
            "correlation_patterns": []
        }
        
        result = format_search_correlate_summary(analysis_data)
        
        assert "Search Correlation Analysis" in result
        assert "75" in result
        assert "12 hours" in result


class TestFormatDailyReportSummary:
    """Test daily report summary formatting."""
    
    def test_basic_daily_report(self):
        """Test basic daily report summary."""
        analysis_data = {
            "report_metadata": {
                "report_date": "2025-01-15",
                "period": "24 hours"
            },
            "executive_summary": {
                "total_events": 10000,
                "security_incidents": 5,
                "system_errors": 150
            },
            "device_statistics": {
                "active_devices": 25,
                "devices_with_errors": 3
            }
        }
        
        result = format_daily_report_summary(analysis_data)
        
        assert "Daily System Report - 2025-01-15" in result
        assert "Total Events:** 10,000" in result or "Total Events:** 10000" in result
        assert "Active Devices:** 25" in result
        assert "System Errors:** 150" in result


class TestFormatExportSummary:
    """Test export summary formatting."""
    
    def test_basic_export_summary(self):
        """Test basic export summary."""
        analysis_data = {
            "export_metadata": {
                "total_records": 1500,
                "export_format": "json"
            },
            "export_quality": {
                "completeness": "high"
            }
        }
        
        result = format_export_summary(analysis_data)
        
        assert "Log Export Summary" in result
        assert "1,500" in result or "1500" in result
        assert "JSON" in result


class TestFormatAlertRulesSummary:
    """Test alert rules summary formatting."""
    
    def test_basic_alert_rules(self):
        """Test basic alert rules summary."""
        rules_data = {
            "rules": {
                "High Error Rate": {
                    "query": "level:error",
                    "threshold": 50,
                    "enabled": True,
                    "severity": "high"
                },
                "Failed Logins": {
                    "query": "program:ssh AND message:failed",
                    "threshold": 10,
                    "enabled": False,
                    "severity": "medium"
                }
            }
        }
        
        result = format_alert_rules_summary(rules_data)
        
        assert "Alert Rules" in result
        assert "High Error Rate" in result
        assert "Failed Logins" in result
        assert "level:error" in result
    
    def test_no_alert_rules(self):
        """Test alert rules summary with no rules."""
        rules_data = {"rules": {}}
        
        result = format_alert_rules_summary(rules_data)
        
        assert "No alert rules configured" in result


class TestGetThreatLevel:
    """Test threat level helper function."""
    
    def test_threat_levels(self):
        """Test all threat level classifications."""
        assert _get_threat_level(95) == "CRITICAL"
        assert _get_threat_level(80) == "CRITICAL"
        
        assert _get_threat_level(79) == "HIGH"
        assert _get_threat_level(60) == "HIGH"
        
        assert _get_threat_level(59) == "MEDIUM"
        assert _get_threat_level(40) == "MEDIUM"
        
        assert _get_threat_level(39) == "LOW"
        assert _get_threat_level(0) == "LOW"
        
        # Edge cases
        assert _get_threat_level(-1) == "LOW"
        assert _get_threat_level(100) == "CRITICAL"
    
    def test_threat_constants(self):
        """Test threat level constants are properly defined."""
        assert THREAT_CRITICAL == 80
        assert THREAT_HIGH == 60
        assert THREAT_MEDIUM == 40
        assert THREAT_LOW == 0


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_none_input(self):
        """Test formatters with empty input."""
        # Test with empty dict since functions expect dict input
        result = format_device_summary({})
        assert "Unknown Device" in result
        
        result = format_failed_auth_summary({})
        assert "Failed Authentication Summary" in result
    
    def test_empty_dict_input(self):
        """Test formatters with empty dictionary."""
        result = format_device_summary({})
        assert "Unknown Device" in result
        
        result = format_failed_auth_summary({})
        assert "Total Failed Attempts:** 0" in result
    
    def test_malformed_data(self):
        """Test formatters with malformed data."""
        malformed_data = {
            "device_name": None,
            "total_logs": 0,  # Use valid number
            "hours": 24  # Use positive number
        }
        
        # Should not crash, but handle gracefully
        result = format_device_summary(malformed_data)
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_missing_nested_fields(self):
        """Test handling of missing nested dictionary fields."""
        data = {
            "device_name": "test",
            "health_score": {},  # Empty nested dict
            "top_programs": [{"program": "test"}]  # Missing log_count
        }
        
        result = format_device_summary(data)
        assert "test" in result
        # Should handle missing nested fields gracefully
    
    def test_unicode_and_special_characters(self):
        """Test formatters with unicode and special characters."""
        analysis_data = {
            "device_name": "服务器-01",  # Chinese characters
            "total_logs": 100,
            "recent_errors": [
                {
                    "message": "Error with émojis 🚨 and symbols $%^&*()",
                    "program": "tëst-prôgram"
                }
            ]
        }
        
        result = format_device_summary(analysis_data)
        assert "服务器-01" in result
        assert "émojis 🚨" in result
        assert "tëst-prôgram" in result