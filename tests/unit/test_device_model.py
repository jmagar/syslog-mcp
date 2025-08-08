"""
Tests for device information models and health scoring.
"""

import pytest
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Dict, Any, List

from pydantic import ValidationError

from syslog_mcp.models.device import (
    DeviceInfo, DeviceStatus, DeviceType, DeviceList, LogActivitySummary
)


class TestDeviceStatus:
    """Test DeviceStatus enum and classification."""
    
    def test_device_status_values(self):
        """Test that all device status values are properly defined."""
        assert DeviceStatus.HEALTHY == "healthy"
        assert DeviceStatus.WARNING == "warning"
        assert DeviceStatus.CRITICAL == "critical"
        assert DeviceStatus.OFFLINE == "offline"
        assert DeviceStatus.UNKNOWN == "unknown"
    
    def test_from_health_score_healthy(self):
        """Test healthy device classification."""
        # High health score, recent activity
        status = DeviceStatus.from_health_score(0.9, 1.0)
        assert status == DeviceStatus.HEALTHY
        
        status = DeviceStatus.from_health_score(0.8, 0.5)
        assert status == DeviceStatus.HEALTHY
    
    def test_from_health_score_warning(self):
        """Test warning device classification."""
        status = DeviceStatus.from_health_score(0.7, 2.0)
        assert status == DeviceStatus.WARNING
        
        status = DeviceStatus.from_health_score(0.6, 1.0)
        assert status == DeviceStatus.WARNING
    
    def test_from_health_score_critical(self):
        """Test critical device classification."""
        status = DeviceStatus.from_health_score(0.5, 3.0)
        assert status == DeviceStatus.CRITICAL
        
        status = DeviceStatus.from_health_score(0.3, 1.0)
        assert status == DeviceStatus.CRITICAL
        
        status = DeviceStatus.from_health_score(0.1, 2.0)
        assert status == DeviceStatus.CRITICAL
    
    def test_from_health_score_offline(self):
        """Test offline device classification."""
        # Over 24 hours since last activity = offline
        status = DeviceStatus.from_health_score(0.9, 25.0)
        assert status == DeviceStatus.OFFLINE
        
        status = DeviceStatus.from_health_score(0.1, 48.0)
        assert status == DeviceStatus.OFFLINE
    
    def test_from_health_score_unknown(self):
        """Test unknown device classification."""
        status = DeviceStatus.from_health_score(0.0, 1.0)
        assert status == DeviceStatus.UNKNOWN


class TestLogActivitySummary:
    """Test LogActivitySummary model and calculations."""
    
    def test_basic_log_activity(self):
        """Test basic log activity summary."""
        activity = LogActivitySummary(
            total_logs=1000,
            error_count=50,
            warning_count=100,
            critical_count=5,
            logs_per_hour=25.5,
            peak_logs_per_hour=75.0
        )
        
        assert activity.total_logs == 1000
        assert activity.error_count == 50
        assert activity.warning_count == 100
        assert activity.critical_count == 5
    
    def test_error_rate_calculation(self):
        """Test error rate calculation."""
        activity = LogActivitySummary(
            total_logs=1000,
            error_count=50,
            critical_count=10
        )
        
        # Error rate = (errors + critical) / total = (50 + 10) / 1000 = 0.06
        assert activity.error_rate == 0.06
    
    def test_error_rate_no_logs(self):
        """Test error rate when no logs exist."""
        activity = LogActivitySummary(total_logs=0)
        assert activity.error_rate == 0.0
    
    def test_hours_since_last_log(self):
        """Test calculation of hours since last log."""
        now = datetime.now(timezone.utc)
        two_hours_ago = now - timedelta(hours=2)
        
        activity = LogActivitySummary(last_log_timestamp=two_hours_ago)
        
        # Should be approximately 2 hours
        assert 1.9 <= activity.hours_since_last_log <= 2.1
    
    def test_hours_since_last_log_no_timestamp(self):
        """Test hours calculation when no timestamp available."""
        activity = LogActivitySummary()
        assert activity.hours_since_last_log == float('inf')
    
    def test_activity_duration_calculation(self):
        """Test activity duration calculation."""
        now = datetime.now(timezone.utc)
        six_hours_ago = now - timedelta(hours=6)
        
        activity = LogActivitySummary(
            first_log_timestamp=six_hours_ago,
            last_log_timestamp=now
        )
        
        # Should be approximately 6 hours
        assert 5.9 <= activity.activity_duration_hours <= 6.1
    
    def test_activity_duration_no_timestamps(self):
        """Test activity duration when timestamps missing."""
        activity = LogActivitySummary()
        assert activity.activity_duration_hours == 0.0


class TestDeviceInfo:
    """Test DeviceInfo model and validation."""
    
    def test_minimal_device_info(self):
        """Test creation with minimal required fields."""
        device = DeviceInfo(name="test-server")
        
        assert device.name == "test-server"
        assert device.device_type == DeviceType.UNKNOWN
        # With no log activity, device should be offline or unknown
        assert device.status in [DeviceStatus.UNKNOWN, DeviceStatus.OFFLINE]
        assert 0.0 <= device.health_score <= 1.0
        assert device.last_updated is not None
    
    def test_complete_device_info(self):
        """Test creation with all fields."""
        now = datetime.now(timezone.utc)
        device = DeviceInfo(
            name="web-server-01",
            device_type=DeviceType.SERVER,
            ip_addresses=["192.168.1.100", "10.0.0.50"],
            mac_addresses=["aa:bb:cc:dd:ee:ff"],
            location="Datacenter-A-Rack-05",
            environment="production",
            tags={"team": "platform", "criticality": "high"},
            log_activity=LogActivitySummary(
                total_logs=1000,
                error_count=10,
                logs_per_hour=50.0,
                last_log_timestamp=now - timedelta(hours=1)
            )
        )
        
        assert device.name == "web-server-01"
        assert device.device_type == DeviceType.SERVER
        assert len(device.ip_addresses) == 2
        assert isinstance(device.ip_addresses[0], IPv4Address)
        assert device.location == "Datacenter-A-Rack-05"
        assert device.environment == "production"
        assert device.tags["team"] == "platform"
    
    def test_device_name_validation(self):
        """Test device name validation and normalization."""
        # Valid names should be normalized to lowercase
        device = DeviceInfo(name="  TEST-SERVER  ")
        assert device.name == "test-server"
        
        # IP addresses should be valid
        device = DeviceInfo(name="192.168.1.100")
        assert device.name == "192.168.1.100"
        
        device = DeviceInfo(name="2001:db8::1")
        assert device.name == "2001:db8::1"
    
    def test_device_name_invalid(self):
        """Test invalid device name handling."""
        with pytest.raises(ValidationError, match="Device name cannot be empty"):
            DeviceInfo(name="")
        
        with pytest.raises(ValidationError, match="Device name cannot be empty"):
            DeviceInfo(name="   ")
        
        with pytest.raises(ValidationError, match="Invalid device name format"):
            DeviceInfo(name="invalid@name")
    
    def test_ip_address_validation(self):
        """Test IP address validation and normalization."""
        # Single IP as string
        device = DeviceInfo(
            name="test",
            ip_addresses="192.168.1.100"
        )
        assert len(device.ip_addresses) == 1
        assert isinstance(device.ip_addresses[0], IPv4Address)
        
        # Multiple IPs
        device = DeviceInfo(
            name="test",
            ip_addresses=["192.168.1.100", "2001:db8::1", "10.0.0.1"]
        )
        assert len(device.ip_addresses) == 3
        assert isinstance(device.ip_addresses[0], IPv4Address)
        assert isinstance(device.ip_addresses[1], IPv6Address)
        
        # Duplicate IPs should be removed
        device = DeviceInfo(
            name="test",
            ip_addresses=["192.168.1.100", "192.168.1.100"]
        )
        assert len(device.ip_addresses) == 1
    
    def test_ip_address_validation_invalid(self):
        """Test invalid IP address handling."""
        with pytest.raises(ValidationError, match="Invalid IP address"):
            DeviceInfo(
                name="test",
                ip_addresses=["invalid.ip.address"]
            )
    
    def test_tags_validation(self):
        """Test device tags validation."""
        # Valid tags
        device = DeviceInfo(
            name="test",
            tags={"team": "platform", "env": "prod", "backup": "enabled"}
        )
        assert device.tags["team"] == "platform"
        assert device.tags["env"] == "prod"
    
    def test_tags_validation_invalid(self):
        """Test invalid tags handling."""
        # Too many tags
        many_tags = {f"tag_{i}": f"value_{i}" for i in range(25)}
        with pytest.raises(ValidationError, match="Too many tags"):
            DeviceInfo(name="test", tags=many_tags)
        
        # Invalid key format
        with pytest.raises(ValidationError, match="Invalid tag key format"):
            DeviceInfo(name="test", tags={"invalid-key!": "value"})
    
    def test_health_score_calculation(self):
        """Test health score calculation."""
        now = datetime.now(timezone.utc)
        
        # Healthy device with good metrics
        device = DeviceInfo(
            name="healthy-server",
            log_activity=LogActivitySummary(
                total_logs=2000,
                error_count=5,  # Low error count
                logs_per_hour=75.0,  # Good activity
                last_log_timestamp=now - timedelta(minutes=30)  # Recent activity
            )
        )
        
        # Should have high health score
        assert device.health_score > 0.6
        assert device.status in [DeviceStatus.HEALTHY, DeviceStatus.WARNING]
    
    def test_health_score_unhealthy(self):
        """Test health score for unhealthy device."""
        now = datetime.now(timezone.utc)
        
        # Unhealthy device with poor metrics
        device = DeviceInfo(
            name="unhealthy-server",
            log_activity=LogActivitySummary(
                total_logs=100,
                error_count=40,  # High error rate
                critical_count=10,
                logs_per_hour=2.0,  # Low activity
                last_log_timestamp=now - timedelta(hours=8)  # Old activity
            )
        )
        
        # Should have low health score (allowing some tolerance for calculation)
        assert device.health_score <= 0.51
        assert device.status in [DeviceStatus.CRITICAL, DeviceStatus.WARNING]
    
    def test_status_reason_generation(self):
        """Test status reason generation."""
        device = DeviceInfo(name="test")
        
        # Should have a status reason
        assert device.status_reason is not None
        assert isinstance(device.status_reason, str)
        assert len(device.status_reason) > 0
    
    def test_add_ip_address(self):
        """Test adding IP addresses to device."""
        device = DeviceInfo(name="test")
        
        # Add new IP
        result = device.add_ip_address("192.168.1.100")
        assert result is True
        assert len(device.ip_addresses) == 1
        
        # Add duplicate IP
        result = device.add_ip_address("192.168.1.100")
        assert result is False
        assert len(device.ip_addresses) == 1
        
        # Add invalid IP
        result = device.add_ip_address("invalid.ip")
        assert result is False
        assert len(device.ip_addresses) == 1
    
    def test_get_primary_ip(self):
        """Test getting primary IP address."""
        # No IPs
        device = DeviceInfo(name="test")
        assert device.get_primary_ip() is None
        
        # IPv4 and IPv6 - should prefer IPv4
        device = DeviceInfo(
            name="test",
            ip_addresses=["2001:db8::1", "192.168.1.100"]
        )
        primary = device.get_primary_ip()
        assert isinstance(primary, IPv4Address)
        assert str(primary) == "192.168.1.100"
        
        # Only IPv6
        device = DeviceInfo(
            name="test",
            ip_addresses=["2001:db8::1"]
        )
        primary = device.get_primary_ip()
        assert isinstance(primary, IPv6Address)
    
    def test_is_active(self):
        """Test device activity check."""
        now = datetime.now(timezone.utc)
        
        # Recent activity - should be active
        device = DeviceInfo(
            name="test",
            log_activity=LogActivitySummary(
                last_log_timestamp=now - timedelta(hours=2)
            )
        )
        assert device.is_active() is True
        assert device.is_active(hours_threshold=1.0) is False
        
        # Old activity - should be inactive
        device = DeviceInfo(
            name="test",
            log_activity=LogActivitySummary(
                last_log_timestamp=now - timedelta(hours=30)
            )
        )
        assert device.is_active() is False
    
    def test_criticality_score(self):
        """Test criticality score calculation."""
        # Critical device type in production
        device = DeviceInfo(
            name="firewall",
            device_type=DeviceType.FIREWALL,
            environment="production",
            log_activity=LogActivitySummary(
                total_logs=100,
                error_count=50,  # High error rate
                critical_count=20
            )
        )
        
        criticality = device.get_criticality_score()
        assert 0.0 <= criticality <= 1.0
        
        # Should be high criticality due to type and errors
        assert criticality > 0.5
    
    def test_to_summary_dict(self):
        """Test conversion to summary dictionary."""
        device = DeviceInfo(
            name="test-server",
            device_type=DeviceType.SERVER,
            ip_addresses=["192.168.1.100"]
        )
        
        summary = device.to_summary_dict()
        
        assert summary["name"] == "test-server"
        assert summary["status"] in [s.value for s in DeviceStatus]
        assert "health_score" in summary
        assert "device_type" in summary
        assert "primary_ip" in summary
        assert "total_logs" in summary
        assert "error_rate" in summary
        assert "status_reason" in summary
    
    def test_update_log_activity(self):
        """Test updating device with new log activity."""
        device = DeviceInfo(name="test")
        original_updated = device.last_updated
        
        # Wait a tiny bit to ensure timestamp difference
        import time
        time.sleep(0.01)
        
        new_activity = LogActivitySummary(
            total_logs=500,
            error_count=25,
            logs_per_hour=30.0
        )
        
        device.update_log_activity(new_activity)
        
        assert device.log_activity.total_logs == 500
        assert device.log_activity.error_count == 25
        assert device.last_updated > original_updated


class TestDeviceList:
    """Test DeviceList model and operations."""
    
    def create_sample_devices(self) -> List[DeviceInfo]:
        """Create sample devices for testing."""
        now = datetime.now(timezone.utc)
        
        return [
            DeviceInfo(
                name="healthy-server",
                device_type=DeviceType.SERVER,
                log_activity=LogActivitySummary(
                    total_logs=1000,
                    error_count=5,
                    logs_per_hour=50.0,
                    last_log_timestamp=now - timedelta(minutes=30)
                )
            ),
            DeviceInfo(
                name="warning-server", 
                device_type=DeviceType.SERVER,
                log_activity=LogActivitySummary(
                    total_logs=500,
                    error_count=50,
                    logs_per_hour=20.0,
                    last_log_timestamp=now - timedelta(hours=4)
                )
            ),
            DeviceInfo(
                name="critical-firewall",
                device_type=DeviceType.FIREWALL,
                environment="production",
                log_activity=LogActivitySummary(
                    total_logs=200,
                    error_count=80,
                    critical_count=20,
                    logs_per_hour=5.0,
                    last_log_timestamp=now - timedelta(hours=10)
                )
            )
        ]
    
    def test_device_list_creation(self):
        """Test basic device list creation."""
        devices = self.create_sample_devices()
        device_list = DeviceList(devices=devices, total_count=len(devices))
        
        assert len(device_list.devices) == 3
        assert device_list.total_count == 3
        assert device_list.generated_at is not None
    
    def test_status_summary(self):
        """Test device status summary calculation."""
        devices = self.create_sample_devices()
        device_list = DeviceList(devices=devices)
        
        summary = device_list.status_summary
        
        # Should have counts for each status
        assert isinstance(summary, dict)
        assert all(status.value in summary for status in DeviceStatus)
        assert sum(summary.values()) == len(devices)
    
    def test_health_statistics(self):
        """Test health statistics calculation."""
        devices = self.create_sample_devices()
        device_list = DeviceList(devices=devices)
        
        stats = device_list.health_statistics
        
        assert "min" in stats
        assert "max" in stats
        assert "mean" in stats
        assert "median" in stats
        
        assert 0.0 <= stats["min"] <= 1.0
        assert 0.0 <= stats["max"] <= 1.0
        assert stats["min"] <= stats["mean"] <= stats["max"]
        assert stats["min"] <= stats["median"] <= stats["max"]
    
    def test_health_statistics_empty(self):
        """Test health statistics with empty device list."""
        device_list = DeviceList()
        stats = device_list.health_statistics
        
        assert stats["min"] == 0.0
        assert stats["max"] == 0.0
        assert stats["mean"] == 0.0
        assert stats["median"] == 0.0
    
    def test_filter_by_status(self):
        """Test filtering devices by status."""
        devices = self.create_sample_devices()
        device_list = DeviceList(devices=devices)
        
        # Filter by a specific status
        filtered = device_list.filter_by_status(DeviceStatus.HEALTHY)
        
        assert isinstance(filtered, DeviceList)
        assert all(d.status == DeviceStatus.HEALTHY for d in filtered.devices)
        assert filtered.filter_applied == "status=healthy"
    
    def test_filter_by_health_range(self):
        """Test filtering devices by health score range."""
        devices = self.create_sample_devices()
        device_list = DeviceList(devices=devices)
        
        # Filter for high health scores
        filtered = device_list.filter_by_health_range(min_health=0.7)
        
        assert isinstance(filtered, DeviceList)
        assert all(d.health_score >= 0.7 for d in filtered.devices)
        assert filtered.filter_applied == "health_score=0.7-1.0"
    
    def test_sort_by_criticality(self):
        """Test sorting devices by criticality score."""
        devices = self.create_sample_devices()
        device_list = DeviceList(devices=devices)
        
        sorted_list = device_list.sort_by_criticality(descending=True)
        
        assert isinstance(sorted_list, DeviceList)
        assert len(sorted_list.devices) == len(devices)
        
        # Check that criticality scores are in descending order
        scores = [d.get_criticality_score() for d in sorted_list.devices]
        assert scores == sorted(scores, reverse=True)
    
    def test_get_top_critical(self):
        """Test getting top critical devices."""
        devices = self.create_sample_devices()
        device_list = DeviceList(devices=devices)
        
        top_critical = device_list.get_top_critical(limit=2)
        
        # Should return list of devices, not DeviceList
        assert isinstance(top_critical, list)
        assert len(top_critical) <= 2
        assert all(isinstance(d, DeviceInfo) for d in top_critical)