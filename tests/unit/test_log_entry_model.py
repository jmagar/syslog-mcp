"""
Tests for LogEntry model validation and functionality.
"""

import pytest
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict

from pydantic import ValidationError

from syslog_mcp.models.log_entry import LogEntry, LogLevel


class TestLogLevel:
    """Test LogLevel enum and normalization."""
    
    def test_log_level_enum_values(self):
        """Test that all log levels are properly defined."""
        assert LogLevel.DEBUG == "DEBUG"
        assert LogLevel.INFO == "INFO"
        assert LogLevel.WARN == "WARN"
        assert LogLevel.WARNING == "WARNING"
        assert LogLevel.ERROR == "ERROR"
        assert LogLevel.CRITICAL == "CRITICAL"
        assert LogLevel.FATAL == "FATAL"
    
    def test_normalize_string_levels(self):
        """Test string log level normalization."""
        assert LogLevel.normalize("debug") == LogLevel.DEBUG
        assert LogLevel.normalize("DEBUG") == LogLevel.DEBUG
        assert LogLevel.normalize("  INFO  ") == LogLevel.INFO
        assert LogLevel.normalize("error") == LogLevel.ERROR
        assert LogLevel.normalize("CRITICAL") == LogLevel.CRITICAL
    
    def test_normalize_aliases(self):
        """Test log level alias normalization."""
        assert LogLevel.normalize("WARNING") == LogLevel.WARN
        assert LogLevel.normalize("FATAL") == LogLevel.CRITICAL
        assert LogLevel.normalize("NOTICE") == LogLevel.INFO
        assert LogLevel.normalize("INFORMATIONAL") == LogLevel.INFO
        assert LogLevel.normalize("ERR") == LogLevel.ERROR
        assert LogLevel.normalize("CRIT") == LogLevel.CRITICAL
    
    def test_normalize_numeric_levels(self):
        """Test RFC 5424 numeric log level normalization."""
        assert LogLevel.normalize(0) == LogLevel.CRITICAL  # Emergency
        assert LogLevel.normalize(1) == LogLevel.CRITICAL  # Alert
        assert LogLevel.normalize(2) == LogLevel.CRITICAL  # Critical
        assert LogLevel.normalize(3) == LogLevel.ERROR     # Error
        assert LogLevel.normalize(4) == LogLevel.WARN      # Warning
        assert LogLevel.normalize(5) == LogLevel.INFO      # Notice
        assert LogLevel.normalize(6) == LogLevel.INFO      # Informational
        assert LogLevel.normalize(7) == LogLevel.DEBUG     # Debug
    
    def test_normalize_invalid_values(self):
        """Test normalization with invalid values."""
        with pytest.raises(ValueError, match="Invalid log level"):
            LogLevel.normalize("INVALID")
        
        with pytest.raises(ValueError, match="Invalid numeric log level"):
            LogLevel.normalize(99)
        
        with pytest.raises(ValueError, match="Invalid log level type"):
            LogLevel.normalize(None)


class TestLogEntryBasic:
    """Test basic LogEntry functionality."""
    
    def test_minimal_valid_log_entry(self):
        """Test creation with minimal required fields."""
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test-server",
            level="INFO",
            message="Test message"
        )
        
        assert entry.device == "test-server"
        assert entry.level == LogLevel.INFO
        assert entry.message == "Test message"
        assert entry.timestamp.tzinfo is not None
        assert entry.metadata == {}
        assert entry.parsed_at is not None
    
    def test_complete_log_entry(self):
        """Test creation with all fields."""
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="web-server-01",
            level="ERROR",
            message="Database connection failed",
            facility="daemon",
            process_id=1234,
            process_name="mysqld",
            source_ip="192.168.1.100",
            metadata={"error_code": 1045, "retry_count": 3}
        )
        
        assert entry.device == "web-server-01"
        assert entry.level == LogLevel.ERROR
        assert entry.facility == "daemon"
        assert entry.process_id == 1234
        assert entry.process_name == "mysqld"
        assert isinstance(entry.source_ip, IPv4Address)
        assert str(entry.source_ip) == "192.168.1.100"
        assert entry.metadata == {"error_code": 1045, "retry_count": 3}
    
    def test_index_name_generation(self):
        """Test automatic index name generation."""
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test-server",
            level="INFO", 
            message="Test message"
        )
        
        assert entry.index_name == "syslog-2024-01"
    
    def test_custom_index_name(self):
        """Test custom index name preservation."""
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test-server",
            level="INFO",
            message="Test message",
            index_name="custom-index"
        )
        
        assert entry.index_name == "custom-index"


class TestTimestampValidation:
    """Test timestamp parsing and validation."""
    
    def test_datetime_object(self):
        """Test with datetime object input."""
        dt = datetime(2024, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
        entry = LogEntry(
            timestamp=dt,
            device="test",
            level="INFO",
            message="test"
        )
        assert entry.timestamp == dt
    
    def test_naive_datetime_gets_utc(self):
        """Test that naive datetime gets UTC timezone."""
        dt = datetime(2024, 1, 15, 10, 30, 45)  # No timezone
        entry = LogEntry(
            timestamp=dt,
            device="test",
            level="INFO",
            message="test"
        )
        assert entry.timestamp.tzinfo == timezone.utc
    
    def test_unix_timestamp(self):
        """Test Unix timestamp parsing."""
        timestamp = 1705315845  # 2024-01-15 10:30:45 UTC
        entry = LogEntry(
            timestamp=timestamp,
            device="test",
            level="INFO",
            message="test"
        )
        assert entry.timestamp.year == 2024
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 15
        assert entry.timestamp.tzinfo == timezone.utc
    
    def test_iso8601_formats(self):
        """Test various ISO 8601 timestamp formats."""
        formats = [
            "2024-01-15T10:30:45Z",
            "2024-01-15T10:30:45.123Z",
            "2024-01-15T10:30:45+00:00",
            "2024-01-15T10:30:45.123+00:00"
        ]
        
        for fmt in formats:
            entry = LogEntry(
                timestamp=fmt,
                device="test",
                level="INFO", 
                message="test"
            )
            assert entry.timestamp.year == 2024
            assert entry.timestamp.month == 1
    
    def test_common_formats(self):
        """Test common timestamp string formats."""
        formats = [
            "2024-01-15 10:30:45",
            "2024/01/15 10:30:45",
            "01/15/2024 10:30:45",
            "Jan 15 10:30:45"
        ]
        
        for fmt in formats:
            entry = LogEntry(
                timestamp=fmt,
                device="test",
                level="INFO",
                message="test"
            )
            assert entry.timestamp.tzinfo is not None
    
    def test_future_timestamp_validation(self):
        """Test validation of timestamps in the future."""
        # Far future should fail
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        
        with pytest.raises(ValidationError, match="Timestamp too far in future"):
            LogEntry(
                timestamp=future,
                device="test",
                level="INFO",
                message="test"
            )
    
    def test_near_future_timestamp_allowed(self):
        """Test that near-future timestamps (clock skew) are allowed."""
        # 2 minutes in future should be allowed
        near_future = datetime.now(timezone.utc) + timedelta(minutes=2)
        
        entry = LogEntry(
            timestamp=near_future,
            device="test",
            level="INFO",
            message="test"
        )
        assert entry.timestamp == near_future
    
    def test_invalid_timestamp_format(self):
        """Test invalid timestamp format handling."""
        with pytest.raises(ValidationError, match="Unable to parse timestamp"):
            LogEntry(
                timestamp="invalid-timestamp",
                device="test",
                level="INFO",
                message="test"
            )


class TestDeviceValidation:
    """Test device name validation."""
    
    def test_valid_hostnames(self):
        """Test valid hostname formats."""
        valid_names = [
            "web-server-01",
            "db.example.com",
            "192.168.1.100",
            "2001:db8::1",
            "server_01",
            "TEST-HOST"
        ]
        
        for name in valid_names:
            entry = LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device=name,
                level="INFO",
                message="test"
            )
            # Device names are normalized to lowercase
            assert entry.device == name.lower()
    
    def test_ipv4_device(self):
        """Test IPv4 address as device name."""
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="192.168.1.100",
            level="INFO",
            message="test"
        )
        assert entry.device == "192.168.1.100"
    
    def test_ipv6_device(self):
        """Test IPv6 address as device name."""
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="2001:db8::1",
            level="INFO",
            message="test"
        )
        assert entry.device == "2001:db8::1"
    
    def test_invalid_device_names(self):
        """Test invalid device name formats."""
        invalid_names = [
            "",
            "   ",
            "device with spaces",
            "device@invalid",
            "device#invalid",
            "a" * 256  # Too long
        ]
        
        for name in invalid_names:
            with pytest.raises(ValidationError):
                LogEntry(
                    timestamp="2024-01-15T10:30:45Z",
                    device=name,
                    level="INFO",
                    message="test"
                )
    
    def test_device_normalization(self):
        """Test device name normalization."""
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="  TEST-SERVER  ",
            level="INFO",
            message="test"
        )
        assert entry.device == "test-server"


class TestMessageValidation:
    """Test log message validation."""
    
    def test_valid_messages(self):
        """Test valid log messages."""
        messages = [
            "Simple message",
            "Message with numbers 123",
            "Message with special chars: @#$%",
            "Multi-line\nmessage\nhere",
            "Message with tab\tcharacter"
        ]
        
        for msg in messages:
            entry = LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message=msg
            )
            assert entry.message == msg.strip()
    
    def test_empty_message_validation(self):
        """Test empty message validation."""
        # Empty string fails due to min_length constraint
        with pytest.raises(ValidationError, match="String should have at least 1 character"):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message=""
            )
        
        # Whitespace only should fail
        with pytest.raises(ValidationError, match="Log message cannot be empty"):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="   "
            )
        
        # Newlines only should fail  
        with pytest.raises(ValidationError, match="Log message cannot be empty"):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="\n\n\n"
            )
        
        # Control characters only should fail with different message
        with pytest.raises(ValidationError, match="Log message contains only control characters"):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="\x00\x01\x02"
            )
    
    def test_message_length_limit(self):
        """Test message length validation."""
        # Max length should be accepted
        long_message = "x" * 8192
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test",
            level="INFO",
            message=long_message
        )
        assert len(entry.message) == 8192
        
        # Over max length should fail
        with pytest.raises(ValidationError):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="x" * 8193
            )
    
    def test_control_character_cleaning(self):
        """Test control character removal from messages."""
        message_with_control = "Test\x00message\x01with\x02control\x03chars"
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test",
            level="INFO",
            message=message_with_control
        )
        # Control characters should be removed
        assert "\x00" not in entry.message
        assert "Test" in entry.message
        assert "message" in entry.message


class TestOptionalFieldValidation:
    """Test optional field validation."""
    
    def test_facility_validation(self):
        """Test facility field validation."""
        valid_facilities = [
            "auth", "daemon", "mail", "kern", "local0",
            "custom_facility", "my-facility"
        ]
        
        for facility in valid_facilities:
            entry = LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="test",
                facility=facility
            )
            assert entry.facility == facility.lower()
    
    def test_process_id_validation(self):
        """Test process ID validation."""
        # Valid process IDs
        valid_pids = [0, 1, 1234, 65535]
        for pid in valid_pids:
            entry = LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="test",
                process_id=pid
            )
            assert entry.process_id == pid
        
        # Invalid process IDs
        with pytest.raises(ValidationError):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="test",
                process_id=-1
            )
        
        with pytest.raises(ValidationError):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="test",
                process_id=65536
            )
    
    def test_source_ip_validation(self):
        """Test source IP address validation."""
        # Valid IPv4
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test",
            level="INFO",
            message="test",
            source_ip="192.168.1.100"
        )
        assert isinstance(entry.source_ip, IPv4Address)
        
        # Valid IPv6
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test",
            level="INFO",
            message="test",
            source_ip="2001:db8::1"
        )
        assert isinstance(entry.source_ip, IPv6Address)
        
        # Invalid IP
        with pytest.raises(ValidationError, match="Invalid IP address format"):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="test",
                source_ip="invalid.ip.address"
            )
    
    def test_metadata_validation(self):
        """Test metadata dictionary validation."""
        # Valid metadata
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test",
            level="INFO",
            message="test",
            metadata={
                "user_id": "12345",
                "session_id": "abc123",
                "error_code": 404,
                "retry_count": 3
            }
        )
        assert len(entry.metadata) == 4
        
        # Too many fields
        large_metadata = {f"field_{i}": i for i in range(51)}
        with pytest.raises(ValidationError, match="Too many metadata fields"):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="test",
                metadata=large_metadata
            )
        
        # Invalid key format
        with pytest.raises(ValidationError, match="Invalid metadata key format"):
            LogEntry(
                timestamp="2024-01-15T10:30:45Z",
                device="test",
                level="INFO",
                message="test",
                metadata={"invalid-key!": "value"}
            )


class TestLogEntryMethods:
    """Test LogEntry utility methods."""
    
    def test_to_elasticsearch_doc(self):
        """Test Elasticsearch document conversion."""
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test-server",
            level="INFO",
            message="Test message",
            source_ip="192.168.1.100",
            metadata={"user": "john"}
        )
        
        doc = entry.to_elasticsearch_doc()
        
        assert "index_name" not in doc  # Should be excluded
        assert doc["device"] == "test-server"
        assert doc["level"] == "INFO"
        assert doc["source_ip"] == "192.168.1.100"  # Converted to string
        assert "timestamp" in doc
        assert isinstance(doc["timestamp"], str)  # ISO format string
    
    def test_get_search_text(self):
        """Test search text generation."""
        entry = LogEntry(
            timestamp="2024-01-15T10:30:45Z",
            device="test-server",
            level="INFO",
            message="User login failed",
            facility="auth",
            process_name="sshd",
            metadata={"user": "john", "count": 5}
        )
        
        search_text = entry.get_search_text()
        
        assert "User login failed" in search_text
        assert "test-server" in search_text
        assert "auth" in search_text
        assert "sshd" in search_text
        assert "john" in search_text  # String metadata value
        # Numeric metadata should not be included
        assert "5" not in search_text
    
    def test_config_example(self):
        """Test that the config example is valid."""
        example_data = {
            "timestamp": "2024-01-15T10:30:45Z",
            "device": "web-server-01",
            "level": "INFO",
            "message": "User login successful",
            "facility": "auth",
            "process_id": 1234,
            "process_name": "sshd",
            "source_ip": "192.168.1.100",
            "metadata": {
                "user_id": "john_doe",
                "session_id": "sess_abc123"
            }
        }
        
        # Should create valid LogEntry
        entry = LogEntry(**example_data)
        assert entry.device == "web-server-01"
        assert entry.level == LogLevel.INFO
        assert entry.message == "User login successful"