"""
Tests for custom validators and validation utilities.
"""

import pytest
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict, List

from pydantic import ValidationError

from syslog_mcp.models.validators import (
    validate_hostname, validate_ip_address_list, validate_mac_address_list,
    validate_tag_dictionary, validate_time_range_consistency, validate_log_message_content,
    validate_facility_name, validate_metadata_dictionary, validate_query_string,
    create_length_validator, create_range_validator, create_choice_validator,
    ValidationHelpers
)


class TestHostnameValidation:
    """Test hostname validation function."""
    
    def test_valid_hostnames(self):
        """Test valid hostname formats."""
        valid_hostnames = [
            "example.com",
            "web-server-01",
            "db.internal.local",
            "a.b.c.d.example.org",
            "test123",
            "my-host",
            "192.168.1.1",
            "2001:db8::1"
        ]
        
        for hostname in valid_hostnames:
            result = validate_hostname(hostname)
            assert result == hostname.lower()
    
    def test_hostname_normalization(self):
        """Test hostname case normalization."""
        result = validate_hostname("  TEST-SERVER.EXAMPLE.COM  ")
        assert result == "test-server.example.com"
    
    def test_invalid_hostnames(self):
        """Test invalid hostname formats."""
        invalid_hostnames = [
            "",
            "   ",
            "host_with_underscores",  # Underscores not allowed in hostnames
            "host..double.dot",
            "host.",
            ".host",
            "-startswithdassh",
            "endswithdassh-",
            "a" * 64,  # Label too long
            "a" * 254  # Hostname too long
        ]
        
        for hostname in invalid_hostnames:
            with pytest.raises(ValueError):
                validate_hostname(hostname)
    
    def test_ip_addresses_as_hostnames(self):
        """Test that IP addresses are valid hostnames."""
        ipv4 = validate_hostname("192.168.1.100")
        assert ipv4 == "192.168.1.100"
        
        ipv6 = validate_hostname("2001:db8::1")
        assert ipv6 == "2001:db8::1"


class TestIPAddressValidation:
    """Test IP address list validation."""
    
    def test_single_ipv4_string(self):
        """Test validation of single IPv4 string."""
        result = validate_ip_address_list("192.168.1.1")
        assert len(result) == 1
        assert isinstance(result[0], IPv4Address)
        assert str(result[0]) == "192.168.1.1"
    
    def test_single_ipv6_string(self):
        """Test validation of single IPv6 string."""
        result = validate_ip_address_list("2001:db8::1")
        assert len(result) == 1
        assert isinstance(result[0], IPv6Address)
        assert str(result[0]) == "2001:db8::1"
    
    def test_multiple_ip_addresses(self):
        """Test validation of multiple IP addresses."""
        ips = ["192.168.1.1", "10.0.0.1", "2001:db8::1"]
        result = validate_ip_address_list(ips)
        
        assert len(result) == 3
        assert isinstance(result[0], IPv4Address)
        assert isinstance(result[1], IPv4Address)
        assert isinstance(result[2], IPv6Address)
    
    def test_duplicate_removal(self):
        """Test that duplicate IPs are removed."""
        ips = ["192.168.1.1", "192.168.1.1", "10.0.0.1"]
        result = validate_ip_address_list(ips)
        
        assert len(result) == 2
        assert str(result[0]) == "192.168.1.1"
        assert str(result[1]) == "10.0.0.1"
    
    def test_empty_list_handling(self):
        """Test empty list handling."""
        # Allow empty by default
        result = validate_ip_address_list([])
        assert result == []
        
        # Disallow empty
        with pytest.raises(ValueError, match="At least one IP address is required"):
            validate_ip_address_list([], allow_empty=False)
    
    def test_invalid_ip_addresses(self):
        """Test invalid IP address handling."""
        invalid_ips = [
            "256.256.256.256",
            "192.168.1",
            "invalid.ip.address",
            "gggg::1"
        ]
        
        for ip in invalid_ips:
            with pytest.raises(ValueError, match="Invalid IP address"):
                validate_ip_address_list([ip])
    
    def test_max_addresses_limit(self):
        """Test maximum addresses limit."""
        # Within limit
        ips = [f"192.168.1.{i}" for i in range(1, 6)]
        result = validate_ip_address_list(ips, max_addresses=5)
        assert len(result) == 5
        
        # Over limit
        ips = [f"192.168.1.{i}" for i in range(1, 12)]
        with pytest.raises(ValueError, match="Too many IP addresses"):
            validate_ip_address_list(ips, max_addresses=5)


class TestMACAddressValidation:
    """Test MAC address validation."""
    
    def test_valid_mac_formats(self):
        """Test valid MAC address formats."""
        valid_macs = [
            "aa:bb:cc:dd:ee:ff",
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "01:23:45:67:89:ab"
        ]
        
        for mac in valid_macs:
            result = validate_mac_address_list([mac])
            assert len(result) == 1
            # Should normalize to lowercase with colons
            assert result[0] == mac.lower().replace('-', ':')
    
    def test_mac_normalization(self):
        """Test MAC address normalization."""
        result = validate_mac_address_list(["AA-BB-CC-DD-EE-FF"])
        assert result[0] == "aa:bb:cc:dd:ee:ff"
    
    def test_invalid_mac_addresses(self):
        """Test invalid MAC addresses."""
        invalid_macs = [
            "aa:bb:cc:dd:ee",  # Too short
            "aa:bb:cc:dd:ee:ff:gg",  # Too long
            "gg:bb:cc:dd:ee:ff",  # Invalid hex
            "aa:bb:cc:dd:ee:ff:gg:hh"  # Wrong format
        ]
        
        for mac in invalid_macs:
            with pytest.raises(ValueError, match="Invalid MAC address format"):
                validate_mac_address_list([mac])
    
    def test_duplicate_mac_removal(self):
        """Test duplicate MAC removal."""
        macs = ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "11:22:33:44:55:66"]
        result = validate_mac_address_list(macs)
        
        # First two are duplicates after normalization
        assert len(result) == 2
        assert "aa:bb:cc:dd:ee:ff" in result
        assert "11:22:33:44:55:66" in result


class TestTagDictionaryValidation:
    """Test tag dictionary validation."""
    
    def test_valid_tags(self):
        """Test valid tag dictionary."""
        tags = {
            "environment": "production",
            "team": "platform",
            "version": "1.2.3",
            "backup_enabled": "true"
        }
        
        result = validate_tag_dictionary(tags)
        assert len(result) == 4
        assert result["environment"] == "production"
    
    def test_tag_key_normalization(self):
        """Test tag key normalization to lowercase."""
        tags = {"ENVIRONMENT": "prod", "Team": "platform"}
        result = validate_tag_dictionary(tags)
        
        assert "environment" in result
        assert "team" in result
        assert result["environment"] == "prod"
    
    def test_invalid_tag_keys(self):
        """Test invalid tag key formats."""
        invalid_tags = [
            {"123invalid": "value"},  # Can't start with number
            {"invalid-key!": "value"},  # Invalid character
            {"": "value"},  # Empty key
            {"a" * 50: "value"}  # Too long
        ]
        
        for tags in invalid_tags:
            with pytest.raises(ValueError):
                validate_tag_dictionary(tags)
    
    def test_tag_value_length_limit(self):
        """Test tag value length limits."""
        long_value = "x" * 100
        tags = {"test": long_value}
        
        with pytest.raises(ValueError, match="Tag value too long"):
            validate_tag_dictionary(tags, max_value_length=50)
    
    def test_too_many_tags(self):
        """Test maximum tag count limit."""
        many_tags = {f"tag_{i}": f"value_{i}" for i in range(25)}
        
        with pytest.raises(ValueError, match="Too many tags"):
            validate_tag_dictionary(many_tags, max_tags=20)
    
    def test_empty_tag_dictionary(self):
        """Test empty tag dictionary handling."""
        result = validate_tag_dictionary({})
        assert result == {}
        
        result = validate_tag_dictionary(None)
        assert result == {}


class TestTimeRangeValidation:
    """Test time range consistency validation."""
    
    def test_valid_time_range(self):
        """Test valid time range."""
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 2, tzinfo=timezone.utc)
        
        # Should not raise exception
        validate_time_range_consistency(start, end)
    
    def test_invalid_time_order(self):
        """Test invalid time order."""
        start = datetime(2024, 1, 2, tzinfo=timezone.utc)
        end = datetime(2024, 1, 1, tzinfo=timezone.utc)  # Before start
        
        with pytest.raises(ValueError, match="End time must be after start time"):
            validate_time_range_consistency(start, end)
    
    def test_time_range_too_large(self):
        """Test time range too large."""
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 4, 1, tzinfo=timezone.utc)  # 3 months
        
        with pytest.raises(ValueError, match="Time range too large"):
            validate_time_range_consistency(start, end, max_range_days=30)
    
    def test_future_timestamps(self):
        """Test future timestamp validation."""
        now = datetime.now(timezone.utc)
        future = now + timedelta(hours=1)
        
        with pytest.raises(ValueError, match="cannot be in the future"):
            validate_time_range_consistency(future, None)
    
    def test_near_future_tolerance(self):
        """Test tolerance for near-future timestamps."""
        now = datetime.now(timezone.utc)
        near_future = now + timedelta(minutes=2)  # Within tolerance
        
        # Should not raise exception
        validate_time_range_consistency(near_future, None)


class TestLogMessageValidation:
    """Test log message content validation."""
    
    def test_valid_messages(self):
        """Test valid log messages."""
        valid_messages = [
            "Simple log message",
            "Message with numbers 123",
            "Multi-line\nmessage here",
            "Message with special chars: @#$%^&*()",
            "Message with\ttabs\tand\nlines"
        ]
        
        for message in valid_messages:
            result = validate_log_message_content(message)
            assert result == message.strip()
    
    def test_message_length_limit(self):
        """Test message length validation."""
        long_message = "x" * 5000
        result = validate_log_message_content(long_message, max_length=6000)
        assert len(result) == 5000
        
        # Over limit
        with pytest.raises(ValueError, match="Log message too long"):
            validate_log_message_content(long_message, max_length=1000)
    
    def test_empty_message_validation(self):
        """Test empty message handling."""
        empty_messages = ["", "   ", "\n\n\n", "\t\t\t"]
        
        for message in empty_messages:
            with pytest.raises(ValueError, match="Log message cannot be empty"):
                validate_log_message_content(message)
    
    def test_control_character_removal(self):
        """Test control character removal."""
        message_with_control = "Test\x00message\x01with\x02control\x03chars"
        result = validate_log_message_content(message_with_control)
        
        # Control characters should be removed
        assert "\x00" not in result
        assert "\x01" not in result
        assert "Test" in result
        assert "message" in result
    
    def test_control_characters_only(self):
        """Test message with only control characters."""
        control_only = "\x00\x01\x02\x03"
        
        with pytest.raises(ValueError, match="contains only control characters"):
            validate_log_message_content(control_only)


class TestFacilityValidation:
    """Test facility name validation."""
    
    def test_standard_facilities(self):
        """Test standard RFC 5424 facilities."""
        standard_facilities = [
            "auth", "daemon", "mail", "kern", "local0", "syslog"
        ]
        
        for facility in standard_facilities:
            result = validate_facility_name(facility)
            assert result == facility.lower()
    
    def test_custom_facilities(self):
        """Test custom facility names."""
        custom_facilities = ["myapp", "web_server", "custom-facility"]
        
        for facility in custom_facilities:
            result = validate_facility_name(facility)
            assert result == facility.lower()
    
    def test_invalid_facilities(self):
        """Test invalid facility names."""
        invalid_facilities = [
            "123invalid",  # Can't start with number
            "facility!",   # Invalid character
            "a" * 50      # Too long
        ]
        
        for facility in invalid_facilities:
            with pytest.raises(ValueError, match="Invalid facility"):
                validate_facility_name(facility)
    
    def test_empty_facility(self):
        """Test empty facility handling."""
        assert validate_facility_name(None) is None
        assert validate_facility_name("") is None
        assert validate_facility_name("   ") is None


class TestMetadataValidation:
    """Test metadata dictionary validation."""
    
    def test_valid_metadata(self):
        """Test valid metadata dictionary."""
        metadata = {
            "user_id": "12345",
            "session_id": "abc123",
            "error_code": 404,
            "retry_count": 3,
            "timestamp": "2024-01-01T12:00:00Z"
        }
        
        result = validate_metadata_dictionary(metadata)
        assert len(result) == 5
        assert result["user_id"] == "12345"
    
    def test_metadata_key_validation(self):
        """Test metadata key validation."""
        # Valid keys
        valid_metadata = {
            "user_id": "123",
            "session_info": "data",
            "trace.id": "trace123"
        }
        result = validate_metadata_dictionary(valid_metadata)
        assert len(result) == 3
        
        # Invalid keys
        invalid_keys = ["123invalid", "key!", "", "a" * 100]
        for key in invalid_keys:
            with pytest.raises(ValueError):
                validate_metadata_dictionary({key: "value"})
    
    def test_string_value_truncation(self):
        """Test string value truncation."""
        long_value = "x" * 2000
        metadata = {"test": long_value}
        
        result = validate_metadata_dictionary(metadata, max_string_value_length=100)
        assert len(result["test"]) == 103  # 100 + "..."
        assert result["test"].endswith("...")
    
    def test_too_many_fields(self):
        """Test maximum field count limit."""
        many_fields = {f"field_{i}": i for i in range(60)}
        
        with pytest.raises(ValueError, match="Too many metadata fields"):
            validate_metadata_dictionary(many_fields, max_fields=50)


class TestQueryStringValidation:
    """Test query string validation."""
    
    def test_valid_query_strings(self):
        """Test valid query strings."""
        valid_queries = [
            "authentication failed",
            "error AND database",
            "level:ERROR",
            "device:web-* AND timestamp:[now-1d TO now]",
            "message:/error.*/i"
        ]
        
        for query in valid_queries:
            result = validate_query_string(query)
            assert result == query
    
    def test_query_length_limit(self):
        """Test query length validation."""
        long_query = "test " * 300
        
        with pytest.raises(ValueError, match="Query string too long"):
            validate_query_string(long_query, max_length=500)
    
    def test_dangerous_content_detection(self):
        """Test detection of dangerous query content."""
        dangerous_queries = [
            "eval(document.cookie)",
            "exec('rm -rf /')",
            "<script>alert('xss')</script>",
            "javascript:alert('xss')"
        ]
        
        for query in dangerous_queries:
            with pytest.raises(ValueError, match="potentially unsafe content"):
                validate_query_string(query)
    
    def test_empty_query_handling(self):
        """Test empty query handling."""
        assert validate_query_string(None) is None
        assert validate_query_string("") is None
        assert validate_query_string("   ") is None


class TestValidatorFactories:
    """Test validator factory functions."""
    
    def test_length_validator(self):
        """Test length validator factory."""
        validator = create_length_validator(min_length=3, max_length=10, field_name="username")
        
        # Valid length
        result = validator("testuser")
        assert result == "testuser"
        
        # Too short
        with pytest.raises(ValueError, match="username too short"):
            validator("ab")
        
        # Too long
        with pytest.raises(ValueError, match="username too long"):
            validator("verylongusername")
    
    def test_range_validator(self):
        """Test range validator factory."""
        validator = create_range_validator(min_value=0, max_value=100, field_name="score")
        
        # Valid range
        assert validator(50) == 50
        assert validator(0.5) == 0.5
        
        # Out of range
        with pytest.raises(ValueError, match="score too small"):
            validator(-1)
        
        with pytest.raises(ValueError, match="score too large"):
            validator(101)
    
    def test_choice_validator(self):
        """Test choice validator factory."""
        validator = create_choice_validator(
            allowed_values=["red", "green", "blue"],
            case_sensitive=False,
            field_name="color"
        )
        
        # Valid choices
        assert validator("red") == "red"
        assert validator("RED") == "red"  # Case insensitive match
        
        # Invalid choice
        with pytest.raises(ValueError, match="Invalid color"):
            validator("yellow")


class TestValidationHelpers:
    """Test ValidationHelpers utility class."""
    
    def test_email_validation(self):
        """Test email validation helper."""
        valid_emails = [
            "user@example.com",
            "test.email+tag@domain.co.uk",
            "user123@test-domain.com"
        ]
        
        invalid_emails = [
            "invalid.email",
            "@domain.com",
            "user@",
            "user space@domain.com"
        ]
        
        for email in valid_emails:
            assert ValidationHelpers.is_valid_email(email) is True
        
        for email in invalid_emails:
            assert ValidationHelpers.is_valid_email(email) is False
    
    def test_url_validation(self):
        """Test URL validation helper."""
        valid_urls = [
            "https://example.com",
            "http://test.domain.co.uk/path",
            "https://api.service.com/v1/endpoint?param=value"
        ]
        
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "https://",
            "file:///etc/passwd"
        ]
        
        for url in valid_urls:
            assert ValidationHelpers.is_valid_url(url) is True
        
        for url in invalid_urls:
            assert ValidationHelpers.is_valid_url(url) is False
    
    def test_whitespace_normalization(self):
        """Test whitespace normalization."""
        text = "  multiple   spaces    here  "
        result = ValidationHelpers.normalize_whitespace(text)
        assert result == "multiple spaces here"
    
    def test_filename_sanitization(self):
        """Test filename sanitization."""
        unsafe_filename = 'file<>:"/\\|?*name.txt'
        result = ValidationHelpers.sanitize_filename(unsafe_filename)
        assert result == "file_________name.txt"
        
        # Test length limit
        long_filename = "a" * 300
        result = ValidationHelpers.sanitize_filename(long_filename)
        assert len(result) <= 255
    
    def test_json_structure_validation(self):
        """Test JSON structure validation."""
        # Valid structure
        data = {"name": "test", "age": 30, "email": "test@example.com"}
        required = ["name", "age"]
        optional = ["email", "phone"]
        
        result = ValidationHelpers.validate_json_structure(data, required, optional)
        assert result == data
        
        # Missing required field
        incomplete_data = {"name": "test"}
        with pytest.raises(ValueError, match="Missing required fields"):
            ValidationHelpers.validate_json_structure(incomplete_data, required, optional)
        
        # Unexpected field
        extra_data = {"name": "test", "age": 30, "unexpected": "value"}
        with pytest.raises(ValueError, match="Unexpected fields"):
            ValidationHelpers.validate_json_structure(extra_data, required, optional)