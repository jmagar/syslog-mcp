"""
Log entry models with comprehensive validation and timezone handling.

Provides Pydantic models for syslog data with custom validators,
timezone-aware datetime parsing, and structured metadata handling.
"""

import re
from datetime import UTC, datetime
from enum import Enum
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class LogLevel(str, Enum):
    """
    Syslog severity levels with RFC 5424 compatibility.

    Supports both numeric and string representations with
    case-insensitive parsing and normalization.
    """

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    WARNING = "WARNING"  # Alias for WARN
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    FATAL = "FATAL"  # Alias for CRITICAL

    @classmethod
    def normalize(cls, value: str | int) -> "LogLevel":
        """
        Normalize various log level representations to standard enum values.

        Args:
            value: Log level as string or RFC 5424 numeric code

        Returns:
            Normalized LogLevel enum value

        Raises:
            ValueError: If value cannot be normalized to a valid log level
        """
        if isinstance(value, int):
            # RFC 5424 numeric severity codes
            level_map = {
                0: cls.CRITICAL,  # Emergency
                1: cls.CRITICAL,  # Alert
                2: cls.CRITICAL,  # Critical
                3: cls.ERROR,     # Error
                4: cls.WARN,      # Warning
                5: cls.INFO,      # Notice
                6: cls.INFO,      # Informational
                7: cls.DEBUG,     # Debug
            }
            if value in level_map:
                return level_map[value]
            raise ValueError(f"Invalid numeric log level: {value}")

        if isinstance(value, str):
            # Normalize string representations
            normalized = value.upper().strip()

            # Handle common aliases
            alias_map = {
                "WARNING": cls.WARN,
                "FATAL": cls.CRITICAL,
                "NOTICE": cls.INFO,
                "INFORMATIONAL": cls.INFO,
                "INFORMATION": cls.INFO,
                "ERR": cls.ERROR,
                "CRIT": cls.CRITICAL,
            }

            if normalized in alias_map:
                return alias_map[normalized]

            # Try direct enum match
            for level in cls:
                if level.value == normalized:
                    return level

            raise ValueError(f"Invalid log level: {value}")

        raise ValueError(f"Invalid log level type: {type(value)}")


class LogEntry(BaseModel):
    """
    Comprehensive syslog entry model with validation and timezone handling.

    Represents a single log message with structured fields, metadata,
    and proper datetime handling for various input formats.
    """

    # Core required fields
    timestamp: datetime = Field(
        ...,
        description="Log entry timestamp with timezone information",
        examples=["2024-01-15T10:30:45Z", "2024-01-15 10:30:45 UTC"]
    )

    device: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Source device or hostname",
        examples=["web-server-01", "firewall.local", "192.168.1.100"]
    )

    level: LogLevel = Field(
        ...,
        description="Log severity level",
        examples=["INFO", "ERROR", "DEBUG"]
    )

    message: str = Field(
        ...,
        min_length=1,
        max_length=8192,
        description="Log message content",
        examples=["User authentication successful", "Database connection failed"]
    )

    # Optional fields with defaults
    facility: str | None = Field(
        None,
        max_length=64,
        description="Syslog facility (mail, auth, cron, etc.)",
        examples=["auth", "mail", "daemon"]
    )

    process_id: int | None = Field(
        None,
        ge=0,
        le=65535,
        description="Process ID that generated the log",
        examples=[1234, 5678]
    )

    process_name: str | None = Field(
        None,
        max_length=64,
        description="Name of the process that generated the log",
        examples=["sshd", "nginx", "mysqld"]
    )

    source_ip: IPv4Address | IPv6Address | None = Field(
        None,
        description="Source IP address if available",
        examples=["192.168.1.100", "2001:db8::1"]
    )

    metadata: dict[str, Any] | None = Field(
        default_factory=dict,
        description="Additional structured metadata",
        examples=[{"user_id": "12345", "session_id": "abc123"}]
    )

    # Elasticsearch indexing fields
    index_name: str | None = Field(
        None,
        description="Target Elasticsearch index for this entry",
        examples=["syslog-2024-01", "logs-web-server"]
    )

    # Computed fields
    parsed_at: datetime | None = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when this entry was parsed"
    )

    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        """
        Parse timestamp from various formats with timezone handling.

        Supports multiple datetime formats commonly found in syslog entries:
        - ISO 8601 with timezone
        - RFC 3164 format
        - Unix timestamps
        - Various string formats
        """
        if isinstance(v, datetime):
            # Ensure timezone awareness
            if v.tzinfo is None:
                return v.replace(tzinfo=UTC)
            return v

        if isinstance(v, int | float):
            # Unix timestamp
            return datetime.fromtimestamp(v, tz=UTC)

        if isinstance(v, str):
            # Common datetime string formats
            formats = [
                # ISO 8601 variants
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                # RFC 3164 format
                "%b %d %H:%M:%S",
                "%b  %d %H:%M:%S",  # Single digit day
                # Common formats
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y/%m/%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
                # With timezone info
                "%Y-%m-%d %H:%M:%S %Z",
                "%Y-%m-%d %H:%M:%S %z",
            ]

            # Try parsing with each format
            for fmt in formats:
                try:
                    dt = datetime.strptime(v.strip(), fmt)
                    # Add UTC timezone if none specified
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=UTC)
                    return dt
                except ValueError:
                    continue

            # If no format matched, try parsing with dateutil as fallback
            try:
                from dateutil import parser
                dt = parser.parse(v)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            except ImportError:
                pass
            except (ValueError, TypeError):
                pass

        raise ValueError(f"Unable to parse timestamp: {v}")

    @field_validator('device', mode='before')
    @classmethod
    def validate_device(cls, v: Any) -> str:
        """
        Validate and normalize device names.

        Accepts hostnames, IP addresses, and device identifiers
        with proper validation and normalization.
        """
        if not isinstance(v, str):
            v = str(v)

        device = v.strip()
        if not device:
            raise ValueError("Device name cannot be empty")

        # Check if it's an IP address
        try:
            # IPv4 or IPv6 address is valid
            IPv4Address(device)
            return str(device)
        except AddressValueError:
            try:
                IPv6Address(device)
                return str(device)
            except AddressValueError:
                pass

        # Validate hostname format
        # Allow alphanumeric, hyphens, dots, underscores
        hostname_pattern = re.compile(r'^[a-zA-Z0-9._-]+$')
        if not hostname_pattern.match(device):
            raise ValueError(f"Invalid device name format: {device}")

        # Check length constraints
        if len(device) > 255:
            raise ValueError(f"Device name too long: {len(device)} characters")

        return str(device.lower())  # Normalize to lowercase

    @field_validator('level', mode='before')
    @classmethod
    def validate_log_level(cls, v: Any) -> LogLevel:
        """
        Validate and normalize log levels from various representations.
        """
        return LogLevel.normalize(v)

    @field_validator('message')
    @classmethod
    def validate_message(cls, v: str) -> str:
        """
        Validate and clean log message content.
        """
        if not v or not v.strip():
            raise ValueError("Log message cannot be empty")

        # Strip leading/trailing whitespace but preserve internal spacing
        message = v.strip()

        # Remove control characters except newlines and tabs
        cleaned = ''.join(char for char in message
                         if ord(char) >= 32 or char in '\n\t')

        if not cleaned:
            raise ValueError("Log message contains only control characters")

        return cleaned

    @field_validator('facility', mode='before')
    @classmethod
    def validate_facility(cls, v: Any) -> str | None:
        """
        Validate syslog facility names.
        """
        if v is None:
            return None

        if not isinstance(v, str):
            v = str(v)

        facility = v.strip().lower()
        if not facility:
            return None

        # RFC 5424 standard facilities
        valid_facilities = {
            'kern', 'user', 'mail', 'daemon', 'auth', 'syslog',
            'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp',
            'ntp', 'security', 'console', 'local0', 'local1',
            'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
        }

        if facility not in valid_facilities:
            # Allow custom facilities but validate format
            if not re.match(r'^[a-z][a-z0-9_-]*$', facility):
                raise ValueError(f"Invalid facility format: {facility}")

        return str(facility)

    @field_validator('source_ip', mode='before')
    @classmethod
    def validate_source_ip(cls, v: Any) -> IPv4Address | IPv6Address | None:
        """
        Validate IP addresses from various input formats.
        """
        if v is None or v == "":
            return None

        if isinstance(v, IPv4Address | IPv6Address):
            return v

        if isinstance(v, str):
            v = v.strip()
            if not v:
                return None

            try:
                # Try IPv4 first
                return IPv4Address(v)
            except AddressValueError:
                try:
                    # Try IPv6
                    return IPv6Address(v)
                except AddressValueError:
                    raise ValueError(f"Invalid IP address format: {v}")

        raise ValueError(f"Invalid IP address type: {type(v)}")

    @field_validator('metadata')
    @classmethod
    def validate_metadata(cls, v: dict[str, Any] | None) -> dict[str, Any]:
        """
        Validate and sanitize metadata dictionary.
        """
        if v is None:
            return {}

        if not isinstance(v, dict):
            raise ValueError("Metadata must be a dictionary")

        # Limit metadata size and depth
        if len(v) > 50:
            raise ValueError("Too many metadata fields (max 50)")

        # Validate keys and basic structure
        sanitized = {}
        for key, value in v.items():
            if not isinstance(key, str):
                key = str(key)

            # Validate key format
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_.-]*$', key):
                raise ValueError(f"Invalid metadata key format: {key}")

            if len(key) > 64:
                raise ValueError(f"Metadata key too long: {key}")

            # Basic value sanitization
            if isinstance(value, str) and len(value) > 1024:
                value = value[:1024] + "..."

            sanitized[key] = value

        return sanitized

    @model_validator(mode='after')
    def validate_consistency(self) -> 'LogEntry':
        """
        Cross-field validation for data consistency.
        """
        # Ensure timestamp is not in the future (with some tolerance)
        now = datetime.now(UTC)
        if self.timestamp > now.replace(microsecond=0):
            # Allow up to 5 minutes in the future for clock skew
            max_future = now.replace(microsecond=0, second=0, minute=now.minute + 5)
            if self.timestamp > max_future:
                raise ValueError(f"Timestamp too far in future: {self.timestamp}")

        # Generate index name if not provided
        if not self.index_name:
            date_str = self.timestamp.strftime("%Y-%m")
            self.index_name = f"syslog-{date_str}"

        return self

    def to_elasticsearch_doc(self) -> dict[str, Any]:
        """
        Convert to Elasticsearch document format.

        Returns:
            Dictionary suitable for Elasticsearch indexing
        """
        doc = self.model_dump(
            exclude={'index_name'},
            by_alias=True
        )

        # Ensure proper datetime serialization
        doc['timestamp'] = self.timestamp.isoformat()
        if self.parsed_at:
            doc['parsed_at'] = self.parsed_at.isoformat()

        # Convert IP addresses to strings
        if self.source_ip:
            doc['source_ip'] = str(self.source_ip)

        return doc

    def get_search_text(self) -> str:
        """
        Get searchable text content for full-text search.

        Returns:
            Combined searchable text from message, device, and metadata
        """
        parts = [self.message, self.device]

        if self.process_name:
            parts.append(self.process_name)

        if self.facility:
            parts.append(self.facility)

        # Add metadata values that are strings
        if self.metadata:
            for value in self.metadata.values():
                if isinstance(value, str):
                    parts.append(value)

        return " ".join(parts)

    model_config = {
        # Allow population by field name or alias
        "populate_by_name": True,

        # JSON schema customization
        "json_schema_extra": {
            "example": {
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
        }
    }
