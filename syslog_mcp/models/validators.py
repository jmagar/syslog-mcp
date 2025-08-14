"""
Custom validators and validation utilities for Pydantic models.

Provides reusable validation functions, custom field validators,
and specialized validation logic for syslog data processing.
"""

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Any


def validate_device(value: Any) -> str:
    """
    Validate device name format according to RFC standards.

    Accepts:
    - Standard device names (alphanumeric, hyphens, dots)
    - IP addresses (IPv4 and IPv6)
    - Fully qualified domain names

    Args:
        value: Value to validate as device name

    Returns:
        Normalized device name string

    Raises:
        ValueError: If device name format is invalid
    """
    if not isinstance(value, str):
        value = str(value)

    device_name = value.strip().lower()
    if not device_name:
        raise ValueError("Device name cannot be empty")

    # Check length constraints
    if len(device_name) > 253:
        raise ValueError(f"Device name too long: {len(device_name)} characters (max 253)")

    # Check if it's an IP address (valid device name)
    try:
        IPv4Address(device_name)
        return str(device_name)
    except AddressValueError:
        try:
            IPv6Address(device_name)
            return str(device_name)
        except AddressValueError:
            pass

    # Validate as device name/FQDN
    # Each label can be 1-63 characters
    labels = device_name.split('.')
    if len(labels) > 127:
        raise ValueError("Too many labels in device name")

    for label in labels:
        if not label:
            raise ValueError("Empty label in device name")

        if len(label) > 63:
            raise ValueError(f"Label too long: {label} ({len(label)} characters, max 63)")

        # Label must start and end with alphanumeric
        if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', label):
            raise ValueError(f"Invalid label format: {label}")

    return str(device_name)


def validate_ip_address_list(
    value: Any,
    max_addresses: int = 10,
    allow_empty: bool = True
) -> list[IPv4Address | IPv6Address]:
    """
    Validate and normalize a list of IP addresses.

    Args:
        value: IP address or list of IP addresses
        max_addresses: Maximum number of addresses allowed
        allow_empty: Whether empty list is allowed

    Returns:
        List of validated IP address objects

    Raises:
        ValueError: If IP addresses are invalid or constraints violated
    """
    if not value:
        if allow_empty:
            return []
        raise ValueError("At least one IP address is required")

    # Convert single IP to list
    if isinstance(value, str):
        value = [value]
    elif isinstance(value, IPv4Address | IPv6Address):
        value = [value]

    if not isinstance(value, list):
        raise ValueError("IP addresses must be a string or list")

    if len(value) > max_addresses:
        raise ValueError(f"Too many IP addresses: {len(value)} (max {max_addresses})")

    validated_ips = []
    seen_ips = set()

    for ip in value:
        if isinstance(ip, IPv4Address | IPv6Address):
            ip_obj = ip
            ip_str = str(ip)
        elif isinstance(ip, str):
            ip = ip.strip()
            if not ip:
                continue

            try:
                # Try IPv4 first
                ip_obj = IPv4Address(ip)
                ip_str = str(ip_obj)
            except AddressValueError:
                try:
                    # Try IPv6
                    ip_obj = IPv6Address(ip)
                    ip_str = str(ip_obj)
                except AddressValueError as e:
                    raise ValueError(f"Invalid IP address: {ip}") from e
        else:
            raise ValueError(f"Invalid IP address type: {type(ip)}")

        # Avoid duplicates
        if ip_str not in seen_ips:
            seen_ips.add(ip_str)
            validated_ips.append(ip_obj)

    return validated_ips


def validate_mac_address_list(
    value: Any,
    max_addresses: int = 5,
    allow_empty: bool = True
) -> list[str]:
    """
    Validate and normalize MAC addresses.

    Args:
        value: MAC address or list of MAC addresses
        max_addresses: Maximum number of addresses allowed
        allow_empty: Whether empty list is allowed

    Returns:
        List of normalized MAC addresses

    Raises:
        ValueError: If MAC addresses are invalid
    """
    if not value:
        if allow_empty:
            return []
        raise ValueError("At least one MAC address is required")

    if isinstance(value, str):
        value = [value]

    if not isinstance(value, list):
        raise ValueError("MAC addresses must be a string or list")

    if len(value) > max_addresses:
        raise ValueError(f"Too many MAC addresses: {len(value)} (max {max_addresses})")

    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    validated_macs = []
    seen_macs = set()

    for mac in value:
        if not isinstance(mac, str):
            mac = str(mac)

        mac = mac.strip().lower()
        if not mac:
            continue

        # Normalize separators to colons
        mac = mac.replace('-', ':')

        if not mac_pattern.match(mac):
            raise ValueError(f"Invalid MAC address format: {mac}")

        if mac not in seen_macs:
            seen_macs.add(mac)
            validated_macs.append(mac)

    return validated_macs


def validate_tag_dictionary(
    value: Any,
    max_tags: int = 20,
    max_key_length: int = 32,
    max_value_length: int = 64
) -> dict[str, str]:
    """
    Validate tag dictionary with key/value constraints.

    Args:
        value: Dictionary of tags
        max_tags: Maximum number of tags
        max_key_length: Maximum key length
        max_value_length: Maximum value length

    Returns:
        Validated and normalized tag dictionary

    Raises:
        ValueError: If tags violate constraints
    """
    if not value:
        return {}

    if not isinstance(value, dict):
        raise ValueError("Tags must be a dictionary")

    if len(value) > max_tags:
        raise ValueError(f"Too many tags: {len(value)} (max {max_tags})")

    validated_tags = {}
    key_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.-]*$')

    for key, val in value.items():
        # Normalize key and value to strings
        if not isinstance(key, str):
            key = str(key)
        if not isinstance(val, str):
            val = str(val)

        key = key.strip()
        val = val.strip()

        # Validate key format
        if not key:
            raise ValueError("Tag key cannot be empty")

        if len(key) > max_key_length:
            raise ValueError(f"Tag key too long: {key} ({len(key)} chars, max {max_key_length})")

        if not key_pattern.match(key):
            raise ValueError(f"Invalid tag key format: {key}")

        # Validate value
        if len(val) > max_value_length:
            raise ValueError(f"Tag value too long for key '{key}': {val} ({len(val)} chars, max {max_value_length})")

        validated_tags[key.lower()] = val

    return validated_tags


def validate_time_range_consistency(
    start_time: datetime | None,
    end_time: datetime | None,
    max_range_days: int = 90
) -> None:
    """
    Validate time range consistency and constraints.

    Args:
        start_time: Range start time
        end_time: Range end time
        max_range_days: Maximum allowed range in days

    Raises:
        ValueError: If time range is invalid
    """
    if start_time and end_time:
        if end_time <= start_time:
            raise ValueError("End time must be after start time")

        range_duration = end_time - start_time
        if range_duration.days > max_range_days:
            raise ValueError(f"Time range too large: {range_duration.days} days (max {max_range_days})")

    # Check for future timestamps (with tolerance)
    now = datetime.now(UTC)
    tolerance = timedelta(minutes=5)

    if start_time and start_time > now + tolerance:
        raise ValueError("Start time cannot be in the future")

    if end_time and end_time > now + tolerance:
        raise ValueError("End time cannot be in the future")


def validate_log_message_content(value: str, max_length: int = 8192) -> str:
    """
    Validate and sanitize log message content.

    Args:
        value: Log message string
        max_length: Maximum message length

    Returns:
        Cleaned and validated message

    Raises:
        ValueError: If message is invalid
    """
    if not isinstance(value, str):
        value = str(value)

    # Strip whitespace but preserve internal formatting
    message = value.strip()

    if not message:
        raise ValueError("Log message cannot be empty")

    if len(message) > max_length:
        raise ValueError(f"Log message too long: {len(message)} characters (max {max_length})")

    # Remove control characters except newlines, tabs, and carriage returns
    cleaned = ''.join(
        char for char in message
        if ord(char) >= 32 or char in '\n\t\r'
    )

    if not cleaned.strip():
        raise ValueError("Log message contains only control characters")

    return cleaned


def validate_facility_name(value: str | None) -> str | None:
    """
    Validate syslog facility name.

    Args:
        value: Facility name string

    Returns:
        Validated facility name or None

    Raises:
        ValueError: If facility name is invalid
    """
    if not value:
        return None

    if not isinstance(value, str):
        value = str(value)

    facility = value.strip().lower()
    if not facility:
        return None

    # RFC 5424 standard facilities
    standard_facilities = {
        'kern', 'user', 'mail', 'daemon', 'auth', 'syslog',
        'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp',
        'ntp', 'security', 'console', 'local0', 'local1',
        'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
    }

    if facility in standard_facilities:
        return facility

    # Allow custom facilities with valid format
    if not re.match(r'^[a-z][a-z0-9_-]*$', facility):
        raise ValueError(f"Invalid facility name format: {facility}")

    if len(facility) > 32:
        raise ValueError(f"Facility name too long: {facility}")

    return facility


def validate_metadata_dictionary(
    value: dict[str, Any] | None,
    max_fields: int = 50,
    max_key_length: int = 64,
    max_string_value_length: int = 1024
) -> dict[str, Any]:
    """
    Validate metadata dictionary structure and content.

    Args:
        value: Metadata dictionary
        max_fields: Maximum number of fields
        max_key_length: Maximum key length
        max_string_value_length: Maximum string value length

    Returns:
        Validated metadata dictionary

    Raises:
        ValueError: If metadata violates constraints
    """
    if not value:
        return {}

    if not isinstance(value, dict):
        raise ValueError("Metadata must be a dictionary")

    if len(value) > max_fields:
        raise ValueError(f"Too many metadata fields: {len(value)} (max {max_fields})")

    validated_metadata = {}
    key_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_.-]*$')

    for key, val in value.items():
        # Normalize key
        if not isinstance(key, str):
            key = str(key)

        key = key.strip()

        # Validate key
        if not key:
            raise ValueError("Metadata key cannot be empty")

        if len(key) > max_key_length:
            raise ValueError(f"Metadata key too long: {key}")

        if not key_pattern.match(key):
            raise ValueError(f"Invalid metadata key format: {key}")

        # Validate and potentially truncate string values
        if isinstance(val, str) and len(val) > max_string_value_length:
            val = val[:max_string_value_length] + "..."

        validated_metadata[key] = val

    return validated_metadata


def validate_query_string(value: str | None, max_length: int = 1024) -> str | None:
    """
    Validate search query string.

    Args:
        value: Query string
        max_length: Maximum query length

    Returns:
        Validated query string or None

    Raises:
        ValueError: If query string is invalid
    """
    if not value:
        return None

    if not isinstance(value, str):
        value = str(value)

    query = value.strip()
    if not query:
        return None

    if len(query) > max_length:
        raise ValueError(f"Query string too long: {len(query)} characters (max {max_length})")

    # Basic validation - check for potentially dangerous patterns
    dangerous_patterns = [
        r'(^|[^a-zA-Z])eval\s*\(',
        r'(^|[^a-zA-Z])exec\s*\(',
        r'<script\s*>',
        r'javascript:',
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            raise ValueError("Query contains potentially unsafe content")

    return query


def create_length_validator(
    min_length: int = 0,
    max_length: int = 255,
    field_name: str = "field"
) -> Callable[[Any], str]:
    """
    Create a length validator function for string fields.

    Args:
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        field_name: Field name for error messages

    Returns:
        Validator function
    """
    def validate_length(value: Any) -> str:
        if not isinstance(value, str):
            value = str(value)

        value = value.strip()

        if len(value) < min_length:
            raise ValueError(f"{field_name} too short: {len(value)} characters (min {min_length})")

        if len(value) > max_length:
            raise ValueError(f"{field_name} too long: {len(value)} characters (max {max_length})")

        return str(value)

    return validate_length


def create_range_validator(
    min_value: int | float,
    max_value: int | float,
    field_name: str = "field"
) -> Callable[[int | float], int | float]:
    """
    Create a numeric range validator function.

    Args:
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        field_name: Field name for error messages

    Returns:
        Validator function
    """
    def validate_range(value: int | float) -> int | float:
        if not isinstance(value, int | float):
            raise ValueError(f"{field_name} must be numeric")

        if value < min_value:
            raise ValueError(f"{field_name} too small: {value} (min {min_value})")

        if value > max_value:
            raise ValueError(f"{field_name} too large: {value} (max {max_value})")

        return value

    return validate_range


def create_choice_validator(
    allowed_values: list[Any],
    case_sensitive: bool = True,
    field_name: str = "field"
) -> Callable[[Any], Any]:
    """
    Create a choice validator function for enumerated values.

    Args:
        allowed_values: List of allowed values
        case_sensitive: Whether comparison is case sensitive
        field_name: Field name for error messages

    Returns:
        Validator function
    """
    def validate_choice(value: Any) -> Any:
        if not case_sensitive and isinstance(value, str):
            # Compare lowercase versions
            normalized_value = value.lower()
            for allowed in allowed_values:
                if isinstance(allowed, str) and allowed.lower() == normalized_value:
                    return allowed

            raise ValueError(f"Invalid {field_name}: {value}. Allowed values: {allowed_values}")

        if value not in allowed_values:
            raise ValueError(f"Invalid {field_name}: {value}. Allowed values: {allowed_values}")

        return value

    return validate_choice


class ValidationHelpers:
    """
    Helper class with common validation utilities.
    """

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Check if string is a valid email address."""
        email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        return bool(email_pattern.match(email))

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if string is a valid URL."""
        url_pattern = re.compile(
            r'^https?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})?(?:/.*)?$',
            re.IGNORECASE
        )
        return bool(url_pattern.match(url))

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        """Normalize whitespace in text (collapse multiple spaces)."""
        return re.sub(r'\s+', ' ', text.strip())

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename by removing invalid characters."""
        # Remove or replace invalid filename characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Remove control characters
        sanitized = ''.join(char for char in sanitized if ord(char) >= 32)
        # Limit length and strip
        return sanitized[:255].strip()

    @staticmethod
    def validate_json_structure(
        data: dict[str, Any],
        required_fields: list[str],
        optional_fields: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Validate JSON structure has required fields and only allowed fields.

        Args:
            data: Data dictionary to validate
            required_fields: List of required field names
            optional_fields: List of optional field names

        Returns:
            Validated data dictionary

        Raises:
            ValueError: If structure is invalid
        """
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")

        # Check required fields
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            raise ValueError(f"Missing required fields: {missing_fields}")

        # Check for unexpected fields
        allowed_fields = set(required_fields)
        if optional_fields:
            allowed_fields.update(optional_fields)

        unexpected_fields = [field for field in data.keys() if field not in allowed_fields]
        if unexpected_fields:
            raise ValueError(f"Unexpected fields: {unexpected_fields}")

        return data
