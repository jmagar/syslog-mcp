"""
Device information models with health scoring and status tracking.

Provides comprehensive device monitoring capabilities with health metrics,
activity tracking, and status classification for network infrastructure.
"""

import math
import re
from datetime import UTC, datetime
from enum import Enum
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Any

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator
from pydantic.types import confloat, conint, constr


class DeviceStatus(str, Enum):
    """
    Device operational status classification.

    Based on health metrics, activity patterns, and error rates
    to provide clear operational visibility.
    """

    HEALTHY = "healthy"      # Normal operation, low error rate
    WARNING = "warning"      # Elevated errors or reduced activity
    CRITICAL = "critical"    # High error rate or concerning patterns
    OFFLINE = "offline"      # No recent activity or unreachable
    UNKNOWN = "unknown"      # Insufficient data for classification

    @classmethod
    def from_health_score(cls, health_score: float, last_seen_hours: float = 0.0) -> "DeviceStatus":
        """
        Determine device status from health score and activity.

        Args:
            health_score: Calculated health score (0.0 to 1.0)
            last_seen_hours: Hours since last log message

        Returns:
            Appropriate DeviceStatus enum value
        """
        # Check if device appears offline first
        if last_seen_hours > 24:  # No activity for over 24 hours
            return cls.OFFLINE

        # Classify based on health score
        if health_score >= 0.8:
            return cls.HEALTHY
        elif health_score >= 0.6:
            return cls.WARNING
        elif health_score >= 0.3:
            return cls.CRITICAL
        elif health_score > 0.0:
            return cls.CRITICAL  # Very low but some data
        else:
            return cls.UNKNOWN   # No meaningful data


class DeviceType(str, Enum):
    """
    Device type classification for specialized monitoring.
    """

    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    DATABASE = "database"
    APPLICATION = "application"
    IOT_DEVICE = "iot_device"
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER = "container"
    UNKNOWN = "unknown"


class LogActivitySummary(BaseModel):
    """
    Summary of log activity patterns for a device.
    """

    total_logs: int = Field(
        default=0,
        ge=0,
        description="Total number of log entries"
    )

    error_count: int = Field(
        default=0,
        ge=0,
        description="Number of error-level log entries"
    )

    warning_count: int = Field(
        default=0,
        ge=0,
        description="Number of warning-level log entries"
    )

    critical_count: int = Field(
        default=0,
        ge=0,
        description="Number of critical-level log entries"
    )

    last_log_timestamp: datetime | None = Field(
        None,
        description="Timestamp of most recent log entry"
    )

    first_log_timestamp: datetime | None = Field(
        None,
        description="Timestamp of oldest log entry in current dataset"
    )

    logs_per_hour: float = Field(
        default=0.0,
        ge=0.0,
        description="Average logs per hour over recent period"
    )

    peak_logs_per_hour: float = Field(
        default=0.0,
        ge=0.0,
        description="Peak logs per hour in recent period"
    )

    @computed_field
    def error_rate(self) -> float:
        """Calculate error rate as percentage of total logs."""
        if self.total_logs == 0:
            return 0.0
        return (self.error_count + self.critical_count) / self.total_logs

    @computed_field
    def hours_since_last_log(self) -> float:
        """Calculate hours since last log entry."""
        if not self.last_log_timestamp:
            return float('inf')

        now = datetime.now(UTC)
        delta = now - self.last_log_timestamp.replace(tzinfo=UTC)
        return delta.total_seconds() / 3600.0

    @computed_field
    def activity_duration_hours(self) -> float:
        """Calculate total duration of log activity in hours."""
        if not self.first_log_timestamp or not self.last_log_timestamp:
            return 0.0

        delta = self.last_log_timestamp - self.first_log_timestamp
        return max(delta.total_seconds() / 3600.0, 1.0)  # Minimum 1 hour


class DeviceInfo(BaseModel):
    """
    Comprehensive device information with health monitoring.

    Tracks device identity, activity patterns, health metrics,
    and operational status for infrastructure monitoring.
    """

    # Core identity fields
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Device name or hostname",
        examples=["web-server-01", "firewall.local", "192.168.1.100"]
    )

    device_type: DeviceType = Field(
        default=DeviceType.UNKNOWN,
        description="Classification of device type"
    )

    # Network information
    ip_addresses: list[IPv4Address | IPv6Address] = Field(
        default_factory=list,
        description="Known IP addresses for this device",
        max_length=10
    )

    mac_addresses: list[str] = Field(
        default_factory=list,
        description="Known MAC addresses for this device",
        max_length=5
    )

    # Location and grouping
    location: str | None = Field(
        None,
        max_length=128,
        description="Physical or logical location",
        examples=["Datacenter-A-Rack-05", "Office-Floor-2", "AWS-us-east-1"]
    )

    environment: str | None = Field(
        None,
        max_length=32,
        description="Environment classification",
        examples=["production", "staging", "development", "test"]
    )

    tags: dict[str, str] = Field(
        default_factory=dict,
        description="Custom tags for device classification",
        examples=[{"team": "platform", "criticality": "high", "backup": "enabled"}]
    )

    # Activity and health tracking
    log_activity: LogActivitySummary = Field(
        default_factory=lambda: LogActivitySummary(
            last_log_timestamp=None,
            first_log_timestamp=None
        ),
        description="Summary of recent log activity"
    )

    health_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Calculated health score (0.0 = unhealthy, 1.0 = perfect health)"
    )

    # Timestamps
    first_seen: datetime | None = Field(
        None,
        description="When this device was first discovered"
    )

    last_updated: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this device information was last updated"
    )

    # Status tracking
    status: DeviceStatus = Field(
        default=DeviceStatus.UNKNOWN,
        description="Current operational status"
    )

    status_reason: str | None = Field(
        None,
        max_length=256,
        description="Human-readable explanation of current status"
    )

    # Metadata
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional device-specific metadata"
    )

    @field_validator('name', mode='before')
    @classmethod
    def validate_device_name(cls, v: Any) -> str:
        """Validate and normalize device names."""
        if not isinstance(v, str):
            v = str(v)

        name = str(v).strip()
        if not name:
            raise ValueError("Device name cannot be empty")

        # Check if it's an IP address (valid device name)
        try:
            IPv4Address(name)
            return str(name.lower())
        except AddressValueError:
            try:
                IPv6Address(name)
                return str(name.lower())
            except AddressValueError:
                pass

        # Validate hostname format (allow alphanumeric, hyphens, dots, underscores)
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', name):
            raise ValueError(f"Invalid device name format: {name}")

        return str(name.lower())

    @field_validator('ip_addresses', mode='before')
    @classmethod
    def validate_ip_addresses(cls, v: Any) -> list[IPv4Address | IPv6Address]:
        """Validate and normalize IP address list."""
        if not v:
            return []

        if isinstance(v, str):
            # Single IP address as string
            v = [v]

        validated_ips: list[IPv4Address | IPv6Address] = []
        seen_ips = set()

        for ip in v:
            ip_obj: IPv4Address | IPv6Address
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
                    except AddressValueError:
                        raise ValueError(f"Invalid IP address: {ip}")
            else:
                raise ValueError(f"Invalid IP address type: {type(ip)}")

            # Avoid duplicates
            if ip_str not in seen_ips:
                seen_ips.add(ip_str)
                validated_ips.append(ip_obj)

        return validated_ips

    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v: dict[str, str]) -> dict[str, str]:
        """Validate device tags dictionary."""
        if not isinstance(v, dict):
            raise ValueError("Tags must be a dictionary")

        if len(v) > 20:
            raise ValueError("Too many tags (maximum 20)")

        validated = {}
        for key, value in v.items():
            if not isinstance(key, str):
                key = str(key)
            if not isinstance(value, str):
                value = str(value)

            # Validate key format
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_.-]*$', key):
                raise ValueError(f"Invalid tag key format: {key}")

            if len(key) > 32:
                raise ValueError(f"Tag key too long: {key}")

            if len(value) > 64:
                raise ValueError(f"Tag value too long for key '{key}': {value}")

            validated[key.lower()] = value

        return validated

    @model_validator(mode='after')
    def calculate_health_and_status(self) -> 'DeviceInfo':
        """
        Calculate health score and determine device status.
        """
        # Calculate health score based on multiple factors
        health_factors = []

        # Activity factor (0.0 to 1.0)
        activity_score = self._calculate_activity_score()
        health_factors.append(activity_score)

        # Error rate factor (1.0 - error_rate)
        error_rate_value = float(self.log_activity.error_rate)
        error_score = 1.0 - min(error_rate_value, 1.0)
        health_factors.append(error_score)

        # Recency factor (based on time since last log)
        recency_score = self._calculate_recency_score()
        health_factors.append(recency_score)

        # Volume stability factor
        volume_score = self._calculate_volume_stability_score()
        health_factors.append(volume_score)

        # Weighted average (activity and error rate are most important)
        weights = [0.3, 0.4, 0.2, 0.1]  # activity, error_rate, recency, volume
        self.health_score = sum(score * weight for score, weight in zip(health_factors, weights, strict=False))

        # Determine status from health score and activity
        hours_since_last = float(self.log_activity.hours_since_last_log)
        self.status = DeviceStatus.from_health_score(self.health_score, hours_since_last)

        # Generate status reason
        self.status_reason = self._generate_status_reason()

        return self

    def _manual_health_calculation(self) -> None:
        """Manually recalculate health score and status."""
        # Calculate health score based on multiple factors
        health_factors = []

        # Activity factor (0.0 to 1.0)
        activity_score = self._calculate_activity_score()
        health_factors.append(activity_score)

        # Error rate factor (1.0 - error_rate)
        error_rate_value = float(self.log_activity.error_rate)
        error_score = 1.0 - min(error_rate_value, 1.0)
        health_factors.append(error_score)

        # Recency factor (based on time since last log)
        recency_score = self._calculate_recency_score()
        health_factors.append(recency_score)

        # Volume stability factor
        volume_score = self._calculate_volume_stability_score()
        health_factors.append(volume_score)

        # Weighted average (activity and error rate are most important)
        weights = [0.3, 0.4, 0.2, 0.1]  # activity, error_rate, recency, volume
        self.health_score = sum(score * weight for score, weight in zip(health_factors, weights, strict=False))

        # Determine status from health score and activity
        hours_since_last = float(self.log_activity.hours_since_last_log)
        self.status = DeviceStatus.from_health_score(self.health_score, hours_since_last)

        # Generate status reason
        self.status_reason = self._generate_status_reason()

    def _calculate_activity_score(self) -> float:
        """Calculate activity health score (0.0 to 1.0)."""
        if self.log_activity.total_logs == 0:
            return 0.0

        # Score based on log volume (logarithmic scale)
        # Assumes healthy devices generate 10-100 logs per day
        daily_logs = self.log_activity.logs_per_hour * 24
        if daily_logs <= 0:
            return 0.0

        # Logarithmic scoring: log10(daily_logs / 10) / 2
        # This gives: 10 logs/day = 0.0, 100 logs/day = 0.5, 1000 logs/day = 1.0
        score = math.log10(daily_logs / 10.0) / 2.0
        return max(0.0, min(1.0, score))

    def _calculate_recency_score(self) -> float:
        """Calculate recency health score based on time since last log."""
        hours_since = float(self.log_activity.hours_since_last_log)

        if hours_since == float('inf'):
            return 0.0

        # Exponential decay: score = e^(-hours/12)
        # This gives: 0 hours = 1.0, 6 hours = 0.6, 12 hours = 0.37, 24 hours = 0.14
        return math.exp(-hours_since / 12.0)

    def _calculate_volume_stability_score(self) -> float:
        """Calculate volume stability score based on peak vs average."""
        if self.log_activity.logs_per_hour <= 0:
            return 0.0

        if self.log_activity.peak_logs_per_hour <= 0:
            return 1.0

        # Ratio of average to peak (lower ratio = more spiky = lower score)
        ratio = self.log_activity.logs_per_hour / self.log_activity.peak_logs_per_hour

        # Sigmoid function to convert ratio to score
        # score = 2 / (1 + e^(-10*(ratio - 0.5)))
        return 2.0 / (1.0 + math.exp(-10.0 * (ratio - 0.5))) - 1.0

    def _generate_status_reason(self) -> str:
        """Generate human-readable status explanation."""
        if self.status == DeviceStatus.HEALTHY:
            return f"Normal operation (health: {self.health_score:.2f}, {self.log_activity.total_logs} logs)"

        elif self.status == DeviceStatus.WARNING:
            reasons = []
            if float(self.log_activity.error_rate) > 0.1:
                reasons.append(f"{float(self.log_activity.error_rate):.1%} error rate")
            hours_since = float(self.log_activity.hours_since_last_log)
            if hours_since > 6:
                reasons.append(f"{hours_since:.1f}h since last log")
            if self.health_score < 0.7:
                reasons.append(f"low health score ({self.health_score:.2f})")
            return f"Warning: {', '.join(reasons) if reasons else 'reduced performance'}"

        elif self.status == DeviceStatus.CRITICAL:
            reasons = []
            if float(self.log_activity.error_rate) > 0.3:
                reasons.append(f"high error rate ({float(self.log_activity.error_rate):.1%})")
            hours_since = float(self.log_activity.hours_since_last_log)
            if hours_since > 12:
                reasons.append(f"{hours_since:.1f}h inactive")
            if self.health_score < 0.4:
                reasons.append(f"very low health ({self.health_score:.2f})")
            return f"Critical: {', '.join(reasons) if reasons else 'severe issues detected'}"

        elif self.status == DeviceStatus.OFFLINE:
            hours = float(self.log_activity.hours_since_last_log)
            if hours == float('inf'):
                return "Offline: no log activity recorded"
            return f"Offline: {hours:.1f} hours since last activity"

        else:  # UNKNOWN
            return f"Unknown: insufficient data ({self.log_activity.total_logs} logs)"

    def update_log_activity(self, log_summary: LogActivitySummary) -> None:
        """
        Update device with new log activity data.

        Args:
            log_summary: Updated log activity summary
        """
        self.log_activity = log_summary
        self.last_updated = datetime.now(UTC)

        # Recalculate health and status manually
        self._manual_health_calculation()

    def add_ip_address(self, ip: str | IPv4Address | IPv6Address) -> bool:
        """
        Add an IP address to this device.

        Args:
            ip: IP address to add

        Returns:
            True if added, False if already present
        """
        try:
            if isinstance(ip, str):
                try:
                    ip_obj: IPv4Address | IPv6Address = IPv4Address(ip)
                except AddressValueError:
                    ip_obj = IPv6Address(ip)
            else:
                ip_obj = ip

            if ip_obj not in self.ip_addresses:
                self.ip_addresses.append(ip_obj)
                self.last_updated = datetime.now(UTC)
                return True
            return False

        except (AddressValueError, ValueError):
            return False

    def get_primary_ip(self) -> IPv4Address | IPv6Address | None:
        """Get the primary IP address for this device."""
        if not self.ip_addresses:
            return None

        # Prefer IPv4 addresses
        ipv4_addrs = [ip for ip in self.ip_addresses if isinstance(ip, IPv4Address)]
        if ipv4_addrs:
            return ipv4_addrs[0]

        return self.ip_addresses[0]

    def is_active(self, hours_threshold: float = 24.0) -> bool:
        """
        Check if device is considered active.

        Args:
            hours_threshold: Hours threshold for activity

        Returns:
            True if device has recent activity
        """
        hours_since = float(self.log_activity.hours_since_last_log)
        return hours_since <= hours_threshold

    def get_criticality_score(self) -> float:
        """
        Calculate overall criticality score for prioritization.

        Combines health score with device importance indicators.
        """
        base_score = 1.0 - self.health_score  # Lower health = higher criticality

        # Adjust for device type importance
        type_multipliers = {
            DeviceType.FIREWALL: 1.5,
            DeviceType.LOAD_BALANCER: 1.4,
            DeviceType.DATABASE: 1.3,
            DeviceType.SERVER: 1.2,
            DeviceType.NETWORK_DEVICE: 1.1,
            DeviceType.APPLICATION: 1.0,
            DeviceType.WORKSTATION: 0.8,
            DeviceType.IOT_DEVICE: 0.6,
            DeviceType.CONTAINER: 0.7,
            DeviceType.VIRTUAL_MACHINE: 0.9,
            DeviceType.UNKNOWN: 0.5,
        }

        multiplier = type_multipliers.get(self.device_type, 1.0)

        # Adjust for environment
        if self.environment == "production":
            multiplier *= 1.3
        elif self.environment == "staging":
            multiplier *= 1.1
        elif self.environment in ("development", "test"):
            multiplier *= 0.8

        # Adjust for error volume
        if self.log_activity.error_count > 100:
            multiplier *= 1.2

        return min(base_score * multiplier, 1.0)

    def to_summary_dict(self) -> dict[str, Any]:
        """Convert to summary dictionary for API responses."""
        return {
            "name": self.name,
            "status": self.status.value,
            "health_score": round(self.health_score, 3),
            "device_type": self.device_type.value,
            "primary_ip": str(self.get_primary_ip()) if self.get_primary_ip() else None,
            "total_logs": self.log_activity.total_logs,
            "error_rate": round(float(self.log_activity.error_rate), 3),
            "hours_since_last_log": round(float(self.log_activity.hours_since_last_log), 1),
            "last_updated": self.last_updated.isoformat(),
            "status_reason": self.status_reason
        }

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "example": {
                "name": "web-server-01",
                "device_type": "server",
                "ip_addresses": ["192.168.1.100", "10.0.0.50"],
                "location": "Datacenter-A-Rack-05",
                "environment": "production",
                "tags": {"team": "platform", "criticality": "high"},
                "log_activity": {
                    "total_logs": 15420,
                    "error_count": 23,
                    "warning_count": 156,
                    "critical_count": 2,
                    "logs_per_hour": 45.2,
                    "peak_logs_per_hour": 120.5
                },
                "health_score": 0.82,
                "status": "healthy"
            }
        }
    }


class DeviceList(BaseModel):
    """
    Collection of devices with filtering and aggregation capabilities.
    """

    devices: list[DeviceInfo] = Field(
        default_factory=list,
        description="List of device information objects"
    )

    total_count: int = Field(
        default=0,
        ge=0,
        description="Total number of devices (may be more than returned)"
    )

    filter_applied: str | None = Field(
        None,
        description="Description of any filters applied to this list"
    )

    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When this device list was generated"
    )

    @computed_field
    def status_summary(self) -> dict[str, int]:
        """Summary of devices by status."""
        summary = {status.value: 0 for status in DeviceStatus}
        for device in self.devices:
            summary[device.status.value] += 1
        return summary

    @computed_field
    def health_statistics(self) -> dict[str, float]:
        """Health score statistics for the device list."""
        if not self.devices:
            return {"min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0}

        scores = [device.health_score for device in self.devices]
        scores.sort()

        n = len(scores)
        return {
            "min": scores[0],
            "max": scores[-1],
            "mean": sum(scores) / n,
            "median": scores[n // 2] if n % 2 == 1 else (scores[n // 2 - 1] + scores[n // 2]) / 2
        }

    def filter_by_status(self, status: DeviceStatus) -> "DeviceList":
        """Filter devices by status."""
        filtered_devices = [d for d in self.devices if d.status == status]
        return DeviceList(
            devices=filtered_devices,
            total_count=len(filtered_devices),
            filter_applied=f"status={status.value}",
            generated_at=datetime.now(UTC)
        )

    def filter_by_health_range(self, min_health: float = 0.0, max_health: float = 1.0) -> "DeviceList":
        """Filter devices by health score range."""
        filtered_devices = [
            d for d in self.devices
            if min_health <= d.health_score <= max_health
        ]
        return DeviceList(
            devices=filtered_devices,
            total_count=len(filtered_devices),
            filter_applied=f"health_score={min_health}-{max_health}",
            generated_at=datetime.now(UTC)
        )

    def sort_by_criticality(self, descending: bool = True) -> "DeviceList":
        """Sort devices by criticality score."""
        sorted_devices = sorted(
            self.devices,
            key=lambda d: d.get_criticality_score(),
            reverse=descending
        )
        return DeviceList(
            devices=sorted_devices,
            total_count=len(sorted_devices),
            filter_applied="sorted_by_criticality",
            generated_at=datetime.now(UTC)
        )

    def get_top_critical(self, limit: int = 10) -> "DeviceList":
        """Get the most critical devices."""
        sorted_list = self.sort_by_criticality(descending=True)
        return DeviceList(
            devices=sorted_list.devices[:limit],
            total_count=min(limit, len(sorted_list.devices)),
            filter_applied=f"top_{limit}_critical",
            generated_at=datetime.now(UTC)
        )
