"""
Device analysis coordinator.

This module coordinates device analysis by importing and delegating to
specialized device analysis modules. Acts as a central point for all
device analysis operations.
"""

# Import specialized analyzers
from ...utils.logging import get_logger
from .device_health_analyzer import analyze_device_health_data
from .error_pattern_analyzer import (
    analyze_error_message_patterns,
    analyze_error_patterns_data,
)
from .performance_analyzer import (
    analyze_resource_utilization_patterns,
    analyze_system_performance_data,
)

logger = get_logger(__name__)

# Re-export all analysis functions for backward compatibility
__all__ = [
    "analyze_device_health_data",
    "analyze_error_patterns_data",
    "analyze_error_message_patterns",
    "analyze_system_performance_data",
    "analyze_resource_utilization_patterns"
]
