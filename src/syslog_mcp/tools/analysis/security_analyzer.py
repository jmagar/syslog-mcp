"""
Security analysis coordinator.

This module coordinates security analysis by importing and delegating to
specialized security analysis modules. Acts as a central point for all
security analysis operations.
"""

# Import specialized analyzers
from .auth_analyzer import analyze_failed_authentication_data
from .timeline_analyzer import analyze_authentication_timeline_data
from .ip_analyzer import analyze_ip_reputation_data
from .suspicious_analyzer import analyze_suspicious_activity_data

from ...utils.logging import get_logger

logger = get_logger(__name__)

# Re-export all analysis functions for backward compatibility
__all__ = [
    "analyze_failed_authentication_data",
    "analyze_ip_reputation_data",
    "analyze_suspicious_activity_data",
    "analyze_authentication_timeline_data"
]
