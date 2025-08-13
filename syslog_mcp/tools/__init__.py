"""
MCP tools for the Syslog MCP server.

This module contains the MCP tool implementations for searching logs,
health checking, and advanced analytics.
"""

from .device_analysis import register_device_analysis_tools
from .search_logs import register_search_tools

__all__ = ["register_search_tools", "register_device_analysis_tools"]
