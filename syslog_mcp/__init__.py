"""
Syslog MCP Server - A Model Context Protocol server for querying and analyzing syslog data.

This package provides MCP tools for interacting with syslog data stored in Elasticsearch.
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .server import create_server

__all__ = ["create_server", "__version__"]
