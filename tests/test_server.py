"""
Basic tests for the MCP server.

These tests verify that the server can be created and initialized properly.
"""

from syslog_mcp.server import create_server


def test_create_server():
    """Test that the server can be created successfully."""
    server = create_server()
    assert server is not None
    assert server.name == "Syslog-MCP"


def test_server_type():
    """Test that the server is of the correct type."""
    from fastmcp import FastMCP

    server = create_server()
    assert isinstance(server, FastMCP)
