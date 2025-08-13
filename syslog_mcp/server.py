"""
Main FastMCP server setup and configuration.

This module creates and configures the FastMCP server with all tools and resources.
"""

import argparse
import asyncio

from dotenv import load_dotenv
from fastmcp import FastMCP

from .prompts.forensics import register_forensics_prompts
from .prompts.security_analysis import register_security_analysis_prompts
from .prompts.system_administration import register_system_administration_prompts
from .tools import register_device_analysis_tools, register_search_tools
from .utils.logging import configure_logging, get_logger


def create_server() -> FastMCP:
    """Create and configure the FastMCP server."""
    mcp = FastMCP("Syslog-MCP")

    # Register search tools
    register_search_tools(mcp)

    # Register device analysis tools
    register_device_analysis_tools(mcp)

    # Register prompts
    register_security_analysis_prompts(mcp)
    register_system_administration_prompts(mcp)
    register_forensics_prompts(mcp)

    return mcp


async def run_http_server(host: str = "localhost", port: int = 8000) -> None:
    """Run the MCP server with HTTP transport."""
    logger = get_logger(__name__)

    try:
        mcp = create_server()
        logger.info(f"Starting Syslog MCP Server on http://{host}:{port}")

        # Run the server with HTTP transport
        await mcp.run_http_async(host=host, port=port)
    except Exception as e:
        logger.error(f"Failed to start HTTP server: {e}")
        raise


def run_stdio_server() -> None:
    """Run the MCP server with stdio transport (default)."""
    logger = get_logger(__name__)

    try:
        mcp = create_server()
        logger.info("Starting Syslog MCP Server with stdio transport")

        # Run with stdio transport (default)
        mcp.run()
    except Exception as e:
        logger.error(f"Failed to start stdio server: {e}")
        raise


def main(host: str | None = None, port: int | None = None) -> None:
    """Main entry point for the MCP server."""
    # Configure structured logging
    configure_logging()

    # Load environment variables from .env file
    load_dotenv()

    logger = get_logger(__name__)

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Syslog MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport type to use (default: stdio)"
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host to bind to for HTTP transport (default: localhost)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to for HTTP transport (default: 8000)"
    )

    args = parser.parse_args()

    # Use command line arguments or function parameters
    final_host = host or args.host
    final_port = port or args.port
    transport = args.transport

    logger.info(f"Syslog MCP Server starting with {transport} transport")

    if transport == "http":
        # Run HTTP server
        asyncio.run(run_http_server(final_host, final_port))
    else:
        # Run stdio server (default for MCP clients)
        run_stdio_server()


if __name__ == "__main__":
    main()
