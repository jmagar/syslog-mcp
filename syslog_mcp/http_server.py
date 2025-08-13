#!/usr/bin/env python3
"""
HTTP server entry point for the Syslog MCP server.

This script starts the MCP server with streamable-http transport.
"""

import argparse
import asyncio
import sys

from .server import run_http_server
from .utils.logging import configure_logging, get_logger


async def main() -> None:
    """Main entry point for HTTP server."""
    parser = argparse.ArgumentParser(
        description="Syslog MCP Server - HTTP Transport",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host to bind to"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Configure logging
    configure_logging(verbose=args.verbose)
    logger = get_logger(__name__)

    try:
        logger.info(f"Starting Syslog MCP Server on http://{args.host}:{args.port}")
        await run_http_server(args.host, args.port)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
