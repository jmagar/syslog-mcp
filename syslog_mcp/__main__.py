"""
Entry point for running the syslog-mcp server as a module.

This allows running the server with: python -m syslog_mcp
"""

from .server import main

if __name__ == "__main__":
    main()
