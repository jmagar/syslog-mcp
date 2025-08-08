#!/bin/bash

# Syslog MCP Server startup script
# Kills any existing server process and starts fresh on HTTP transport

PORT=8005
SERVER_NAME="syslog_mcp.server"

echo "🔍 Checking for existing server processes..."

# Kill any existing server processes
pkill -f "$SERVER_NAME" && echo "✅ Killed existing server process" || echo "ℹ️  No existing server process found"

# Wait a moment for cleanup
sleep 1

echo "🚀 Starting Syslog MCP Server on HTTP transport (port $PORT)..."

# Start the server with HTTP transport
uv run python -m syslog_mcp.server --transport http --host localhost --port $PORT