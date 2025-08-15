#!/bin/bash

# Syslog MCP Server startup script
# Kills any existing server process and starts fresh on HTTP transport
# Usage:
#   ./run.sh        - Start server and stream logs
#   ./run.sh logs   - Stream logs of running server only

# Check if this is a logs-only request
if [ "$1" = "logs" ]; then
    # Load .env file if it exists
    if [ -f .env ]; then
        export $(grep -v '^#' .env | xargs)
    fi
    
    LOG_FILE="${MCP_LOG_FILE:-/tmp/syslog_mcp_server.log}"
    PID_FILE="/tmp/syslog_mcp_server.pid"
    
    if [ -f "$PID_FILE" ]; then
        SERVER_PID=$(cat "$PID_FILE")
        if kill -0 "$SERVER_PID" 2>/dev/null; then
            # Set up trap to handle Ctrl+C gracefully BEFORE showing streaming message
            trap 'echo ""; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "📄 Log streaming stopped. Server continues running with PID: $SERVER_PID"; echo "🔧 To stop the server: kill $SERVER_PID"; echo "📺 To restart log streaming: ./run.sh logs"; exit 0' INT TERM
            
            echo "📺 Streaming logs for server PID: $SERVER_PID"
            echo "📝 Press Ctrl+C to stop streaming (server continues running)"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            
            exec tail -f "$LOG_FILE"
        else
            echo "❌ Server with PID $SERVER_PID is not running"
            rm -f "$PID_FILE"
            exit 1
        fi
    else
        echo "❌ No server PID file found. Is the server running?"
        echo "🚀 To start the server: ./run.sh"
        exit 1
    fi
    exit 0
fi

# Load .env file if it exists
if [ -f .env ]; then
    echo "📄 Loading environment from .env file..."
    export $(grep -v '^#' .env | xargs)
fi

# Configuration with environment variable support
HOST="${MCP_HOST:-localhost}"
PORT="${MCP_PORT:-8005}"
TRANSPORT="${MCP_TRANSPORT:-http}"
LOG_FILE="${MCP_LOG_FILE:-/tmp/syslog_mcp_server.log}"

PID_FILE="/tmp/syslog_mcp_server.pid"

# Ensure logs directory exists
LOG_DIR=$(dirname "$LOG_FILE")
if [ ! -d "$LOG_DIR" ]; then
    echo "📁 Creating logs directory: $LOG_DIR"
    mkdir -p "$LOG_DIR"
fi

echo "🔧 Configuration:"
echo "   Host: $HOST"
echo "   Port: $PORT"
echo "   Transport: $TRANSPORT"
echo "   Log File: $LOG_FILE"
echo ""

echo "🔍 Checking for existing server processes..."

# Kill any existing server process using stored PID
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "✅ Killing existing server process (PID: $OLD_PID)"
        kill "$OLD_PID"
        # Wait for graceful shutdown
        for i in {1..5}; do
            if ! kill -0 "$OLD_PID" 2>/dev/null; then
                break
            fi
            sleep 1
        done
        # Force kill if still running
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo "⚠️  Force killing unresponsive process"
            kill -9 "$OLD_PID"
        fi
    fi
    rm -f "$PID_FILE"
else
    echo "ℹ️  No PID file found, checking for any running instances..."
    # More specific pattern matching - only our exact command with current config
    RUNNING_PID=$(pgrep -f "python -m syslog_mcp --transport $TRANSPORT --host $HOST --port $PORT")
    if [ -n "$RUNNING_PID" ]; then
        echo "✅ Found and killing running server process (PID: $RUNNING_PID)"
        kill "$RUNNING_PID"
        sleep 2
    else
        echo "ℹ️  No existing server process found"
    fi
fi

echo "🚀 Starting Syslog MCP Server on $TRANSPORT transport ($HOST:$PORT)..."

# Start the server with configurable transport in background, fully detached from terminal
setsid nohup uv run python -m syslog_mcp --transport "$TRANSPORT" --host "$HOST" --port "$PORT" > "$LOG_FILE" 2>&1 &

# Store the PID for future cleanup  
SERVER_PID=$!
echo $SERVER_PID > "$PID_FILE"

echo "✅ Server started in background with PID: $SERVER_PID"
echo "📝 Logs are being written to: $LOG_FILE"
echo "🔧 To stop the server, run: kill $SERVER_PID"
echo ""
echo "🔍 Checking server startup..."
sleep 2

# Verify the server is still running
if kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "✅ Server is running successfully!"
    if [ "$TRANSPORT" = "http" ]; then
        echo "🌐 MCP endpoint available at: http://$HOST:$PORT/mcp"
        echo "   WebSocket endpoint: ws://$HOST:$PORT/mcp"
    else
        echo "🌐 Server is running with $TRANSPORT transport on $HOST:$PORT"
    fi
    echo ""
    # Set up trap to handle Ctrl+C gracefully BEFORE showing streaming message
    trap 'echo ""; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "📄 Log streaming stopped. Server continues running with PID: $SERVER_PID"; echo "🔧 To stop the server: kill $SERVER_PID"; echo "📺 To restart log streaming: ./run.sh logs"; exit 0' INT TERM
    
    echo "📝 Streaming logs (Ctrl+C to stop streaming, server continues running)..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Stream the logs
    exec tail -f "$LOG_FILE"
else
    echo "❌ Server failed to start. Check logs:"
    tail -10 "$LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
fi