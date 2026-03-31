#!/bin/bash
set -euo pipefail
: "${SYSLOG_MCP_TOKEN:?SYSLOG_MCP_TOKEN must be set}"
exec "$@"
