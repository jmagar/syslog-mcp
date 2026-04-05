# Channel Integration -- syslog-mcp

syslog-mcp does not use channels. It does not send or receive messages from external messaging platforms.

## Why no channels

syslog-mcp is a passive data store -- it receives syslog messages via UDP/TCP and answers MCP queries. It does not generate outbound notifications or integrate with messaging services.

For alerting on syslog events, use the `gotify-mcp` plugin to send notifications based on `get_errors` or `search_logs` results.

## See also

- [../mcp/TOOLS.md](../mcp/TOOLS.md) -- tools for querying log data
