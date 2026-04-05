# Agent Definitions -- syslog-mcp

syslog-mcp does not define any agents. The MCP tools are consumed directly by external agents (Claude Code, Codex, Gemini) without an intermediary agent layer.

## Why no agents

syslog-mcp is a data source (log receiver + query interface), not an orchestration layer. Agents that consume syslog data are defined elsewhere:
- `claude-homelab` homelab-core agents can call syslog-mcp tools for log analysis
- Custom agents in other repos can connect to syslog-mcp via HTTP transport

## See also

- [../mcp/TOOLS.md](../mcp/TOOLS.md) -- tools available for agent consumption
- [../mcp/CONNECT.md](../mcp/CONNECT.md) -- how agents connect to syslog-mcp
