# Slash Commands -- syslog-mcp

syslog-mcp does not define any slash commands. Tool access is through the MCP protocol, not slash command invocations.

## Why no commands

The 7 MCP tools (search_logs, tail_logs, get_errors, list_hosts, correlate_events, get_stats, syslog_help) are invoked directly by MCP clients. Slash commands would add an unnecessary abstraction layer for a service that is purely a query interface.

## See also

- [../mcp/TOOLS.md](../mcp/TOOLS.md) -- MCP tool reference
- [SKILLS.md](SKILLS.md) -- skill documentation that guides tool usage
