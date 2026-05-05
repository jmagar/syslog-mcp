# Slash Commands -- syslog-mcp

syslog-mcp does not define any slash commands. Tool access is through the MCP protocol, not slash command invocations.

## Why no commands

The `syslog` MCP tool and its actions (`search`, `tail`, `errors`, `hosts`, `correlate`, `stats`, `help`) are invoked directly by MCP clients. Slash commands would add an unnecessary abstraction layer for a service that is purely a query interface.

## See also

- [../mcp/TOOLS.md](../mcp/TOOLS.md) -- MCP tool reference
- [SKILLS.md](SKILLS.md) -- skill documentation that guides tool usage
