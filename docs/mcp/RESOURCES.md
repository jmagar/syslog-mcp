# MCP Resources Reference -- syslog-mcp

## Overview

MCP resources expose read-only data via URI-based access. Unlike tools, resources do not perform mutations -- they return the current state of a data source.

## Available resources

syslog-mcp does not expose any MCP resources. All data access is through the 7 MCP tools:

| Action | Equivalent resource use case |
| --- | --- |
| `syslog stats` | Database status and health metrics |
| `syslog hosts` | Host registry |
| `syslog tail` | Recent log stream |
| `syslog search` | Log search and filtering |

Tools are preferred over resources for syslog-mcp because all queries benefit from parameterized filtering (hostname, severity, time range, FTS5 query) that URI templating cannot express efficiently.

## Future considerations

If resources are added in the future, they would use the `syslog-mcp://` URI scheme:

```
syslog-mcp://stats           # Database statistics
syslog-mcp://hosts           # Host registry
syslog-mcp://hosts/{name}    # Logs for a specific host
```

## See also

- [TOOLS.md](TOOLS.md) -- MCP tool reference
