# Skill Definitions -- syslog-mcp

Patterns for defining skills (domain knowledge modules) within the syslog-mcp plugin.

## Directory structure

```
skills/
  syslog/
    SKILL.md           # Skill definition with tool reference and workflows
```

## Skill: syslog

The `syslog` skill provides the client-facing documentation for all syslog-mcp tools. It is consumed by Claude Code, Codex, and Gemini to understand available capabilities.

### Contents

`skills/syslog/SKILL.md` includes:
- Tool inventory (all 7 tools with descriptions)
- Parameter reference for each tool
- FTS5 query syntax guide
- Common workflow patterns (health check, incident investigation, host onboarding)
- Severity level reference (emerg through debug)

### Validation

```bash
just validate-skills
# Checks: skills/syslog/SKILL.md exists
```

## Adding a skill

syslog-mcp ships a single skill. If additional skills are needed:

1. Create `skills/<name>/SKILL.md`
2. Add frontmatter with `name` and `description`
3. Document tools, workflows, and examples
4. Update `just validate-skills` to check the new path

## See also

- [PLUGINS.md](PLUGINS.md) -- plugin manifest references the skill
- [../mcp/TOOLS.md](../mcp/TOOLS.md) -- MCP tool definitions
