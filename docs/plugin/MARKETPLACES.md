# Marketplace Publishing -- syslog-mcp

Registration and publishing patterns for Claude, Codex, and Gemini marketplaces.

## Marketplace locations

| Marketplace | Manifest | Registry entry |
| --- | --- | --- |
| Claude Code | `.claude-plugin/plugin.json` | `claude-homelab` marketplace |
| Codex | `.codex-plugin/plugin.json` | `claude-homelab` marketplace |
| Gemini | `gemini-extension.json` | `claude-homelab` marketplace |
| MCP Registry | `server.json` | `tv.tootie/syslog-mcp` |

## Installation

### Claude Code

```bash
/plugin marketplace add jmagar/claude-homelab
/plugin install syslog-mcp @jmagar-claude-homelab
```

### Codex CLI

```bash
codex plugin add jmagar/syslog-mcp
```

### Gemini CLI

Place `gemini-extension.json` in the project root or `~/.gemini/`.

## MCP Registry

syslog-mcp is registered under the `tv.tootie` namespace with DNS verification via the `tootie.tv` domain.

Registry entry in `server.json`:

```json
{
  "name": "tv.tootie/syslog-mcp",
  "packages": [
    {
      "registryType": "oci",
      "identifier": "ghcr.io/jmagar/syslog-mcp:0.2.6"
    }
  ]
}
```

## OCI publishing

syslog-mcp uses OCI (Docker) images as the primary distribution package, not PyPI or npm:

| Registry | Image |
| --- | --- |
| GHCR | `ghcr.io/jmagar/syslog-mcp:latest` |
| GHCR (versioned) | `ghcr.io/jmagar/syslog-mcp:v0.3.1` |

Additionally published to crates.io for `cargo install` usage.

## See also

- [PLUGINS.md](PLUGINS.md) -- manifest file details
- [../mcp/PUBLISH.md](../mcp/PUBLISH.md) -- versioning and release workflow
