# Claude Code Instructions

## Project Overview
Syslog MCP Server - A Model Context Protocol (MCP) server for querying and analyzing syslog data stored in Elasticsearch.

## Python Environment & Dependencies
- Use `uv` for Python environment management
- Target FastMCP version: 2.11.1
- Python 3.11+ required (as per pyproject.toml)
- Key dependencies to be added: fastmcp, elasticsearch-py, pydantic

## Development Workflow
- Follow async/await patterns throughout
- Use proper error handling and logging
- Implement comprehensive type hints
- Write unit tests for all MCP tools

## Architecture Guidelines
- MCP Server with async Elasticsearch client
- Tools for log searching, filtering, and aggregation
- Health checks and connection management
- Rate limiting and caching for production use

## Key Files Structure
```
├── main.py              # MCP server entry point
├── elasticsearch_client.py  # Async ES connection
├── tools/               # MCP tool implementations
│   ├── search_logs.py
│   ├── health_check.py
│   └── aggregations.py
├── tests/               # Unit and integration tests
└── .env                # Configuration (ES host, etc.)
```

## Development Commands
```bash
# Install dependencies
uv sync

# Run MCP server
uv run python main.py

# Run tests
uv run pytest

# Type checking
uv run mypy .

# Format code
uv run black .
uv run ruff check --fix .
```

## Infrastructure
- Elasticsearch running at squirts:9200
- Environment configuration in .env file
- Docker support for containerized deployment

## Task Master AI Instructions
**Import Task Master's development workflow commands and guidelines, treat as if import is in the main CLAUDE.md file.**
@./.taskmaster/CLAUDE.md