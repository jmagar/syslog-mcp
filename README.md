# Syslog MCP Server

A Model Context Protocol (MCP) server for querying and analyzing syslog data stored in Elasticsearch.

## Features

- Search and filter syslog entries with advanced query capabilities
- Real-time log monitoring and analysis
- Device-based filtering and aggregations
- Fast async Elasticsearch integration

## Setup

1. Install dependencies:
```bash
uv sync
```

2. Configure Elasticsearch connection:
```bash
cp .env.example .env
# Edit .env with your Elasticsearch host
```

3. Run the MCP server:
```bash
uv run python main.py
```

## Configuration

Set your Elasticsearch host in `.env`:
```
ELASTICSEARCH_HOST=your-elasticsearch-host:9200
```

## Usage

This MCP server provides tools for:
- Searching log entries with filters
- Aggregating log data by device, level, and time
- Real-time log monitoring
- Advanced query building with complex filters

Connect to this server through any MCP-compatible client like Claude Desktop or other MCP implementations.