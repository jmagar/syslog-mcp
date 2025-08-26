# Syslog-MCP Makefile
# Provides convenient commands for development, testing, and maintenance

.PHONY: help install test test-unit test-integration test-all test-coverage clean lint typecheck format deps-update

# Default target
help:
	@echo "Syslog-MCP Development Commands"
	@echo "================================"
	@echo
	@echo "Setup:"
	@echo "  install          Install all dependencies"
	@echo "  deps-update      Update dependencies"
	@echo
	@echo "Testing:"
	@echo "  test             Run unit tests (fast)"
	@echo "  test-unit        Run unit tests with coverage"
	@echo "  test-integration Run integration tests (requires Docker)"
	@echo "  test-all         Run all tests with coverage"
	@echo "  test-error       Run error handling tests"
	@echo "  test-security    Run security tests" 
	@echo "  test-performance Run performance benchmarks"
	@echo
	@echo "Code Quality:"
	@echo "  lint             Run ruff linting"
	@echo "  typecheck        Run mypy type checking"
	@echo "  format           Format code with black and ruff"
	@echo "  quality          Run all quality checks (lint + typecheck)"
	@echo
	@echo "Server:"
	@echo "  run              Run MCP server (stdio mode)"
	@echo "  run-http         Run MCP server (HTTP mode)"
	@echo
	@echo "Maintenance:"
	@echo "  clean            Clean cache and temporary files"
	@echo "  docker-up        Start Docker services for testing"
	@echo "  docker-down      Stop Docker services"

# Setup
install:
	uv sync --dev

deps-update:
	uv lock --upgrade
	uv sync --dev

# Testing
test:
	uv run python scripts/run_tests.py --mode unit

test-unit:
	uv run python scripts/run_tests.py --mode unit --coverage --verbose

test-integration:
	uv run python scripts/run_tests.py --mode integration --verbose

test-all:
	uv run python scripts/run_tests.py --mode all --coverage --verbose

test-error:
	uv run python scripts/run_tests.py --mode error --verbose

test-security:
	uv run python scripts/run_tests.py --mode security --verbose

test-performance:
	uv run python scripts/run_tests.py --mode performance --verbose

test-coverage: test-unit
	@echo "Coverage report: file://$$(pwd)/.cache/coverage/htmlcov/index.html"

# Code Quality
lint:
	uv run ruff check syslog_mcp/
	uv run ruff check tests/

lint-fix:
	uv run ruff check --fix syslog_mcp/
	uv run ruff check --fix tests/

typecheck:
	uv run mypy syslog_mcp/

format:
	uv run black syslog_mcp/ tests/
	uv run ruff format syslog_mcp/ tests/

quality: lint typecheck
	@echo "✅ All quality checks passed"

# Server
run:
	uv run python -m syslog_mcp

run-http:
	uv run python -m syslog_mcp --transport http --host localhost --port 8000

# Docker
docker-up:
	docker-compose -f docker-compose.test.yml up -d elasticsearch-test
	@echo "Waiting for Elasticsearch to be ready..."
	@timeout 60 bash -c 'until curl -s http://localhost:9200/_cluster/health | grep -q yellow; do sleep 2; done' || echo "Elasticsearch may not be ready"

docker-down:
	docker-compose -f docker-compose.test.yml down

docker-logs:
	docker-compose -f docker-compose.test.yml logs -f elasticsearch-test

# Maintenance  
clean:
	uv run python scripts/run_tests.py --clean
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .eggs/ 2>/dev/null || true

# Development workflow
dev-setup: install quality test-unit
	@echo "✅ Development environment ready!"

# CI/CD workflow  
ci: quality test-all
	@echo "✅ CI checks passed!"

# Quick development cycle
quick: lint-fix test
	@echo "✅ Quick development cycle complete!"

# Full development cycle
full: format quality test-all
	@echo "✅ Full development cycle complete!"