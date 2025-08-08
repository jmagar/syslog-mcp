"""
Structured logging configuration for the Syslog MCP server.

This module provides structured JSON logging with configurable levels,
FastMCP integration, and correlation ID support for request tracing.
"""

import json
import logging
import logging.handlers
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import structlog


class CorrelationIDProcessor:
    """Processor to add correlation IDs to log records."""

    def __init__(self) -> None:
        self._local = threading.local()

    def __call__(self, logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
        """Add correlation ID to log event."""
        correlation_id = getattr(self._local, "correlation_id", None)
        if correlation_id:
            event_dict["correlation_id"] = correlation_id
        return event_dict

    def set_correlation_id(self, correlation_id: str | None = None) -> str:
        """Set correlation ID for current thread."""
        if correlation_id is None:
            correlation_id = str(uuid4())
        self._local.correlation_id = correlation_id
        return correlation_id

    def clear_correlation_id(self) -> None:
        """Clear correlation ID for current thread."""
        if hasattr(self._local, "correlation_id"):
            delattr(self._local, "correlation_id")


# Global correlation ID processor instance
correlation_processor = CorrelationIDProcessor()


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=UTC
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation ID if available
        correlation_id = getattr(correlation_processor._local, "correlation_id", None)
        if correlation_id:
            log_entry["correlation_id"] = correlation_id

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add any extra fields from the log record
        for key, value in record.__dict__.items():
            if key not in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "getMessage",
                "message",
            }:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


def configure_logging(
    log_level: str | None = None,
    log_file: str | None = None,
    enable_console: bool = True,
    enable_file: bool = True,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    enable_json_logging: bool = True,
    verbose: bool = False,
) -> None:
    """
    Configure structured logging for the application.

    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (defaults to logs/syslog-mcp.log)
        enable_console: Enable console logging
        enable_file: Enable file logging
        max_file_size: Maximum size of log file before rotation
        backup_count: Number of backup files to keep
        enable_json_logging: Enable JSON structured logging
        verbose: Enable verbose/debug logging
    """
    # Get log level from environment or parameter
    if log_level is None:
        if verbose:
            log_level = "DEBUG"
        else:
            log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    # Convert string level to logging level
    numeric_level = getattr(logging, log_level, logging.INFO)

    # Create logs directory if it doesn't exist
    if log_file is None:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        log_file = str(log_dir / "syslog-mcp.log")

    # Clear existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Set root logger level
    root_logger.setLevel(numeric_level)

    handlers: list[logging.Handler] = []

    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler()
        if enable_json_logging:
            console_handler.setFormatter(JSONFormatter())
        else:
            console_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
            )
        handlers.append(console_handler)

    # File handler with rotation
    if enable_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_file_size, backupCount=backup_count
        )
        if enable_json_logging:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
            )
        handlers.append(file_handler)

    # Add handlers to root logger
    for handler in handlers:
        handler.setLevel(numeric_level)
        root_logger.addHandler(handler)

    # Configure structlog if JSON logging is enabled
    if enable_json_logging:
        from typing import cast
        processors: list[Any] = [
            correlation_processor,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ]
        structlog.configure(
            processors=cast(Any, processors),
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

    # Set specific logger levels
    logging.getLogger("elasticsearch").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def set_correlation_id(correlation_id: str | None = None) -> str:
    """
    Set correlation ID for the current thread.

    Args:
        correlation_id: Correlation ID to set (generates UUID4 if None)

    Returns:
        The correlation ID that was set
    """
    return correlation_processor.set_correlation_id(correlation_id)


def clear_correlation_id() -> None:
    """Clear correlation ID for the current thread."""
    correlation_processor.clear_correlation_id()


def log_mcp_request(tool_name: str, arguments: dict[str, Any]) -> None:
    """
    Log MCP tool request.

    Args:
        tool_name: Name of the MCP tool
        arguments: Tool arguments
    """
    logger = get_logger("syslog_mcp.mcp")
    logger.info(
        "MCP tool request",
        extra={
            "tool_name": tool_name,
            "arguments": arguments,
            "event_type": "mcp_request",
        },
    )


def log_mcp_response(
    tool_name: str, success: bool, response_data: dict[str, Any] | None = None, error: str | None = None
) -> None:
    """
    Log MCP tool response.

    Args:
        tool_name: Name of the MCP tool
        success: Whether the request was successful
        response_data: Response data (if successful)
        error: Error message (if failed)
    """
    logger = get_logger("syslog_mcp.mcp")
    extra = {
        "tool_name": tool_name,
        "success": success,
        "event_type": "mcp_response",
    }

    if response_data:
        extra["response_data"] = response_data
    if error:
        extra["error"] = error

    if success:
        logger.info("MCP tool response", extra=extra)
    else:
        logger.error("MCP tool error", extra=extra)


def log_elasticsearch_query(index: str, query: dict[str, Any], took_ms: int | None = None) -> None:
    """
    Log Elasticsearch query.

    Args:
        index: Elasticsearch index
        query: Query body
        took_ms: Query execution time in milliseconds
    """
    logger = get_logger("syslog_mcp.elasticsearch")
    extra: dict[str, Any] = {
        "index": index,
        "query": query,
        "event_type": "elasticsearch_query",
    }

    if took_ms is not None:
        extra["took_ms"] = took_ms

    logger.info("Elasticsearch query", extra=extra)


def log_elasticsearch_error(index: str, error: str, query: dict[str, Any] | None = None) -> None:
    """
    Log Elasticsearch error.

    Args:
        index: Elasticsearch index
        error: Error message
        query: Query that caused the error (optional)
    """
    logger = get_logger("syslog_mcp.elasticsearch")
    extra: dict[str, Any] = {
        "index": index,
        "error": error,
        "event_type": "elasticsearch_error",
    }

    if query:
        extra["query"] = query

    logger.error("Elasticsearch error", extra=extra)
