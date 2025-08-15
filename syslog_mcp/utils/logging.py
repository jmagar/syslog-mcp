"""
Structured logging configuration for the Syslog MCP server.

This module provides structured JSON logging with configurable levels,
FastMCP integration, and correlation ID support for request tracing.
"""

import json
import logging
import logging.handlers
import os
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import structlog


class RestartingFileHandler(logging.FileHandler):
    """
    File handler that restarts (truncates) the log file when it reaches max size
    instead of rotating with backup files.
    """

    def __init__(
        self,
        filename: str,
        *,
        max_bytes: int = 10 * 1024 * 1024,
        mode: str = 'a',
        encoding: str | None = None,
        delay: bool = False,
        errors: str | None = None
    ) -> None:
        """
        Initialize the handler.
        
        Args:
            filename: Log file path
            max_bytes: Maximum file size before restarting (default: 10MB)
            mode: File open mode
            encoding: File encoding
            delay: Whether to delay file opening
            errors: How to handle encoding errors
        """
        super().__init__(filename, mode, encoding, delay, errors)
        self.max_bytes = max_bytes
        
    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a record, checking file size and restarting if necessary.
        """
        try:
            # Check if we need to restart the file
            if self.should_restart():
                self.restart_file()
            
            # Emit the record normally
            super().emit(record)
        except Exception:
            self.handleError(record)
            
    def should_restart(self) -> bool:
        """
        Check if the file should be restarted based on size.
        """
        if not os.path.exists(self.baseFilename):
            return False
            
        try:
            return os.path.getsize(self.baseFilename) >= self.max_bytes
        except OSError:
            return False
            
    def restart_file(self) -> None:
        """
        Restart the log file by closing, truncating, and reopening.
        """
        try:
            # Close current stream
            if self.stream:
                self.stream.close()
            
            # Truncate the file by opening in write mode
            with open(self.baseFilename, 'w', encoding=self.encoding, errors=self.errors) as f:
                f.write(f"=== Log file restarted at {datetime.now(UTC).isoformat()} ===\n")
            
            # Reopen in append mode
            self.stream = self._open()
        except Exception as e:
            # If restart fails, continue with existing stream
            print(f"Failed to restart log file: {e}", file=sys.stderr)


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
    enable_json_logging: bool = True,
    verbose: bool = False,
) -> None:
    """
    Configure structured logging for the application.

    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (defaults to /tmp/syslog-mcp.log)
        enable_console: Enable console logging
        enable_file: Enable file logging
        max_file_size: Maximum size of log file before restarting (truncating)
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

    # Use /tmp for log files by default
    if log_file is None:
        log_file = "/tmp/syslog-mcp.log"

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

    # File handler with restart (truncate when size limit reached)
    if enable_file:
        file_handler = RestartingFileHandler(
            log_file, max_bytes=max_file_size
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
