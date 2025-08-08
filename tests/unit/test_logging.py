"""
Tests for the logging utility module.
"""

import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import patch

from syslog_mcp.utils.logging import (
    JSONFormatter,
    clear_correlation_id,
    configure_logging,
    correlation_processor,
    get_logger,
    set_correlation_id,
)


class TestCorrelationIDProcessor:
    """Tests for correlation ID processor."""

    def test_correlation_id_lifecycle(self):
        """Test setting and clearing correlation ID."""
        # Initially no correlation ID
        assert not hasattr(correlation_processor._local, "correlation_id")

        # Set correlation ID
        correlation_id = set_correlation_id("test-123")
        assert correlation_id == "test-123"
        assert correlation_processor._local.correlation_id == "test-123"

        # Clear correlation ID
        clear_correlation_id()
        assert not hasattr(correlation_processor._local, "correlation_id")

    def test_auto_generated_correlation_id(self):
        """Test auto-generation of correlation ID."""
        correlation_id = set_correlation_id()
        assert correlation_id is not None
        assert len(correlation_id) > 0

        # Should be a UUID format
        import uuid
        uuid.UUID(correlation_id)  # Will raise ValueError if not valid UUID


class TestJSONFormatter:
    """Tests for JSON formatter."""

    def test_basic_formatting(self):
        """Test basic JSON log formatting."""
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/path.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        assert log_data["level"] == "INFO"
        assert log_data["logger"] == "test.logger"
        assert log_data["message"] == "Test message"
        assert log_data["line"] == 42
        assert "timestamp" in log_data

    def test_formatting_with_correlation_id(self):
        """Test JSON formatting with correlation ID."""
        formatter = JSONFormatter()
        set_correlation_id("test-correlation-123")

        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="/test/path.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        formatted = formatter.format(record)
        log_data = json.loads(formatted)

        assert log_data["correlation_id"] == "test-correlation-123"

        # Clean up
        clear_correlation_id()

    def test_formatting_with_exception(self):
        """Test JSON formatting with exception info."""
        formatter = JSONFormatter()

        try:
            raise ValueError("Test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

            record = logging.LogRecord(
                name="test.logger",
                level=logging.ERROR,
                pathname="/test/path.py",
                lineno=42,
                msg="Error occurred",
                args=(),
                exc_info=exc_info,
            )

            formatted = formatter.format(record)
            log_data = json.loads(formatted)

            assert log_data["level"] == "ERROR"
            assert log_data["message"] == "Error occurred"
            assert "exception" in log_data
            assert "ValueError: Test error" in log_data["exception"]


class TestConfigureLogging:
    """Tests for logging configuration."""

    def test_configure_logging_default(self):
        """Test default logging configuration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"

            configure_logging(
                log_level="INFO",
                log_file=str(log_file),
                enable_console=False,
                enable_file=True,
            )

            logger = get_logger("test.logger")
            logger.info("Test message")

            # Check that log file was created and contains content
            assert log_file.exists()
            content = log_file.read_text()
            assert "Test message" in content

    def test_configure_logging_json_disabled(self):
        """Test logging configuration with JSON disabled."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"

            configure_logging(
                log_level="INFO",
                log_file=str(log_file),
                enable_console=False,
                enable_file=True,
                enable_json_logging=False,
            )

            logger = get_logger("test.logger")
            logger.info("Test message")

            # Check that log file contains plain text format
            content = log_file.read_text()
            assert "Test message" in content
            # Should not be JSON format
            assert not content.strip().startswith("{")

    def test_configure_logging_levels(self):
        """Test different log levels."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"

            configure_logging(
                log_level="WARNING",
                log_file=str(log_file),
                enable_console=False,
                enable_file=True,
            )

            logger = get_logger("test.logger")
            logger.debug("Debug message")  # Should not appear
            logger.info("Info message")    # Should not appear
            logger.warning("Warning message")  # Should appear
            logger.error("Error message")     # Should appear

            content = log_file.read_text()
            assert "Debug message" not in content
            assert "Info message" not in content
            assert "Warning message" in content
            assert "Error message" in content

    @patch.dict("os.environ", {"LOG_LEVEL": "DEBUG"})
    def test_configure_logging_from_env(self):
        """Test logging configuration from environment variable."""
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"

            configure_logging(
                log_file=str(log_file),
                enable_console=False,
                enable_file=True,
            )

            logger = get_logger("test.logger")
            logger.debug("Debug message")  # Should appear with DEBUG level

            content = log_file.read_text()
            assert "Debug message" in content


class TestLoggerHelpers:
    """Tests for logger helper functions."""

    def test_get_logger(self):
        """Test getting logger instance."""
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test.module"

    def test_logger_singleton(self):
        """Test that same logger name returns same instance."""
        logger1 = get_logger("test.module")
        logger2 = get_logger("test.module")
        assert logger1 is logger2
