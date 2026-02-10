"""Tests for structured logging utilities."""

from __future__ import annotations

import logging

import pytest

from taipanstack.utils.logging import (
    DEFAULT_FORMAT,
    JSON_FORMAT,
    StackLogger,
    get_logger,
    log_operation,
    setup_logging,
)


class TestStackLogger:
    """Tests for StackLogger class."""

    def test_init_with_defaults(self) -> None:
        """Test logger initialization with defaults."""
        logger = StackLogger()
        assert logger.name == "stack"
        assert logger.level == "INFO"

    def test_init_with_custom_name(self) -> None:
        """Test logger with custom name."""
        logger = StackLogger(name="my_module")
        assert logger.name == "my_module"

    def test_init_with_custom_level(self) -> None:
        """Test logger with custom level."""
        logger = StackLogger(level="DEBUG")
        assert logger.level == "DEBUG"

    def test_bind_adds_context(self) -> None:
        """Test that bind adds context."""
        logger = StackLogger()
        logger.bind(request_id="123", user="test")
        assert logger._context["request_id"] == "123"
        assert logger._context["user"] == "test"

    def test_bind_returns_self(self) -> None:
        """Test that bind returns self for chaining."""
        logger = StackLogger()
        result = logger.bind(key="value")
        assert result is logger

    def test_unbind_removes_context(self) -> None:
        """Test that unbind removes context keys."""
        logger = StackLogger()
        logger.bind(key1="value1", key2="value2")
        logger.unbind("key1")
        assert "key1" not in logger._context
        assert "key2" in logger._context

    def test_unbind_missing_key_ok(self) -> None:
        """Test that unbind works for non-existent keys."""
        logger = StackLogger()
        logger.unbind("nonexistent")  # Should not raise

    def test_unbind_returns_self(self) -> None:
        """Test that unbind returns self for chaining."""
        logger = StackLogger()
        result = logger.unbind("key")
        assert result is logger

    def test_debug_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test debug logging."""
        with caplog.at_level(logging.DEBUG):
            logger = StackLogger(level="DEBUG")
            logger.debug("debug message")
        assert "debug message" in caplog.text

    def test_info_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test info logging."""
        with caplog.at_level(logging.INFO):
            logger = StackLogger(level="INFO")
            logger.info("info message")
        assert "info message" in caplog.text

    def test_warning_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test warning logging."""
        with caplog.at_level(logging.WARNING):
            logger = StackLogger(level="WARNING")
            logger.warning("warning message")
        assert "warning message" in caplog.text

    def test_error_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test error logging."""
        with caplog.at_level(logging.ERROR):
            logger = StackLogger(level="ERROR")
            logger.error("error message")
        assert "error message" in caplog.text

    def test_critical_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test critical logging."""
        with caplog.at_level(logging.CRITICAL):
            logger = StackLogger(level="CRITICAL")
            logger.critical("critical message")
        assert "critical message" in caplog.text

    def test_exception_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test exception logging with traceback."""
        with caplog.at_level(logging.ERROR):
            logger = StackLogger()
            try:
                raise ValueError("test error")
            except ValueError:
                logger.exception("caught error")
        assert "caught error" in caplog.text

    def test_context_in_message(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that context appears in log message."""
        with caplog.at_level(logging.INFO):
            logger = StackLogger()
            logger.bind(request_id="abc123")
            logger.info("test message")
        assert "request_id=abc123" in caplog.text


class TestGetLogger:
    """Tests for get_logger function."""

    def test_returns_stack_logger(self) -> None:
        """Test that get_logger returns StackLogger instance."""
        logger = get_logger()
        assert isinstance(logger, StackLogger)

    def test_custom_name(self) -> None:
        """Test logger with custom name."""
        logger = get_logger(name="custom")
        assert logger.name == "custom"

    def test_custom_level(self) -> None:
        """Test logger with custom level."""
        logger = get_logger(level="DEBUG")
        assert logger.level == "DEBUG"


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_setup_with_defaults(self) -> None:
        """Test setup_logging with default parameters."""
        setup_logging()
        # Should not raise

    def test_setup_with_debug_level(self) -> None:
        """Test setup with DEBUG level."""
        setup_logging(level="DEBUG")

    def test_setup_with_simple_format(self) -> None:
        """Test setup with simple format."""
        setup_logging(format_type="simple")

    def test_setup_with_json_format(self) -> None:
        """Test setup with JSON format."""
        setup_logging(format_type="json")

    def test_setup_with_detailed_format(self) -> None:
        """Test setup with detailed format."""
        setup_logging(format_type="detailed")


class TestLogOperation:
    """Tests for log_operation context manager."""

    def test_logs_start_and_end(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that operation start and end are logged."""
        with caplog.at_level(logging.INFO):
            with log_operation("test_operation"):
                pass
        assert "Starting: test_operation" in caplog.text
        assert "Completed: test_operation" in caplog.text

    def test_logs_duration(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that duration is logged."""
        with caplog.at_level(logging.INFO):
            with log_operation("test_operation"):
                pass
        assert "duration_seconds" in caplog.text

    def test_logs_exception_on_failure(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that exception is logged on failure."""
        with caplog.at_level(logging.ERROR):
            with pytest.raises(ValueError):
                with log_operation("failing_operation"):
                    raise ValueError("test error")
        assert "Failed: failing_operation" in caplog.text

    def test_reraises_exception(self) -> None:
        """Test that exceptions are re-raised."""
        with pytest.raises(ValueError, match="original"):
            with log_operation("test"):
                raise ValueError("original")


class TestFormatConstants:
    """Tests for format string constants."""

    def test_default_format_has_required_fields(self) -> None:
        """Test DEFAULT_FORMAT has required placeholders."""
        assert "%(asctime)s" in DEFAULT_FORMAT
        assert "%(levelname)" in DEFAULT_FORMAT
        assert "%(name)s" in DEFAULT_FORMAT
        assert "%(message)s" in DEFAULT_FORMAT

    def test_json_format_is_valid_json_template(self) -> None:
        """Test JSON_FORMAT produces valid JSON structure."""
        assert "timestamp" in JSON_FORMAT
        assert "level" in JSON_FORMAT
        assert "logger" in JSON_FORMAT
        assert "message" in JSON_FORMAT
