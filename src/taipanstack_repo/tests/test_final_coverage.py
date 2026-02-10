"""Final tests to reach 100% coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from taipanstack.security.guards import SecurityError


class TestLoggingComplete:
    """Complete tests for logging module covering all branches."""

    def test_logger_all_levels(self) -> None:
        """Test StackLogger all log levels."""
        from taipanstack.utils.logging import StackLogger

        logger = StackLogger(name="test", level="DEBUG")

        # Test all levels
        logger.debug("debug msg")
        logger.info("info msg")
        logger.warning("warning msg")
        logger.error("error msg")
        logger.critical("critical msg")

    def test_logger_exception(self) -> None:
        """Test StackLogger exception method."""
        from taipanstack.utils.logging import StackLogger

        logger = StackLogger()
        try:
            raise RuntimeError("test")
        except RuntimeError:
            logger.exception("caught exception")

    def test_log_operation_context_manager(self) -> None:
        """Test log_operation context manager."""
        from taipanstack.utils.logging import log_operation

        with log_operation("test_operation") as log:
            log.info("inside operation")


class TestGuardsComplete:
    """Complete tests for guards module."""

    def test_guard_env_variable_pattern_not_in_allowed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test guard_env_variable when pattern matches but not in allowed."""
        from taipanstack.security.guards import guard_env_variable

        # Set a secret-like env variable
        monkeypatch.setenv("CUSTOM_API_KEY", "secret123")

        # Should raise because matches *API*KEY* pattern
        with pytest.raises(SecurityError):
            guard_env_variable("CUSTOM_API_KEY")

    def test_guard_env_variable_pattern_in_allowed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test guard_env_variable when pattern matches and in allowed."""
        from taipanstack.security.guards import guard_env_variable

        monkeypatch.setenv("CUSTOM_API_KEY", "allowed_secret")

        # Should work because explicitly allowed
        result = guard_env_variable(
            "CUSTOM_API_KEY",
            allowed_names=["CUSTOM_API_KEY"],
        )
        assert result == "allowed_secret"


class TestSubprocessComplete:
    """Complete tests for subprocess module."""

    def test_run_safe_command_with_all_options(self) -> None:
        """Test run_safe_command with all options."""
        from taipanstack.utils.subprocess import run_safe_command

        result = run_safe_command(
            ["echo", "hello"],
            timeout=30.0,
            capture_output=True,
            check=False,
        )
        assert result.success
        assert "hello" in result.stdout

    def test_check_command_exists_false(self) -> None:
        """Test check_command_exists returns False for nonexistent."""
        from taipanstack.utils.subprocess import check_command_exists

        result = check_command_exists("nonexistent_command_xyz_123")
        assert result is False

    def test_check_command_exists_true(self) -> None:
        """Test check_command_exists returns True for existing."""
        from taipanstack.utils.subprocess import check_command_exists

        result = check_command_exists("python")
        assert result is True


class TestSanitizersComplete:
    """Complete tests for sanitizers module."""

    def test_sanitize_string_with_unicode(self) -> None:
        """Test sanitize_string with allow_unicode=False."""
        from taipanstack.security.sanitizers import sanitize_string

        result = sanitize_string("Héllo Wörld", allow_unicode=False)
        assert "é" not in result
        assert "ö" not in result

    def test_sanitize_string_with_max_length(self) -> None:
        """Test sanitize_string with max_length."""
        from taipanstack.security.sanitizers import sanitize_string

        result = sanitize_string("This is a long string", max_length=10)
        assert len(result) == 10

    def test_sanitize_filename_long_name(self) -> None:
        """Test sanitize_filename with very long name."""
        from taipanstack.security.sanitizers import sanitize_filename

        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name, max_length=100)
        assert len(result) <= 100

    def test_sanitize_env_value_multiline(self) -> None:
        """Test sanitize_env_value with multiline."""
        from taipanstack.security.sanitizers import sanitize_env_value

        # Without allowing multiline
        result = sanitize_env_value("line1\nline2", allow_multiline=False)
        assert "\n" not in result

        # With allowing multiline
        result = sanitize_env_value("line1\nline2", allow_multiline=True)
        assert "\n" in result


class TestValidatorsComplete:
    """Complete tests for validators module."""

    def test_validate_email_valid(self) -> None:
        """Test validate_email with valid email."""
        from taipanstack.security.validators import validate_email

        result = validate_email("user@example.com")
        assert result == "user@example.com"

    def test_validate_url_https(self) -> None:
        """Test validate_url with https."""
        from taipanstack.security.validators import validate_url

        result = validate_url("https://secure.example.com/path?query=1")
        assert "secure.example.com" in result


class TestFilesystemComplete:
    """Complete tests for filesystem module."""

    def test_safe_write_non_atomic(self, tmp_path: Path) -> None:
        """Test safe_write with atomic=False."""
        from taipanstack.utils.filesystem import safe_write

        test_file = tmp_path / "non_atomic.txt"
        result = safe_write(test_file, "content", atomic=False)
        assert result.read_text() == "content"

    def test_safe_delete_recursive(self, tmp_path: Path) -> None:
        """Test safe_delete with recursive=True."""
        from taipanstack.utils.filesystem import safe_delete

        # Create a directory with files
        test_dir = tmp_path / "to_delete"
        test_dir.mkdir()
        (test_dir / "file.txt").write_text("content")

        safe_delete(test_dir, recursive=True)
        assert not test_dir.exists()

    def test_get_file_hash_sha256(self, tmp_path: Path) -> None:
        """Test get_file_hash with sha256."""
        from taipanstack.utils.filesystem import get_file_hash

        test_file = tmp_path / "hash_test.txt"
        test_file.write_text("test content")

        hash_result = get_file_hash(test_file)
        assert len(hash_result) == 64  # SHA256 hex length


class TestConfigModelsComplete:
    """Complete tests for config models."""

    def test_stack_config_all_options(self) -> None:
        """Test StackConfig with all options."""
        from taipanstack.config.models import StackConfig

        config = StackConfig(
            project_name="myproject",
            python_version="3.11",
            dry_run=True,
            force=True,
        )
        assert config.project_name == "myproject"
        assert config.python_version == "3.11"
        assert config.dry_run is True


class TestDecoratorsComplete:
    """Complete tests for decorators module."""

    def test_validate_inputs_with_validation(self) -> None:
        """Test validate_inputs with actual validation."""
        from taipanstack.security.decorators import ValidationError, validate_inputs

        def must_be_positive(x: int) -> int:
            if x <= 0:
                raise ValueError("Must be positive")
            return x

        @validate_inputs(value=must_be_positive)
        def process(value: int) -> int:
            return value * 2

        # Valid input
        assert process(value=5) == 10

        # Invalid input
        with pytest.raises(ValidationError):
            process(value=-1)

    def test_guard_exceptions_reraise_non_security(self) -> None:
        """Test guard_exceptions with non-SecurityError reraise."""
        from taipanstack.security.decorators import guard_exceptions

        @guard_exceptions(catch=(ValueError,), reraise_as=TypeError)
        def raise_value_error() -> None:
            raise ValueError("original")

        with pytest.raises(TypeError):
            raise_value_error()

    def test_deprecated_with_removal_version(self) -> None:
        """Test deprecated with removal_version."""
        import warnings

        from taipanstack.security.decorators import deprecated

        @deprecated("Use new_func", removal_version="3.0.0")
        def old_func() -> str:
            return "old"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_func()
            assert result == "old"
            assert len(w) == 1
            assert "3.0.0" in str(w[0].message)

    def test_require_type_passes(self) -> None:
        """Test require_type with valid types."""
        from taipanstack.security.decorators import require_type

        @require_type(name=str, count=int)
        def greet(name: str, count: int) -> str:
            return name * count

        result = greet(name="hi", count=2)
        assert result == "hihi"

    def test_require_type_fails(self) -> None:
        """Test require_type with invalid types."""
        from taipanstack.security.decorators import require_type

        @require_type(name=str)
        def greet(name: str) -> str:
            return name

        with pytest.raises(TypeError, match="expected str, got int"):
            greet(name=123)


class TestCircuitBreakerComplete:
    """Complete tests for circuit breaker."""

    def test_excluded_exceptions_work(self) -> None:
        """Test that excluded exceptions don't trip circuit."""
        from taipanstack.utils.circuit_breaker import CircuitBreaker, CircuitState

        breaker = CircuitBreaker(
            failure_threshold=2,
            excluded_exceptions=(ValueError,),
        )

        @breaker
        def raise_value() -> None:
            raise ValueError("excluded")

        # These should not trip the circuit
        for _ in range(5):
            with pytest.raises(ValueError):
                raise_value()

        assert breaker.state == CircuitState.CLOSED
        assert breaker.failure_count == 0


class TestRetryComplete:
    """Complete tests for retry module."""

    def test_retry_backoff_exponential(self) -> None:
        """Test retry with exponential backoff."""
        from taipanstack.utils.retry import RetryConfig, calculate_delay

        config = RetryConfig(
            initial_delay=1.0,
            exponential_base=2.0,
            jitter=False,
        )

        delay1 = calculate_delay(1, config)
        delay2 = calculate_delay(2, config)
        delay3 = calculate_delay(3, config)

        assert delay2 > delay1
        assert delay3 > delay2
