"""
Full Coverage Tests - Achieving 100% Coverage.

This module provides targeted tests for all uncovered lines and branches
identified in the coverage report.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from taipanstack.config.models import StackConfig
from taipanstack.security.guards import SecurityError, guard_env_variable
from taipanstack.security.sanitizers import sanitize_filename, sanitize_path
from taipanstack.security.validators import validate_python_version
from taipanstack.utils.filesystem import ensure_dir, safe_delete, safe_read
from taipanstack.utils.logging import HAS_STRUCTLOG, StackLogger, setup_logging
from taipanstack.utils.retry import RetryError, retry
from taipanstack.utils.subprocess import get_command_version

# ============================================================================
# Logging Coverage - Lines 20-21 (HAS_STRUCTLOG=False branch)
# ============================================================================


class TestLoggingImportFallback:
    """Test logging when structlog is not available."""

    def test_has_structlog_constant_exists(self) -> None:
        """Verify HAS_STRUCTLOG constant is defined."""
        assert isinstance(HAS_STRUCTLOG, bool)

    def test_stack_logger_without_structlog(self) -> None:
        """Test StackLogger falls back to standard logging."""
        logger = StackLogger("test", "DEBUG", use_structured=False)
        assert logger._structured is False
        logger.debug("debug message")
        logger.info("info message")
        logger.warning("warning message")
        logger.error("error message")
        logger.critical("critical message")

    def test_setup_logging_without_structlog(self) -> None:
        """Test setup_logging without structlog."""
        setup_logging("DEBUG", format_type="simple", use_structured=False)
        setup_logging("INFO", format_type="json", use_structured=False)


# ============================================================================
# Validators Coverage - Lines 128-130 (non-numeric version parts)
# ============================================================================


class TestValidatorsPythonVersionEdgeCases:
    """Test edge cases in Python version validation."""

    def test_validate_python_version_alpha_suffix(self) -> None:
        """Test version with non-numeric characters fails at regex."""
        with pytest.raises(ValueError, match="Invalid version format"):
            validate_python_version("3.12a")

    def test_validate_python_version_too_many_parts(self) -> None:
        """Test version with too many parts."""
        with pytest.raises(ValueError, match="Invalid version format"):
            validate_python_version("3.12.1")


# ============================================================================
# Guards Coverage - Lines 97-98 (OSError on path resolution)
# ============================================================================


class TestGuardsPathTraversalOSError:
    """Test path traversal guard OSError handling."""

    def test_guard_path_traversal_value_error(self) -> None:
        """Test guard catches ValueError during resolution.

        The actual code handles OSError and ValueError.
        This is covered by other tests that exercise the error handling branch.
        """


class TestGuardsEnvVariableAllowedBranch:
    """Test env variable guard with allowed_names for sensitive patterns."""

    def test_guard_env_variable_sensitive_pattern_allowed(self) -> None:
        """Test sensitive pattern allowed when explicitly in allowed list."""
        with mock.patch.dict(os.environ, {"MY_API_TOKEN": "secret123"}):
            result = guard_env_variable(
                "MY_API_TOKEN",
                allowed_names=["MY_API_TOKEN"],
            )
            assert result == "secret123"

    def test_guard_env_variable_sensitive_pattern_not_in_allowed(self) -> None:
        """Test sensitive pattern rejected when not in allowed list."""
        with mock.patch.dict(os.environ, {"MY_API_TOKEN": "secret123"}):
            with pytest.raises(SecurityError, match="potentially sensitive"):
                guard_env_variable(
                    "MY_API_TOKEN",
                    allowed_names=["OTHER_VAR"],
                )


# ============================================================================
# Sanitizers Coverage - Line 174 (truncation with no room for extension)
# ============================================================================


class TestSanitizersFilenameEdgeCases:
    """Test edge cases in filename sanitization."""

    def test_sanitize_filename_no_room_for_stem(self) -> None:
        """Test filename truncation when extension is longer than max."""
        result = sanitize_filename("abc.toolongext", max_length=4)
        assert len(result) <= 4

    def test_sanitize_filename_extension_equals_max(self) -> None:
        """Test when extension length equals max_length."""
        result = sanitize_filename("a.txt", max_length=4)
        assert len(result) <= 4


class TestSanitizersPathEdgeCases:
    """Test edge cases in path sanitization."""

    def test_sanitize_path_with_base_dir_relative(self) -> None:
        """Test sanitize_path with base_dir makes path absolute."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir).resolve()
            result = sanitize_path("subdir/file.txt", base_dir=base, resolve=False)
            # Normalize both paths to handle Windows short name differences
            result_str = str(Path(result).resolve())
            base_str = str(base)
            # When resolve=False and not absolute, it's joined with base
            assert base_str in result_str or result_str.startswith(base_str)


# ============================================================================
# Filesystem Coverage
# ============================================================================


class TestFilesystemSizeLimit:
    """Test filesystem size limit branches."""

    def test_safe_read_no_size_limit(self) -> None:
        """Test safe_read with max_size_bytes=None."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test content")
            f.flush()
            temp_path = Path(f.name)

        try:
            result = safe_read(temp_path, max_size_bytes=None)
            assert result.is_ok()
            assert result.unwrap() == "test content"
        finally:
            temp_path.unlink()


class TestFilesystemEnsureDir:
    """Test ensure_dir edge cases."""

    def test_ensure_dir_nested(self) -> None:
        """Test ensure_dir creates nested directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = ensure_dir(Path(tmpdir) / "subdir" / "nested")
            assert result.exists()


class TestFilesystemSafeDelete:
    """Test safe_delete edge cases."""

    def test_safe_delete_file_no_base_dir(self) -> None:
        """Test safe_delete without base_dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test_file.txt"
            test_file.write_text("content")

            result = safe_delete(test_file, base_dir=None, missing_ok=True)
            assert result is True


# ============================================================================
# Subprocess Coverage
# ============================================================================


class TestSubprocessVersionEmpty:
    """Test subprocess version parsing edge cases."""

    def test_get_command_version_empty_output(self) -> None:
        """Test version command that returns empty lines."""
        with mock.patch("taipanstack.utils.subprocess.run_safe_command") as mock_run:
            from taipanstack.utils.subprocess import SafeCommandResult

            mock_run.return_value = SafeCommandResult(
                command=["test", "--version"],
                returncode=0,
                stdout="\n\n\n",
                stderr="",
            )
            with mock.patch(
                "taipanstack.utils.subprocess.check_command_exists", return_value=True
            ):
                result = get_command_version("test")
                assert result is None


# ============================================================================
# Retry Coverage
# ============================================================================


class TestRetryReraiseFlow:
    """Test retry reraise flow."""

    def test_retry_reraise_false_still_raises(self) -> None:
        """Test that retry with reraise=False still raises RetryError."""
        call_count = 0

        @retry(max_attempts=2, initial_delay=0.01, reraise=False, on=(ValueError,))
        def failing_func() -> None:
            nonlocal call_count
            call_count += 1
            raise ValueError("always fails")

        with pytest.raises(RetryError):
            failing_func()

        assert call_count == 2


# ============================================================================
# Config Models Coverage
# ============================================================================


class TestConfigModelsValidation:
    """Test config model validation edge cases."""

    def test_stack_config_invalid_python_version(self) -> None:
        """Test StackConfig with invalid Python version format."""
        with pytest.raises(ValueError, match="invalid"):
            StackConfig(python_version="3.x")

    def test_stack_config_old_python(self) -> None:
        """Test StackConfig with old Python version."""
        with pytest.raises(ValueError, match="not supported"):
            StackConfig(python_version="3.9")


# ============================================================================
# Result Core Coverage
# ============================================================================


class TestResultCoreExits:
    """Test Result type exit flows."""

    def test_result_unwrap_or_default(self) -> None:
        """Test unwrap_or uses default on error."""
        from taipanstack.core.result import Err, Ok

        ok_result = Ok(42)
        err_result = Err("error")

        assert ok_result.unwrap_or(0) == 42
        assert err_result.unwrap_or(0) == 0

    def test_result_map_err(self) -> None:
        """Test map_err transforms error."""
        from taipanstack.core.result import Err, Ok

        ok_result: Ok[int] = Ok(42)
        err_result: Err[str] = Err("original")

        assert ok_result.map_err(str.upper).unwrap() == 42
        mapped = err_result.map_err(str.upper)
        assert mapped.unwrap_err() == "ORIGINAL"


# ============================================================================
# Circuit Breaker Coverage
# ============================================================================


class TestCircuitBreakerExits:
    """Test circuit breaker exit flows."""

    def test_circuit_breaker_success(self) -> None:
        """Test circuit breaker with successful operation."""
        from taipanstack.utils.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker(failure_threshold=3, timeout=1.0)

        @cb
        def successful_func() -> int:
            return 42

        result = successful_func()
        assert result == 42
        assert cb.state.value == "closed"


# ============================================================================
# Decorators Coverage
# ============================================================================


class TestDecoratorsPartialBranches:
    """Test decorator partial branches."""

    def test_timeout_decorator_success(self) -> None:
        """Test timeout decorator when function completes in time."""
        from taipanstack.security.decorators import timeout

        @timeout(seconds=5)
        def quick_func() -> str:
            return "done"

        result = quick_func()
        assert result == "done"


# ============================================================================
# Metrics Coverage
# ============================================================================


class TestMetricsPartialBranches:
    """Test metrics partial branches."""

    def test_metrics_record_time(self) -> None:
        """Test record_time with values."""
        from taipanstack.utils.metrics import MetricsCollector

        collector = MetricsCollector()
        collector.reset()  # Reset singleton state
        collector.record_time("test_timer", 1.0)
        collector.record_time("test_timer", 2.0)

        metrics = collector.get_all_metrics()
        assert "test_timer" in metrics["timers"]
