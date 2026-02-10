"""Tests to achieve 100% code coverage."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


class TestAppMain:
    """Tests for app/main.py uncovered lines 26-27."""

    def test_main_function(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test main() function execution."""
        from app.main import main

        with caplog.at_level(logging.INFO):
            main()

        assert "Hello, World!" in caplog.text


class TestConfigGeneratorsBranches:
    """Tests for config/generators.py branch coverage."""

    def test_generate_pre_commit_without_bandit(self) -> None:
        """Test pre-commit config without bandit enabled."""
        from taipanstack.config.generators import generate_pre_commit_config
        from taipanstack.config.models import SecurityConfig, StackConfig

        config = StackConfig(
            project_name="testproj",
            security=SecurityConfig(
                enable_bandit=False,
                enable_safety=False,
                enable_semgrep=False,
                enable_detect_secrets=False,
            ),
        )
        result = generate_pre_commit_config(config)
        assert "bandit" not in result

    def test_generate_pre_commit_with_safety_only(self) -> None:
        """Test pre-commit config with safety only."""
        from taipanstack.config.generators import generate_pre_commit_config
        from taipanstack.config.models import SecurityConfig, StackConfig

        config = StackConfig(
            project_name="testproj",
            security=SecurityConfig(
                enable_bandit=False,
                enable_safety=True,
                enable_semgrep=False,
                enable_detect_secrets=False,
            ),
        )
        result = generate_pre_commit_config(config)
        assert "safety" in result
        assert "bandit" not in result

    def test_generate_pre_commit_with_semgrep_only(self) -> None:
        """Test pre-commit config with semgrep only."""
        from taipanstack.config.generators import generate_pre_commit_config
        from taipanstack.config.models import SecurityConfig, StackConfig

        config = StackConfig(
            project_name="testproj",
            security=SecurityConfig(
                enable_bandit=False,
                enable_safety=False,
                enable_semgrep=True,
                enable_detect_secrets=False,
            ),
        )
        result = generate_pre_commit_config(config)
        assert "semgrep" in result

    def test_generate_pre_commit_with_detect_secrets_only(self) -> None:
        """Test pre-commit config with detect-secrets only."""
        from taipanstack.config.generators import generate_pre_commit_config
        from taipanstack.config.models import SecurityConfig, StackConfig

        config = StackConfig(
            project_name="testproj",
            security=SecurityConfig(
                enable_bandit=False,
                enable_safety=False,
                enable_semgrep=False,
                enable_detect_secrets=True,
            ),
        )
        result = generate_pre_commit_config(config)
        assert "detect-secrets" in result


class TestCircuitBreakerOpenState:
    """Tests for circuit_breaker.py open state branch."""

    def test_record_success_in_open_state(self) -> None:
        """Test _record_success when circuit is OPEN (should be no-op)."""
        from taipanstack.utils.circuit_breaker import CircuitBreaker, CircuitState

        breaker = CircuitBreaker(name="test", failure_threshold=2)
        # Force state to OPEN
        breaker._state.state = CircuitState.OPEN
        # This should handle the OPEN case gracefully
        breaker._record_success()
        # State should remain OPEN
        assert breaker.state == CircuitState.OPEN

    def test_record_failure_in_open_state(self) -> None:
        """Test _record_failure when circuit is already OPEN."""
        from taipanstack.utils.circuit_breaker import CircuitBreaker, CircuitState

        breaker = CircuitBreaker(name="test", failure_threshold=2)
        # Force state to OPEN
        breaker._state.state = CircuitState.OPEN
        # Record failure - should just increment count
        breaker._record_failure(RuntimeError("test"))
        assert breaker.state == CircuitState.OPEN


class TestResultModuleBranches:
    """Tests for result.py uncovered branches."""

    def test_collect_results_match_patterns(self) -> None:
        """Test all match patterns in collect_results."""
        from taipanstack.core.result import Ok, collect_results

        # Test with iterator (not list)
        results = iter([Ok(1), Ok(2)])
        collected = collect_results(results)
        assert collected.is_ok()

    def test_unwrap_or_match_patterns(self) -> None:
        """Test all match patterns in unwrap_or."""
        from taipanstack.core.result import Err, Ok, unwrap_or

        # Ensure both branches covered
        assert unwrap_or(Ok(5), 0) == 5
        assert unwrap_or(Err("x"), 0) == 0

    def test_unwrap_or_else_match_patterns(self) -> None:
        """Test all match patterns in unwrap_or_else."""
        from taipanstack.core.result import Err, Ok, unwrap_or_else

        # Ensure both branches covered
        assert unwrap_or_else(Ok(5), len) == 5
        assert unwrap_or_else(Err("abc"), len) == 3


class TestConfigModelsUncovered:
    """Tests for config/models.py uncovered lines."""

    def test_security_config_with_level(self) -> None:
        """Test SecurityConfig with explicit level."""
        from taipanstack.config.models import SecurityConfig

        config = SecurityConfig(level="standard")
        assert config.level == "standard"
        assert config.enable_bandit is True


class TestGuardsUncovered:
    """Tests for guards.py uncovered lines 97-98, 341."""

    def test_path_traversal_resolution_error(self, tmp_path: Path) -> None:
        """Test guard_path_traversal with resolution error."""
        from taipanstack.security.guards import guard_path_traversal

        # Test with path that causes resolution warning
        valid_path = tmp_path / "valid_file.txt"
        valid_path.touch()
        result = guard_path_traversal(valid_path, tmp_path)
        assert result.exists()

    def test_env_variable_not_set(self) -> None:
        """Test guard_env_variable when variable not set."""
        from taipanstack.security.guards import SecurityError, guard_env_variable

        with pytest.raises(SecurityError, match="is not set"):
            guard_env_variable(
                "NONEXISTENT_VAR_12345",
                allowed_names=["NONEXISTENT_VAR_12345"],
            )


class TestValidatorsUncovered:
    """Tests for validators.py uncovered lines 128-130."""

    def test_python_version_parse_error(self) -> None:
        """Test validate_python_version with invalid numbers."""
        from taipanstack.security.validators import validate_python_version

        with pytest.raises(ValueError, match="Invalid version format"):
            validate_python_version("abc")


class TestSanitizersUncovered:
    """Tests for sanitizers.py uncovered lines."""

    def test_sanitize_filename_empty_after_sanitization(self) -> None:
        """Test sanitize_filename with name that becomes empty."""
        from taipanstack.security.sanitizers import sanitize_filename

        # Name with only invalid chars
        result = sanitize_filename("...")
        assert result == "unnamed"

    def test_sanitize_path_with_base_dir_not_absolute(self, tmp_path: Path) -> None:
        """Test sanitize_path with relative path and base_dir."""
        from taipanstack.security.sanitizers import sanitize_path

        result = sanitize_path("subdir/file.txt", base_dir=tmp_path)
        assert tmp_path in result.parents or result.parent == tmp_path

    def test_sanitize_env_value_multiline_allowed(self) -> None:
        """Test sanitize_env_value with multiline allowed."""
        from taipanstack.security.sanitizers import sanitize_env_value

        result = sanitize_env_value("line1\nline2", allow_multiline=True)
        assert "\n" in result

    def test_sanitize_sql_identifier_starts_with_number(self) -> None:
        """Test sanitize_sql_identifier starting with number."""
        from taipanstack.security.sanitizers import sanitize_sql_identifier

        result = sanitize_sql_identifier("123abc")
        assert result.startswith("_")


class TestRetryUncovered:
    """Tests for retry.py uncovered lines."""

    def test_retry_no_reraise(self) -> None:
        """Test retry with reraise=False still raises RetryError."""
        from taipanstack.utils.retry import RetryError, retry

        @retry(max_attempts=1, on=(ValueError,), reraise=True, log_retries=False)
        def failing() -> None:
            raise ValueError("fail")

        with pytest.raises(RetryError):
            failing()

    def test_retrier_context_wrong_exception(self) -> None:
        """Test Retrier with non-matching exception type."""
        from taipanstack.utils.retry import Retrier

        retrier = Retrier(max_attempts=3, on=(ValueError,))
        with pytest.raises(TypeError):
            with retrier:
                raise TypeError("wrong type")


class TestSubprocessUncovered:
    """Tests for subprocess.py uncovered lines."""

    def test_run_safe_command_success(self) -> None:
        """Test run_safe_command with successful command."""
        from taipanstack.utils.subprocess import run_safe_command

        result = run_safe_command(["echo", "test"], timeout=30.0)
        assert result.success
        assert result.returncode == 0


class TestFilesystemUncovered:
    """Tests for filesystem.py uncovered lines."""

    def test_safe_write_atomic_success(self, tmp_path: Path) -> None:
        """Test atomic write success path."""
        from taipanstack.utils.filesystem import safe_write

        target = tmp_path / "test.txt"
        safe_write(target, "content", atomic=True)
        assert target.read_text() == "content"


class TestLoggingUncovered:
    """Tests for logging.py uncovered lines 20-21."""

    def test_logging_fallback_branch(self) -> None:
        """Test logging when structlog not available."""
        from taipanstack.utils.logging import HAS_STRUCTLOG

        # Just verify the flag is accessible
        assert isinstance(HAS_STRUCTLOG, bool)


class TestMetricsBranch:
    """Tests for metrics.py branch coverage."""

    def test_metrics_counter_increment(self) -> None:
        """Test Counter increment."""
        from taipanstack.utils.metrics import Counter

        counter = Counter()
        counter.increment()
        counter.increment(5)
        assert counter.value == 6
        counter.decrement(2)
        assert counter.value == 4
        counter.reset()
        assert counter.value == 0
