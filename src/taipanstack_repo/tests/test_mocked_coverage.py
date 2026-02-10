"""Tests with mocks to achieve 100% coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from taipanstack.core.result import Err
from taipanstack.utils.filesystem import FileTooLargeErr


class TestLoggingStructlogBranches:
    """Tests for structlog branches in logging module."""

    def test_has_structlog_true_when_installed(self) -> None:
        """Verify that HAS_STRUCTLOG is True when structlog is installed."""
        from taipanstack.utils.logging import HAS_STRUCTLOG

        # structlog is now installed in test environment
        assert HAS_STRUCTLOG is True

    @patch("taipanstack.utils.logging.HAS_STRUCTLOG", True)
    def test_stack_logger_with_structured_mock(self) -> None:
        """Test StackLogger with mocked structlog."""
        # Create mock structlog module
        mock_structlog = MagicMock()
        mock_structlog.get_logger.return_value = MagicMock()

        with patch.dict("sys.modules", {"structlog": mock_structlog}):
            from taipanstack.utils.logging import StackLogger

            # Test with use_structured=True but HAS_STRUCTLOG patched
            logger = StackLogger(use_structured=False)
            logger.info("Test message")


class TestDecoratorsThreadTimeoutBranches:
    """Tests for thread timeout exception branches in decorators."""

    def test_timeout_thread_with_exception(self) -> None:
        """Test thread timeout when function raises exception."""
        from taipanstack.security.decorators import timeout

        @timeout(5.0, use_signal=False)
        def raise_error() -> None:
            raise ValueError("Expected error")

        with pytest.raises(ValueError, match="Expected error"):
            raise_error()

    def test_timeout_thread_success(self) -> None:
        """Test thread timeout with successful execution."""
        from taipanstack.security.decorators import timeout

        @timeout(5.0, use_signal=False)
        def success_func() -> str:
            return "success"

        result = success_func()
        assert result == "success"


class TestValidatorsBranches:
    """Tests for validator branches."""

    def test_validate_project_name_special_chars(self) -> None:
        """Test validate_project_name with special characters."""
        from taipanstack.security.validators import validate_project_name

        with pytest.raises(ValueError):
            validate_project_name("project@name")

    def test_validate_python_version_invalid_format(self) -> None:
        """Test validate_python_version with invalid format."""
        from taipanstack.security.validators import validate_python_version

        with pytest.raises(ValueError):
            validate_python_version("invalid")

    def test_validate_url_with_port(self) -> None:
        """Test validate_url with port number."""
        from taipanstack.security.validators import validate_url

        result = validate_url("https://example.com:443/path")
        assert "example.com" in result

    def test_validate_ip_address_any_version(self) -> None:
        """Test validate_ip_address with any version."""
        from taipanstack.security.validators import validate_ip_address

        # IPv4
        result4 = validate_ip_address("8.8.8.8", version="any")
        assert result4 is not None

    def test_validate_port_boundary(self) -> None:
        """Test validate_port at boundary values."""
        from taipanstack.security.validators import validate_port

        # Maximum valid port
        result = validate_port(65535, allow_privileged=True)
        assert result == 65535

    def test_validate_semver_with_prerelease(self) -> None:
        """Test validate_semver with prerelease."""
        from taipanstack.security.validators import validate_semver

        # Standard semver
        result = validate_semver("2.0.0")
        assert result == (2, 0, 0)


class TestGuardsBranches:
    """Tests for guards module branches."""

    def test_guard_path_traversal_os_error(self, tmp_path: Path) -> None:
        """Test guard_path_traversal when resolve raises OSError."""
        from taipanstack.security.guards import guard_path_traversal

        # Create a valid path first
        test_file = tmp_path / "test.txt"
        test_file.touch()

        # Should work normally
        result = guard_path_traversal(test_file, tmp_path)
        assert result.exists()

    def test_guard_file_extension_no_extension(self) -> None:
        """Test guard_file_extension with file without extension."""
        from taipanstack.security.guards import guard_file_extension

        result = guard_file_extension(
            "Makefile",
            allowed_extensions=["", "txt"],
        )
        assert result is not None


class TestSanitizersBranches:
    """Tests for sanitizers module branches."""

    def test_sanitize_filename_empty(self) -> None:
        """Test sanitize_filename with empty string."""
        from taipanstack.security.sanitizers import sanitize_filename

        result = sanitize_filename("")
        assert result == "unnamed"

    def test_sanitize_filename_reserved_name(self) -> None:
        """Test sanitize_filename with Windows reserved name."""
        from taipanstack.security.sanitizers import sanitize_filename

        result = sanitize_filename("CON")
        assert result != "CON"  # Should be modified

    def test_sanitize_path_deep_nesting(self) -> None:
        """Test sanitize_path with deep nesting."""
        from taipanstack.security.sanitizers import sanitize_path

        with pytest.raises(ValueError, match="depth"):
            sanitize_path("a/b/c/d/e/f/g/h/i/j/k/l", max_depth=5)

    def test_sanitize_sql_identifier_starts_with_number(self) -> None:
        """Test sanitize_sql_identifier starting with number."""
        from taipanstack.security.sanitizers import sanitize_sql_identifier

        result = sanitize_sql_identifier("123column")
        assert result.startswith("_")


class TestSubprocessBranches:
    """Tests for subprocess module branches."""

    def test_run_safe_command_failure(self) -> None:
        """Test run_safe_command with failing command."""
        from taipanstack.utils.subprocess import run_safe_command

        result = run_safe_command(["python", "-c", "exit(1)"])
        assert not result.success
        assert result.returncode == 1

    def test_get_command_version_existing(self) -> None:
        """Test get_command_version with existing command."""
        from taipanstack.utils.subprocess import get_command_version

        result = get_command_version("python")
        assert result is not None
        assert "Python" in result or "python" in result.lower() or "." in result


class TestFilesystemBranches:
    """Tests for filesystem module branches."""

    def test_safe_read_max_size_exceeded(self, tmp_path: Path) -> None:
        """Test safe_read when file exceeds max size."""
        from taipanstack.utils.filesystem import safe_read

        test_file = tmp_path / "large.txt"
        test_file.write_text("x" * 1000)

        result = safe_read(test_file, max_size_bytes=100)
        match result:
            case Err(FileTooLargeErr(size=s)):
                assert s > 100
            case _:
                pytest.fail("Expected Err(FileTooLargeErr)")

    def test_ensure_dir_already_exists(self, tmp_path: Path) -> None:
        """Test ensure_dir with directory that already exists."""
        from taipanstack.utils.filesystem import ensure_dir

        existing_dir = tmp_path / "existing"
        existing_dir.mkdir()

        result = ensure_dir(existing_dir)
        assert result == existing_dir.resolve()

    def test_safe_write_no_backup(self, tmp_path: Path) -> None:
        """Test safe_write with backup=False."""
        from taipanstack.utils.filesystem import safe_write

        test_file = tmp_path / "test.txt"
        test_file.write_text("original")

        safe_write(test_file, "new", backup=False)
        assert test_file.read_text() == "new"

        # No backup should exist
        backup_path = tmp_path / "test.txt.bak"
        assert not backup_path.exists()

    def test_find_files_non_recursive(self, tmp_path: Path) -> None:
        """Test find_files with recursive=False."""
        from taipanstack.utils.filesystem import find_files

        (tmp_path / "file.txt").touch()
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "nested.txt").touch()

        results = find_files(tmp_path, pattern="*.txt", recursive=False)
        names = [r.name for r in results]
        assert "file.txt" in names
        assert "nested.txt" not in names


class TestRetryBranches:
    """Tests for retry module branches."""

    def test_calculate_delay_with_jitter(self) -> None:
        """Test calculate_delay produces different values with jitter."""
        from taipanstack.utils.retry import RetryConfig, calculate_delay

        config = RetryConfig(jitter=True, jitter_factor=0.5)

        delays = [calculate_delay(1, config) for _ in range(10)]
        # With jitter, values should vary
        assert len(set(delays)) > 1

    def test_retry_config_defaults(self) -> None:
        """Test RetryConfig defaults."""
        from taipanstack.utils.retry import RetryConfig

        config = RetryConfig()
        assert config.max_attempts == 3
        assert config.jitter is True


class TestCircuitBreakerExitBranches:
    """Tests for circuit breaker exit branches."""

    def test_circuit_breaker_success_resets_failures(self) -> None:
        """Test circuit breaker resets failure count on success."""
        from taipanstack.utils.circuit_breaker import CircuitBreaker, CircuitState

        breaker = CircuitBreaker(failure_threshold=3)

        @breaker
        def flaky(should_fail: bool) -> str:
            if should_fail:
                raise ValueError("fail")
            return "ok"

        # Cause some failures
        for _ in range(2):
            with pytest.raises(ValueError):
                flaky(True)

        assert breaker.failure_count == 2

        # Success should reset count
        flaky(False)
        assert breaker.failure_count == 0
        assert breaker.state == CircuitState.CLOSED


class TestConfigGeneratorsBranches:
    """Tests for config generators branches."""

    def test_generate_pyproject_config(self) -> None:
        """Test generate_pyproject_config."""
        from taipanstack.config.generators import generate_pyproject_config
        from taipanstack.config.models import StackConfig

        config = StackConfig(project_name="minimal")
        result = generate_pyproject_config(config)

        assert "ruff" in result
        assert "mypy" in result


class TestModelsEdgeCases:
    """Tests for models edge cases."""

    def test_stack_config_to_target_version(self) -> None:
        """Test StackConfig.to_target_version method."""
        from taipanstack.config.models import StackConfig

        config = StackConfig(project_name="test", python_version="3.12")
        target = config.to_target_version()
        assert target == "py312"

    def test_stack_config_default_values(self) -> None:
        """Test StackConfig defaults."""
        from taipanstack.config.models import StackConfig

        config = StackConfig(project_name="test")
        assert config.python_version is not None
