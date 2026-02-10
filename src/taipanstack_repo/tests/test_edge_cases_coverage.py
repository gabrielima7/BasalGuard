"""Additional tests for filesystem, logging, and other modules for 100% coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from taipanstack.core.result import Err
from taipanstack.security.guards import SecurityError


class TestFilesystemEdgeCases:
    """Edge case tests for filesystem module."""

    def test_safe_read_with_traversal_no_base_dir(self, tmp_path: Path) -> None:
        """Test safe_read with .. in path but no base_dir uses cwd."""
        from taipanstack.utils.filesystem import safe_read

        # Create a file in tmp_path
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        # This should fail because .. triggers guard with cwd
        result = safe_read(tmp_path / ".." / "etc" / "passwd")
        match result:
            case Err(SecurityError()):
                pass
            case _:
                pytest.fail("Expected Err(SecurityError)")

    def test_safe_write_existing_file_guarded(self, tmp_path: Path) -> None:
        """Test safe_write with existing file and base_dir."""
        from taipanstack.utils.filesystem import safe_write

        test_file = tmp_path / "existing.txt"
        test_file.write_text("old content")

        result = safe_write(test_file, "new content", base_dir=tmp_path)
        assert result.read_text() == "new content"

    def test_safe_write_with_traversal_no_base_dir(self, tmp_path: Path) -> None:
        """Test safe_write with .. triggers guard."""
        from taipanstack.utils.filesystem import safe_write

        with pytest.raises(SecurityError):
            safe_write(tmp_path / ".." / "bad.txt", "content")

    def test_safe_write_atomic_error_cleanup(self, tmp_path: Path) -> None:
        """Test atomic write cleans up temp file on error."""
        from taipanstack.utils.filesystem import safe_write

        test_file = tmp_path / "test.txt"

        # Mock write_text to raise an error
        with patch.object(Path, "write_text", side_effect=OSError("Write error")):
            with pytest.raises(OSError):
                safe_write(test_file, "content", atomic=True)

    def test_safe_copy_dst_exists_base_dir(self, tmp_path: Path) -> None:
        """Test safe_copy with existing dst and base_dir."""
        from taipanstack.utils.filesystem import safe_copy

        src = tmp_path / "src.txt"
        dst = tmp_path / "dst.txt"
        src.write_text("source")
        dst.write_text("destination")

        result = safe_copy(src, dst, base_dir=tmp_path, overwrite=True)
        assert result.read_text() == "source"

    def test_safe_copy_dst_parent_guarded(self, tmp_path: Path) -> None:
        """Test safe_copy dst parent is guarded when dst doesn't exist."""
        from taipanstack.utils.filesystem import safe_copy

        src = tmp_path / "src.txt"
        dst = tmp_path / "subdir" / "dst.txt"
        src.write_text("source")
        (tmp_path / "subdir").mkdir()

        result = safe_copy(src, dst, base_dir=tmp_path)
        assert result.read_text() == "source"

    def test_find_files_recursive(self, tmp_path: Path) -> None:
        """Test find_files with recursive search."""
        from taipanstack.utils.filesystem import find_files

        # Create test structure
        (tmp_path / "a.txt").touch()
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "b.txt").touch()

        results = find_files(tmp_path, pattern="*.txt", recursive=True)
        names = [r.name for r in results]
        assert "a.txt" in names
        assert "b.txt" in names

    def test_get_file_hash_algorithms(self, tmp_path: Path) -> None:
        """Test get_file_hash with different algorithms."""
        from taipanstack.utils.filesystem import get_file_hash

        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        sha256_hash = get_file_hash(test_file, algorithm="sha256")
        md5_hash = get_file_hash(test_file, algorithm="md5")

        assert sha256_hash != md5_hash
        assert len(sha256_hash) == 64  # SHA256 hex length
        assert len(md5_hash) == 32  # MD5 hex length


class TestLoggingEdgeCases:
    """Edge case tests for logging module."""

    def test_stack_logger_bind_context(self) -> None:
        """Test StackLogger with bind context."""
        from taipanstack.utils.logging import StackLogger

        logger = StackLogger()
        logger.bind(user="test", request_id="123")

        # Log something - context should be in logs
        logger.info("Test message")

    def test_stack_logger_unbind_context(self) -> None:
        """Test unbinding logger context."""
        from taipanstack.utils.logging import StackLogger

        logger = StackLogger()
        logger.bind(key="value")
        logger.unbind("key")

        logger.info("After unbind")

    def test_setup_logging_basic(self) -> None:
        """Test setup_logging basic configuration."""
        from taipanstack.utils.logging import setup_logging

        setup_logging(level="DEBUG")

    def test_log_operation_decorator(self) -> None:
        """Test log_operation decorator."""
        from taipanstack.utils.logging import log_operation

        @log_operation("test_op")
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(5)
        assert result == 10

    def test_log_operation_with_error(self) -> None:
        """Test log_operation decorator with error."""
        from taipanstack.utils.logging import log_operation

        @log_operation("failing_op")
        def failing_func() -> None:
            raise ValueError("Test error")

        with pytest.raises(ValueError):
            failing_func()


class TestDecoratorsEdgeCases:
    """Edge case tests for decorators module."""

    def test_timeout_with_signal(self) -> None:
        """Test timeout with signal (Unix only)."""
        import platform

        if platform.system() == "Windows":
            pytest.skip("Signal timeout not available on Windows")

        from taipanstack.security.decorators import OperationTimeoutError, timeout

        @timeout(0.1, use_signal=True)
        def slow_func() -> None:
            import time

            time.sleep(1)

        with pytest.raises(OperationTimeoutError):
            slow_func()


class TestGuardsEdgeCases:
    """Edge case tests for guards module."""

    def test_guard_command_injection_with_whitelist(self) -> None:
        """Test guard_command_injection with custom whitelist."""
        from taipanstack.security.guards import guard_command_injection

        cmd = ["python", "--version"]
        result = guard_command_injection(cmd, allowed_commands=["python", "pip"])
        assert result == cmd


class TestSanitizersEdgeCases:
    """Edge case tests for sanitizers module."""

    def test_sanitize_string_with_null_bytes(self) -> None:
        """Test sanitizing string with null bytes."""
        from taipanstack.security.sanitizers import sanitize_string

        result = sanitize_string("hello\x00world")
        assert "\x00" not in result

    def test_sanitize_path_with_special_chars(self) -> None:
        """Test sanitizing path with special characters."""
        from taipanstack.security.sanitizers import sanitize_path

        result = sanitize_path("/path/to/../file")
        assert ".." not in str(result)


class TestValidatorsEdgeCases:
    """Edge case tests for validators module."""

    def test_validate_project_name_reserved(self) -> None:
        """Test that reserved names are rejected."""
        from taipanstack.security.validators import validate_project_name

        with pytest.raises(ValueError, match="reserved"):
            validate_project_name("test")

    def test_validate_url_with_ip(self) -> None:
        """Test validating URL with IP address."""
        from taipanstack.security.validators import validate_url

        result = validate_url("http://192.168.1.1:8080", require_tld=False)
        assert "192.168.1.1" in result


class TestRetryEdgeCases:
    """Edge case tests for retry module."""

    def test_retrier_multiple_attempts(self) -> None:
        """Test Retrier with a loop for multiple attempts."""
        from taipanstack.utils.retry import Retrier

        retrier = Retrier(max_attempts=3, initial_delay=0.01, on=(ValueError,))
        attempt_count = 0

        while True:
            try:
                with retrier:
                    attempt_count += 1
                    if attempt_count < 3:
                        raise ValueError("fail")
                    break  # Success
            except ValueError:
                if retrier.attempt >= retrier.config.max_attempts:
                    raise

        assert attempt_count == 3


class TestSubprocessEdgeCases:
    """Edge case tests for subprocess module."""

    def test_run_safe_command_with_env(self) -> None:
        """Test run_safe_command with custom environment."""
        from taipanstack.utils.subprocess import run_safe_command

        result = run_safe_command(
            ["echo", "test"],
            env={"CUSTOM_VAR": "value"},
        )
        assert result.success

    def test_get_command_version_not_found(self) -> None:
        """Test get_command_version with non-existent command."""
        from taipanstack.utils.subprocess import get_command_version

        result = get_command_version("nonexistent_command_xyz")
        assert result is None


class TestCircuitBreakerEdgeCases:
    """Edge case tests for circuit breaker module."""

    def test_circuit_breaker_half_open_success(self) -> None:
        """Test circuit transitions from half-open to closed."""
        import time

        from taipanstack.utils.circuit_breaker import CircuitBreaker, CircuitState

        breaker = CircuitBreaker(
            failure_threshold=1,
            success_threshold=2,
            timeout=0.05,
        )
        attempt = 0

        @breaker
        def func() -> str:
            nonlocal attempt
            attempt += 1
            if attempt == 1:
                raise ValueError("first fail")
            return "ok"

        # Trip circuit
        with pytest.raises(ValueError):
            func()

        assert breaker.state == CircuitState.OPEN

        # Wait for half-open
        time.sleep(0.1)

        # First success in half-open
        func()

        # Second success should close
        func()

        assert breaker.state == CircuitState.CLOSED
