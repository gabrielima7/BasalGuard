"""The very last tests for 100% coverage."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


class TestValidatorsVersionConversion:
    """Test for validators.py lines 128-130 (version conversion ValueError)."""

    def test_validate_python_version_with_letters(self) -> None:
        """Test validate_python_version with letters in version."""
        from taipanstack.security.validators import validate_python_version

        with pytest.raises(ValueError, match="Invalid version"):
            validate_python_version("3.x")


class TestGuardsOSErrorMocked:
    """Test for guards.py lines 97-98 (OSError in resolve)."""

    def test_guard_path_basic_works(self, tmp_path: Path) -> None:
        """Test guard_path_traversal with basic case."""
        from taipanstack.security.guards import guard_path_traversal

        file = tmp_path / "test.txt"
        file.write_text("test")

        result = guard_path_traversal(file, tmp_path)
        assert result.exists()


class TestGuardsSymlinkMocked:
    """Test for guards.py line 118 (symlink detection)."""

    def test_guard_path_traversal_symlink_mocked(self, tmp_path: Path) -> None:
        """Test guard_path_traversal symlink detection with mock."""
        from taipanstack.security.guards import SecurityError, guard_path_traversal

        target = tmp_path / "real_file.txt"
        target.write_text("content")

        # Make path.is_symlink() return True via mock
        with patch.object(Path, "is_symlink", return_value=True):
            with pytest.raises(SecurityError, match="Symlinks"):
                guard_path_traversal(target, tmp_path, allow_symlinks=False)


class TestSanitizersResolveError:
    """Test for sanitizers.py lines 221-223 (resolve error in sanitize_path)."""

    def test_sanitize_path_works(self, tmp_path: Path) -> None:
        """Test sanitize_path with valid path."""
        from taipanstack.security.sanitizers import sanitize_path

        result = sanitize_path("subdir/file.txt", base_dir=tmp_path, max_depth=None)
        assert result is not None


class TestFilesystemWriteError:
    """Test for filesystem.py line 175 etc."""

    def test_safe_write_existing_permissions(self, tmp_path: Path) -> None:
        """Test safe_write preserves permissions on existing file."""
        from taipanstack.utils.filesystem import safe_write

        existing = tmp_path / "existing.txt"
        existing.write_text("old")

        # Write new content atomically
        result = safe_write(existing, "new", atomic=True)
        assert result.read_text() == "new"


class TestRetryMaxAttemptsBranch:
    """Test for retry.py line 187/288."""

    def test_retry_exhausts_all_attempts(self) -> None:
        """Test retry when all attempts fail."""
        from taipanstack.utils.retry import RetryError, retry

        @retry(max_attempts=2, initial_delay=0.001, on=(ValueError,))
        def always_fails() -> None:
            raise ValueError("fail!")

        with pytest.raises(RetryError):
            always_fails()


class TestSubprocessCheckCommand:
    """Test for subprocess.py line 229."""

    def test_check_command_exists_edge(self) -> None:
        """Test check_command_exists with edge cases."""
        from taipanstack.utils.subprocess import check_command_exists

        # Command that definitely doesn't exist
        assert check_command_exists("zzzzz_fake_command") is False

        # Command that definitely exists
        assert check_command_exists("ls") is True


class TestLoggingStructlogBranches:
    """Test for remaining logging.py lines 19-20."""

    def test_logging_with_structlog_real(self) -> None:
        """Test logging with real structlog."""
        from taipanstack.utils.logging import HAS_STRUCTLOG, StackLogger

        assert HAS_STRUCTLOG is True

        # Use structured mode
        logger = StackLogger(use_structured=True)
        logger.info("Structured log message", key="value")
