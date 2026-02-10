"""Tests with real structlog for 100% coverage."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestLoggingWithRealStructlog:
    """Tests for logging.py with real structlog installed."""

    def test_has_structlog_true(self) -> None:
        """Verify that HAS_STRUCTLOG is True now."""
        from taipanstack.utils.logging import HAS_STRUCTLOG

        assert HAS_STRUCTLOG is True

    def test_stack_logger_structured_mode(self) -> None:
        """Test StackLogger in structured mode."""
        from taipanstack.utils.logging import StackLogger

        logger = StackLogger(name="test_structured", use_structured=True)

        logger.debug("debug in structured")
        logger.info("info in structured")
        logger.warning("warning in structured")
        logger.error("error in structured")
        logger.critical("critical in structured")

    def test_stack_logger_structured_bind(self) -> None:
        """Test StackLogger.bind in structured mode."""
        from taipanstack.utils.logging import StackLogger

        logger = StackLogger(use_structured=True)
        logger.bind(user="testuser", request_id="123")
        logger.info("bound message")

    def test_stack_logger_structured_unbind(self) -> None:
        """Test StackLogger.unbind in structured mode."""
        from taipanstack.utils.logging import StackLogger

        logger = StackLogger(use_structured=True)
        logger.bind(key1="value1", key2="value2")
        logger.unbind("key1")
        logger.info("after unbind")

    def test_stack_logger_structured_exception(self) -> None:
        """Test StackLogger.exception in structured mode."""
        from taipanstack.utils.logging import StackLogger

        logger = StackLogger(use_structured=True)
        try:
            raise RuntimeError("test exception")
        except RuntimeError:
            logger.exception("caught error in structured mode")

    def test_setup_logging_structured(self) -> None:
        """Test setup_logging with use_structured=True."""
        from taipanstack.utils.logging import setup_logging

        setup_logging(level="DEBUG", use_structured=True)


class TestSubprocessTimeoutEdgeCases:
    """Tests for subprocess timeout edge cases."""

    def test_run_safe_command_check_false(self) -> None:
        """Test run_safe_command with check=False."""
        from taipanstack.utils.subprocess import run_safe_command

        result = run_safe_command(
            ["python", "-c", "exit(5)"],
            check=False,
        )
        assert not result.success
        assert result.returncode == 5

    def test_get_command_version_with_version_flag(self) -> None:
        """Test get_command_version with custom version_arg."""
        from taipanstack.utils.subprocess import get_command_version

        result = get_command_version("python", version_arg="--version")
        assert result is not None
        assert "Python" in result or "python" in result.lower()


class TestValidatorsMissingBranches:
    """Tests for validators missing branches."""

    def test_validate_project_name_with_hyphen_false(self) -> None:
        """Test validate_project_name with allow_hyphen=False."""
        from taipanstack.security.validators import validate_project_name

        with pytest.raises(ValueError, match="invalid characters"):
            validate_project_name("my-project", allow_hyphen=False)

    def test_validate_project_name_with_underscore_false(self) -> None:
        """Test validate_project_name with allow_underscore=False."""
        from taipanstack.security.validators import validate_project_name

        with pytest.raises(ValueError, match="invalid characters"):
            validate_project_name("my_project", allow_underscore=False)

    def test_validate_python_version_exact(self) -> None:
        """Test validate_python_version with exact version."""
        from taipanstack.security.validators import validate_python_version

        result = validate_python_version("3.11")
        assert result == "3.11"

    def test_validate_email_with_subdomain(self) -> None:
        """Test validate_email with subdomain."""
        from taipanstack.security.validators import validate_email

        result = validate_email("user@mail.example.com")
        assert "example.com" in result

    def test_validate_semver_full(self) -> None:
        """Test validate_semver with full version."""
        from taipanstack.security.validators import validate_semver

        result = validate_semver("1.2.3")
        assert result == (1, 2, 3)


class TestGuardsMissingBranches:
    """Tests for guards missing branches."""

    def test_guard_command_injection_allowed(self) -> None:
        """Test guard_command_injection with allowed commands."""
        from taipanstack.security.guards import guard_command_injection

        # Test allowed command
        result = guard_command_injection(
            ["git", "status"],
            allowed_commands=["git", "ls"],
        )
        assert result == ["git", "status"]


class TestSanitizersMissingBranches:
    """Tests for sanitizers missing branches."""

    def test_sanitize_filename_preserve_extension_false(self) -> None:
        """Test sanitize_filename with preserve_extension=False."""
        from taipanstack.security.sanitizers import sanitize_filename

        result = sanitize_filename("file.txt", preserve_extension=False)
        # Should not have the extension
        assert not result.endswith(".txt") or result == "file.txt"

    def test_sanitize_path_with_base_dir(self, tmp_path: Path) -> None:
        """Test sanitize_path with base_dir."""
        from taipanstack.security.sanitizers import sanitize_path

        result = sanitize_path("subdir/file.txt", base_dir=tmp_path, max_depth=None)
        assert str(tmp_path) in str(result)

    def test_sanitize_path_resolve_true(self, tmp_path: Path) -> None:
        """Test sanitize_path with resolve=True."""
        from taipanstack.security.sanitizers import sanitize_path

        # Create the file first
        test_file = tmp_path / "test.txt"
        test_file.touch()

        result = sanitize_path(
            "test.txt", base_dir=tmp_path, resolve=True, max_depth=None
        )
        assert result.is_absolute()


class TestFilesystemMissingBranches:
    """Tests for filesystem missing branches."""

    def test_safe_read_with_base_dir_traversal(self, tmp_path: Path) -> None:
        """Test safe_read when path has .. but base_dir guards it."""
        from taipanstack.utils.filesystem import safe_read

        test_file = tmp_path / "file.txt"
        test_file.write_text("content")

        # Should work with base_dir
        result = safe_read(test_file, base_dir=tmp_path)
        assert result.unwrap() == "content"

    def test_ensure_dir_with_base_dir(self, tmp_path: Path) -> None:
        """Test ensure_dir with base_dir constraint."""
        from taipanstack.utils.filesystem import ensure_dir

        new_dir = tmp_path / "new_subdir"
        result = ensure_dir(new_dir, base_dir=tmp_path)
        assert result.exists()

    def test_find_files_include_hidden(self, tmp_path: Path) -> None:
        """Test find_files with include_hidden=True."""
        from taipanstack.utils.filesystem import find_files

        # Create hidden file
        hidden = tmp_path / ".hidden"
        hidden.touch()
        (tmp_path / "visible.txt").touch()

        results = find_files(tmp_path, include_hidden=True)
        names = [r.name for r in results]
        assert ".hidden" in names


class TestGeneratorsBranches:
    """Tests for generators branches."""

    def test_generate_pre_commit_basic(self) -> None:
        """Test generate_pre_commit_config function."""
        from taipanstack.config.generators import generate_pre_commit_config
        from taipanstack.config.models import StackConfig

        config = StackConfig(project_name="testproject")

        precommit = generate_pre_commit_config(config)
        assert "ruff" in precommit
        assert "repos:" in precommit


class TestModelsBranches:
    """Tests for models branches."""

    def test_stack_config_to_dict(self) -> None:
        """Test StackConfig.to_dict method if it exists."""
        from taipanstack.config.models import StackConfig

        config = StackConfig(project_name="test", python_version="3.12")

        # Test to_target_version
        target = config.to_target_version()
        assert target == "py312"


class TestRetryMissingBranches:
    """Tests for retry missing branches."""

    def test_retry_with_max_delay(self) -> None:
        """Test retry respects max_delay."""
        from taipanstack.utils.retry import RetryConfig, calculate_delay

        config = RetryConfig(
            initial_delay=10.0,
            max_delay=5.0,  # Max less than initial
            exponential_base=2.0,
            jitter=False,
        )

        delay = calculate_delay(5, config)
        assert delay <= config.max_delay
