"""Tests for safe subprocess execution utilities."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from taipanstack.security.guards import SecurityError
from taipanstack.utils.subprocess import (
    DEFAULT_ALLOWED_COMMANDS,
    SafeCommandResult,
    check_command_exists,
    get_command_version,
    run_git_command,
    run_poetry_command,
    run_safe_command,
)


class TestSafeCommandResult:
    """Tests for SafeCommandResult dataclass."""

    def test_success_true_when_returncode_zero(self) -> None:
        """Test success property returns True for returncode 0."""
        result = SafeCommandResult(
            command=["echo", "hello"],
            returncode=0,
            stdout="hello\n",
            stderr="",
        )
        assert result.success is True

    def test_success_false_when_returncode_nonzero(self) -> None:
        """Test success property returns False for non-zero returncode."""
        result = SafeCommandResult(
            command=["false"],
            returncode=1,
            stdout="",
            stderr="error",
        )
        assert result.success is False

    def test_raise_on_error_success(self) -> None:
        """Test raise_on_error returns self on success."""
        result = SafeCommandResult(
            command=["echo", "test"],
            returncode=0,
            stdout="test\n",
        )
        assert result.raise_on_error() is result

    def test_raise_on_error_failure(self) -> None:
        """Test raise_on_error raises CalledProcessError on failure."""
        result = SafeCommandResult(
            command=["bad", "command"],
            returncode=1,
            stdout="",
            stderr="error message",
        )
        with pytest.raises(subprocess.CalledProcessError) as exc_info:
            result.raise_on_error()
        assert exc_info.value.returncode == 1
        assert exc_info.value.cmd == ["bad", "command"]

    def test_duration_seconds_default(self) -> None:
        """Test duration_seconds has default value."""
        result = SafeCommandResult(command=["test"], returncode=0)
        assert result.duration_seconds == 0.0


class TestDefaultAllowedCommands:
    """Tests for DEFAULT_ALLOWED_COMMANDS."""

    def test_contains_essential_commands(self) -> None:
        """Test that essential commands are in the whitelist."""
        essential = ["python", "poetry", "git", "pytest", "mypy", "ruff"]
        for cmd in essential:
            assert cmd in DEFAULT_ALLOWED_COMMANDS

    def test_is_frozenset(self) -> None:
        """Test that it's immutable."""
        assert isinstance(DEFAULT_ALLOWED_COMMANDS, frozenset)


class TestRunSafeCommand:
    """Tests for run_safe_command function."""

    def test_run_echo_command(self) -> None:
        """Test running a simple echo command."""
        result = run_safe_command(["echo", "hello"])
        assert result.success is True
        assert "hello" in result.stdout
        assert result.returncode == 0

    def test_dry_run_mode(self) -> None:
        """Test dry-run mode doesn't execute command."""
        result = run_safe_command(["rm", "-rf", "/"], dry_run=True)
        assert result.success is True
        assert "[DRY-RUN]" in result.stdout
        assert result.returncode == 0

    def test_command_not_in_whitelist(self) -> None:
        """Test that commands not in whitelist are rejected."""
        with pytest.raises(SecurityError, match="Command not in allowed list"):
            run_safe_command(
                ["dangerous_command"],
                allowed_commands=["safe_command"],
            )

    def test_empty_command_rejected(self) -> None:
        """Test that empty command raises SecurityError."""
        with pytest.raises(SecurityError, match="Empty command"):
            run_safe_command([])

    def test_command_injection_blocked(self) -> None:
        """Test that shell metacharacters are blocked."""
        with pytest.raises(SecurityError, match="Dangerous"):
            run_safe_command(["echo", "hello; rm -rf /"])

    def test_command_not_found(self) -> None:
        """Test that non-existent command raises SecurityError."""
        with pytest.raises(SecurityError, match="Command not found"):
            run_safe_command(
                ["nonexistent_command_xyz"],
                allowed_commands=["nonexistent_command_xyz"],
            )

    def test_timeout_handling(self) -> None:
        """Test command timeout is handled."""
        # Use sleep command which is safer than Python -c with semicolons
        result = run_safe_command(
            ["sleep", "5"],
            timeout=0.1,
            allowed_commands=["sleep"],
        )
        assert result.success is False
        assert result.returncode == -1
        assert "timed out" in result.stderr

    def test_working_directory(self, tmp_path: Path) -> None:
        """Test that working directory is respected."""
        # Create a file in tmp_path to verify we can access it
        test_file = tmp_path / "test_cwd.txt"
        test_file.write_text("test")

        # Use echo which works on both Windows and Linux
        result = run_safe_command(
            ["echo", "hello"],
            cwd=tmp_path,
        )
        assert result.success is True

    def test_invalid_working_directory(self) -> None:
        """Test that non-existent working directory raises error."""
        with pytest.raises(SecurityError, match="Working directory does not exist"):
            run_safe_command(["echo", "test"], cwd="/nonexistent/path/xyz")

    def test_custom_allowed_commands(self) -> None:
        """Test custom allowed commands list."""
        result = run_safe_command(
            ["echo", "custom"],
            allowed_commands=["echo"],
        )
        assert result.success is True

    def test_duration_is_tracked(self) -> None:
        """Test that command duration is tracked."""
        result = run_safe_command(["echo", "test"])
        assert result.duration_seconds >= 0


class TestRunPoetryCommand:
    """Tests for run_poetry_command function."""

    @patch("taipanstack.utils.subprocess.run_safe_command")
    def test_calls_poetry_with_args(self, mock_run: MagicMock) -> None:
        """Test that poetry command is called correctly."""
        mock_run.return_value = SafeCommandResult(
            command=["poetry", "version"],
            returncode=0,
            stdout="1.0.0",
        )
        run_poetry_command(["version"])
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["poetry", "version"]

    @patch("taipanstack.utils.subprocess.run_safe_command")
    def test_dry_run_passed_through(self, mock_run: MagicMock) -> None:
        """Test dry-run is passed to run_safe_command."""
        mock_run.return_value = SafeCommandResult(
            command=["poetry", "install"],
            returncode=0,
        )
        run_poetry_command(["install"], dry_run=True)
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["dry_run"] is True


class TestRunGitCommand:
    """Tests for run_git_command function."""

    @patch("taipanstack.utils.subprocess.run_safe_command")
    def test_calls_git_with_args(self, mock_run: MagicMock) -> None:
        """Test that git command is called correctly."""
        mock_run.return_value = SafeCommandResult(
            command=["git", "status"],
            returncode=0,
            stdout="On branch main",
        )
        run_git_command(["status"])
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["git", "status"]

    @patch("taipanstack.utils.subprocess.run_safe_command")
    def test_dry_run_passed_through(self, mock_run: MagicMock) -> None:
        """Test dry-run is passed to run_safe_command."""
        mock_run.return_value = SafeCommandResult(
            command=["git", "init"],
            returncode=0,
        )
        run_git_command(["init"], dry_run=True)
        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["dry_run"] is True


class TestCheckCommandExists:
    """Tests for check_command_exists function."""

    def test_python_exists(self) -> None:
        """Test that python command is found."""
        assert check_command_exists("python") is True

    def test_nonexistent_command(self) -> None:
        """Test that nonexistent command returns False."""
        assert check_command_exists("nonexistent_xyz_123") is False

    def test_git_exists(self) -> None:
        """Test that git command is found (if installed)."""
        # Git should be available in most CI environments
        result = check_command_exists("git")
        assert isinstance(result, bool)


class TestGetCommandVersion:
    """Tests for get_command_version function."""

    def test_python_version(self) -> None:
        """Test getting Python version."""
        version = get_command_version("python")
        assert version is not None
        assert "Python" in version or "python" in version.lower()

    def test_nonexistent_command_returns_none(self) -> None:
        """Test that nonexistent command returns None."""
        version = get_command_version("nonexistent_xyz_123")
        assert version is None

    def test_custom_version_arg(self) -> None:
        """Test custom version argument."""
        # Echo with -n as "version" arg
        version = get_command_version("echo", version_arg="-n")
        # Echo -n returns empty or nothing, so version could be None or empty
        assert version is None or version == ""
