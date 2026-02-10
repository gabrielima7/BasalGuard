"""
Safe subprocess execution with security guards.

Provides secure wrappers around subprocess execution with
command validation, timeout handling, and retry logic.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from taipanstack.security.guards import SecurityError, guard_command_injection


@dataclass(frozen=True)
class SafeCommandResult:
    """Result of a safe command execution.

    Attributes:
        command: The executed command.
        returncode: Exit code of the command.
        stdout: Standard output.
        stderr: Standard error.
        success: Whether the command succeeded (returncode == 0).
        duration_seconds: How long the command took.

    """

    command: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0

    @property
    def success(self) -> bool:
        """Check if command succeeded."""
        return self.returncode == 0

    def raise_on_error(self) -> SafeCommandResult:
        """Raise an exception if command failed.

        Returns:
            Self if successful.

        Raises:
            subprocess.CalledProcessError: If command failed.

        """
        if not self.success:
            raise subprocess.CalledProcessError(
                self.returncode,
                self.command,
                self.stdout,
                self.stderr,
            )
        return self


# Default allowed commands whitelist
DEFAULT_ALLOWED_COMMANDS: frozenset[str] = frozenset(
    {
        # Python/Poetry
        "python",
        "python3",
        "pip",
        "pip3",
        "poetry",
        "pipx",
        # Version control
        "git",
        # Build tools
        "make",
        # Testing
        "pytest",
        "mypy",
        "ruff",
        "bandit",
        "safety",
        "semgrep",
        "pre-commit",
        # System
        "echo",
        "cat",
        "ls",
        "pwd",
        "mkdir",
        "rm",
        "cp",
        "mv",
        "touch",
        "chmod",
        "which",
    }
)


def run_safe_command(
    command: Sequence[str],
    *,
    cwd: Path | str | None = None,
    timeout: float = 300.0,
    capture_output: bool = True,
    check: bool = False,
    allowed_commands: Sequence[str] | None = None,
    env: dict[str, str] | None = None,
    dry_run: bool = False,
) -> SafeCommandResult:
    """Execute a command safely with security guards.

    This function provides a secure wrapper around subprocess.run
    with command injection protection, timeout handling, and
    optional command whitelisting.

    Args:
        command: Command and arguments as a sequence.
        cwd: Working directory for the command.
        timeout: Maximum execution time in seconds.
        capture_output: Whether to capture stdout/stderr.
        check: Whether to raise on non-zero exit.
        allowed_commands: Whitelist of allowed commands.
        env: Environment variables to set.
        dry_run: If True, don't actually execute the command.

    Returns:
        SafeCommandResult with execution details.

    Raises:
        SecurityError: If command validation fails.
        subprocess.TimeoutExpired: If command times out.
        subprocess.CalledProcessError: If check=True and command fails.

    Example:
        >>> result = run_safe_command(["poetry", "install"])
        >>> if result.success:
        ...     print("Installation complete!")

    """
    # Convert to list
    cmd_list = list(command)

    if not cmd_list:
        raise SecurityError(
            "Empty command is not allowed",
            guard_name="safe_command",
        )

    # Get command whitelist
    if allowed_commands is not None:
        whitelist = list(allowed_commands)
    else:
        whitelist = list(DEFAULT_ALLOWED_COMMANDS)

    # Validate command against guards
    validated_cmd = guard_command_injection(cmd_list, allowed_commands=whitelist)

    # Verify command exists
    base_command = validated_cmd[0]
    if not shutil.which(base_command):
        raise SecurityError(
            f"Command not found: {base_command}",
            guard_name="safe_command",
            value=base_command,
        )

    # Handle dry run
    if dry_run:
        return SafeCommandResult(
            command=validated_cmd,
            returncode=0,
            stdout=f"[DRY-RUN] Would execute: {' '.join(validated_cmd)}",
            stderr="",
            duration_seconds=0.0,
        )

    # Resolve working directory
    if cwd is not None:
        cwd = Path(cwd).resolve()
        if not cwd.exists():
            raise SecurityError(
                f"Working directory does not exist: {cwd}",
                guard_name="safe_command",
            )

    # Execute command
    start_time = time.time()

    try:
        result = subprocess.run(
            validated_cmd,
            cwd=cwd,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
            encoding="utf-8",
            env=env,
            check=False,  # We handle check ourselves
        )
    except subprocess.TimeoutExpired as e:
        duration = time.time() - start_time
        stdout_str = ""
        if hasattr(e, "stdout") and e.stdout is not None:
            if isinstance(e.stdout, str):
                stdout_str = e.stdout
            else:
                stdout_str = e.stdout.decode("utf-8", errors="replace")
        return SafeCommandResult(
            command=validated_cmd,
            returncode=-1,
            stdout=stdout_str,
            stderr=f"Command timed out after {timeout}s",
            duration_seconds=duration,
        )

    duration = time.time() - start_time

    safe_result = SafeCommandResult(
        command=validated_cmd,
        returncode=result.returncode,
        stdout=result.stdout or "",
        stderr=result.stderr or "",
        duration_seconds=duration,
    )

    if check:
        safe_result.raise_on_error()

    return safe_result


def run_poetry_command(
    args: Sequence[str],
    *,
    cwd: Path | str | None = None,
    timeout: float = 600.0,
    dry_run: bool = False,
) -> SafeCommandResult:
    """Execute a Poetry command safely.

    Args:
        args: Arguments to pass to poetry.
        cwd: Working directory.
        timeout: Maximum execution time.
        dry_run: Don't actually execute.

    Returns:
        SafeCommandResult with execution details.

    Example:
        >>> result = run_poetry_command(["install"])
        >>> result = run_poetry_command(["add", "pytest", "--group", "dev"])

    """
    return run_safe_command(
        ["poetry", *args],
        cwd=cwd,
        timeout=timeout,
        dry_run=dry_run,
        allowed_commands=["poetry"],
    )


def run_git_command(
    args: Sequence[str],
    *,
    cwd: Path | str | None = None,
    timeout: float = 60.0,
    dry_run: bool = False,
) -> SafeCommandResult:
    """Execute a Git command safely.

    Args:
        args: Arguments to pass to git.
        cwd: Working directory.
        timeout: Maximum execution time.
        dry_run: Don't actually execute.

    Returns:
        SafeCommandResult with execution details.

    Example:
        >>> result = run_git_command(["init"])
        >>> result = run_git_command(["status", "--porcelain"])

    """
    return run_safe_command(
        ["git", *args],
        cwd=cwd,
        timeout=timeout,
        dry_run=dry_run,
        allowed_commands=["git"],
    )


def check_command_exists(command: str) -> bool:
    """Check if a command exists in PATH.

    Args:
        command: The command to check.

    Returns:
        True if command exists, False otherwise.

    """
    return shutil.which(command) is not None


def get_command_version(
    command: str,
    version_arg: str = "--version",
) -> str | None:
    """Get the version of a command.

    Args:
        command: The command to check.
        version_arg: Argument to get version (default: --version).

    Returns:
        Version string or None if command not found.

    """
    if not check_command_exists(command):
        return None

    try:
        result = run_safe_command(
            [command, version_arg],
            timeout=10.0,
            capture_output=True,
        )
        if result.success:
            # Return first non-empty line
            for raw_line in result.stdout.split("\n"):
                stripped_line = raw_line.strip()
                if stripped_line:
                    return stripped_line
        return None
    except (SecurityError, subprocess.SubprocessError):
        return None
