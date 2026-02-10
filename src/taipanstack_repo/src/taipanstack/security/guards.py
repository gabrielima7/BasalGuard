"""
Runtime guards for protection against errors and AI hallucinations.

These guards provide runtime protection against common security issues
and programming errors that can occur from incorrect AI-generated code.
All guards raise SecurityError on violation.
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from pathlib import Path


class SecurityError(Exception):
    """Raised when a security guard detects a violation.

    Attributes:
        guard_name: Name of the guard that was triggered.
        message: Description of the violation.
        value: The offending value (if safe to log).

    """

    def __init__(
        self,
        message: str,
        guard_name: str = "unknown",
        value: str | None = None,
    ) -> None:
        """Initialize SecurityError.

        Args:
            message: Description of the violation.
            guard_name: Name of the guard that triggered.
            value: The offending value (sanitized).

        """
        self.guard_name = guard_name
        self.value = value
        super().__init__(f"[{guard_name}] {message}")


def guard_path_traversal(
    path: Path | str,
    base_dir: Path | str | None = None,
    *,
    allow_symlinks: bool = False,
) -> Path:
    """Prevent path traversal attacks.

    Ensures that the given path does not escape the base directory
    using techniques like '..' or symlinks.

    Args:
        path: The path to validate.
        base_dir: The base directory to constrain to. Defaults to cwd.
        allow_symlinks: Whether to allow symlinks (default: False).

    Returns:
        The resolved, validated path.

    Raises:
        SecurityError: If path traversal is detected.

    Example:
        >>> guard_path_traversal("../etc/passwd", Path("/app"))
        SecurityError: [path_traversal] Path escapes base directory

    """
    path = Path(path) if isinstance(path, str) else path
    base_dir = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()

    # Check for explicit traversal patterns before resolution
    path_str = str(path)
    traversal_patterns = [
        "..",
        "~",
        r"\.\.",
        "%2e%2e",  # URL encoded ..
        "%252e%252e",  # Double URL encoded
    ]

    for pattern in traversal_patterns:
        if pattern.lower() in path_str.lower():
            raise SecurityError(
                f"Path traversal pattern detected: {pattern}",
                guard_name="path_traversal",
                value=path_str[:50],  # Truncate for safety
            )

    # Resolve the path
    try:
        resolved = path.resolve() if path.is_absolute() else (base_dir / path).resolve()
    except (OSError, ValueError) as e:
        raise SecurityError(
            f"Invalid path: {e}",
            guard_name="path_traversal",
        ) from e

    # Check if resolved path is within base_dir
    try:
        resolved.relative_to(base_dir)
    except ValueError as e:
        raise SecurityError(
            f"Path escapes base directory: {resolved} is not under {base_dir}",
            guard_name="path_traversal",
            value=str(resolved)[:100],
        ) from e

    # Check for symlinks if not allowed
    is_existing_symlink = (
        not allow_symlinks and resolved.exists() and resolved.is_symlink()
    )
    if is_existing_symlink:
        raise SecurityError(
            "Symlinks are not allowed",
            guard_name="path_traversal",
            value=str(resolved),
        )

    return resolved


def guard_command_injection(
    command: Sequence[str],
    *,
    allowed_commands: Sequence[str] | None = None,
) -> list[str]:
    """Prevent command injection attacks.

    Validates that command arguments don't contain shell metacharacters
    that could lead to command injection.

    Args:
        command: The command and arguments as a sequence.
        allowed_commands: Optional whitelist of allowed base commands.

    Returns:
        The validated command as a list.

    Raises:
        SecurityError: If command injection is detected.

    Example:
        >>> guard_command_injection(["echo", "hello; rm -rf /"])
        SecurityError: [command_injection] Dangerous characters detected

    """
    if not command:
        raise SecurityError(
            "Empty command is not allowed",
            guard_name="command_injection",
        )

    cmd_list = list(command)

    # Dangerous shell metacharacters
    dangerous_patterns: list[tuple[str, str]] = [
        (";", "command separator"),
        ("|", "pipe"),
        ("&", "background/and operator"),
        ("$", "variable expansion"),
        ("`", "command substitution"),
        ("$(", "command substitution"),
        ("${", "variable expansion"),
        (">", "redirect"),
        ("<", "redirect"),
        (">>", "redirect append"),
        ("||", "or operator"),
        ("&&", "and operator"),
        ("\n", "newline"),
        ("\r", "carriage return"),
        ("\x00", "null byte"),
    ]

    for arg in cmd_list:
        for pattern, description in dangerous_patterns:
            if pattern in arg:
                raise SecurityError(
                    f"Dangerous shell character detected: {description}",
                    guard_name="command_injection",
                    value=arg[:50],
                )

    # Check against allowed commands whitelist
    if allowed_commands is not None:
        base_command = cmd_list[0]
        # Get just the command name without path
        command_name = Path(base_command).name
        cmd_not_allowed = (
            command_name not in allowed_commands
            and base_command not in allowed_commands
        )
        if cmd_not_allowed:
            raise SecurityError(
                f"Command not in allowed list: {command_name}",
                guard_name="command_injection",
                value=command_name,
            )

    return cmd_list


def guard_file_extension(
    filename: str | Path,
    *,
    allowed_extensions: Sequence[str] | None = None,
    denied_extensions: Sequence[str] | None = None,
) -> Path:
    """Validate file extension against allow/deny lists.

    Args:
        filename: The filename to check.
        allowed_extensions: Extensions to allow (with or without dot).
        denied_extensions: Extensions to deny (with or without dot).

    Returns:
        The filename as a Path.

    Raises:
        SecurityError: If extension is not allowed or is denied.

    """
    path = Path(filename)
    ext = path.suffix.lower().lstrip(".")

    # Default dangerous extensions
    default_denied = {
        "exe",
        "dll",
        "so",
        "dylib",  # Executables
        "sh",
        "bash",
        "zsh",
        "ps1",
        "bat",
        "cmd",  # Scripts
        "php",
        "jsp",
        "asp",
        "aspx",  # Server-side scripts
    }

    # Normalize extension lists
    def normalize_ext(e: str) -> str:
        return e.lower().lstrip(".")

    if denied_extensions is not None:
        denied = {normalize_ext(e) for e in denied_extensions}
    else:
        denied = default_denied

    if ext in denied:
        raise SecurityError(
            f"File extension '{ext}' is not allowed",
            guard_name="file_extension",
            value=str(path.name),
        )

    if allowed_extensions is not None:
        allowed = {normalize_ext(e) for e in allowed_extensions}
        if ext not in allowed:
            raise SecurityError(
                f"File extension '{ext}' is not in allowed list",
                guard_name="file_extension",
                value=str(path.name),
            )

    return path


def guard_env_variable(
    name: str,
    *,
    allowed_names: Sequence[str] | None = None,
    denied_names: Sequence[str] | None = None,
) -> str:
    """Guard against accessing sensitive environment variables.

    Args:
        name: The environment variable name.
        allowed_names: Variable names to allow.
        denied_names: Variable names to deny.

    Returns:
        The environment variable value if safe.

    Raises:
        SecurityError: If variable access is not allowed.

    """
    # Default sensitive variables
    default_denied = {
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITLAB_TOKEN",
        "DATABASE_URL",
        "DB_PASSWORD",
        "PASSWORD",
        "SECRET_KEY",
        "PRIVATE_KEY",
        "API_KEY",
        "API_SECRET",
    }

    name_upper = name.upper()

    if denied_names is not None:
        denied = {n.upper() for n in denied_names}
    else:
        denied = default_denied

    # Check against patterns
    sensitive_patterns = [
        r".*SECRET.*",
        r".*PASSWORD.*",
        r".*TOKEN.*",
        r".*PRIVATE.*KEY.*",
        r".*API.*KEY.*",
    ]

    if name_upper in denied:
        raise SecurityError(
            f"Access to sensitive variable '{name}' is denied",
            guard_name="env_variable",
            value=name,
        )

    for pattern in sensitive_patterns:
        if re.match(pattern, name_upper):
            # Only block if not explicitly allowed
            if allowed_names is not None:
                allowed = {n.upper() for n in allowed_names}
                if name_upper not in allowed:
                    raise SecurityError(
                        f"Access to potentially sensitive variable '{name}' is denied",
                        guard_name="env_variable",
                        value=name,
                    )
            else:
                raise SecurityError(
                    f"Access to potentially sensitive variable '{name}' is denied",
                    guard_name="env_variable",
                    value=name,
                )

    # Get the variable
    value = os.environ.get(name)
    if value is None:
        raise SecurityError(
            f"Environment variable '{name}' is not set",
            guard_name="env_variable",
            value=name,
        )

    return value
