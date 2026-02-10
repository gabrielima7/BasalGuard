"""
Input sanitizers for cleaning untrusted data.

Provides functions to sanitize strings, filenames, and paths
to remove potentially dangerous characters.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

# Constants to avoid magic values (PLR2004)
MAX_SQL_IDENTIFIER_LENGTH = 128


def sanitize_string(
    value: str,
    *,
    max_length: int | None = None,
    allow_html: bool = False,
    allow_unicode: bool = True,
    strip_whitespace: bool = True,
) -> str:
    """Sanitize a string by removing dangerous characters.

    Args:
        value: The string to sanitize.
        max_length: Maximum length to truncate to.
        allow_html: Whether to keep HTML tags (default: False).
        allow_unicode: Whether to keep non-ASCII characters.
        strip_whitespace: Whether to strip leading/trailing whitespace.

    Returns:
        The sanitized string.

    Example:
        >>> sanitize_string("<script>alert('xss')</script>Hello")
        "scriptalert('xss')/scriptHello"

    """
    if not value:
        return ""

    result = value

    # Strip whitespace first
    if strip_whitespace:
        result = result.strip()

    # Remove null bytes and control characters
    result = result.replace("\x00", "")
    result = "".join(
        c for c in result if unicodedata.category(c) != "Cc" or c in "\n\r\t"
    )

    # Handle HTML
    if not allow_html:
        # Remove HTML tags
        result = re.sub(r"<[^>]+>", "", result)
        # Escape HTML entities
        result = result.replace("&", "&amp;")
        result = result.replace("<", "&lt;")
        result = result.replace(">", "&gt;")

    # Handle unicode
    if not allow_unicode:
        result = result.encode("ascii", errors="ignore").decode("ascii")

    # Truncate if needed
    if max_length is not None and len(result) > max_length:
        result = result[:max_length]

    return result


def sanitize_filename(
    filename: str,
    *,
    max_length: int = 255,
    replacement: str = "_",
    preserve_extension: bool = True,
) -> str:
    """Sanitize a filename to be safe for filesystem use.

    Removes or replaces characters that are:
    - Not allowed in filenames on various OSes
    - Potentially dangerous (path separators, etc.)

    Args:
        filename: The filename to sanitize.
        max_length: Maximum length for the filename.
        replacement: Character to replace invalid chars with.
        preserve_extension: Keep original extension.

    Returns:
        The sanitized filename.

    Example:
        >>> sanitize_filename("my/../file<>:name.txt")
        'my_file_name.txt'

    """
    if not filename:
        return "unnamed"

    # Get parts
    original_path = Path(filename)
    stem = original_path.stem
    suffix = original_path.suffix if preserve_extension else ""

    # Characters not allowed in filenames (Windows + Unix)
    invalid_chars = r'[<>:"/\\|?*\x00-\x1f]'

    # Remove invalid characters
    safe_stem = re.sub(invalid_chars, replacement, stem)

    # Remove leading/trailing dots and spaces (Windows issues)
    safe_stem = safe_stem.strip(". ")

    # Remove path separators that might have snuck through
    safe_stem = safe_stem.replace("/", replacement)
    safe_stem = safe_stem.replace("\\", replacement)

    # Collapse multiple replacement chars
    if replacement:
        safe_stem = re.sub(f"{re.escape(replacement)}+", replacement, safe_stem)
        safe_stem = safe_stem.strip(replacement)

    # Handle reserved names (Windows)
    reserved_names = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }

    if safe_stem.upper() in reserved_names:
        safe_stem = f"{replacement}{safe_stem}"

    # Handle empty result
    if not safe_stem:
        safe_stem = "unnamed"

    # Construct result
    result = f"{safe_stem}{suffix}"

    # Truncate if needed (keeping extension)
    if len(result) > max_length:
        available = max_length - len(suffix)
        if available > 0:
            safe_stem = safe_stem[:available]
            result = f"{safe_stem}{suffix}"
        else:
            result = result[:max_length]

    return result


def sanitize_path(
    path: str | Path,
    *,
    base_dir: Path | None = None,
    max_depth: int | None = 10,
    resolve: bool = False,
) -> Path:
    """Sanitize a path to prevent traversal and normalize it.

    Args:
        path: The path to sanitize.
        base_dir: Optional base directory to constrain to.
        max_depth: Maximum directory depth allowed.
        resolve: Whether to resolve the path (requires it to exist).

    Returns:
        The sanitized Path object.

    Raises:
        ValueError: If path is invalid or too deep.

    """
    if isinstance(path, str):
        path = Path(path)

    # Remove any null bytes
    path_str = str(path).replace("\x00", "")

    # Normalize the path
    path = Path(path_str)

    # Remove any .. or . components manually
    parts: list[str] = []
    for part in path.parts:
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            # Skip the .. entirely if at root
        elif part != ".":
            # Sanitize each component
            safe_part = sanitize_filename(part, preserve_extension=True)
            if safe_part:  # Skip empty parts
                parts.append(safe_part)

    # Reconstruct path
    if path.is_absolute():
        sanitized = Path("/").joinpath(*parts) if parts else Path("/")
    else:
        sanitized = Path().joinpath(*parts) if parts else Path()

    # Check depth (skip if max_depth is None)
    depth = len(sanitized.parts)
    if max_depth is not None and depth > max_depth:
        msg = f"Path depth {depth} exceeds maximum of {max_depth}"
        raise ValueError(msg)

    # Constrain to base_dir if provided
    if base_dir is not None:
        base = Path(base_dir).resolve()
        if resolve:
            try:
                sanitized = sanitized.resolve()
            except (OSError, RuntimeError) as e:
                msg = f"Cannot resolve path: {e}"
                raise ValueError(msg) from e
        # Make absolute relative to base
        elif not sanitized.is_absolute():
            sanitized = base / sanitized

    return sanitized


def sanitize_env_value(
    value: str,
    *,
    max_length: int = 4096,
    allow_multiline: bool = False,
) -> str:
    """Sanitize a value for use as an environment variable.

    Args:
        value: The value to sanitize.
        max_length: Maximum length allowed.
        allow_multiline: Whether to allow newlines.

    Returns:
        The sanitized value.

    """
    if not value:
        return ""

    result = value

    # Remove null bytes
    result = result.replace("\x00", "")

    # Handle newlines
    if not allow_multiline:
        result = result.replace("\n", " ").replace("\r", " ")

    # Truncate
    if len(result) > max_length:
        result = result[:max_length]

    return result


def sanitize_sql_identifier(identifier: str) -> str:
    """Sanitize a SQL identifier (table/column name).

    Note: This is NOT for SQL values - use parameterized queries for those!

    Args:
        identifier: The identifier to sanitize.

    Returns:
        The sanitized identifier.

    Raises:
        ValueError: If identifier is empty or too long.

    """
    if not identifier:
        msg = "SQL identifier cannot be empty"
        raise ValueError(msg)

    # Only allow alphanumeric and underscore
    result = re.sub(r"[^a-zA-Z0-9_]", "", identifier)

    # Must start with letter or underscore
    if result and not (result[0].isalpha() or result[0] == "_"):
        result = f"_{result}"

    # Check length (most DBs limit to 128 chars)
    if len(result) > MAX_SQL_IDENTIFIER_LENGTH:
        result = result[:MAX_SQL_IDENTIFIER_LENGTH]

    if not result:
        msg = "SQL identifier contains no valid characters"
        raise ValueError(msg)

    return result
