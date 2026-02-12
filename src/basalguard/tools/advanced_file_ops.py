"""Advanced file operations for AI agents.

This module provides safe, high-level file operations that replace
dangerous shell commands like 'grep' or 'cat' on large files.
"""

from __future__ import annotations

import logging
from pathlib import Path

from taipanstack.security.guards import guard_path_traversal

logger = logging.getLogger("basalguard.tools.file_ops")


def search_in_file(
    path: str,
    pattern: str,
    case_sensitive: bool = False,
    base_dir: Path | str | None = None,
) -> list[str]:
    """Search for a text pattern in a file (grep replacement).

    This function reads the file line by line to avoid loading the entire
    file into memory, making it safe for large files.

    Args:
        path: Relative path to the file.
        pattern: The text string to search for.
        case_sensitive: If True, performs a case-sensitive search.
                        Defaults to False (case-insensitive).
        base_dir: The base directory (workspace root) to restrict access to.
                  If None, defaults to current working directory (use with caution).

    Returns:
        A list of strings, where each string is a matching line from the file.

    Raises:
        SecurityError: If path traversal is detected or file is outside base_dir.
        FileNotFoundError: If the file does not exist.
        OSError: If there is an error reading the file.

    """
    # Validate path using TaipanStack's guard
    resolved_path = guard_path_traversal(path, base_dir=base_dir)

    if not resolved_path.is_file():
        raise FileNotFoundError(f"Path is not a file: {resolved_path}")

    matches: list[str] = []

    # Prepare pattern for comparison
    search_pattern = pattern if case_sensitive else pattern.lower()

    try:
        with resolved_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                # Prepare line for comparison
                line_to_check = line if case_sensitive else line.lower()

                if search_pattern in line_to_check:
                    matches.append(line.rstrip("\n"))

    except OSError as exc:
        logger.error("Error searching in file %s: %s", resolved_path, exc)
        raise

    return matches


def read_file_paged(
    path: str,
    offset: int = 0,
    limit: int = 2000,
    base_dir: Path | str | None = None,
) -> str:
    """Read a specific chunk of a file (pagination).

    Useful for reading large files without consuming excessive memory.

    Args:
        path: Relative path to the file.
        offset: The byte offset to start reading from.
        limit: The maximum number of characters (or bytes approx) to read.
        base_dir: The base directory (workspace root) to restrict access to.

    Returns:
        The content read from the file.

    Raises:
        SecurityError: If path traversal is detected.
        FileNotFoundError: If the file does not exist.
        OSError: If there is an error reading the file.

    """
    # Validate path using TaipanStack's guard
    resolved_path = guard_path_traversal(path, base_dir=base_dir)

    if not resolved_path.is_file():
        raise FileNotFoundError(f"Path is not a file: {resolved_path}")

    if offset < 0:
        offset = 0
    if limit < 0:
        limit = 0

    try:
        # Open in binary mode to allow safe seeking to arbitrary byte offsets
        with resolved_path.open("rb") as f:
            f.seek(offset)
            content_bytes = f.read(limit)
            # Decode with replacement to handle potential cut multibyte chars
            return content_bytes.decode("utf-8", errors="replace")
    except OSError as exc:
        logger.error("Error reading file paged %s: %s", resolved_path, exc)
        raise
