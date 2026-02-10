"""
Safe filesystem operations.

Provides secure wrappers around file operations with path validation,
atomic writes, and proper error handling using Result types.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from taipanstack.core.result import Err, Ok, Result
from taipanstack.security.guards import SecurityError, guard_path_traversal
from taipanstack.security.sanitizers import sanitize_filename


@dataclass(frozen=True)
class FileNotFoundErr:
    """Error when file is not found."""

    path: Path
    message: str = ""

    def __post_init__(self) -> None:
        """Set default message."""
        object.__setattr__(
            self, "message", self.message or f"File not found: {self.path}"
        )


@dataclass(frozen=True)
class NotAFileErr:
    """Error when path is not a file."""

    path: Path
    message: str = ""

    def __post_init__(self) -> None:
        """Set default message."""
        object.__setattr__(self, "message", self.message or f"Not a file: {self.path}")


@dataclass(frozen=True)
class FileTooLargeErr:
    """Error when file exceeds size limit."""

    path: Path
    size: int
    max_size: int
    message: str = ""

    def __post_init__(self) -> None:
        """Set default message."""
        object.__setattr__(
            self,
            "message",
            self.message or f"File too large: {self.size} bytes (max: {self.max_size})",
        )


# Union type for safe_read errors
ReadFileError: TypeAlias = (
    FileNotFoundErr | NotAFileErr | FileTooLargeErr | SecurityError
)


def safe_read(
    path: Path | str,
    *,
    base_dir: Path | str | None = None,
    encoding: str = "utf-8",
    max_size_bytes: int | None = 10 * 1024 * 1024,  # 10MB default
) -> Result[str, ReadFileError]:
    """Read a file safely with path validation.

    Args:
        path: Path to the file to read.
        base_dir: Base directory to constrain to.
        encoding: File encoding.
        max_size_bytes: Maximum file size to read (None for no limit).

    Returns:
        Ok(str): File contents on success.
        Err(ReadFileError): Error details on failure.

    Example:
        >>> match safe_read("config.json"):
        ...     case Ok(content):
        ...         data = json.loads(content)
        ...     case Err(FileNotFoundErr(path=p)):
        ...         print(f"Missing: {p}")
        ...     case Err(FileTooLargeErr(size=s)):
        ...         print(f"Too big: {s} bytes")

    """
    path = Path(path)

    # Validate path
    try:
        if base_dir is not None:
            path = guard_path_traversal(path, Path(base_dir))
        elif ".." in str(path):
            path = guard_path_traversal(path, Path.cwd())
    except SecurityError as e:
        return Err(e)

    if not path.exists():
        return Err(FileNotFoundErr(path=path))

    if not path.is_file():
        return Err(NotAFileErr(path=path))

    # Check file size
    if max_size_bytes is not None:
        file_size = path.stat().st_size
        if file_size > max_size_bytes:
            return Err(
                FileTooLargeErr(path=path, size=file_size, max_size=max_size_bytes)
            )

    return Ok(path.read_text(encoding=encoding))


def safe_write(
    path: Path | str,
    content: str,
    *,
    base_dir: Path | str | None = None,
    encoding: str = "utf-8",
    create_parents: bool = True,
    backup: bool = True,
    atomic: bool = True,
) -> Path:
    """Write to a file safely with path validation.

    Args:
        path: Path to write to.
        content: Content to write.
        base_dir: Base directory to constrain to.
        encoding: File encoding.
        create_parents: Create parent directories if needed.
        backup: Create backup of existing file.
        atomic: Use atomic write (write to temp, then rename).

    Returns:
        Path to the written file.

    Raises:
        SecurityError: If path validation fails.

    """
    path = Path(path)

    # Validate path
    if base_dir is not None:
        base = Path(base_dir).resolve()
        # For new files, validate the parent
        if not path.exists():
            parent = path.parent
            guard_path_traversal(parent, base)
        else:
            guard_path_traversal(path, base)
    elif ".." in str(path):
        guard_path_traversal(path, Path.cwd())

    # Sanitize filename
    safe_name = sanitize_filename(path.name)
    path = path.parent / safe_name

    # Create parents if needed
    if create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)

    # Create backup if file exists
    if backup and path.exists():
        backup_path = path.with_suffix(f"{path.suffix}.bak")
        shutil.copy2(path, backup_path)

    # Write file
    if atomic:
        # Write to temp file first, then rename
        _fd, temp_path = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        try:
            # Close the file descriptor immediately - required for Windows
            os.close(_fd)
            temp_file = Path(temp_path)
            temp_file.write_text(content, encoding=encoding)
            # Preserve permissions if original exists
            if path.exists():
                shutil.copymode(path, temp_file)
            # On Windows, we need to remove the target first if it exists
            if path.exists():
                path.unlink()
            temp_file.rename(path)
        except Exception:
            # Clean up temp file on error
            with contextlib.suppress(OSError):
                Path(temp_path).unlink(missing_ok=True)
            raise
    else:
        path.write_text(content, encoding=encoding)

    return path.resolve()


def ensure_dir(
    path: Path | str,
    *,
    base_dir: Path | str | None = None,
    mode: int = 0o755,
) -> Path:
    """Ensure a directory exists, creating it if needed.

    Args:
        path: Path to the directory.
        base_dir: Base directory to constrain to.
        mode: Directory permissions.

    Returns:
        Path to the directory.

    Raises:
        SecurityError: If path validation fails.

    """
    path = Path(path)

    # Validate path
    if base_dir is not None:
        path = guard_path_traversal(path, Path(base_dir), allow_symlinks=True)
    elif ".." in str(path):
        path = guard_path_traversal(path, Path.cwd())

    path.mkdir(parents=True, exist_ok=True, mode=mode)
    return path.resolve()


def safe_copy(
    src: Path | str,
    dst: Path | str,
    *,
    base_dir: Path | str | None = None,
    overwrite: bool = False,
) -> Path:
    """Copy a file safely.

    Args:
        src: Source file path.
        dst: Destination file path.
        base_dir: Base directory to constrain both paths to.
        overwrite: Allow overwriting existing file.

    Returns:
        Path to the destination file.

    Raises:
        SecurityError: If path validation fails.
        FileExistsError: If destination exists and overwrite=False.

    """
    src = Path(src)
    dst = Path(dst)

    # Validate paths
    if base_dir is not None:
        base = Path(base_dir)
        src = guard_path_traversal(src, base)
        # For dst, validate parent if file doesn't exist
        if dst.exists():
            dst = guard_path_traversal(dst, base)
        else:
            guard_path_traversal(dst.parent, base)

    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src}")

    if dst.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists: {dst}")

    # Ensure parent directory exists
    dst.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy2(src, dst)
    return dst.resolve()


def safe_delete(
    path: Path | str,
    *,
    base_dir: Path | str | None = None,
    missing_ok: bool = True,
    recursive: bool = False,
) -> bool:
    """Delete a file or directory safely.

    Args:
        path: Path to delete.
        base_dir: Base directory to constrain to.
        missing_ok: Don't raise if path doesn't exist.
        recursive: Allow deleting directories recursively.

    Returns:
        True if something was deleted.

    Raises:
        SecurityError: If path validation fails.
        FileNotFoundError: If path doesn't exist and missing_ok=False.

    """
    path = Path(path)

    # Validate path
    if base_dir is not None:
        path = guard_path_traversal(path, Path(base_dir))
    elif ".." in str(path):
        path = guard_path_traversal(path, Path.cwd())

    if not path.exists():
        if missing_ok:
            return False
        raise FileNotFoundError(f"Path not found: {path}")

    if path.is_dir():
        if recursive:
            shutil.rmtree(path)
        else:
            path.rmdir()
    else:
        path.unlink()

    return True


def get_file_hash(
    path: Path | str,
    *,
    algorithm: str = "sha256",
    base_dir: Path | str | None = None,
) -> str:
    """Get hash of a file.

    Args:
        path: Path to the file.
        algorithm: Hash algorithm (sha256, md5, etc).
        base_dir: Base directory to constrain to.

    Returns:
        Hex digest of the file hash.

    """
    path = Path(path)

    # Validate path
    if base_dir is not None:
        path = guard_path_traversal(path, Path(base_dir))

    hasher = hashlib.new(algorithm)

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def find_files(
    directory: Path | str,
    pattern: str = "*",
    *,
    base_dir: Path | str | None = None,
    recursive: bool = True,
    include_hidden: bool = False,
) -> list[Path]:
    """Find files matching a pattern.

    Args:
        directory: Directory to search in.
        pattern: Glob pattern to match.
        base_dir: Base directory to constrain to.
        recursive: Search recursively.
        include_hidden: Include hidden files (starting with .).

    Returns:
        List of matching file paths.

    """
    directory = Path(directory)

    # Validate path
    if base_dir is not None:
        directory = guard_path_traversal(directory, Path(base_dir))

    if not directory.exists():
        return []

    if recursive:
        files = list(directory.rglob(pattern))
    else:
        files = list(directory.glob(pattern))

    # Filter hidden files if needed
    if not include_hidden:
        files = [f for f in files if not any(p.startswith(".") for p in f.parts)]

    # Only return files, not directories
    return [f for f in files if f.is_file()]
