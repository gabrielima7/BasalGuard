"""Tests for safe filesystem operations."""

from __future__ import annotations

from pathlib import Path

import pytest

from taipanstack.core.result import Err, Ok
from taipanstack.security.guards import SecurityError
from taipanstack.utils.filesystem import (
    FileNotFoundErr,
    FileTooLargeErr,
    NotAFileErr,
    ensure_dir,
    find_files,
    get_file_hash,
    safe_copy,
    safe_delete,
    safe_read,
    safe_write,
)


class TestSafeRead:
    """Tests for safe_read function."""

    def test_read_existing_file(self, tmp_path: Path) -> None:
        """Test reading an existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!", encoding="utf-8")

        result = safe_read(test_file)
        match result:
            case Ok(content):
                assert content == "Hello, World!"
            case Err():
                pytest.fail("Expected Ok but got Err")

    def test_read_with_base_dir(self, tmp_path: Path) -> None:
        """Test reading with base directory constraint."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content", encoding="utf-8")

        result = safe_read(test_file, base_dir=tmp_path)
        match result:
            case Ok(content):
                assert content == "content"
            case Err():
                pytest.fail("Expected Ok but got Err")

    def test_read_nonexistent_file(self, tmp_path: Path) -> None:
        """Test reading non-existent file returns Err."""
        result = safe_read(tmp_path / "nonexistent.txt")
        match result:
            case Err(FileNotFoundErr(path=p)):
                assert "nonexistent.txt" in str(p)
            case _:
                pytest.fail("Expected Err(FileNotFoundErr)")

    def test_read_directory_fails(self, tmp_path: Path) -> None:
        """Test reading a directory returns Err."""
        result = safe_read(tmp_path)
        match result:
            case Err(NotAFileErr(path=p)):
                assert p == tmp_path
            case _:
                pytest.fail("Expected Err(NotAFileErr)")

    def test_read_file_too_large(self, tmp_path: Path) -> None:
        """Test reading file exceeding max_size returns Err."""
        test_file = tmp_path / "large.txt"
        test_file.write_text("A" * 1000, encoding="utf-8")

        result = safe_read(test_file, max_size_bytes=100)
        match result:
            case Err(FileTooLargeErr(size=s, max_size=m)):
                assert s >= 1000
                assert m == 100
            case _:
                pytest.fail("Expected Err(FileTooLargeErr)")

    def test_read_with_custom_encoding(self, tmp_path: Path) -> None:
        """Test reading with custom encoding."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("ÄÖÅÜ", encoding="utf-8")

        result = safe_read(test_file, encoding="utf-8")
        match result:
            case Ok(content):
                assert content == "ÄÖÅÜ"
            case Err():
                pytest.fail("Expected Ok")

    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        """Test that path traversal is blocked."""
        result = safe_read(tmp_path / ".." / "etc" / "passwd", base_dir=tmp_path)
        match result:
            case Err(SecurityError()):
                pass  # Expected
            case _:
                pytest.fail("Expected Err(SecurityError)")


class TestSafeWrite:
    """Tests for safe_write function."""

    def test_write_new_file(self, tmp_path: Path) -> None:
        """Test writing a new file."""
        test_file = tmp_path / "new.txt"
        result = safe_write(test_file, "content")

        assert result.exists()
        assert result.read_text() == "content"

    def test_write_creates_parent_dirs(self, tmp_path: Path) -> None:
        """Test that parent directories are created."""
        test_file = tmp_path / "subdir" / "nested" / "file.txt"
        safe_write(test_file, "nested content")

        assert test_file.exists()

    def test_write_creates_backup(self, tmp_path: Path) -> None:
        """Test that backup is created for existing file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("original")

        safe_write(test_file, "updated", backup=True)

        assert test_file.read_text() == "updated"
        assert (tmp_path / "test.txt.bak").exists()
        assert (tmp_path / "test.txt.bak").read_text() == "original"

    def test_write_no_backup(self, tmp_path: Path) -> None:
        """Test writing without backup."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("original")

        safe_write(test_file, "updated", backup=False)

        assert test_file.read_text() == "updated"
        assert not (tmp_path / "test.txt.bak").exists()

    def test_atomic_write(self, tmp_path: Path) -> None:
        """Test atomic write mode."""
        test_file = tmp_path / "atomic.txt"
        safe_write(test_file, "atomic content", atomic=True)

        assert test_file.read_text() == "atomic content"

    def test_non_atomic_write(self, tmp_path: Path) -> None:
        """Test non-atomic write mode."""
        test_file = tmp_path / "direct.txt"
        safe_write(test_file, "direct content", atomic=False)

        assert test_file.read_text() == "direct content"

    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        """Test that path traversal is blocked."""
        with pytest.raises(SecurityError):
            safe_write(
                tmp_path / ".." / "etc" / "evil.txt",
                "malicious",
                base_dir=tmp_path,
            )


class TestEnsureDir:
    """Tests for ensure_dir function."""

    def test_create_new_directory(self, tmp_path: Path) -> None:
        """Test creating a new directory."""
        new_dir = tmp_path / "new_dir"
        result = ensure_dir(new_dir)

        assert result.exists()
        assert result.is_dir()

    def test_existing_directory_ok(self, tmp_path: Path) -> None:
        """Test that existing directory is OK."""
        result = ensure_dir(tmp_path)
        assert result.exists()

    def test_create_nested_directories(self, tmp_path: Path) -> None:
        """Test creating nested directories."""
        nested = tmp_path / "a" / "b" / "c"
        result = ensure_dir(nested)

        assert result.exists()
        assert result.is_dir()


class TestSafeCopy:
    """Tests for safe_copy function."""

    def test_copy_file(self, tmp_path: Path) -> None:
        """Test copying a file."""
        src = tmp_path / "source.txt"
        src.write_text("content")
        dst = tmp_path / "dest.txt"

        result = safe_copy(src, dst)

        assert result.exists()
        assert result.read_text() == "content"

    def test_copy_nonexistent_source(self, tmp_path: Path) -> None:
        """Test copying non-existent source raises error."""
        with pytest.raises(FileNotFoundError):
            safe_copy(tmp_path / "nonexistent.txt", tmp_path / "dest.txt")

    def test_copy_overwrite_denied(self, tmp_path: Path) -> None:
        """Test overwriting denied by default."""
        src = tmp_path / "source.txt"
        src.write_text("source")
        dst = tmp_path / "dest.txt"
        dst.write_text("existing")

        with pytest.raises(FileExistsError):
            safe_copy(src, dst, overwrite=False)

    def test_copy_overwrite_allowed(self, tmp_path: Path) -> None:
        """Test overwriting when allowed."""
        src = tmp_path / "source.txt"
        src.write_text("new content")
        dst = tmp_path / "dest.txt"
        dst.write_text("old content")

        safe_copy(src, dst, overwrite=True)

        assert dst.read_text() == "new content"

    def test_copy_creates_parent_dirs(self, tmp_path: Path) -> None:
        """Test that parent directories are created."""
        src = tmp_path / "source.txt"
        src.write_text("content")
        dst = tmp_path / "subdir" / "dest.txt"

        safe_copy(src, dst)

        assert dst.exists()


class TestSafeDelete:
    """Tests for safe_delete function."""

    def test_delete_file(self, tmp_path: Path) -> None:
        """Test deleting a file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        deleted = safe_delete(test_file)

        assert deleted is True
        assert not test_file.exists()

    def test_delete_nonexistent_missing_ok(self, tmp_path: Path) -> None:
        """Test deleting non-existent file with missing_ok=True."""
        deleted = safe_delete(tmp_path / "nonexistent.txt", missing_ok=True)
        assert deleted is False

    def test_delete_nonexistent_missing_not_ok(self, tmp_path: Path) -> None:
        """Test deleting non-existent file with missing_ok=False."""
        with pytest.raises(FileNotFoundError):
            safe_delete(tmp_path / "nonexistent.txt", missing_ok=False)

    def test_delete_directory_non_recursive(self, tmp_path: Path) -> None:
        """Test deleting empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        deleted = safe_delete(empty_dir, recursive=False)

        assert deleted is True
        assert not empty_dir.exists()

    def test_delete_directory_recursive(self, tmp_path: Path) -> None:
        """Test deleting directory recursively."""
        dir_path = tmp_path / "dir"
        dir_path.mkdir()
        (dir_path / "file.txt").write_text("content")

        deleted = safe_delete(dir_path, recursive=True)

        assert deleted is True
        assert not dir_path.exists()

    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        """Test that path traversal is blocked."""
        with pytest.raises(SecurityError):
            safe_delete(tmp_path / ".." / "etc" / "passwd", base_dir=tmp_path)


class TestGetFileHash:
    """Tests for get_file_hash function."""

    def test_sha256_hash(self, tmp_path: Path) -> None:
        """Test SHA256 hash computation."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")

        file_hash = get_file_hash(test_file)

        # Known SHA256 hash of "hello"
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        assert file_hash == expected

    def test_md5_hash(self, tmp_path: Path) -> None:
        """Test MD5 hash computation."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")

        file_hash = get_file_hash(test_file, algorithm="md5")

        # Known MD5 hash of "hello"
        expected = "5d41402abc4b2a76b9719d911017c592"
        assert file_hash == expected

    def test_same_content_same_hash(self, tmp_path: Path) -> None:
        """Test that same content produces same hash."""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        file1.write_text("identical content")
        file2.write_text("identical content")

        assert get_file_hash(file1) == get_file_hash(file2)


class TestFindFiles:
    """Tests for find_files function."""

    def test_find_all_files(self, tmp_path: Path) -> None:
        """Test finding all files."""
        (tmp_path / "file1.txt").write_text("1")
        (tmp_path / "file2.txt").write_text("2")

        files = find_files(tmp_path)

        assert len(files) == 2

    def test_find_by_pattern(self, tmp_path: Path) -> None:
        """Test finding files by pattern."""
        (tmp_path / "test.py").write_text("python")
        (tmp_path / "test.txt").write_text("text")

        files = find_files(tmp_path, pattern="*.py")

        assert len(files) == 1
        assert files[0].suffix == ".py"

    def test_find_recursive(self, tmp_path: Path) -> None:
        """Test recursive file search."""
        (tmp_path / "root.txt").write_text("root")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("nested")

        files = find_files(tmp_path, recursive=True)

        assert len(files) == 2

    def test_find_non_recursive(self, tmp_path: Path) -> None:
        """Test non-recursive file search."""
        (tmp_path / "root.txt").write_text("root")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("nested")

        files = find_files(tmp_path, pattern="*.txt", recursive=False)

        assert len(files) == 1
        assert files[0].name == "root.txt"

    def test_find_excludes_hidden_by_default(self, tmp_path: Path) -> None:
        """Test that hidden files are excluded by default."""
        (tmp_path / "visible.txt").write_text("visible")
        (tmp_path / ".hidden.txt").write_text("hidden")

        files = find_files(tmp_path, include_hidden=False)

        assert len(files) == 1
        assert files[0].name == "visible.txt"

    def test_find_includes_hidden(self, tmp_path: Path) -> None:
        """Test including hidden files."""
        (tmp_path / "visible.txt").write_text("visible")
        (tmp_path / ".hidden.txt").write_text("hidden")

        files = find_files(tmp_path, include_hidden=True)

        assert len(files) == 2

    def test_find_in_nonexistent_dir(self, tmp_path: Path) -> None:
        """Test finding in non-existent directory returns empty list."""
        files = find_files(tmp_path / "nonexistent")
        assert files == []
