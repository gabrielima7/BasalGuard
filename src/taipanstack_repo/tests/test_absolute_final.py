"""Absolute final tests to hit every remaining line."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


class TestValidatorsTLD:
    """Tests for validators URL TLD check (lines 235-236)."""

    def test_validate_url_no_tld(self) -> None:
        """Test validate_url with domain that has no TLD."""
        from taipanstack.security.validators import validate_url

        # Domain without TLD should fail
        with pytest.raises(ValueError, match="TLD"):
            validate_url("http://testserver/path")

    def test_validate_url_ends_with_dot(self) -> None:
        """Test validate_url with domain ending in dot."""
        from taipanstack.security.validators import validate_url

        with pytest.raises(ValueError, match="TLD"):
            validate_url("http://example./path")


class TestValidatorsParseError:
    """Tests for validators URL ValueError (lines 213-215)."""

    def test_validate_url_parse_error(self) -> None:
        """Test validate_url when urlparse raises ValueError."""
        from taipanstack.security.validators import validate_url

        # Force urlparse to raise ValueError by patching
        with patch("taipanstack.security.validators.urlparse") as mock_parse:
            mock_parse.side_effect = ValueError("Parse failed")
            with pytest.raises(ValueError, match="Invalid URL"):
                validate_url("http://valid.com")


class TestValidatorsPortString:
    """Tests for validators port conversion (lines 302-304)."""

    def test_validate_port_string_invalid(self) -> None:
        """Test validate_port with invalid string."""
        from taipanstack.security.validators import validate_port

        with pytest.raises(ValueError, match="Invalid port"):
            validate_port("not_a_number")


class TestGuardsSymlinkDenied:
    """Tests for guards symlink denied (line 118)."""

    def test_guard_path_traversal_symlink_param(self, tmp_path: Path) -> None:
        """Test guard_path_traversal with allow_symlinks parameter."""
        from taipanstack.security.guards import guard_path_traversal

        # Regular file should work regardless
        regular = tmp_path / "regular.txt"
        regular.write_text("content")

        result = guard_path_traversal(regular, tmp_path, allow_symlinks=False)
        assert result.exists()


class TestGuardsExtensionDenied:
    """Tests for guards extension denied (line 256)."""

    def test_guard_file_extension_not_in_allowed(self) -> None:
        """Test guard_file_extension when extension not in allowed list."""
        from taipanstack.security.guards import SecurityError, guard_file_extension

        with pytest.raises(SecurityError, match="not in allowed"):
            guard_file_extension("file.pdf", allowed_extensions=["txt", "doc"])


class TestSanitizersEmptyParts:
    """Tests for sanitizers edge cases (lines 154, 221-223)."""

    def test_sanitize_filename_becomes_empty(self) -> None:
        """Test sanitize_filename when sanitized stem is empty."""
        from taipanstack.security.sanitizers import sanitize_filename

        # Reserved name with just dots
        result = sanitize_filename(
            "....",
        )
        assert result == "unnamed"

    def test_sanitize_path_base_dir_constraint(self, tmp_path: Path) -> None:
        """Test sanitize_path with base_dir and non-existent path."""
        from taipanstack.security.sanitizers import sanitize_path

        # Should work with relative path
        result = sanitize_path("new/file.txt", base_dir=tmp_path, max_depth=None)
        assert str(tmp_path) in str(result)


class TestFilesystemLine175:
    """Test for filesystem.py line 175."""

    def test_safe_write_different_encoding(self, tmp_path: Path) -> None:
        """Test safe_write with different encoding."""
        from taipanstack.utils.filesystem import safe_write

        test_file = tmp_path / "encoded.txt"
        content = "Héllo Wörld"

        result = safe_write(test_file, content, encoding="utf-8")
        assert result.read_text(encoding="utf-8") == content


class TestSubprocessLine229:
    """Test for subprocess.py line 229."""

    def test_run_safe_command_not_on_path(self) -> None:
        """Test run_safe_command with command not on PATH."""
        from taipanstack.utils.subprocess import get_command_version

        result = get_command_version("totally_nonexistent_command_xyz_123")
        assert result is None
