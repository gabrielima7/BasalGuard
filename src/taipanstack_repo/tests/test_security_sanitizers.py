"""Tests for input sanitizers."""

from __future__ import annotations

from pathlib import Path

import pytest

from taipanstack.security.sanitizers import (
    sanitize_env_value,
    sanitize_filename,
    sanitize_path,
    sanitize_sql_identifier,
    sanitize_string,
)


class TestSanitizeString:
    """Tests for sanitize_string function."""

    def test_empty_string(self) -> None:
        """Test empty string returns empty."""
        assert sanitize_string("") == ""

    def test_normal_string_unchanged(self) -> None:
        """Test normal string passes through."""
        assert sanitize_string("Hello World") == "Hello World"

    def test_strips_whitespace(self) -> None:
        """Test whitespace is stripped by default."""
        assert sanitize_string("  hello  ") == "hello"

    def test_no_strip_whitespace(self) -> None:
        """Test whitespace preserved when disabled."""
        result = sanitize_string("  hello  ", strip_whitespace=False)
        assert result == "  hello  "

    def test_removes_null_bytes(self) -> None:
        """Test null bytes are removed."""
        assert sanitize_string("hel\x00lo") == "hello"

    def test_removes_html_tags(self) -> None:
        """Test HTML tags are removed by default."""
        result = sanitize_string("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "alert" in result  # Text content preserved

    def test_allows_html_when_enabled(self) -> None:
        """Test HTML tags preserved when allowed."""
        result = sanitize_string("<b>bold</b>", allow_html=True)
        assert "<b>" in result

    def test_removes_control_characters(self) -> None:
        """Test control characters are removed."""
        result = sanitize_string("hello\x01\x02world")
        assert result == "helloworld"

    def test_preserves_newlines(self) -> None:
        """Test newlines are preserved."""
        result = sanitize_string("line1\nline2")
        assert "\n" in result

    def test_removes_unicode_when_disabled(self) -> None:
        """Test unicode removed when not allowed."""
        result = sanitize_string("héllo wörld", allow_unicode=False)
        assert "é" not in result
        assert "ö" not in result

    def test_truncates_to_max_length(self) -> None:
        """Test string is truncated."""
        result = sanitize_string("hello world", max_length=5)
        assert result == "hello"
        assert len(result) == 5

    def test_escapes_html_entities(self) -> None:
        """Test HTML entities are escaped after tag removal."""
        # Note: < and > inside text (not as tags) get escaped after tag stripping
        result = sanitize_string("text&more")
        assert "&amp;" in result


class TestSanitizeFilename:
    """Tests for sanitize_filename function."""

    def test_empty_filename(self) -> None:
        """Test empty filename returns 'unnamed'."""
        assert sanitize_filename("") == "unnamed"

    def test_normal_filename(self) -> None:
        """Test normal filename passes through."""
        assert sanitize_filename("test.txt") == "test.txt"

    def test_removes_path_characters(self) -> None:
        """Test path characters are removed."""
        result = sanitize_filename("../etc/passwd.txt")
        assert "/" not in result
        assert ".." not in result

    def test_removes_invalid_windows_chars(self) -> None:
        """Test Windows invalid chars are removed."""
        result = sanitize_filename("file<>:name.txt")
        assert "<" not in result
        assert ">" not in result
        assert ":" not in result

    def test_preserves_extension(self) -> None:
        """Test extension is preserved by default."""
        result = sanitize_filename("bad<file>name.txt")
        assert result.endswith(".txt")

    def test_no_preserve_extension(self) -> None:
        """Test extension not preserved when disabled."""
        result = sanitize_filename("test.txt", preserve_extension=False)
        assert result == "test"

    def test_handles_reserved_names(self) -> None:
        """Test Windows reserved names are handled."""
        result = sanitize_filename("CON")
        assert result != "CON"
        assert result.upper() != "CON"

    def test_max_length_with_extension(self) -> None:
        """Test max length preserves extension."""
        result = sanitize_filename("verylongfilename.txt", max_length=10)
        assert len(result) <= 10
        assert result.endswith(".txt")

    def test_custom_replacement(self) -> None:
        """Test custom replacement character."""
        result = sanitize_filename("bad:name.txt", replacement="-")
        assert ":" not in result
        assert "-" in result

    def test_collapses_multiple_replacements(self) -> None:
        """Test multiple invalid chars become single replacement."""
        result = sanitize_filename("a:::b.txt")
        assert "___" not in result  # Collapsed to single _


class TestSanitizePath:
    """Tests for sanitize_path function."""

    def test_simple_path(self) -> None:
        """Test simple path passes through."""
        result = sanitize_path("test/file.txt")
        assert "test" in str(result)
        assert "file.txt" in str(result)

    def test_removes_traversal(self) -> None:
        """Test path traversal is removed."""
        result = sanitize_path("../etc/passwd")
        assert ".." not in str(result)

    def test_removes_null_bytes(self) -> None:
        """Test null bytes in path are removed."""
        result = sanitize_path("test\x00file.txt")
        assert "\x00" not in str(result)

    def test_max_depth_enforced(self) -> None:
        """Test max depth is enforced."""
        deep_path = "/".join(["dir"] * 20)
        with pytest.raises(ValueError, match="depth"):
            sanitize_path(deep_path, max_depth=5)

    def test_with_base_dir(self, tmp_path: Path) -> None:
        """Test path with base directory."""
        base = tmp_path / "base"
        base.mkdir()
        # max_depth=None to avoid depth check (CI paths can be very long)
        result = sanitize_path("subdir/file.txt", base_dir=base, max_depth=None)
        # Check result is under base directory using Path comparison
        assert str(base) in str(result)


class TestSanitizeEnvValue:
    """Tests for sanitize_env_value function."""

    def test_empty_value(self) -> None:
        """Test empty value returns empty."""
        assert sanitize_env_value("") == ""

    def test_normal_value(self) -> None:
        """Test normal value passes through."""
        assert sanitize_env_value("hello") == "hello"

    def test_removes_null_bytes(self) -> None:
        """Test null bytes are removed."""
        assert sanitize_env_value("hel\x00lo") == "hello"

    def test_removes_newlines_by_default(self) -> None:
        """Test newlines are replaced by default."""
        result = sanitize_env_value("line1\nline2")
        assert "\n" not in result

    def test_allows_multiline(self) -> None:
        """Test newlines preserved when allowed."""
        result = sanitize_env_value("line1\nline2", allow_multiline=True)
        assert "\n" in result

    def test_truncates_to_max_length(self) -> None:
        """Test truncation to max length."""
        long_value = "a" * 5000
        result = sanitize_env_value(long_value, max_length=100)
        assert len(result) == 100


class TestSanitizeSqlIdentifier:
    """Tests for sanitize_sql_identifier function."""

    def test_empty_identifier_raises(self) -> None:
        """Test empty identifier raises ValueError."""
        with pytest.raises(ValueError, match="cannot be empty"):
            sanitize_sql_identifier("")

    def test_normal_identifier(self) -> None:
        """Test normal identifier passes through."""
        assert sanitize_sql_identifier("users") == "users"

    def test_removes_special_characters(self) -> None:
        """Test special characters are removed."""
        result = sanitize_sql_identifier("users;DROP TABLE--")
        assert ";" not in result
        assert "-" not in result
        assert "DROP" in result  # Letters preserved

    def test_prefix_if_starts_with_number(self) -> None:
        """Test underscore added if starts with number."""
        result = sanitize_sql_identifier("123column")
        assert result.startswith("_")

    def test_truncates_long_identifier(self) -> None:
        """Test long identifier is truncated."""
        long_name = "a" * 200
        result = sanitize_sql_identifier(long_name)
        assert len(result) <= 128

    def test_invalid_chars_only_raises(self) -> None:
        """Test identifier with only invalid chars raises."""
        with pytest.raises(ValueError, match="no valid characters"):
            sanitize_sql_identifier(";--")

    def test_allows_underscores(self) -> None:
        """Test underscores are allowed."""
        result = sanitize_sql_identifier("user_name")
        assert result == "user_name"
