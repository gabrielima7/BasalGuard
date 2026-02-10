"""Tests for stack.security.guards module."""

from pathlib import Path

import pytest

from taipanstack.security.guards import (
    SecurityError,
    guard_command_injection,
    guard_file_extension,
    guard_path_traversal,
)


class TestGuardPathTraversal:
    """Tests for guard_path_traversal function."""

    def test_safe_path_passes(self, tmp_path: Path) -> None:
        """Test that safe paths pass validation."""
        safe_file = tmp_path / "test.txt"
        safe_file.touch()

        result = guard_path_traversal(safe_file, tmp_path)
        assert result == safe_file.resolve()

    def test_relative_path_within_base(self, tmp_path: Path) -> None:
        """Test that relative paths within base dir pass."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        test_file = subdir / "test.txt"
        test_file.touch()

        result = guard_path_traversal(Path("subdir/test.txt"), tmp_path)
        assert result == test_file.resolve()

    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        """Test that path traversal attempts are blocked."""
        with pytest.raises(SecurityError) as exc_info:
            guard_path_traversal("../etc/passwd", tmp_path)

        assert "path_traversal" in str(exc_info.value)
        assert exc_info.value.guard_name == "path_traversal"

    def test_double_dot_blocked(self, tmp_path: Path) -> None:
        """Test that .. patterns are blocked."""
        with pytest.raises(SecurityError):
            guard_path_traversal("foo/../../../etc/passwd", tmp_path)

    def test_url_encoded_traversal_blocked(self, tmp_path: Path) -> None:
        """Test that URL encoded traversal is blocked."""
        with pytest.raises(SecurityError):
            guard_path_traversal("%2e%2e/etc/passwd", tmp_path)

    def test_path_escapes_base_dir(self, tmp_path: Path) -> None:
        """Test that paths escaping base dir are blocked."""
        # Create a separate base directory
        subdir = tmp_path / "allowed"
        subdir.mkdir()

        # Try to access a file outside the allowed base
        outside_file = tmp_path / "outside.txt"
        outside_file.touch()

        with pytest.raises(SecurityError) as exc_info:
            guard_path_traversal(outside_file, subdir)
        # The error should indicate path is not under base dir
        assert "path_traversal" in str(exc_info.value).lower()


class TestGuardCommandInjection:
    """Tests for guard_command_injection function."""

    def test_safe_command_passes(self) -> None:
        """Test that safe commands pass validation."""
        cmd = ["python", "-m", "pytest", "-v"]
        result = guard_command_injection(cmd)
        assert result == cmd

    def test_empty_command_blocked(self) -> None:
        """Test that empty commands are blocked."""
        with pytest.raises(SecurityError) as exc_info:
            guard_command_injection([])
        assert "Empty command" in str(exc_info.value)

    def test_semicolon_blocked(self) -> None:
        """Test that semicolons are blocked."""
        with pytest.raises(SecurityError):
            guard_command_injection(["echo", "hello; rm -rf /"])

    def test_pipe_blocked(self) -> None:
        """Test that pipe characters are blocked."""
        with pytest.raises(SecurityError):
            guard_command_injection(["cat", "file | rm -rf /"])

    def test_backtick_blocked(self) -> None:
        """Test that backticks are blocked."""
        with pytest.raises(SecurityError):
            guard_command_injection(["echo", "`whoami`"])

    def test_dollar_expansion_blocked(self) -> None:
        """Test that dollar expansion is blocked."""
        with pytest.raises(SecurityError):
            guard_command_injection(["echo", "$(whoami)"])

    def test_allowed_commands_whitelist(self) -> None:
        """Test command whitelist functionality."""
        cmd = ["python", "-c", "print('hello')"]
        result = guard_command_injection(cmd, allowed_commands=["python"])
        assert result == cmd

    def test_command_not_in_whitelist_blocked(self) -> None:
        """Test that commands not in whitelist are blocked."""
        with pytest.raises(SecurityError) as exc_info:
            guard_command_injection(["rm", "-rf", "/"], allowed_commands=["python"])
        assert "not in allowed list" in str(exc_info.value)


class TestGuardFileExtension:
    """Tests for guard_file_extension function."""

    def test_safe_extension_passes(self) -> None:
        """Test that safe extensions pass."""
        result = guard_file_extension("script.py", allowed_extensions=["py", "txt"])
        assert result == Path("script.py")

    def test_dangerous_extension_blocked(self) -> None:
        """Test that dangerous extensions are blocked."""
        with pytest.raises(SecurityError) as exc_info:
            guard_file_extension("evil.exe")
        assert "not allowed" in str(exc_info.value)

    def test_custom_denied_extensions(self) -> None:
        """Test custom denied extensions."""
        with pytest.raises(SecurityError):
            guard_file_extension("config.yaml", denied_extensions=["yaml", "yml"])

    def test_extension_with_dot(self) -> None:
        """Test that extensions with dots are handled."""
        result = guard_file_extension("file.txt", allowed_extensions=[".txt"])
        assert result == Path("file.txt")


class TestGuardEnvVariable:
    """Tests for guard_env_variable function."""

    def test_safe_env_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that safe environment variables are returned."""
        from taipanstack.security.guards import guard_env_variable

        monkeypatch.setenv("SAFE_VAR", "safe_value")
        result = guard_env_variable("SAFE_VAR")
        assert result == "safe_value"

    def test_blocked_default_sensitive(self) -> None:
        """Test that default sensitive variables are blocked."""
        from taipanstack.security.guards import guard_env_variable

        with pytest.raises(SecurityError, match="denied"):
            guard_env_variable("AWS_SECRET_ACCESS_KEY")

    def test_blocked_password_pattern(self) -> None:
        """Test that PASSWORD pattern is blocked."""
        from taipanstack.security.guards import guard_env_variable

        with pytest.raises(SecurityError, match="denied"):
            guard_env_variable("DB_PASSWORD")

    def test_blocked_token_pattern(self) -> None:
        """Test that TOKEN pattern is blocked."""
        from taipanstack.security.guards import guard_env_variable

        with pytest.raises(SecurityError, match="denied"):
            guard_env_variable("GITHUB_TOKEN")

    def test_missing_env_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that missing variables raise error."""
        from taipanstack.security.guards import guard_env_variable

        monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
        with pytest.raises(SecurityError, match="not set"):
            guard_env_variable("NONEXISTENT_VAR")

    def test_custom_denied_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test custom denied names."""
        from taipanstack.security.guards import guard_env_variable

        with pytest.raises(SecurityError, match="denied"):
            guard_env_variable("CUSTOM_SECRET", denied_names=["CUSTOM_SECRET"])

    def test_allowed_names_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that allowed_names override pattern blocking."""
        from taipanstack.security.guards import guard_env_variable

        monkeypatch.setenv("MY_TOKEN", "allowed_token")
        result = guard_env_variable("MY_TOKEN", allowed_names=["MY_TOKEN"])
        assert result == "allowed_token"
