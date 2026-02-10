"""Tests for configuration generators."""

from __future__ import annotations

from pathlib import Path

from taipanstack.config.generators import (
    generate_dependabot_config,
    generate_editorconfig,
    generate_pre_commit_config,
    generate_pyproject_config,
    generate_security_policy,
    write_config_file,
)
from taipanstack.config.models import StackConfig


class TestGeneratePyprojectConfig:
    """Tests for generate_pyproject_config function."""

    def test_generates_ruff_config(self) -> None:
        """Test that Ruff configuration is generated."""
        config = StackConfig(project_name="test-project")
        result = generate_pyproject_config(config)

        assert "[tool.ruff]" in result
        assert "line-length" in result

    def test_generates_mypy_config(self) -> None:
        """Test that Mypy configuration is generated."""
        config = StackConfig(project_name="test-project")
        result = generate_pyproject_config(config)

        assert "[tool.mypy]" in result
        assert "python_version" in result

    def test_generates_pytest_config(self) -> None:
        """Test that Pytest configuration is generated."""
        config = StackConfig(project_name="test-project")
        result = generate_pyproject_config(config)

        assert "[tool.pytest" in result


class TestGeneratePreCommitConfig:
    """Tests for generate_pre_commit_config function."""

    def test_generates_yaml(self) -> None:
        """Test that valid YAML is generated."""
        config = StackConfig(project_name="test-project")
        result = generate_pre_commit_config(config)

        assert "repos:" in result
        assert "hooks:" in result

    def test_includes_ruff_hook(self) -> None:
        """Test that Ruff hook is included."""
        config = StackConfig(project_name="test-project")
        result = generate_pre_commit_config(config)

        assert "ruff" in result.lower()

    def test_includes_mypy_hook(self) -> None:
        """Test that Mypy hook is included."""
        config = StackConfig(project_name="test-project")
        result = generate_pre_commit_config(config)

        assert "mypy" in result.lower()


class TestGenerateDependabotConfig:
    """Tests for generate_dependabot_config function."""

    def test_generates_yaml(self) -> None:
        """Test that valid YAML is generated."""
        result = generate_dependabot_config()

        assert "version:" in result
        assert "updates:" in result

    def test_includes_pip_ecosystem(self) -> None:
        """Test that pip ecosystem is included."""
        result = generate_dependabot_config()

        assert "pip" in result

    def test_includes_github_actions(self) -> None:
        """Test that GitHub Actions is included."""
        result = generate_dependabot_config()

        assert "github-actions" in result


class TestGenerateSecurityPolicy:
    """Tests for generate_security_policy function."""

    def test_generates_markdown(self) -> None:
        """Test that Markdown is generated."""
        result = generate_security_policy()

        assert "# Security Policy" in result

    def test_includes_reporting_instructions(self) -> None:
        """Test that reporting instructions are included."""
        result = generate_security_policy()

        assert "report" in result.lower() or "vulnerabilit" in result.lower()

    def test_includes_supported_versions(self) -> None:
        """Test that supported versions section exists."""
        result = generate_security_policy()

        assert "version" in result.lower()


class TestGenerateEditorconfig:
    """Tests for generate_editorconfig function."""

    def test_generates_editorconfig(self) -> None:
        """Test that valid EditorConfig is generated."""
        result = generate_editorconfig()

        assert "root = true" in result

    def test_includes_python_settings(self) -> None:
        """Test that Python settings are included."""
        result = generate_editorconfig()

        assert "*.py" in result or "[*.py]" in result

    def test_includes_indent_settings(self) -> None:
        """Test that indentation settings are included."""
        result = generate_editorconfig()

        assert "indent_" in result


class TestWriteConfigFile:
    """Tests for write_config_file function."""

    def test_writes_file(self, tmp_path: Path) -> None:
        """Test that file is written."""
        config = StackConfig(project_name="test-project", dry_run=False)
        file_path = tmp_path / "test.txt"

        result = write_config_file(file_path, "test content", config)

        assert result is True
        assert file_path.exists()
        assert file_path.read_text() == "test content"

    def test_dry_run_does_not_write(self, tmp_path: Path) -> None:
        """Test that dry_run mode doesn't write."""
        config = StackConfig(project_name="test-project", dry_run=True)
        file_path = tmp_path / "test.txt"

        result = write_config_file(file_path, "test content", config)

        assert result is False
        assert not file_path.exists()

    def test_overwrites_existing_file(self, tmp_path: Path) -> None:
        """Test that existing file is overwritten."""
        config = StackConfig(project_name="test-project", dry_run=False, force=True)
        file_path = tmp_path / "test.txt"
        file_path.write_text("original")

        write_config_file(file_path, "new content", config)

        assert file_path.read_text() == "new content"

    def test_creates_backup_without_force(self, tmp_path: Path) -> None:
        """Test that backup is created when not using force mode."""
        config = StackConfig(project_name="test-project", dry_run=False, force=False)
        file_path = tmp_path / "test.txt"
        file_path.write_text("original")

        write_config_file(file_path, "new content", config)

        assert file_path.read_text() == "new content"
        backup_path = tmp_path / "test.txt.bak"
        assert backup_path.exists()
        assert backup_path.read_text() == "original"
