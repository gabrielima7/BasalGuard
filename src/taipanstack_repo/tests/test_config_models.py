"""Tests for stack.config.models module."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from taipanstack.config.models import (
    DependencyConfig,
    LoggingConfig,
    SecurityConfig,
    StackConfig,
)


class TestSecurityConfig:
    """Tests for SecurityConfig model."""

    def test_default_values(self) -> None:
        """Test default security configuration."""
        config = SecurityConfig()

        assert config.level == "strict"
        assert config.enable_bandit is True
        assert config.enable_safety is True
        assert config.enable_semgrep is True
        assert config.enable_detect_secrets is True
        assert config.bandit_severity == "low"

    def test_paranoid_level(self) -> None:
        """Test paranoid security level."""
        config = SecurityConfig(level="paranoid")
        assert config.level == "paranoid"

    def test_frozen_config(self) -> None:
        """Test that config is immutable."""
        config = SecurityConfig()
        with pytest.raises(ValidationError):
            config.level = "standard"  # type: ignore

    def test_extra_fields_forbidden(self) -> None:
        """Test that extra fields are not allowed."""
        with pytest.raises(ValidationError):
            SecurityConfig(invalid_field="value")


class TestDependencyConfig:
    """Tests for DependencyConfig model."""

    def test_default_values(self) -> None:
        """Test default dependency configuration."""
        config = DependencyConfig()

        assert config.install_runtime_deps is False
        assert config.install_dev_deps is True
        assert "ruff" in config.dev_dependencies
        assert "pytest" in config.dev_dependencies

    def test_custom_dependencies(self) -> None:
        """Test custom dependencies."""
        config = DependencyConfig(
            dev_dependencies=["pytest", "mypy"],
            runtime_dependencies=["fastapi"],
        )

        assert config.dev_dependencies == ["pytest", "mypy"]
        assert config.runtime_dependencies == ["fastapi"]


class TestLoggingConfig:
    """Tests for LoggingConfig model."""

    def test_default_values(self) -> None:
        """Test default logging configuration."""
        config = LoggingConfig()

        assert config.level == "INFO"
        assert config.format == "detailed"
        assert config.enable_structured is False

    def test_valid_levels(self) -> None:
        """Test all valid log levels."""
        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            config = LoggingConfig(level=level)
            assert config.level == level

    def test_invalid_level_rejected(self) -> None:
        """Test invalid log level is rejected."""
        with pytest.raises(ValidationError):
            LoggingConfig(level="INVALID")


class TestStackConfig:
    """Tests for StackConfig model."""

    def test_default_values(self) -> None:
        """Test default stack configuration."""
        config = StackConfig()

        assert config.project_name == "my_project"
        assert config.dry_run is False
        assert config.force is False
        assert config.verbose is False
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.dependencies, DependencyConfig)
        assert isinstance(config.logging, LoggingConfig)

    def test_valid_project_name(self) -> None:
        """Test valid project names."""
        config = StackConfig(project_name="my_awesome_project")
        assert config.project_name == "my_awesome_project"

    def test_invalid_project_name_rejected(self) -> None:
        """Test invalid project names are rejected."""
        with pytest.raises(ValidationError, match="invalid"):
            StackConfig(project_name="123invalid")

        with pytest.raises(ValidationError, match="invalid"):
            StackConfig(project_name="has spaces")

    def test_valid_python_version(self) -> None:
        """Test valid Python versions."""
        config = StackConfig(python_version="3.11")
        assert config.python_version == "3.11"

    def test_invalid_python_version_rejected(self) -> None:
        """Test invalid Python versions are rejected."""
        with pytest.raises(ValidationError):
            StackConfig(python_version="2.7")

    def test_path_traversal_rejected(self, tmp_path: Path) -> None:
        """Test path traversal in project_dir is rejected."""
        with pytest.raises(ValidationError, match="Path traversal"):
            StackConfig(project_dir=Path("../../../etc"))

    def test_paranoid_requires_all_tools(self) -> None:
        """Test paranoid mode requires all security tools."""
        with pytest.raises(ValidationError, match="requires all security tools"):
            StackConfig(
                security=SecurityConfig(
                    level="paranoid",
                    enable_bandit=False,
                )
            )

    def test_to_target_version(self) -> None:
        """Test target version conversion."""
        config = StackConfig(python_version="3.12")
        assert config.to_target_version() == "py312"

    def test_nested_configs(self) -> None:
        """Test nested configuration objects."""
        config = StackConfig(
            security=SecurityConfig(level="paranoid"),
            logging=LoggingConfig(level="DEBUG"),
        )

        assert config.security.level == "paranoid"
        assert config.logging.level == "DEBUG"
