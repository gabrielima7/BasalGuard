"""
Configuration models with Pydantic validation.

This module provides type-safe configuration models that validate
all inputs at runtime, preventing errors and AI hallucinations.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

# Constants to avoid magic values (PLR2004)
PYTHON_MAJOR_VERSION = 3
MIN_PYTHON_MINOR_VERSION = 10


class SecurityConfig(BaseModel):
    """Security-related configuration options.

    Attributes:
        level: Security strictness level.
        enable_bandit: Enable Bandit SAST scanner.
        enable_safety: Enable Safety dependency checker.
        enable_semgrep: Enable Semgrep analysis.
        enable_detect_secrets: Enable secret detection.
        bandit_severity: Minimum severity level for Bandit.

    """

    level: Literal["standard", "strict", "paranoid"] = Field(
        default="strict",
        description="Security strictness level",
    )
    enable_bandit: bool = Field(default=True, description="Enable Bandit SAST")
    enable_safety: bool = Field(default=True, description="Enable Safety SCA")
    enable_semgrep: bool = Field(default=True, description="Enable Semgrep")
    enable_detect_secrets: bool = Field(
        default=True, description="Enable secret detection"
    )
    bandit_severity: Literal["low", "medium", "high"] = Field(
        default="low",
        description="Minimum Bandit severity",
    )

    model_config = ConfigDict(frozen=True, extra="forbid")


class DependencyConfig(BaseModel):
    """Dependency management configuration.

    Attributes:
        install_runtime_deps: Install pydantic, orjson, uvloop.
        install_dev_deps: Install development dependencies.
        dev_dependencies: List of dev dependencies to install.
        runtime_dependencies: List of runtime dependencies to install.

    """

    install_runtime_deps: bool = Field(
        default=False,
        description="Install runtime dependencies (pydantic, orjson, uvloop)",
    )
    install_dev_deps: bool = Field(
        default=True,
        description="Install development dependencies",
    )
    dev_dependencies: list[str] = Field(
        default_factory=lambda: [
            "ruff",
            "mypy",
            "bandit",
            "safety",
            "pre-commit",
            "pytest",
            "pytest-cov",
            "py-spy",
            "semgrep",
        ],
        description="Development dependencies to install",
    )
    runtime_dependencies: list[str] = Field(
        default_factory=lambda: ["pydantic>=2.0", "orjson"],
        description="Runtime dependencies to install",
    )

    model_config = ConfigDict(frozen=True, extra="forbid")


class LoggingConfig(BaseModel):
    """Logging configuration options.

    Attributes:
        level: Log level.
        format: Log format type.
        enable_structured: Use structured logging (JSON).

    """

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )
    format: Literal["simple", "detailed", "json"] = Field(
        default="detailed",
        description="Log output format",
    )
    enable_structured: bool = Field(
        default=False,
        description="Enable JSON structured logging",
    )

    model_config = ConfigDict(frozen=True, extra="forbid")


class StackConfig(BaseModel):
    """Main Stack configuration with full validation.

    This is the primary configuration model that validates all Stack
    settings at runtime, preventing configuration errors and catching
    AI hallucinations early.

    Attributes:
        project_name: Name of the project (alphanumeric, _, -).
        python_version: Target Python version (e.g., "3.12").
        project_dir: Directory to initialize project in.
        dry_run: Simulate execution without changes.
        force: Overwrite existing files without backup.
        verbose: Enable verbose logging.
        security: Security configuration.
        dependencies: Dependency configuration.
        logging: Logging configuration.

    Example:
        >>> config = StackConfig(
        ...     project_name="my_project",
        ...     python_version="3.12",
        ... )
        >>> config.project_name
        'my_project'

    """

    project_name: str = Field(
        default="my_project",
        min_length=1,
        max_length=100,
        description="Project name (alphanumeric, underscore, hyphen only)",
    )
    python_version: str = Field(
        default_factory=lambda: f"{sys.version_info.major}.{sys.version_info.minor}",
        description="Target Python version",
    )
    project_dir: Path = Field(
        default_factory=Path.cwd,
        description="Project directory",
    )
    dry_run: bool = Field(
        default=False,
        description="Simulate execution without making changes",
    )
    force: bool = Field(
        default=False,
        description="Overwrite existing files without backup",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output",
    )
    security: SecurityConfig = Field(
        default_factory=SecurityConfig,
        description="Security configuration",
    )
    dependencies: DependencyConfig = Field(
        default_factory=DependencyConfig,
        description="Dependency configuration",
    )
    logging: LoggingConfig = Field(
        default_factory=LoggingConfig,
        description="Logging configuration",
    )

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
    )

    @field_validator("project_name")
    @classmethod
    def validate_project_name(cls, value: str) -> str:
        """Validate that project name is safe.

        Args:
            value: The project name to validate.

        Returns:
            The validated project name.

        Raises:
            ValueError: If project name contains invalid characters.

        """
        pattern = r"^[a-zA-Z][a-zA-Z0-9_-]*$"
        if not re.match(pattern, value):
            msg = (
                f"Project name '{value}' is invalid. "
                "Must start with a letter and contain only alphanumeric, "
                "underscore, or hyphen characters."
            )
            raise ValueError(msg)
        return value

    @field_validator("python_version")
    @classmethod
    def validate_python_version(cls, value: str) -> str:
        """Validate Python version format.

        Args:
            value: The Python version string.

        Returns:
            The validated Python version.

        Raises:
            ValueError: If version format is invalid.

        """
        pattern = r"^\d+\.\d+$"
        if not re.match(pattern, value):
            msg = (
                f"Python version '{value}' is invalid. Use format 'X.Y' (e.g., '3.12')."
            )
            raise ValueError(msg)

        major, minor = map(int, value.split("."))
        is_old_python = major < PYTHON_MAJOR_VERSION or (
            major == PYTHON_MAJOR_VERSION and minor < MIN_PYTHON_MINOR_VERSION
        )
        if is_old_python:
            msg = (
                f"Python version {value} is not supported. "
                f"Minimum is {PYTHON_MAJOR_VERSION}.{MIN_PYTHON_MINOR_VERSION}."
            )
            raise ValueError(msg)

        return value

    @field_validator("project_dir")
    @classmethod
    def validate_project_dir(cls, value: Path) -> Path:
        """Validate project directory is safe.

        Args:
            value: The project directory path.

        Returns:
            The validated and resolved path.

        Raises:
            ValueError: If path is unsafe or contains traversal.

        """
        resolved = value.resolve()

        # Check for path traversal attempts
        if ".." in str(value):
            msg = f"Path traversal detected in project_dir: {value}"
            raise ValueError(msg)

        return resolved

    @model_validator(mode="after")
    def validate_config_consistency(self) -> StackConfig:
        """Validate configuration consistency.

        Returns:
            The validated configuration.

        Raises:
            ValueError: If configuration is inconsistent.

        """
        # If paranoid security, ensure all security tools are enabled
        all_tools_enabled = all(
            [
                self.security.enable_bandit,
                self.security.enable_safety,
                self.security.enable_semgrep,
                self.security.enable_detect_secrets,
            ]
        )
        if self.security.level == "paranoid" and not all_tools_enabled:
            msg = "Paranoid security level requires all security tools enabled."
            raise ValueError(msg)

        return self

    def to_target_version(self) -> str:
        """Get Python version in Ruff target format.

        Returns:
            Version string like 'py312'.

        """
        return f"py{self.python_version.replace('.', '')}"
