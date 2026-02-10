"""
Configuration file generators.

This module generates configuration files (pyproject.toml, pre-commit, etc.)
with proper validation and templating.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from taipanstack.config.models import StackConfig


def generate_pyproject_config(config: StackConfig) -> str:
    """Generate Ruff, Mypy, and Pytest configuration for pyproject.toml.

    Args:
        config: The Stack configuration.

    Returns:
        Configuration string to append to pyproject.toml.

    """
    target_version = config.to_target_version()
    python_version = config.python_version

    return f"""
# --- Stack v2.0 Quality Configuration ---
[tool.ruff]
line-length = 88
target-version = "{target_version}"

[tool.ruff.lint]
select = [
    "F",    # Pyflakes
    "E",    # pycodestyle errors
    "W",    # pycodestyle warnings
    "I",    # isort
    "N",    # pep8-naming
    "D",    # pydocstyle
    "Q",    # flake8-quotes
    "S",    # flake8-bandit
    "B",    # flake8-bugbear
    "A",    # flake8-builtins
    "C4",   # flake8-comprehensions
    "T20",  # flake8-print
    "SIM",  # flake8-simplify
    "PTH",  # flake8-use-pathlib
    "TID",  # flake8-tidy-imports
    "ARG",  # flake8-unused-arguments
    "PIE",  # flake8-pie
    "PLC",  # Pylint Convention
    "PLE",  # Pylint Error
    "PLR",  # Pylint Refactor
    "PLW",  # Pylint Warning
    "RUF",  # Ruff-specific
    "UP",   # pyupgrade
    "ERA",  # eradicate
    "TRY",  # tryceratops
]
ignore = ["D203", "D212", "D213", "D416", "D417", "B905"]

[tool.ruff.lint.mccabe]
max-complexity = 10

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101", "D"]

[tool.ruff.format]
quote-style = "double"
indent-style = "space"

[tool.mypy]
python_version = "{python_version}"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_any_unimported = false
no_implicit_optional = true
check_untyped_defs = true
strict_optional = true
strict_equality = true
ignore_missing_imports = true
show_error_codes = true
enable_error_code = ["ignore-without-code", "redundant-cast", "truthy-bool"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --cov=src --cov-report=html --cov-report=term-missing --cov-fail-under=80 --strict-markers"
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "security: marks tests as security-related",
]

[tool.coverage.run]
branch = true
source = ["src"]
omit = ["*/tests/*", "*/__pycache__/*"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise NotImplementedError",
    "if TYPE_CHECKING:",
    "if __name__ == .__main__.:",
]
"""


def generate_pre_commit_config(config: StackConfig) -> str:
    """Generate .pre-commit-config.yaml content.

    Args:
        config: The Stack configuration.

    Returns:
        Pre-commit configuration YAML string.

    """
    security_hooks = ""

    if config.security.enable_bandit:
        severity = config.security.bandit_severity[0].upper()
        security_hooks += f"""
  - repo: https://github.com/PyCQA/bandit
    rev: '1.8.0'
    hooks:
      - id: bandit
        args: ["-r", ".", "-l{severity}"]
"""

    if config.security.enable_safety:
        security_hooks += """
  - repo: https://github.com/pyupio/safety
    rev: '3.2.11'
    hooks:
      - id: safety
        args: ["check", "--json"]
"""

    if config.security.enable_semgrep:
        security_hooks += """
  - repo: https://github.com/semgrep/pre-commit
    rev: 'v1.99.0'
    hooks:
      - id: semgrep
        args: ['--config=auto']
"""

    if config.security.enable_detect_secrets:
        security_hooks += """
  - repo: https://github.com/Yelp/detect-secrets
    rev: 'v1.5.0'
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
"""

    # Add pip-audit for paranoid mode
    if config.security.level == "paranoid":
        security_hooks += """
  - repo: https://github.com/trailofbits/pip-audit
    rev: 'v2.7.3'
    hooks:
      - id: pip-audit

  - repo: https://github.com/jendrikseipp/vulture
    rev: 'v2.11'
    hooks:
      - id: vulture

  - repo: https://github.com/guilatrova/tryceratops
    rev: 'v2.3.3'
    hooks:
      - id: tryceratops
"""

    return f"""# Stack v2.0 Pre-commit Configuration
# Security Level: {config.security.level}
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-merge-conflict
      - id: check-case-conflict
      - id: detect-private-key

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: 'v0.8.4'
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: 'v1.13.0'
    hooks:
      - id: mypy
        additional_dependencies: [types-all, pydantic]
{security_hooks}"""


def generate_dependabot_config() -> str:
    """Generate .github/dependabot.yml content.

    Returns:
        Dependabot configuration YAML string.

    """
    return """# Stack v2.0 Dependabot Configuration
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    groups:
      dev-dependencies:
        patterns:
          - "ruff"
          - "mypy"
          - "bandit"
          - "safety"
          - "pytest*"
          - "pre-commit"
          - "semgrep"
          - "py-spy"
      security-tools:
        patterns:
          - "bandit"
          - "safety"
          - "semgrep"
          - "pip-audit"
    reviewers:
      - "gabrielima7"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    groups:
      actions:
        patterns:
          - "*"
"""


def generate_security_policy() -> str:
    """Generate SECURITY.md content.

    Returns:
        Security policy markdown string.

    """
    return """# Security Policy

## Supported Versions

We prioritize security fixes for the latest version (Rolling Release).

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| Older   | :x:                |

## Security Features

This project includes multiple layers of security:

- **SAST**: Bandit for static security analysis
- **SCA**: Safety/pip-audit for dependency vulnerabilities
- **Secrets**: detect-secrets for preventing credential leaks
- **Type Safety**: Mypy + Pydantic for runtime validation
- **Runtime Guards**: Protection against path traversal and injection

## Reporting a Vulnerability

1. **DO NOT** create a public issue for security vulnerabilities
2. Report via the [Security tab](../../security/advisories/new)
3. Or email the maintainer directly
4. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Release**: Depends on severity (critical: ASAP, others: next release)
"""


def generate_editorconfig() -> str:
    """Generate .editorconfig content.

    Returns:
        EditorConfig content string.

    """
    return """# Stack v2.0 EditorConfig
root = true

[*]
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
charset = utf-8
indent_style = space
indent_size = 4

[*.py]
max_line_length = 88

[*.{yml,yaml,toml,json}]
indent_size = 2

[Makefile]
indent_style = tab
"""


def write_config_file(
    path: Path,
    content: str,
    config: StackConfig,
) -> bool:
    """Write configuration file with backup support.

    Args:
        path: Path to write the file.
        content: Content to write.
        config: Stack configuration.

    Returns:
        True if file was written, False if in dry-run mode.

    """
    if config.dry_run:
        return False

    if path.exists() and not config.force:
        backup_path = path.with_suffix(f"{path.suffix}.bak")
        path.rename(backup_path)

    path.write_text(content, encoding="utf-8")
    return True
