"""Security package for runtime protection."""

from taipanstack.security.decorators import (
    OperationTimeoutError,
    ValidationError,
    deprecated,
    guard_exceptions,
    require_type,
    timeout,
    validate_inputs,
)
from taipanstack.security.guards import (
    SecurityError,
    guard_command_injection,
    guard_env_variable,
    guard_file_extension,
    guard_path_traversal,
)
from taipanstack.security.sanitizers import (
    sanitize_filename,
    sanitize_path,
    sanitize_string,
)
from taipanstack.security.validators import (
    validate_email,
    validate_project_name,
    validate_python_version,
    validate_url,
)

__all__ = [
    # Decorators
    "OperationTimeoutError",
    # Guards
    "SecurityError",
    "ValidationError",
    "deprecated",
    "guard_command_injection",
    "guard_env_variable",
    "guard_exceptions",
    "guard_file_extension",
    "guard_path_traversal",
    "require_type",
    # Sanitizers
    "sanitize_filename",
    "sanitize_path",
    "sanitize_string",
    "timeout",
    # Validators
    "validate_email",
    "validate_inputs",
    "validate_project_name",
    "validate_python_version",
    "validate_url",
]
