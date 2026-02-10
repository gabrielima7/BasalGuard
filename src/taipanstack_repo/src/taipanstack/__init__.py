"""
TaipanStack - Python Security & Quality Bootstrapper.

A modular, secure, and scalable Python stack for robust development.
Supports Python 3.11+ with version-aware optimizations for 3.13/3.14.
"""

__version__ = "2.0.0"

from taipanstack.config.models import StackConfig
from taipanstack.config.version_config import (
    VersionRecommendations,
    get_version_recommendations,
)
from taipanstack.core.compat import (
    PY311,
    PY312,
    PY313,
    PY314,
    PY_VERSION,
    get_features,
    get_python_info,
)
from taipanstack.core.optimizations import apply_optimizations, get_optimization_profile
from taipanstack.security.guards import (
    guard_command_injection,
    guard_path_traversal,
)
from taipanstack.security.validators import (
    validate_email,
    validate_project_name,
    validate_python_version,
)

__all__ = [
    "PY311",
    "PY312",
    "PY313",
    "PY314",
    "PY_VERSION",
    "StackConfig",
    "VersionRecommendations",
    "apply_optimizations",
    "get_features",
    "get_optimization_profile",
    "get_python_info",
    "get_version_recommendations",
    "guard_command_injection",
    "guard_path_traversal",
    "validate_email",
    "validate_project_name",
    "validate_python_version",
]
