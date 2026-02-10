"""Stack Core Module.

Provides core functionality including Result types, version compatibility,
and optimization utilities.
"""

from taipanstack.core.compat import (
    PY311,
    PY312,
    PY313,
    PY314,
    PY_VERSION,
    PythonFeatures,
    VersionTier,
    get_features,
    get_python_info,
    is_experimental_enabled,
)
from taipanstack.core.optimizations import (
    OptimizationProfile,
    OptimizationResult,
    apply_optimizations,
    get_optimization_profile,
    get_recommended_thread_pool_size,
)
from taipanstack.core.result import Err, Ok, Result

__all__ = [
    "PY311",
    "PY312",
    "PY313",
    "PY314",
    "PY_VERSION",
    "Err",
    "Ok",
    "OptimizationProfile",
    "OptimizationResult",
    "PythonFeatures",
    "Result",
    "VersionTier",
    "apply_optimizations",
    "get_features",
    "get_optimization_profile",
    "get_python_info",
    "get_recommended_thread_pool_size",
    "is_experimental_enabled",
]
