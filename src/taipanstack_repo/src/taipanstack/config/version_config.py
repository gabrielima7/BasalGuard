"""
Version-Specific Configuration Recommendations.

This module provides configuration templates optimized for different
Python versions, helping users get the best performance while
maintaining stability.

Following Stack pillars: Security, Stability, Simplicity, Scalability, Compatibility.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from taipanstack.core.compat import (
    PY312,
    PY313,
    PY314,
    VersionTier,
    get_features,
)
from taipanstack.core.optimizations import get_recommended_thread_pool_size

if TYPE_CHECKING:
    pass

__all__ = [
    "VersionRecommendations",
    "get_version_recommendations",
]

logger = logging.getLogger(__name__)


# =============================================================================
# Version Recommendations
# =============================================================================


@dataclass(frozen=True, slots=True)
class VersionRecommendations:
    """Configuration recommendations for a Python version.

    These recommendations help users configure their Stack-based
    applications for optimal performance on their Python version.
    """

    version_tier: VersionTier
    min_version: str
    max_version: str | None

    # Threading recommendations
    recommended_thread_pool_size: int
    supports_true_parallelism: bool

    # Memory recommendations
    recommended_gc_mode: str
    use_mimalloc: bool

    # Code style recommendations
    use_type_params: bool  # PEP 695 type parameter syntax
    use_exception_groups: bool  # PEP 654 exception groups
    use_match_statements: bool  # PEP 634 structural matching
    use_override_decorator: bool  # PEP 698 @override
    use_deprecated_decorator: bool  # PEP 702 @deprecated

    # Performance recommendations
    jit_available: bool
    recommended_optimization_level: int

    # Notes for user
    notes: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for serialization."""
        return {
            "version_tier": self.version_tier.value,
            "version_range": f"{self.min_version} - {self.max_version or 'latest'}",
            "threading": {
                "pool_size": self.recommended_thread_pool_size,
                "true_parallelism": self.supports_true_parallelism,
            },
            "memory": {
                "gc_mode": self.recommended_gc_mode,
                "mimalloc": self.use_mimalloc,
            },
            "code_style": {
                "type_params": self.use_type_params,
                "exception_groups": self.use_exception_groups,
                "match_statements": self.use_match_statements,
                "override_decorator": self.use_override_decorator,
                "deprecated_decorator": self.use_deprecated_decorator,
            },
            "performance": {
                "jit_available": self.jit_available,
                "optimization_level": self.recommended_optimization_level,
            },
            "notes": list(self.notes),
        }


# =============================================================================
# Recommendation Generators
# =============================================================================


def _get_311_recommendations() -> VersionRecommendations:
    """Get recommendations for Python 3.11."""
    return VersionRecommendations(
        version_tier=VersionTier.STABLE,
        min_version="3.11.0",
        max_version="3.11.x",
        recommended_thread_pool_size=get_recommended_thread_pool_size(),
        supports_true_parallelism=False,
        recommended_gc_mode="default",
        use_mimalloc=False,
        use_type_params=False,
        use_exception_groups=True,
        use_match_statements=True,
        use_override_decorator=False,
        use_deprecated_decorator=False,
        jit_available=False,
        recommended_optimization_level=1,
        notes=(
            "Stable baseline with 25% speedup from specialized bytecode",
            "Use exception groups (PEP 654) for better error handling",
            "Self type available for type hints",
        ),
    )


def _get_312_recommendations() -> VersionRecommendations:
    """Get recommendations for Python 3.12."""
    return VersionRecommendations(
        version_tier=VersionTier.ENHANCED,
        min_version="3.12.0",
        max_version="3.12.x",
        recommended_thread_pool_size=get_recommended_thread_pool_size(),
        supports_true_parallelism=False,
        recommended_gc_mode="default",
        use_mimalloc=False,
        use_type_params=True,
        use_exception_groups=True,
        use_match_statements=True,
        use_override_decorator=True,
        use_deprecated_decorator=False,
        jit_available=False,
        recommended_optimization_level=1,
        notes=(
            "Use type parameter syntax (PEP 695) for cleaner generics",
            "Use @override decorator (PEP 698) for method overrides",
            "Improved f-string parsing and error messages",
        ),
    )


def _get_313_recommendations() -> VersionRecommendations:
    """Get recommendations for Python 3.13."""
    features = get_features()
    return VersionRecommendations(
        version_tier=VersionTier.MODERN,
        min_version="3.13.0",
        max_version="3.13.x",
        recommended_thread_pool_size=get_recommended_thread_pool_size(),
        supports_true_parallelism=features.has_free_threading,
        recommended_gc_mode="tuned" if features.has_mimalloc else "default",
        use_mimalloc=features.has_mimalloc,
        use_type_params=True,
        use_exception_groups=True,
        use_match_statements=True,
        use_override_decorator=True,
        use_deprecated_decorator=True,
        jit_available=features.has_jit,
        recommended_optimization_level=2 if features.experimental_enabled else 1,
        notes=(
            "Use @deprecated decorator (PEP 702) for deprecation warnings",
            "JIT compiler available (experimental) with STACK_ENABLE_EXPERIMENTAL=1",
            "Free-threading available on special builds (no GIL)",
            "mimalloc allocator provides better memory performance",
        ),
    )


def _get_314_recommendations() -> VersionRecommendations:
    """Get recommendations for Python 3.14."""
    features = get_features()
    return VersionRecommendations(
        version_tier=VersionTier.CUTTING_EDGE,
        min_version="3.14.0",
        max_version=None,
        recommended_thread_pool_size=get_recommended_thread_pool_size(),
        supports_true_parallelism=features.has_free_threading,
        recommended_gc_mode="incremental",
        use_mimalloc=True,
        use_type_params=True,
        use_exception_groups=True,
        use_match_statements=True,
        use_override_decorator=True,
        use_deprecated_decorator=True,
        jit_available=features.has_jit,
        recommended_optimization_level=2 if features.experimental_enabled else 1,
        notes=(
            "Tail-call interpreter provides 9-15% speedup",
            "Deferred annotations (PEP 649) for faster startup",
            "Stable free-threading support available",
            "JIT compiler significantly improved from 3.13",
            "Incremental GC reduces pause times",
        ),
    )


def get_version_recommendations() -> VersionRecommendations:
    """Get configuration recommendations for the current Python version.

    Returns:
        VersionRecommendations with optimal settings.

    """
    if PY314:
        return _get_314_recommendations()
    if PY313:
        return _get_313_recommendations()
    if PY312:
        return _get_312_recommendations()
    return _get_311_recommendations()
