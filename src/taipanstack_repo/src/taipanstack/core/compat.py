"""
Python Version Compatibility and Feature Detection.

This module provides runtime detection of Python version and available
performance features, enabling version-specific optimizations while
maintaining compatibility with Python 3.11+.

Following Stack pillars: Security, Stability, Simplicity, Scalability, Compatibility.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Final

__all__ = [
    "PY311",
    "PY312",
    "PY313",
    "PY314",
    "PY_VERSION",
    "PythonFeatures",
    "VersionTier",
    "get_features",
    "get_python_info",
    "is_experimental_enabled",
]

logger = logging.getLogger(__name__)

# =============================================================================
# Version Constants
# =============================================================================

PY_VERSION: Final = sys.version_info
"""Current Python version tuple."""

PY311: Final[bool] = PY_VERSION >= (3, 11)
"""True if running Python 3.11 or higher."""

PY312: Final[bool] = PY_VERSION >= (3, 12)
"""True if running Python 3.12 or higher."""

PY313: Final[bool] = PY_VERSION >= (3, 13)
"""True if running Python 3.13 or higher."""

PY314: Final[bool] = PY_VERSION >= (3, 14)
"""True if running Python 3.14 or higher."""


class VersionTier(StrEnum):
    """Python version tier for optimization profiles."""

    STABLE = "stable"  # 3.11 - fully stable, conservative optimizations
    ENHANCED = "enhanced"  # 3.12 - improved features, moderate optimizations
    MODERN = "modern"  # 3.13 - JIT/free-threading available (experimental)
    CUTTING_EDGE = "cutting_edge"  # 3.14+ - latest optimizations


# =============================================================================
# Environment Variables for Experimental Features
# =============================================================================

ENV_ENABLE_EXPERIMENTAL = "STACK_ENABLE_EXPERIMENTAL"
"""Environment variable to enable experimental features (JIT, free-threading)."""

ENV_OPTIMIZATION_LEVEL = "STACK_OPTIMIZATION_LEVEL"
"""Optimization level: 0=none, 1=safe, 2=aggressive (requires experimental)."""


# =============================================================================
# Feature Detection Functions
# =============================================================================


def _check_jit_available() -> bool:
    """Check if JIT compiler is available and enabled.

    JIT is available in Python 3.13+ when built with --enable-experimental-jit.
    """
    if not PY313:
        return False

    try:
        # Check if the JIT module exists (Python 3.13+)
        # This is a build-time option, not all builds have it
        return hasattr(sys, "_jit") or "jit" in sys.flags.__class__.__annotations__
    except (AttributeError, TypeError):
        return False


def _check_free_threading_available() -> bool:
    """Check if free-threading (no-GIL) build is being used.

    Free-threading is available in Python 3.13+ experimental builds.
    """
    if not PY313:
        return False

    try:
        # In free-threaded builds, sys.flags.nogil is True
        # or the build was configured with --disable-gil
        if hasattr(sys.flags, "nogil"):
            return bool(sys.flags.nogil)

        # Alternative check for 3.13+
        import sysconfig  # noqa: PLC0415

        config_args = sysconfig.get_config_var("CONFIG_ARGS") or ""
    except (AttributeError, TypeError):
        return False
    else:
        return "--disable-gil" in config_args


def _check_mimalloc_available() -> bool:
    """Check if mimalloc allocator is being used.

    mimalloc is the default allocator in Python 3.13+ on some platforms.
    """
    if not PY313:
        return False

    try:
        import sysconfig  # noqa: PLC0415 - lazy import for optional module

        # Check if built with mimalloc
        config_args = sysconfig.get_config_var("CONFIG_ARGS") or ""
        return "mimalloc" in config_args.lower()
    except (AttributeError, TypeError):
        return False


def _check_tail_call_interpreter() -> bool:
    """Check if tail-call interpreter optimization is available.

    Tail-call interpreter is available in Python 3.14+.
    """
    return PY314


def is_experimental_enabled() -> bool:
    """Check if experimental features are explicitly enabled.

    Returns:
        True if STACK_ENABLE_EXPERIMENTAL=1 is set.

    """
    value = os.environ.get(ENV_ENABLE_EXPERIMENTAL, "").lower()
    return value in ("1", "true", "yes", "on")


def get_optimization_level() -> int:
    """Get the configured optimization level.

    Returns:
        0 = No optimizations
        1 = Safe optimizations only (default)
        2 = Aggressive optimizations (requires experimental)

    """
    try:
        level = int(os.environ.get(ENV_OPTIMIZATION_LEVEL, "1"))
        return max(0, min(2, level))  # Clamp to 0-2
    except ValueError:
        return 1


# =============================================================================
# Feature Data Classes
# =============================================================================


@dataclass(frozen=True, slots=True)
class PythonFeatures:
    """Available Python features based on version and build configuration.

    This dataclass is immutable and optimized for performance with slots.
    """

    version: tuple[int, int, int]
    version_string: str
    tier: VersionTier

    # Build features
    has_jit: bool = False
    has_free_threading: bool = False
    has_mimalloc: bool = False
    has_tail_call_interpreter: bool = False

    # Language features by version
    has_exception_groups: bool = False  # 3.11+
    has_self_type: bool = False  # 3.11+
    has_type_params: bool = False  # 3.12+
    has_fstring_improvements: bool = False  # 3.12+
    has_override_decorator: bool = False  # 3.12+
    has_deprecated_decorator: bool = False  # 3.13+
    has_deferred_annotations: bool = False  # 3.14+

    # Experimental features enabled
    experimental_enabled: bool = False

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary for serialization."""
        return {
            "version": ".".join(map(str, self.version)),
            "tier": self.tier.value,
            "features": {
                "jit": self.has_jit,
                "free_threading": self.has_free_threading,
                "mimalloc": self.has_mimalloc,
                "tail_call_interpreter": self.has_tail_call_interpreter,
            },
            "language": {
                "exception_groups": self.has_exception_groups,
                "self_type": self.has_self_type,
                "type_params": self.has_type_params,
                "override_decorator": self.has_override_decorator,
                "deprecated_decorator": self.has_deprecated_decorator,
                "deferred_annotations": self.has_deferred_annotations,
            },
            "experimental_enabled": self.experimental_enabled,
        }


# =============================================================================
# Main Detection Functions
# =============================================================================

# Cache the features after first detection
_cached_features: PythonFeatures | None = None


def get_features(*, force_refresh: bool = False) -> PythonFeatures:
    """Detect and return available Python features.

    Features are cached after first detection for performance.

    Args:
        force_refresh: If True, re-detect features instead of using cache.

    Returns:
        PythonFeatures dataclass with all detected features.

    """
    global _cached_features  # noqa: PLW0603 - intentional cache pattern

    if _cached_features is not None and not force_refresh:
        return _cached_features

    # Determine version tier
    if PY314:
        tier = VersionTier.CUTTING_EDGE
    elif PY313:
        tier = VersionTier.MODERN
    elif PY312:
        tier = VersionTier.ENHANCED
    else:
        tier = VersionTier.STABLE

    experimental = is_experimental_enabled()

    # Build features (only if experimental is enabled for safety)
    has_jit = _check_jit_available() if experimental else False
    has_free_threading = _check_free_threading_available() if experimental else False
    has_mimalloc = _check_mimalloc_available()  # Safe to detect

    features = PythonFeatures(
        version=(PY_VERSION.major, PY_VERSION.minor, PY_VERSION.micro),
        version_string=f"{PY_VERSION.major}.{PY_VERSION.minor}.{PY_VERSION.micro}",
        tier=tier,
        # Build features
        has_jit=has_jit,
        has_free_threading=has_free_threading,
        has_mimalloc=has_mimalloc,
        has_tail_call_interpreter=_check_tail_call_interpreter(),
        # Language features
        has_exception_groups=PY311,
        has_self_type=PY311,
        has_type_params=PY312,
        has_fstring_improvements=PY312,
        has_override_decorator=PY312,
        has_deprecated_decorator=PY313,
        has_deferred_annotations=PY314,
        # Experimental
        experimental_enabled=experimental,
    )

    _cached_features = features

    # Log detected features at DEBUG level
    logger.debug(
        "Python %s detected (tier=%s, experimental=%s)",
        features.version_string,
        tier.value,
        experimental,
    )

    return features


def get_python_info() -> dict[str, object]:
    """Get comprehensive Python runtime information.

    Returns:
        Dictionary with version, platform, and feature information.

    """
    import platform  # noqa: PLC0415 - lazy import for optional module

    features = get_features()

    return {
        "version": features.version_string,
        "version_tuple": features.version,
        "tier": features.tier.value,
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "compiler": platform.python_compiler(),
        "features": features.to_dict(),
        "optimization_level": get_optimization_level(),
    }
