"""
Python Version-Specific Optimization Profiles.

This module provides optimization strategies tailored to different Python
versions, enabling performance improvements while maintaining stability.

Following Stack pillars: Security, Stability, Simplicity, Scalability, Compatibility.
"""

from __future__ import annotations

import gc
import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from taipanstack.core.compat import (
    PY312,
    PY313,
    PY314,
    get_features,
    get_optimization_level,
    is_experimental_enabled,
)

if TYPE_CHECKING:
    pass

__all__ = [
    "OptimizationProfile",
    "OptimizationResult",
    "apply_optimizations",
    "get_optimization_profile",
]

logger = logging.getLogger(__name__)


# =============================================================================
# Optimization Profile
# =============================================================================


# Optimization Levels
OPT_LEVEL_NONE = 0
OPT_LEVEL_SAFE = 1
OPT_LEVEL_AGGRESSIVE = 2


@dataclass(frozen=True, slots=True)
class OptimizationProfile:
    """Version-specific optimization settings.

    This profile defines recommended settings based on Python version
    and available features. All settings follow the stability-first principle.
    """

    # GC tuning
    gc_threshold_0: int = 700  # Default: 700
    gc_threshold_1: int = 10  # Default: 10
    gc_threshold_2: int = 10  # Default: 10
    gc_freeze_enabled: bool = False  # Freeze objects after init

    # Threading
    thread_pool_multiplier: float = 1.0  # Multiplier for CPU count
    max_thread_pool_size: int = 32  # Absolute maximum

    # Memory
    prefer_slots: bool = True  # Use __slots__ in classes
    use_frozen_dataclasses: bool = True  # Prefer frozen dataclasses

    # Code patterns
    prefer_match_statements: bool = False  # 3.10+
    prefer_exception_groups: bool = False  # 3.11+
    prefer_type_params: bool = False  # 3.12+

    # Performance hints
    enable_perf_hints: bool = False  # JIT hints, etc.
    aggressive_inlining: bool = False  # More aggressive optimizations

    # Experimental
    enable_experimental: bool = False


@dataclass(frozen=True, slots=True)
class OptimizationResult:
    """Result of applying optimizations."""

    success: bool
    applied: tuple[str, ...]
    skipped: tuple[str, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "applied": list(self.applied),
            "skipped": list(self.skipped),
            "errors": list(self.errors),
        }


# =============================================================================
# Version-Specific Profiles
# =============================================================================

# Python 3.11 - Stable baseline
_PROFILE_311 = OptimizationProfile(
    gc_threshold_0=700,
    gc_threshold_1=10,
    gc_threshold_2=10,
    gc_freeze_enabled=False,
    thread_pool_multiplier=1.0,
    max_thread_pool_size=32,
    prefer_slots=True,
    use_frozen_dataclasses=True,
    prefer_match_statements=True,
    prefer_exception_groups=True,
    prefer_type_params=False,
    enable_perf_hints=False,
    aggressive_inlining=False,
    enable_experimental=False,
)

# Python 3.12 - Enhanced
_PROFILE_312 = OptimizationProfile(
    gc_threshold_0=800,  # Slightly higher due to better GC
    gc_threshold_1=10,
    gc_threshold_2=10,
    gc_freeze_enabled=True,  # Safe to use
    thread_pool_multiplier=1.0,
    max_thread_pool_size=32,
    prefer_slots=True,
    use_frozen_dataclasses=True,
    prefer_match_statements=True,
    prefer_exception_groups=True,
    prefer_type_params=True,
    enable_perf_hints=False,
    aggressive_inlining=False,
    enable_experimental=False,
)

# Python 3.13 - Modern (with experimental options available)
_PROFILE_313 = OptimizationProfile(
    gc_threshold_0=900,  # Higher with mimalloc
    gc_threshold_1=15,
    gc_threshold_2=15,
    gc_freeze_enabled=True,
    thread_pool_multiplier=1.5,  # Can use more threads with better GIL
    max_thread_pool_size=48,
    prefer_slots=True,
    use_frozen_dataclasses=True,
    prefer_match_statements=True,
    prefer_exception_groups=True,
    prefer_type_params=True,
    enable_perf_hints=True,  # JIT hints available
    aggressive_inlining=False,
    enable_experimental=False,  # Requires explicit opt-in
)

# Python 3.14 - Cutting edge
_PROFILE_314 = OptimizationProfile(
    gc_threshold_0=1000,  # Optimized incremental GC
    gc_threshold_1=20,
    gc_threshold_2=20,
    gc_freeze_enabled=True,
    thread_pool_multiplier=2.0,  # Free-threading ready
    max_thread_pool_size=64,
    prefer_slots=True,
    use_frozen_dataclasses=True,
    prefer_match_statements=True,
    prefer_exception_groups=True,
    prefer_type_params=True,
    enable_perf_hints=True,
    aggressive_inlining=True,  # Tail-call interpreter
    enable_experimental=False,  # Requires explicit opt-in
)


def get_optimization_profile() -> OptimizationProfile:
    """Get the optimization profile for the current Python version.

    Returns:
        OptimizationProfile suitable for the runtime environment.

    """
    _ = get_features()  # Warm up cache, validate version
    experimental = is_experimental_enabled()
    opt_level = get_optimization_level()

    # Select base profile by version
    if PY314:
        profile = _PROFILE_314
    elif PY313:
        profile = _PROFILE_313
    elif PY312:
        profile = _PROFILE_312
    else:
        profile = _PROFILE_311

    # Adjust for optimization level
    if opt_level == OPT_LEVEL_NONE:
        # Minimal optimizations - use 3.11 baseline
        return _PROFILE_311

    if opt_level == OPT_LEVEL_AGGRESSIVE and experimental:
        # Aggressive mode - enable experimental features
        return OptimizationProfile(
            gc_threshold_0=profile.gc_threshold_0,
            gc_threshold_1=profile.gc_threshold_1,
            gc_threshold_2=profile.gc_threshold_2,
            gc_freeze_enabled=profile.gc_freeze_enabled,
            thread_pool_multiplier=profile.thread_pool_multiplier,
            max_thread_pool_size=profile.max_thread_pool_size,
            prefer_slots=profile.prefer_slots,
            use_frozen_dataclasses=profile.use_frozen_dataclasses,
            prefer_match_statements=profile.prefer_match_statements,
            prefer_exception_groups=profile.prefer_exception_groups,
            prefer_type_params=profile.prefer_type_params,
            enable_perf_hints=profile.enable_perf_hints,
            aggressive_inlining=profile.aggressive_inlining,
            enable_experimental=True,
        )

    return profile


# =============================================================================
# Apply Optimizations
# =============================================================================


def _apply_gc_tuning(
    profile: OptimizationProfile,
    applied: list[str],
    errors: list[str],
) -> None:
    """Apply Garbage Collector tuning."""
    try:
        current = gc.get_threshold()
        gc.set_threshold(
            profile.gc_threshold_0,
            profile.gc_threshold_1,
            profile.gc_threshold_2,
        )
        applied.append(
            f"gc_threshold: {current} -> "
            f"({profile.gc_threshold_0}, {profile.gc_threshold_1}, "
            f"{profile.gc_threshold_2})"
        )
    except Exception as e:
        errors.append(f"gc_threshold: {e}")


def _apply_gc_freeze(
    profile: OptimizationProfile,
    freeze_after: bool,
    applied: list[str],
    skipped: list[str],
    errors: list[str],
) -> None:
    """Apply GC freeze if supported."""
    if profile.gc_freeze_enabled and freeze_after and PY312:
        try:
            gc.freeze()
            applied.append("gc_freeze: enabled")
        except Exception as e:
            errors.append(f"gc_freeze: {e}")
    elif profile.gc_freeze_enabled and not PY312:
        skipped.append("gc_freeze: requires Python 3.12+")


def _apply_experimental(
    profile: OptimizationProfile,
    applied: list[str],
    skipped: list[str],
) -> None:
    """Check and log experimental features."""
    if profile.enable_experimental:
        features = get_features()
        if features.has_jit:
            applied.append("jit: available")
        if features.has_free_threading:
            applied.append("free_threading: available")
        logger.warning(
            "EXPERIMENTAL FEATURES ENABLED: Stability and security may be affected."
        )
    else:
        skipped.append("experimental: requires STACK_ENABLE_EXPERIMENTAL=1")


def apply_optimizations(
    *,
    profile: OptimizationProfile | None = None,
    apply_gc: bool = True,
    freeze_after: bool = False,
) -> OptimizationResult:
    """Apply runtime optimizations based on profile.

    This function applies safe, reversible optimizations to the Python
    runtime. It is designed to be called once at application startup.

    Args:
        profile: Optimization profile to use (auto-detected if None).
        apply_gc: Whether to apply GC tuning.
        freeze_after: Whether to freeze objects after applying.

    Returns:
        OptimizationResult with details of what was applied.

    """
    if profile is None:
        profile = get_optimization_profile()

    applied: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    # GC Tuning
    if apply_gc:
        _apply_gc_tuning(profile, applied, errors)
    else:
        skipped.append("gc_threshold: disabled")

    # GC Freeze (3.12+)
    _apply_gc_freeze(profile, freeze_after, applied, skipped, errors)

    # Performance hints logging
    if profile.enable_perf_hints:
        applied.append("perf_hints: enabled (JIT-aware patterns)")
    else:
        skipped.append("perf_hints: disabled")

    # Experimental features
    _apply_experimental(profile, applied, skipped)

    # Log summary
    success = len(errors) == 0
    if applied:
        logger.debug("Applied optimizations: %s", ", ".join(applied))
    if skipped:
        logger.debug("Skipped optimizations: %s", ", ".join(skipped))
    if errors:
        logger.warning("Optimization errors: %s", ", ".join(errors))

    return OptimizationResult(
        success=success,
        applied=tuple(applied),
        skipped=tuple(skipped),
        errors=tuple(errors),
    )


# =============================================================================
# Utility Functions
# =============================================================================


def get_recommended_thread_pool_size() -> int:
    """Get recommended thread pool size based on version and features.

    Returns:
        Recommended number of threads for ThreadPoolExecutor.

    """
    profile = get_optimization_profile()
    cpu_count = os.cpu_count() or 4

    size = int(cpu_count * profile.thread_pool_multiplier)
    return min(size, profile.max_thread_pool_size)


def should_use_slots() -> bool:
    """Check if __slots__ should be used for new classes.

    Returns:
        True if slots are recommended for current version.

    """
    return get_optimization_profile().prefer_slots


def should_use_frozen_dataclass() -> bool:
    """Check if frozen=True should be used for dataclasses.

    Returns:
        True if frozen dataclasses are recommended.

    """
    return get_optimization_profile().use_frozen_dataclasses
