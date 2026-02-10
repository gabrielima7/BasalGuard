"""Comprehensive tests for core.optimizations module."""

from __future__ import annotations

import gc
import os
from unittest.mock import patch

import pytest

from taipanstack.core.optimizations import (
    OptimizationProfile,
    OptimizationResult,
    apply_optimizations,
    get_optimization_profile,
    get_recommended_thread_pool_size,
    should_use_frozen_dataclass,
    should_use_slots,
)


class TestOptimizationProfile:
    """Test OptimizationProfile dataclass."""

    def test_profile_creation(self) -> None:
        """Test creating an optimization profile."""
        profile = OptimizationProfile(
            gc_threshold_0=700,
            gc_threshold_1=10,
            gc_threshold_2=10,
        )
        assert profile.gc_threshold_0 == 700
        assert profile.gc_threshold_1 == 10
        assert profile.gc_threshold_2 == 10

    def test_profile_immutable(self) -> None:
        """Test profiles are immutable (frozen)."""
        profile = OptimizationProfile()
        with pytest.raises(AttributeError):
            profile.gc_threshold_0 = 999  # type: ignore[misc]


class TestOptimizationResult:
    """Test OptimizationResult dataclass."""

    def test_result_creation(self) -> None:
        """Test creating an optimization result."""
        result = OptimizationResult(
            success=True,
            applied=("gc_threshold",),
            skipped=("perf_hints",),
            errors=(),
        )
        assert result.success
        assert "gc_threshold" in result.applied
        assert "perf_hints" in result.skipped
        assert len(result.errors) == 0

    def test_result_to_dict(self) -> None:
        """Test converting result to dictionary."""
        result = OptimizationResult(
            success=True,
            applied=("opt1", "opt2"),
            skipped=("opt3",),
            errors=(),
        )
        data = result.to_dict()

        assert data["success"] is True
        assert data["applied"] == ["opt1", "opt2"]
        assert data["skipped"] == ["opt3"]
        assert data["errors"] == []


class TestGetOptimizationProfile:
    """Test get_optimization_profile function."""

    def test_profile_for_311(self) -> None:
        """Test profile selection for Python 3.11."""
        with patch("taipanstack.core.optimizations.PY312", False):
            with patch("taipanstack.core.optimizations.PY313", False):
                with patch("taipanstack.core.optimizations.PY314", False):
                    with patch.dict(os.environ, {}, clear=True):
                        profile = get_optimization_profile()
                        assert isinstance(profile, OptimizationProfile)
                        assert profile.prefer_exception_groups
                        assert not profile.prefer_type_params

    def test_profile_for_312(self) -> None:
        """Test profile selection for Python 3.12."""
        with patch("taipanstack.core.optimizations.PY312", True):
            with patch("taipanstack.core.optimizations.PY313", False):
                with patch("taipanstack.core.optimizations.PY314", False):
                    with patch.dict(os.environ, {}, clear=True):
                        profile = get_optimization_profile()
                        assert profile.prefer_type_params
                        assert profile.gc_freeze_enabled

    def test_profile_for_313(self) -> None:
        """Test profile selection for Python 3.13."""
        with patch("taipanstack.core.optimizations.PY313", True):
            with patch("taipanstack.core.optimizations.PY314", False):
                with patch.dict(os.environ, {}, clear=True):
                    profile = get_optimization_profile()
                    assert profile.enable_perf_hints
                    assert profile.thread_pool_multiplier == 1.5

    def test_profile_for_314(self) -> None:
        """Test profile selection for Python 3.14."""
        with patch("taipanstack.core.optimizations.PY314", True):
            with patch.dict(os.environ, {}, clear=True):
                profile = get_optimization_profile()
                assert profile.aggressive_inlining
                assert profile.thread_pool_multiplier == 2.0

    def test_profile_opt_level_none(self) -> None:
        """Test profile with OPT_LEVEL_NONE uses minimal settings."""
        with patch.dict(os.environ, {"STACK_OPTIMIZATION_LEVEL": "0"}):
            profile = get_optimization_profile()
            # Should return 3.11 baseline
            assert profile.gc_threshold_0 == 700

    def test_profile_opt_level_aggressive_without_experimental(self) -> None:
        """Test aggressive level without experimental returns normal profile."""
        with patch.dict(os.environ, {"STACK_OPTIMIZATION_LEVEL": "2"}):
            profile = get_optimization_profile()
            assert not profile.enable_experimental

    def test_profile_opt_level_aggressive_with_experimental(self) -> None:
        """Test aggressive level with experimental enables features."""
        with patch.dict(
            os.environ,
            {"STACK_OPTIMIZATION_LEVEL": "2", "STACK_ENABLE_EXPERIMENTAL": "1"},
        ):
            profile = get_optimization_profile()
            assert profile.enable_experimental


class TestApplyOptimizations:
    """Test apply_optimizations function."""

    def test_apply_default_optimizations(self) -> None:
        """Test applying default optimizations."""
        result = apply_optimizations()
        assert isinstance(result, OptimizationResult)
        assert result.success

    def test_apply_with_custom_profile(self) -> None:
        """Test applying optimizations with custom profile."""
        custom_profile = OptimizationProfile(
            gc_threshold_0=999,
            gc_threshold_1=20,
            gc_threshold_2=20,
        )
        result = apply_optimizations(profile=custom_profile)
        assert result.success
        # Verify GC was actually tuned
        thresholds = gc.get_threshold()
        assert thresholds[0] == 999

    def test_apply_without_gc(self) -> None:
        """Test applying optimizations without GC tuning."""
        result = apply_optimizations(apply_gc=False)
        assert result.success
        assert any("gc_threshold: disabled" in s for s in result.skipped)

    def test_apply_with_freeze(self) -> None:
        """Test applying with gc.freeze."""
        # Only works on Python 3.12+
        result = apply_optimizations(freeze_after=True)
        assert result.success

    def test_apply_experimental_enabled(self) -> None:
        """Test experimental features logged when enabled."""
        with patch.dict(os.environ, {"STACK_ENABLE_EXPERIMENTAL": "1"}):
            profile = OptimizationProfile(enable_experimental=True)
            result = apply_optimizations(profile=profile)
            assert result.success

    def test_apply_experimental_disabled(self) -> None:
        """Test experimental features skipped when disabled."""
        profile = OptimizationProfile(enable_experimental=False)
        result = apply_optimizations(profile=profile)
        assert any("experimental" in s for s in result.skipped)

    def test_apply_perf_hints_enabled(self) -> None:
        """Test performance hints reported when enabled."""
        profile = OptimizationProfile(enable_perf_hints=True)
        result = apply_optimizations(profile=profile)
        assert any("perf_hints: enabled" in s for s in result.applied)

    def test_apply_perf_hints_disabled(self) -> None:
        """Test performance hints skipped when disabled."""
        profile = OptimizationProfile(enable_perf_hints=False)
        result = apply_optimizations(profile=profile)
        assert any("perf_hints: disabled" in s for s in result.skipped)


class TestUtilityFunctions:
    """Test utility functions."""

    def test_get_recommended_thread_pool_size(self) -> None:
        """Test thread pool size calculation."""
        size = get_recommended_thread_pool_size()
        assert isinstance(size, int)
        assert size > 0
        assert size <= 64  # Maximum from 3.14 profile

    def test_thread_pool_size_respects_multiplier(self) -> None:
        """Test thread pool size uses profile multiplier."""
        with patch("taipanstack.core.optimizations.PY314", True):
            with patch("os.cpu_count", return_value=8):
                size = get_recommended_thread_pool_size()
                # 3.14 has multiplier of 2.0, so 8 * 2.0 = 16
                assert size == 16

    def test_thread_pool_size_respects_max(self) -> None:
        """Test thread pool size doesn't exceed maximum."""
        with patch("taipanstack.core.optimizations.PY314", True):
            with patch("os.cpu_count", return_value=100):
                size = get_recommended_thread_pool_size()
                # Should be capped at max_thread_pool_size (64 for 3.14)
                assert size == 64

    def test_thread_pool_size_with_none_cpu_count(self) -> None:
        """Test thread pool size when cpu_count returns None."""
        with patch("os.cpu_count", return_value=None):
            size = get_recommended_thread_pool_size()
            # Should default to 4 CPUs
            assert size >= 4

    def test_should_use_slots(self) -> None:
        """Test should_use_slots recommendation."""
        result = should_use_slots()
        assert isinstance(result, bool)
        # All profiles recommend slots
        assert result is True

    def test_should_use_frozen_dataclass(self) -> None:
        """Test should_use_frozen_dataclass recommendation."""
        result = should_use_frozen_dataclass()
        assert isinstance(result, bool)
        # All profiles recommend frozen dataclasses
        assert result is True
