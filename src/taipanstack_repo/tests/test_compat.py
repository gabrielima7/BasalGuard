"""Comprehensive tests for core.compat module (Python version compatibility)."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

from taipanstack.core.compat import (
    PY311,
    PY312,
    PY313,
    PY314,
    PY_VERSION,
    PythonFeatures,
    VersionTier,
    get_features,
    get_optimization_level,
    get_python_info,
    is_experimental_enabled,
)


class TestVersionConstants:
    """Test version detection constants."""

    def test_py_version_tuple(self) -> None:
        """Test PY_VERSION is a tuple."""
        assert isinstance(PY_VERSION, tuple)
        assert len(PY_VERSION) >= 3

    def test_py311_constant(self) -> None:
        """Test PY311 reflects actual Python version."""
        expected = sys.version_info >= (3, 11)
        assert expected == PY311

    def test_py312_constant(self) -> None:
        """Test PY312 reflects actual Python version."""
        expected = sys.version_info >= (3, 12)
        assert expected == PY312

    def test_py313_constant(self) -> None:
        """Test PY313 reflects actual Python version."""
        expected = sys.version_info >= (3, 13)
        assert expected == PY313

    def test_py314_constant(self) -> None:
        """Test PY314 reflects actual Python version."""
        expected = sys.version_info >= (3, 14)
        assert expected == PY314


class TestVersionTier:
    """Test VersionTier enum."""

    def test_version_tier_values(self) -> None:
        """Test VersionTier has all expected values."""
        assert VersionTier.STABLE == "stable"
        assert VersionTier.ENHANCED == "enhanced"
        assert VersionTier.MODERN == "modern"
        assert VersionTier.CUTTING_EDGE == "cutting_edge"

    def test_version_tier_is_str(self) -> None:
        """Test VersionTier members are strings."""
        assert isinstance(VersionTier.STABLE, str)
        assert isinstance(VersionTier.ENHANCED, str)


class TestExperimentalFeatures:
    """Test experimental feature detection."""

    def test_experimental_disabled_by_default(self) -> None:
        """Test experimental features disabled by default."""
        with patch.dict(os.environ, {}, clear=True):
            assert not is_experimental_enabled()

    def test_experimental_enabled_with_1(self) -> None:
        """Test experimental enabled with value '1'."""
        with patch.dict(os.environ, {"STACK_ENABLE_EXPERIMENTAL": "1"}):
            assert is_experimental_enabled()

    def test_experimental_enabled_with_true(self) -> None:
        """Test experimental enabled with value 'true'."""
        with patch.dict(os.environ, {"STACK_ENABLE_EXPERIMENTAL": "true"}):
            assert is_experimental_enabled()

    def test_experimental_enabled_with_yes(self) -> None:
        """Test experimental enabled with value 'yes'."""
        with patch.dict(os.environ, {"STACK_ENABLE_EXPERIMENTAL": "yes"}):
            assert is_experimental_enabled()

    def test_experimental_enabled_with_on(self) -> None:
        """Test experimental enabled with value 'on'."""
        with patch.dict(os.environ, {"STACK_ENABLE_EXPERIMENTAL": "on"}):
            assert is_experimental_enabled()

    def test_experimental_disabled_with_0(self) -> None:
        """Test experimental disabled with value '0'."""
        with patch.dict(os.environ, {"STACK_ENABLE_EXPERIMENTAL": "0"}):
            assert not is_experimental_enabled()

    def test_experimental_case_insensitive(self) -> None:
        """Test experimental check is case-insensitive."""
        with patch.dict(os.environ, {"STACK_ENABLE_EXPERIMENTAL": "TRUE"}):
            assert is_experimental_enabled()


class TestOptimizationLevel:
    """Test optimization level detection."""

    def test_default_optimization_level(self) -> None:
        """Test default optimization level is 1."""
        with patch.dict(os.environ, {}, clear=True):
            assert get_optimization_level() == 1

    def test_optimization_level_0(self) -> None:
        """Test optimization level can be set to 0."""
        with patch.dict(os.environ, {"STACK_OPTIMIZATION_LEVEL": "0"}):
            assert get_optimization_level() == 0

    def test_optimization_level_2(self) -> None:
        """Test optimization level can be set to 2."""
        with patch.dict(os.environ, {"STACK_OPTIMIZATION_LEVEL": "2"}):
            assert get_optimization_level() == 2

    def test_optimization_level_clamped_low(self) -> None:
        """Test optimization level is clamped to minimum 0."""
        with patch.dict(os.environ, {"STACK_OPTIMIZATION_LEVEL": "-5"}):
            assert get_optimization_level() == 0

    def test_optimization_level_clamped_high(self) -> None:
        """Test optimization level is clamped to maximum 2."""
        with patch.dict(os.environ, {"STACK_OPTIMIZATION_LEVEL": "99"}):
            assert get_optimization_level() == 2

    def test_optimization_level_invalid(self) -> None:
        """Test invalid optimization level defaults to 1."""
        with patch.dict(os.environ, {"STACK_OPTIMIZATION_LEVEL": "invalid"}):
            assert get_optimization_level() == 1


class TestPythonFeatures:
    """Test PythonFeatures dataclass."""

    def test_get_features_returns_features(self) -> None:
        """Test get_features returns PythonFeatures instance."""
        features = get_features()
        assert isinstance(features, PythonFeatures)

    def test_features_version(self) -> None:
        """Test features includes correct version."""
        features = get_features()
        assert features.version == (
            PY_VERSION.major,
            PY_VERSION.minor,
            PY_VERSION.micro,
        )
        assert features.version_string == (
            f"{PY_VERSION.major}.{PY_VERSION.minor}.{PY_VERSION.micro}"
        )

    def test_features_tier_stable(self) -> None:
        """Test version tier for Python 3.11."""
        with patch("taipanstack.core.compat.PY312", False):
            with patch("taipanstack.core.compat.PY313", False):
                with patch("taipanstack.core.compat.PY314", False):
                    features = get_features(force_refresh=True)
                    assert features.tier == VersionTier.STABLE

    def test_features_tier_enhanced(self) -> None:
        """Test version tier for Python 3.12."""
        with patch("taipanstack.core.compat.PY312", True):
            with patch("taipanstack.core.compat.PY313", False):
                with patch("taipanstack.core.compat.PY314", False):
                    features = get_features(force_refresh=True)
                    assert features.tier == VersionTier.ENHANCED

    def test_features_tier_modern(self) -> None:
        """Test version tier for Python 3.13."""
        with patch("taipanstack.core.compat.PY313", True):
            with patch("taipanstack.core.compat.PY314", False):
                features = get_features(force_refresh=True)
                assert features.tier == VersionTier.MODERN

    def test_features_tier_cutting_edge(self) -> None:
        """Test version tier for Python 3.14+."""
        with patch("taipanstack.core.compat.PY314", True):
            features = get_features(force_refresh=True)
            assert features.tier == VersionTier.CUTTING_EDGE

    def test_features_language_311(self) -> None:
        """Test language features for Python 3.11."""
        features = get_features()
        if PY311:
            assert features.has_exception_groups
            assert features.has_self_type

    def test_features_language_312(self) -> None:
        """Test language features for Python 3.12."""
        features = get_features()
        if PY312:
            assert features.has_type_params
            assert features.has_fstring_improvements
            assert features.has_override_decorator

    def test_features_language_313(self) -> None:
        """Test language features for Python 3.13."""
        features = get_features()
        if PY313:
            assert features.has_deprecated_decorator

    def test_features_language_314(self) -> None:
        """Test language features for Python 3.14."""
        features = get_features()
        if PY314:
            assert features.has_deferred_annotations

    def test_features_experimental_disabled(self) -> None:
        """Test build features disabled when experimental is off."""
        with patch.dict(os.environ, {}, clear=True):
            features = get_features(force_refresh=True)
            assert not features.experimental_enabled
            assert not features.has_jit
            assert not features.has_free_threading

    def test_features_to_dict(self) -> None:
        """Test features can be converted to dictionary."""
        features = get_features()
        data = features.to_dict()

        assert isinstance(data, dict)
        assert "version" in data
        assert "tier" in data
        assert "features" in data
        assert "language" in data
        assert "experimental_enabled" in data

    def test_features_cached(self) -> None:
        """Test features are cached after first call."""
        features1 = get_features()
        features2 = get_features()
        assert features1 is features2

    def test_features_force_refresh(self) -> None:
        """Test force_refresh bypasses cache."""
        features1 = get_features()
        with patch.dict(os.environ, {"STACK_ENABLE_EXPERIMENTAL": "1"}):
            features2 = get_features(force_refresh=True)
            # Should have different experimental status
            assert features1 is not features2


class TestGetPythonInfo:
    """Test get_python_info function."""

    def test_python_info_structure(self) -> None:
        """Test python info returns expected structure."""
        info = get_python_info()

        assert isinstance(info, dict)
        assert "version" in info
        assert "version_tuple" in info
        assert "tier" in info
        assert "implementation" in info
        assert "platform" in info
        assert "compiler" in info
        assert "features" in info
        assert "optimization_level" in info

    def test_python_info_values(self) -> None:
        """Test python info contains valid values."""
        info = get_python_info()

        assert isinstance(info["version"], str)
        assert isinstance(info["version_tuple"], tuple)
        assert isinstance(info["tier"], str)
        assert isinstance(info["optimization_level"], int)
