"""Comprehensive tests for config.version_config module."""

from __future__ import annotations

from unittest.mock import patch

from taipanstack.config.version_config import (
    VersionRecommendations,
    get_version_recommendations,
)
from taipanstack.core.compat import VersionTier


class TestVersionRecommendations:
    """Test VersionRecommendations dataclass."""

    def test_recommendations_creation(self) -> None:
        """Test creating version recommendations."""
        rec = VersionRecommendations(
            version_tier=VersionTier.STABLE,
            min_version="3.11.0",
            max_version="3.11.x",
            recommended_thread_pool_size=32,
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
            notes=("Test note",),
        )
        assert rec.version_tier == VersionTier.STABLE
        assert rec.min_version == "3.11.0"
        assert not rec.supports_true_parallelism

    def test_recommendations_to_dict(self) -> None:
        """Test converting recommendations to dictionary."""
        rec = VersionRecommendations(
            version_tier=VersionTier.ENHANCED,
            min_version="3.12.0",
            max_version="3.12.x",
            recommended_thread_pool_size=32,
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
            notes=("Note 1", "Note 2"),
        )
        data = rec.to_dict()

        assert data["version_tier"] == "enhanced"
        assert "version_range" in data
        assert data["threading"]["pool_size"] == 32
        assert data["memory"]["gc_mode"] == "default"
        assert data["code_style"]["type_params"] is True
        assert data["performance"]["jit_available"] is False
        assert len(data["notes"]) == 2


class TestGetVersionRecommendations:
    """Test get_version_recommendations function."""

    def test_recommendations_for_311(self) -> None:
        """Test recommendations for Python 3.11."""
        with patch("taipanstack.config.version_config.PY312", False):
            with patch("taipanstack.config.version_config.PY313", False):
                with patch("taipanstack.config.version_config.PY314", False):
                    rec = get_version_recommendations()
                    assert rec.version_tier == VersionTier.STABLE
                    assert rec.min_version == "3.11.0"
                    assert rec.use_exception_groups
                    assert not rec.use_type_params
                    assert not rec.use_override_decorator
                    assert not rec.jit_available
                    assert not rec.supports_true_parallelism

    def test_recommendations_for_312(self) -> None:
        """Test recommendations for Python 3.12."""
        with patch("taipanstack.config.version_config.PY312", True):
            with patch("taipanstack.config.version_config.PY313", False):
                with patch("taipanstack.config.version_config.PY314", False):
                    rec = get_version_recommendations()
                    assert rec.version_tier == VersionTier.ENHANCED
                    assert rec.min_version == "3.12.0"
                    assert rec.use_type_params
                    assert rec.use_override_decorator
                    assert not rec.use_deprecated_decorator
                    assert not rec.jit_available
                    assert rec.recommended_optimization_level == 1

    def test_recommendations_for_313(self) -> None:
        """Test recommendations for Python 3.13."""
        with patch("taipanstack.config.version_config.PY313", True):
            with patch("taipanstack.config.version_config.PY314", False):
                rec = get_version_recommendations()
                assert rec.version_tier == VersionTier.MODERN
                assert rec.min_version == "3.13.0"
                assert rec.use_deprecated_decorator
                assert rec.recommended_optimization_level >= 1

    def test_recommendations_for_313_with_features(self) -> None:
        """Test recommendations for Python 3.13 with features detected."""
        with patch("taipanstack.config.version_config.PY313", True):
            with patch("taipanstack.config.version_config.PY314", False):
                # Mock features with experimental enabled
                from taipanstack.core.compat import PythonFeatures, VersionTier

                mock_features = PythonFeatures(
                    version=(3, 13, 0),
                    version_string="3.13.0",
                    tier=VersionTier.MODERN,
                    has_jit=True,
                    has_free_threading=True,
                    has_mimalloc=True,
                    experimental_enabled=True,
                )

                with patch(
                    "taipanstack.config.version_config.get_features",
                    return_value=mock_features,
                ):
                    rec = get_version_recommendations()
                    assert rec.jit_available
                    assert rec.supports_true_parallelism
                    assert rec.use_mimalloc
                    assert rec.recommended_gc_mode == "tuned"
                    assert rec.recommended_optimization_level == 2

    def test_recommendations_for_313_without_experimental(self) -> None:
        """Test recommendations for Python 3.13 without experimental."""
        with patch("taipanstack.config.version_config.PY313", True):
            with patch("taipanstack.config.version_config.PY314", False):
                from taipanstack.core.compat import PythonFeatures, VersionTier

                mock_features = PythonFeatures(
                    version=(3, 13, 0),
                    version_string="3.13.0",
                    tier=VersionTier.MODERN,
                    has_jit=False,
                    has_free_threading=False,
                    has_mimalloc=False,
                    experimental_enabled=False,
                )

                with patch(
                    "taipanstack.config.version_config.get_features",
                    return_value=mock_features,
                ):
                    rec = get_version_recommendations()
                    assert not rec.jit_available
                    assert not rec.supports_true_parallelism
                    assert not rec.use_mimalloc
                    assert rec.recommended_gc_mode == "default"
                    assert rec.recommended_optimization_level == 1

    def test_recommendations_for_314(self) -> None:
        """Test recommendations for Python 3.14."""
        with patch("taipanstack.config.version_config.PY314", True):
            rec = get_version_recommendations()
            assert rec.version_tier == VersionTier.CUTTING_EDGE
            assert rec.min_version == "3.14.0"
            assert rec.max_version is None  # Latest
            assert rec.use_mimalloc
            assert rec.recommended_gc_mode == "incremental"
            assert len(rec.notes) >= 4  # Should have comprehensive notes

    def test_recommendations_for_314_with_features(self) -> None:
        """Test recommendations for Python 3.14 with experimental features."""
        with patch("taipanstack.config.version_config.PY314", True):
            from taipanstack.core.compat import PythonFeatures, VersionTier

            mock_features = PythonFeatures(
                version=(3, 14, 0),
                version_string="3.14.0",
                tier=VersionTier.CUTTING_EDGE,
                has_jit=True,
                has_free_threading=True,
                has_mimalloc=True,
                has_tail_call_interpreter=True,
                has_deferred_annotations=True,
                experimental_enabled=True,
            )

            with patch(
                "taipanstack.config.version_config.get_features",
                return_value=mock_features,
            ):
                rec = get_version_recommendations()
                assert rec.jit_available
                assert rec.supports_true_parallelism
                assert rec.recommended_optimization_level == 2

    def test_recommendations_always_returns_valid_data(self) -> None:
        """Test that recommendations always return valid data."""
        rec = get_version_recommendations()

        # Verify essential fields are present and valid
        assert isinstance(rec.version_tier, VersionTier)
        assert isinstance(rec.min_version, str)
        assert isinstance(rec.recommended_thread_pool_size, int)
        assert rec.recommended_thread_pool_size > 0
        assert isinstance(rec.recommended_gc_mode, str)
        assert isinstance(rec.recommended_optimization_level, int)
        assert 0 <= rec.recommended_optimization_level <= 2
        assert isinstance(rec.notes, tuple)
        assert len(rec.notes) > 0

    def test_recommendations_threading_values(self) -> None:
        """Test threading recommendations have valid values."""
        rec = get_version_recommendations()
        assert rec.recommended_thread_pool_size > 0
        assert isinstance(rec.supports_true_parallelism, bool)

    def test_recommendations_code_style_values(self) -> None:
        """Test code style recommendations have valid values."""
        rec = get_version_recommendations()
        assert isinstance(rec.use_type_params, bool)
        assert isinstance(rec.use_exception_groups, bool)
        assert isinstance(rec.use_match_statements, bool)
        assert isinstance(rec.use_override_decorator, bool)
        assert isinstance(rec.use_deprecated_decorator, bool)
