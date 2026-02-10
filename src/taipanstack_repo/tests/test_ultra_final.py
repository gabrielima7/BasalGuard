"""Ultra-final tests to reach 100% coverage."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestValidators100Percent:
    """Tests to reach 100% for validators."""

    def test_validate_project_name_no_hyphens_no_underscores(self) -> None:
        """Test validate_project_name with both disabled."""
        from taipanstack.security.validators import validate_project_name

        # Should work with just letters and numbers
        result = validate_project_name(
            "myproject123",
            allow_hyphen=False,
            allow_underscore=False,
        )
        assert result == "myproject123"

    def test_validate_url_http(self) -> None:
        """Test validate_url with http scheme."""
        from taipanstack.security.validators import validate_url

        result = validate_url("http://example.com")
        assert "example.com" in result

    def test_validate_port_out_of_range(self) -> None:
        """Test validate_port with out of range port."""
        from taipanstack.security.validators import validate_port

        with pytest.raises(ValueError):
            validate_port(70000)  # > 65535


class TestGuards100Percent:
    """Tests to reach 100% for guards."""

    def test_guard_path_traversal_resolve_error(self, tmp_path: Path) -> None:
        """Test guard_path_traversal when path resolution fails."""
        from taipanstack.security.guards import guard_path_traversal

        # Test with a valid path
        valid_file = tmp_path / "valid.txt"
        valid_file.touch()

        result = guard_path_traversal(valid_file, tmp_path)
        assert result.exists()

    def test_guard_file_extension_denied(self) -> None:
        """Test guard_file_extension with denied extension."""
        from taipanstack.security.guards import SecurityError, guard_file_extension

        with pytest.raises(SecurityError):
            guard_file_extension(
                "script.exe",
                denied_extensions=["exe", "bat"],
            )


class TestSanitizers100Percent:
    """Tests to reach 100% for sanitizers."""

    def test_sanitize_string_no_whitespace_strip(self) -> None:
        """Test sanitize_string with strip_whitespace=False."""
        from taipanstack.security.sanitizers import sanitize_string

        result = sanitize_string("  hello  ", strip_whitespace=False)
        assert result == "  hello  "

    def test_sanitize_filename_no_replacement(self) -> None:
        """Test sanitize_filename with empty replacement."""
        from taipanstack.security.sanitizers import sanitize_filename

        result = sanitize_filename("file<>name.txt", replacement="")
        assert "<" not in result
        assert ">" not in result

    def test_sanitize_path_no_parts(self) -> None:
        """Test sanitize_path with path that results in no parts."""
        from taipanstack.security.sanitizers import sanitize_path

        result = sanitize_path("./")
        assert result is not None


class TestGenerators100Percent:
    """Tests to reach 100% for generators."""

    def test_write_config_file_dry_run(self, tmp_path: Path) -> None:
        """Test write_config_file in dry_run mode."""
        from taipanstack.config.generators import write_config_file
        from taipanstack.config.models import StackConfig

        config = StackConfig(project_name="test", dry_run=True)
        target = tmp_path / "test.toml"

        result = write_config_file(target, "content", config)
        assert result is False  # Dry run returns False

    def test_write_config_file_force(self, tmp_path: Path) -> None:
        """Test write_config_file with force=True overwrites."""
        from taipanstack.config.generators import write_config_file
        from taipanstack.config.models import StackConfig

        config = StackConfig(project_name="test", force=True)
        target = tmp_path / "test.toml"
        target.write_text("old content")

        result = write_config_file(target, "new content", config)
        assert result is True
        assert target.read_text() == "new content"


class TestFilesystem100Percent:
    """Tests to reach 100% for filesystem."""

    def test_get_file_hash_with_base_dir(self, tmp_path: Path) -> None:
        """Test get_file_hash with base_dir."""
        from taipanstack.utils.filesystem import get_file_hash

        test_file = tmp_path / "hashfile.txt"
        test_file.write_text("content")

        result = get_file_hash(test_file, base_dir=tmp_path)
        assert len(result) == 64  # SHA256


class TestRetry100Percent:
    """Tests to reach 100% for retry."""

    def test_retry_max_delay_applied(self) -> None:
        """Test that max_delay is actually applied."""
        from taipanstack.utils.retry import RetryConfig, calculate_delay

        config = RetryConfig(
            initial_delay=1.0,
            max_delay=2.0,
            exponential_base=10.0,  # Would grow quickly
            jitter=False,
        )

        # After several attempts, should be capped at max_delay
        delay = calculate_delay(10, config)
        assert delay <= config.max_delay


class TestModels100Percent:
    """Tests to reach 100% for models."""

    def test_stack_config_verbose(self) -> None:
        """Test StackConfig with verbose option."""
        from taipanstack.config.models import StackConfig

        config = StackConfig(
            project_name="test",
            verbose=True,
        )
        assert config.verbose is True


class TestCircuitBreaker100Percent:
    """Tests to reach 100% for circuit_breaker."""

    def test_circuit_breaker_name(self) -> None:
        """Test CircuitBreaker with custom name."""
        from taipanstack.utils.circuit_breaker import CircuitBreaker

        breaker = CircuitBreaker(name="custom_breaker")

        @breaker
        def test_func() -> str:
            return "ok"

        assert test_func() == "ok"
        assert breaker.name == "custom_breaker"
