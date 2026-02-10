"""Additional tests for validators to achieve 100% coverage."""

from __future__ import annotations

import pytest

from taipanstack.security.validators import (
    validate_email,
    validate_ip_address,
    validate_port,
    validate_project_name,
    validate_python_version,
    validate_semver,
    validate_url,
)


class TestValidateProjectNameEdgeCases:
    """Additional tests for validate_project_name."""

    def test_name_too_long(self) -> None:
        """Test that names exceeding max_length are rejected."""
        long_name = "a" * 101
        with pytest.raises(ValueError, match="exceeds maximum"):
            validate_project_name(long_name, max_length=100)

    def test_name_starts_with_number(self) -> None:
        """Test that names starting with numbers are rejected."""
        with pytest.raises(ValueError, match="start with a letter"):
            validate_project_name("123project")

    def test_name_starts_with_hyphen(self) -> None:
        """Test that names starting with hyphen are rejected."""
        with pytest.raises(ValueError, match="start with a letter"):
            validate_project_name("-myproject")

    def test_hyphen_not_allowed(self) -> None:
        """Test that hyphens can be disallowed."""
        with pytest.raises(ValueError, match="invalid characters"):
            validate_project_name("my-project", allow_hyphen=False)

    def test_underscore_not_allowed(self) -> None:
        """Test that underscores can be disallowed."""
        with pytest.raises(ValueError, match="invalid characters"):
            validate_project_name("my_project", allow_underscore=False)

    def test_empty_name(self) -> None:
        """Test that empty names are rejected."""
        with pytest.raises(ValueError):
            validate_project_name("")


class TestValidatePythonVersionEdgeCases:
    """Additional tests for validate_python_version."""

    def test_unsupported_major_version(self) -> None:
        """Test that unsupported major versions are rejected."""
        with pytest.raises(ValueError, match="Python 3"):
            validate_python_version("2.7")

    def test_unsupported_minor_version(self) -> None:
        """Test that old minor versions are rejected."""
        with pytest.raises(ValueError, match="3.10"):
            validate_python_version("3.9")


class TestValidateEmailEdgeCases:
    """Additional tests for validate_email."""

    def test_local_part_too_long(self) -> None:
        """Test that local part exceeding max length is rejected."""
        long_local = "a" * 65
        with pytest.raises(ValueError):
            validate_email(f"{long_local}@example.com")

    def test_domain_too_long(self) -> None:
        """Test that domain exceeding max length is rejected."""
        long_domain = "a" * 256
        with pytest.raises(ValueError):
            validate_email(f"test@{long_domain}.com")


class TestValidateUrlEdgeCases:
    """Additional tests for validate_url."""

    def test_invalid_scheme(self) -> None:
        """Test that invalid schemes are rejected."""
        with pytest.raises(ValueError, match="scheme"):
            validate_url("ftp://example.com")

    def test_missing_domain(self) -> None:
        """Test that URLs without domain are rejected."""
        with pytest.raises(ValueError):
            validate_url("http://")

    def test_localhost_allowed(self) -> None:
        """Test that localhost is allowed when TLD not required."""
        result = validate_url("http://localhost:8080", require_tld=False)
        assert "localhost" in result


class TestValidateIpAddress:
    """Tests for validate_ip_address function."""

    def test_valid_ipv4(self) -> None:
        """Test valid IPv4 address."""
        result = validate_ip_address("192.168.1.1")
        assert result is not None

    def test_valid_ipv6(self) -> None:
        """Test valid IPv6 address."""
        result = validate_ip_address("::1", version="v6")
        assert result is not None

    def test_invalid_ip(self) -> None:
        """Test invalid IP address."""
        with pytest.raises(ValueError):
            validate_ip_address("not.an.ip.address")

    def test_ipv4_only(self) -> None:
        """Test that v4-only mode rejects IPv6."""
        with pytest.raises(ValueError):
            validate_ip_address("::1", version="v4")

    def test_ipv6_only(self) -> None:
        """Test that v6-only mode rejects IPv4."""
        with pytest.raises(ValueError):
            validate_ip_address("192.168.1.1", version="v6")

    def test_private_ip_rejected(self) -> None:
        """Test that private IPs can be rejected."""
        with pytest.raises(ValueError):
            validate_ip_address("192.168.1.1", allow_private=False)

    def test_public_ip_allowed(self) -> None:
        """Test that public IPs are allowed."""
        result = validate_ip_address("8.8.8.8", allow_private=False)
        assert result is not None


class TestValidatePort:
    """Tests for validate_port function."""

    def test_valid_port(self) -> None:
        """Test valid port number."""
        result = validate_port(8080)
        assert result == 8080

    def test_port_as_string(self) -> None:
        """Test port as string."""
        result = validate_port("8080")
        assert result == 8080

    def test_port_zero(self) -> None:
        """Test port zero is invalid."""
        with pytest.raises(ValueError):
            validate_port(0)

    def test_port_too_high(self) -> None:
        """Test port above valid range."""
        with pytest.raises(ValueError):
            validate_port(70000)

    def test_privileged_port_rejected(self) -> None:
        """Test that privileged ports are rejected by default."""
        with pytest.raises(ValueError):
            validate_port(80, allow_privileged=False)

    def test_privileged_port_allowed(self) -> None:
        """Test that privileged ports can be allowed."""
        result = validate_port(80, allow_privileged=True)
        assert result == 80

    def test_negative_port(self) -> None:
        """Test negative port number."""
        with pytest.raises(ValueError):
            validate_port(-1)


class TestValidateSemver:
    """Tests for validate_semver function."""

    def test_valid_semver(self) -> None:
        """Test valid semantic version."""
        result = validate_semver("1.2.3")
        assert result == (1, 2, 3)

    def test_semver_with_v_prefix(self) -> None:
        """Test semver with 'v' prefix."""
        result = validate_semver("v1.2.3")
        assert result == (1, 2, 3)

    def test_invalid_semver(self) -> None:
        """Test invalid semantic version."""
        with pytest.raises(ValueError):
            validate_semver("not.a.version")

    def test_partial_version(self) -> None:
        """Test partial version string."""
        with pytest.raises(ValueError):
            validate_semver("1.2")

    def test_zero_version(self) -> None:
        """Test zero version."""
        result = validate_semver("0.0.0")
        assert result == (0, 0, 0)
