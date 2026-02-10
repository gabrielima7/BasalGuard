"""Tests for stack.security.validators module."""

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


class TestValidateProjectName:
    """Tests for validate_project_name function."""

    def test_valid_project_name(self) -> None:
        """Test valid project names pass."""
        assert validate_project_name("my_project") == "my_project"
        assert validate_project_name("MyProject") == "MyProject"
        assert validate_project_name("my-project") == "my-project"
        assert validate_project_name("myproject123") == "myproject123"

    def test_empty_name_rejected(self) -> None:
        """Test empty names are rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_project_name("")

    def test_name_must_start_with_letter(self) -> None:
        """Test names must start with a letter."""
        with pytest.raises(ValueError, match="must start with a letter"):
            validate_project_name("123project")

    def test_reserved_names_rejected(self) -> None:
        """Test reserved names are rejected."""
        with pytest.raises(ValueError, match="is reserved"):
            validate_project_name("test")

    def test_max_length_enforced(self) -> None:
        """Test max length is enforced."""
        with pytest.raises(ValueError, match="exceeds maximum length"):
            validate_project_name("a" * 101)


class TestValidatePythonVersion:
    """Tests for validate_python_version function."""

    def test_valid_versions(self) -> None:
        """Test valid Python versions pass."""
        assert validate_python_version("3.10") == "3.10"
        assert validate_python_version("3.11") == "3.11"
        assert validate_python_version("3.12") == "3.12"

    def test_invalid_format_rejected(self) -> None:
        """Test invalid formats are rejected."""
        with pytest.raises(ValueError, match="Invalid version format"):
            validate_python_version("python3.10")

        with pytest.raises(ValueError, match="Invalid version format"):
            validate_python_version("3.10.5")

    def test_unsupported_version_rejected(self) -> None:
        """Test unsupported versions are rejected."""
        with pytest.raises(ValueError, match="not supported"):
            validate_python_version("3.9")

        with pytest.raises(ValueError, match="Only Python 3.x"):
            validate_python_version("2.7")


class TestValidateEmail:
    """Tests for validate_email function."""

    def test_valid_emails(self) -> None:
        """Test valid emails pass."""
        assert validate_email("user@example.com") == "user@example.com"
        assert validate_email("user.name@example.com") == "user.name@example.com"
        assert validate_email("user+tag@example.com") == "user+tag@example.com"

    def test_empty_email_rejected(self) -> None:
        """Test empty emails are rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_email("")

    def test_invalid_format_rejected(self) -> None:
        """Test invalid formats are rejected."""
        with pytest.raises(ValueError, match="Invalid email format"):
            validate_email("not-an-email")

        with pytest.raises(ValueError, match="Invalid email format"):
            validate_email("user@")


class TestValidateUrl:
    """Tests for validate_url function."""

    def test_valid_urls(self) -> None:
        """Test valid URLs pass."""
        assert validate_url("https://example.com") == "https://example.com"
        assert validate_url("http://localhost:8080") == "http://localhost:8080"
        assert (
            validate_url("https://api.github.com/repos")
            == "https://api.github.com/repos"
        )

    def test_empty_url_rejected(self) -> None:
        """Test empty URLs are rejected."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_url("")

    def test_missing_scheme_rejected(self) -> None:
        """Test URLs without scheme are rejected."""
        with pytest.raises(ValueError, match="must have a scheme"):
            validate_url("example.com")

    def test_invalid_scheme_rejected(self) -> None:
        """Test invalid schemes are rejected."""
        with pytest.raises(ValueError, match="not allowed"):
            validate_url("ftp://example.com")


class TestValidateIpAddress:
    """Tests for validate_ip_address function."""

    def test_valid_ipv4(self) -> None:
        """Test valid IPv4 addresses pass."""
        result = validate_ip_address("192.168.1.1")
        assert str(result) == "192.168.1.1"

    def test_valid_ipv6(self) -> None:
        """Test valid IPv6 addresses pass."""
        result = validate_ip_address("::1")
        assert str(result) == "::1"

    def test_invalid_ip_rejected(self) -> None:
        """Test invalid IPs are rejected."""
        with pytest.raises(ValueError, match="Invalid IP address"):
            validate_ip_address("not.an.ip")


class TestValidatePort:
    """Tests for validate_port function."""

    def test_valid_ports(self) -> None:
        """Test valid ports pass."""
        assert validate_port(8080) == 8080
        assert validate_port("3000") == 3000
        assert validate_port(65535) == 65535

    def test_invalid_port_rejected(self) -> None:
        """Test invalid ports are rejected."""
        with pytest.raises(ValueError, match="must be between"):
            validate_port(70000)

    def test_privileged_ports_blocked(self) -> None:
        """Test privileged ports are blocked by default."""
        with pytest.raises(ValueError, match="Privileged ports"):
            validate_port(80)


class TestValidateSemver:
    """Tests for validate_semver function."""

    def test_valid_semver(self) -> None:
        """Test valid semver strings pass."""
        assert validate_semver("1.0.0") == (1, 0, 0)
        assert validate_semver("v2.3.4") == (2, 3, 4)
        assert validate_semver("0.1.0-beta") == (0, 1, 0)

    def test_invalid_semver_rejected(self) -> None:
        """Test invalid semver is rejected."""
        with pytest.raises(ValueError, match="Invalid semantic version"):
            validate_semver("1.0")
