"""
Input validators for type-safe validation.

Provides validation functions for common input types like email,
project names, URLs, etc. All validators raise ValueError on invalid input.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Literal
from urllib.parse import urlparse

# Constants to avoid magic values (PLR2004)
PYTHON_MAJOR_VERSION = 3
MIN_PYTHON_MINOR_VERSION = 10
MAX_EMAIL_LOCAL_LENGTH = 64
MAX_EMAIL_DOMAIN_LENGTH = 255
MAX_PORT_NUMBER = 65535
MIN_PRIVILEGED_PORT = 1024
LOCALHOST_DOMAINS = ("localhost", "127.0.0.1", "::1")


def validate_project_name(
    name: str,
    *,
    max_length: int = 100,
    allow_hyphen: bool = True,
    allow_underscore: bool = True,
) -> str:
    """Validate a project name.

    Args:
        name: The project name to validate.
        max_length: Maximum allowed length.
        allow_hyphen: Allow hyphens in name.
        allow_underscore: Allow underscores in name.

    Returns:
        The validated project name.

    Raises:
        ValueError: If the name is invalid.

    Example:
        >>> validate_project_name("my_project")
        'my_project'
        >>> validate_project_name("123project")
        ValueError: Project name must start with a letter

    """
    if not name:
        msg = "Project name cannot be empty"
        raise ValueError(msg)

    if len(name) > max_length:
        msg = f"Project name exceeds maximum length of {max_length}"
        raise ValueError(msg)

    # Build allowed characters
    allowed = r"a-zA-Z0-9"
    if allow_hyphen:
        allowed += r"-"
    if allow_underscore:
        allowed += r"_"

    pattern = f"^[a-zA-Z][{allowed}]*$"

    if not re.match(pattern, name):
        if not name[0].isalpha():
            msg = "Project name must start with a letter"
            raise ValueError(msg)
        hyphen_msg = ", hyphens" if allow_hyphen else ""
        underscore_msg = ", underscores" if allow_underscore else ""
        msg = (
            f"Project name contains invalid characters. "
            f"Allowed: letters, numbers{hyphen_msg}{underscore_msg}"
        )
        raise ValueError(msg)

    # Check for reserved names
    reserved = {
        "test",
        "tests",
        "src",
        "lib",
        "bin",
        "build",
        "dist",
        "setup",
        "config",
        "settings",
        "core",
        "main",
        "app",
        "site-packages",
    }

    if name.lower() in reserved:
        msg = f"Project name '{name}' is reserved"
        raise ValueError(msg)

    return name


def validate_python_version(version: str) -> str:
    """Validate Python version string.

    Args:
        version: Version string like "3.12" or "3.10".

    Returns:
        The validated version string.

    Raises:
        ValueError: If version format is invalid or unsupported.

    """
    pattern = r"^\d+\.\d+$"

    if not re.match(pattern, version):
        msg = f"Invalid version format: '{version}'. Use 'X.Y' format (e.g., '3.12')"
        raise ValueError(msg)

    try:
        major, minor = map(int, version.split("."))
    except ValueError as e:
        msg = f"Invalid version numbers in '{version}'"
        raise ValueError(msg) from e

    if major != PYTHON_MAJOR_VERSION:
        msg = f"Only Python 3.x is supported, got {major}.x"
        raise ValueError(msg)

    if minor < MIN_PYTHON_MINOR_VERSION:
        msg = (
            f"Python 3.{minor} is not supported. "
            f"Minimum is 3.{MIN_PYTHON_MINOR_VERSION}"
        )
        raise ValueError(msg)

    return version


def validate_email(email: str) -> str:
    """Validate email address format.

    Uses a reasonable regex pattern that covers most valid emails
    without being overly strict.

    Args:
        email: The email address to validate.

    Returns:
        The validated email address.

    Raises:
        ValueError: If email format is invalid.

    """
    if not email:
        msg = "Email cannot be empty"
        raise ValueError(msg)

    # RFC 5322 compliant pattern (simplified)
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if not re.match(pattern, email):
        msg = f"Invalid email format: {email}"
        raise ValueError(msg)

    # Additional checks
    local, domain = email.rsplit("@", 1)

    if len(local) > MAX_EMAIL_LOCAL_LENGTH:
        msg = f"Email local part exceeds {MAX_EMAIL_LOCAL_LENGTH} characters"
        raise ValueError(msg)

    if len(domain) > MAX_EMAIL_DOMAIN_LENGTH:
        msg = f"Email domain exceeds {MAX_EMAIL_DOMAIN_LENGTH} characters"
        raise ValueError(msg)

    return email


def validate_url(
    url: str,
    *,
    allowed_schemes: tuple[str, ...] = ("http", "https"),
    require_tld: bool = True,
) -> str:
    """Validate URL format and scheme.

    Args:
        url: The URL to validate.
        allowed_schemes: Tuple of allowed URL schemes.
        require_tld: Whether to require a TLD in the domain.

    Returns:
        The validated URL.

    Raises:
        ValueError: If URL format is invalid.

    """
    if not url:
        msg = "URL cannot be empty"
        raise ValueError(msg)

    try:
        parsed = urlparse(url)
    except ValueError as e:
        msg = f"Invalid URL format: {e}"
        raise ValueError(msg) from e

    if not parsed.scheme:
        msg = "URL must have a scheme (e.g., https://)"
        raise ValueError(msg)

    if parsed.scheme not in allowed_schemes:
        msg = f"URL scheme '{parsed.scheme}' is not allowed. Allowed: {allowed_schemes}"
        raise ValueError(msg)

    if not parsed.netloc:
        msg = "URL must have a domain"
        raise ValueError(msg)

    if require_tld:
        # Check for TLD (at least one dot)
        domain = parsed.netloc.split(":")[0]  # Remove port if present
        has_no_tld = "." not in domain or domain.endswith(".")
        is_localhost = domain.lower() in LOCALHOST_DOMAINS
        if has_no_tld and not is_localhost:
            msg = f"URL domain must have a TLD: {domain}"
            raise ValueError(msg)

    return url


def validate_ip_address(
    ip: str,
    *,
    version: Literal["v4", "v6", "any"] = "any",
    allow_private: bool = True,
) -> IPv4Address | IPv6Address:
    """Validate IP address.

    Args:
        ip: The IP address string to validate.
        version: IP version to allow ('v4', 'v6', or 'any').
        allow_private: Whether to allow private/internal IPs.

    Returns:
        The validated IP address object.

    Raises:
        ValueError: If IP address is invalid.

    """
    try:
        addr = ip_address(ip)
    except ValueError as e:
        msg = f"Invalid IP address: {ip}"
        raise ValueError(msg) from e

    if version == "v4" and not isinstance(addr, IPv4Address):
        msg = f"Expected IPv4 address, got IPv6: {ip}"
        raise ValueError(msg)

    if version == "v6" and not isinstance(addr, IPv6Address):
        msg = f"Expected IPv6 address, got IPv4: {ip}"
        raise ValueError(msg)

    if not allow_private and addr.is_private:
        msg = f"Private IP addresses are not allowed: {ip}"
        raise ValueError(msg)

    return addr


def validate_port(
    port: int | str,
    *,
    allow_privileged: bool = False,
) -> int:
    """Validate port number.

    Args:
        port: The port number to validate.
        allow_privileged: Whether to allow ports below 1024.

    Returns:
        The validated port number.

    Raises:
        ValueError: If port is invalid.

    """
    try:
        port_int = int(port)
    except ValueError as e:
        msg = f"Invalid port number: {port}"
        raise ValueError(msg) from e

    if port_int < 0 or port_int > MAX_PORT_NUMBER:
        msg = f"Port must be between 0 and {MAX_PORT_NUMBER}: {port_int}"
        raise ValueError(msg)

    if not allow_privileged and port_int < MIN_PRIVILEGED_PORT:
        msg = f"Privileged ports (< {MIN_PRIVILEGED_PORT}) are not allowed: {port_int}"
        raise ValueError(msg)

    return port_int


def validate_semver(version: str) -> tuple[int, int, int]:
    """Validate semantic version string.

    Args:
        version: Version string like "1.2.3" or "v1.2.3".

    Returns:
        Tuple of (major, minor, patch).

    Raises:
        ValueError: If version format is invalid.

    """
    # Remove leading 'v' if present
    version = version.lstrip("vV")

    pattern = r"^(\d+)\.(\d+)\.(\d+)(?:-[a-zA-Z0-9.]+)?(?:\+[a-zA-Z0-9.]+)?$"
    match = re.match(pattern, version)

    if not match:
        msg = f"Invalid semantic version: {version}. Expected format: X.Y.Z"
        raise ValueError(msg)

    major, minor, patch = map(int, match.groups()[:3])

    return major, minor, patch
