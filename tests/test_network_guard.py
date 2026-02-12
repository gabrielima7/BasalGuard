"""Unit tests for the Network Guard (SSRF protection).

Covers:
    - URL validation (scheme, DNS, IP blocking)
    - Private/reserved IP blocking (127.x, 10.x, 192.168.x, 0.0.0.0, ::1)
    - Domain allowlist enforcement
    - Integration with BasalGuardCore.safe_web_request
    - HTTP method restriction
"""

from __future__ import annotations

from pathlib import Path

import pytest

from basalguard.security.network import validate_url
from taipanstack.security.guards import SecurityError
from basalguard.core.agent_firewall import BasalGuardCore

# Alias for compatibility with existing tests structure if needed,
# or just replace usages.
NetworkSecurityError = SecurityError


# ── validate_url — scheme checks ────────────────────────────────────


class TestValidateUrlScheme:
    """Only http and https schemes are allowed."""

    def test_blocks_ftp(self) -> None:
        with pytest.raises(NetworkSecurityError, match="Blocked scheme"):
            validate_url("ftp://example.com/file.txt")

    def test_blocks_file(self) -> None:
        with pytest.raises(NetworkSecurityError, match="Blocked scheme"):
            validate_url("file:///etc/passwd")

    def test_blocks_empty_url(self) -> None:
        with pytest.raises(NetworkSecurityError):
            validate_url("")


# ── validate_url — private IP blocking ──────────────────────────────


class TestValidateUrlPrivateIPs:
    """Direct IP-address URLs pointing to private ranges are blocked."""

    def test_blocks_localhost_127(self) -> None:
        with pytest.raises(NetworkSecurityError, match="private"):
            validate_url("http://127.0.0.1/admin")

    def test_blocks_localhost_name(self) -> None:
        """localhost resolves to 127.0.0.1 — must be blocked."""
        with pytest.raises(NetworkSecurityError):
            validate_url("http://localhost/")

    def test_blocks_private_192(self) -> None:
        with pytest.raises(NetworkSecurityError, match="private"):
            validate_url("http://192.168.1.1/")

    def test_blocks_private_10(self) -> None:
        with pytest.raises(NetworkSecurityError, match="private"):
            validate_url("http://10.0.0.1/internal")

    def test_blocks_private_172(self) -> None:
        with pytest.raises(NetworkSecurityError, match="private"):
            validate_url("http://172.16.0.1/")

    def test_blocks_zero_ip(self) -> None:
        with pytest.raises(NetworkSecurityError):
            validate_url("http://0.0.0.0/")

    def test_blocks_ipv6_loopback(self) -> None:
        with pytest.raises(NetworkSecurityError):
            validate_url("http://[::1]/")


# ── validate_url — public URLs pass ─────────────────────────────────


class TestValidateUrlPublic:
    """Public IPs and well-known domains should pass validation."""

    def test_public_ip_passes(self) -> None:
        """A known public IP should pass."""
        result = validate_url("https://8.8.8.8/")
        assert result == "https://8.8.8.8/"

    def test_public_domain_passes(self) -> None:
        """google.com resolves to public IPs — should pass."""
        result = validate_url("https://www.google.com/")
        assert result == "https://www.google.com/"


# ── validate_url — domain allowlist ─────────────────────────────────


class TestValidateUrlAllowlist:
    """Optional domain allowlist restricts which domains can be accessed."""

    def test_allowed_domain_passes(self) -> None:
        result = validate_url(
            "https://www.google.com/",
            allowed_domains=["www.google.com", "api.github.com"],
        )
        assert "google.com" in result

    def test_blocked_domain_outside_allowlist(self) -> None:
        with pytest.raises(NetworkSecurityError, match="not in allowed"):
            validate_url(
                "https://evil-site.com/",
                allowed_domains=["www.google.com"],
            )


# ── BasalGuardCore.safe_web_request integration ─────────────────────


@pytest.fixture
def firewall(tmp_path: Path) -> BasalGuardCore:
    """Return a BasalGuardCore instance with a temp workspace."""
    return BasalGuardCore(tmp_path / "ws")


class TestSafeWebRequest:
    """Integration tests for safe_web_request via the firewall."""

    def test_blocks_private_ip_via_core(self, firewall: BasalGuardCore) -> None:
        """safe_web_request returns 'blocked' for private IPs."""
        result = firewall.safe_web_request("http://192.168.1.1/admin")
        assert result["status"] == "blocked"
        assert "192.168.1.1" in result["violator"]

    def test_blocks_localhost_via_core(self, firewall: BasalGuardCore) -> None:
        result = firewall.safe_web_request("http://127.0.0.1:8080/api")
        assert result["status"] == "blocked"

    def test_blocks_post_method(self, firewall: BasalGuardCore) -> None:
        """Only GET and HEAD methods are allowed."""
        result = firewall.safe_web_request("https://example.com", method="POST")
        assert result["status"] == "blocked"
        assert "POST" in result["reason"]

    def test_blocks_delete_method(self, firewall: BasalGuardCore) -> None:
        result = firewall.safe_web_request("https://example.com", method="DELETE")
        assert result["status"] == "blocked"

    def test_validate_intent_routes_web_request(self, firewall: BasalGuardCore) -> None:
        """validate_intent dispatches web_request to safe_web_request."""
        result = firewall.validate_intent(
            "web_request",
            {"url": "http://10.0.0.1/secret"},
        )
        assert result["status"] == "blocked"

    def test_validate_intent_missing_url(self, firewall: BasalGuardCore) -> None:
        result = firewall.validate_intent("web_request", {})
        assert result["status"] == "error"
        assert "url" in result["reason"].lower()

    def test_public_url_success(self, firewall: BasalGuardCore) -> None:
        """A public URL should succeed (actual HTTP call to example.com)."""
        result = firewall.safe_web_request("https://www.example.com/")
        assert result["status"] == "success"
        assert result["status_code"] == 200
        assert "Example Domain" in result["content"]
