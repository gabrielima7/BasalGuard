"""Network Guard — SSRF protection for AI agent HTTP requests.

This module prevents Server-Side Request Forgery (SSRF) by validating
URLs *before* any HTTP request is made.  It resolves the hostname to
an IP address and blocks all private/reserved ranges (RFC 1918,
loopback, link-local, etc.) using the stdlib ``ipaddress`` module.

Usage::

    from basalguard.security.network import validate_url

    safe = validate_url("https://example.com")       # ✅ OK
    bad  = validate_url("http://192.168.1.1/admin")  # 💥 SecurityError

"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

from taipanstack.security.guards import SecurityError

logger = logging.getLogger("basalguard.network")


class NetworkSecurityError(SecurityError):
    """Deprecated: Use SecurityError instead.
    Raised when a URL points to a blocked network destination.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, guard_name="network_guard")


# ── Schemes we allow ─────────────────────────────────────────────────
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def validate_url(
    url: str,
    *,
    allowed_domains: list[str] | None = None,
) -> str:
    """Validate a URL for safe external access.

    Steps:
        1. Parse the URL and check the scheme (http/https only).
        2. Extract the hostname and resolve it via DNS.
        3. Check every resolved IP — if **any** is private/reserved,
           the request is blocked.
        4. Optionally enforce a domain allowlist.

    Args:
        url: The raw URL string to validate.
        allowed_domains: If provided, only these domains are allowed.
                         Case-insensitive comparison.

    Returns:
        The original URL string (unmodified) if it passes validation.

    Raises:
        SecurityError: If the URL is unsafe (private IP, bad
            scheme, blocked domain, unresolvable hostname, etc.).

    """
    # ── 1. Parse ─────────────────────────────────────────────────────
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SecurityError(
            f"Malformed URL: {url}", guard_name="network_guard", value=url
        ) from exc

    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise SecurityError(
            f"Blocked scheme '{parsed.scheme}'. Allowed: {sorted(_ALLOWED_SCHEMES)}",
            guard_name="network_guard",
            value=parsed.scheme,
        )

    hostname = parsed.hostname
    if not hostname:
        raise SecurityError(
            f"No hostname in URL: {url}", guard_name="network_guard", value=url
        )

    # ── 2. Domain allowlist (optional) ───────────────────────────────
    if allowed_domains is not None:
        normalised = [d.lower().strip() for d in allowed_domains]
        if hostname.lower() not in normalised:
            raise SecurityError(
                f"Domain '{hostname}' not in allowed list: {normalised}",
                guard_name="network_guard",
                value=hostname,
            )

    # ── 3. Check if hostname is already a raw IP ─────────────────────
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_reserved or addr.is_loopback:
            raise SecurityError(
                f"Blocked private/reserved IP: {addr}",
                guard_name="network_guard",
                value=str(addr),
            )
        logger.debug("URL %s points to public IP %s — allowed", url, addr)
        return url
    except ValueError:
        pass  # Not a raw IP — it's a hostname, resolve via DNS below.

    # ── 4. DNS resolution ────────────────────────────────────────────
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
    except socket.gaierror as exc:
        raise SecurityError(
            f"DNS resolution failed for '{hostname}': {exc}",
            guard_name="network_guard",
            value=hostname,
        ) from exc

    if not infos:
        raise SecurityError(
            f"DNS returned no results for '{hostname}'",
            guard_name="network_guard",
            value=hostname,
        )

    for family, _type, _proto, _canonname, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if addr.is_private or addr.is_reserved or addr.is_loopback:
            raise SecurityError(
                f"Domain '{hostname}' resolves to private/reserved IP "
                f"{addr} — SSRF blocked",
                guard_name="network_guard",
                value=str(addr),
            )

    logger.debug("URL %s validated — all IPs public", url)
    return url
