"""URL validation: SSRF defense for configured endpoints and server-provided links.

Limitation (documented in docs/THREAT_MODEL.md): this validates literal hosts and
numeric forms only. It does not resolve DNS, so DNS-rebinding to internal addresses
must be mitigated with network egress controls.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


class UnsafeUrlError(ValueError):
    """Raised when a URL fails validation."""


_NUMERIC_LABEL = re.compile(r"0[xX][0-9a-fA-F]+|[0-9]+")


def _blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def check_public_host(host: str) -> None:
    """Reject loopback/private/link-local literals, localhost names and ambiguous numeric hosts."""
    lowered = host.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(".localhost"):
        raise UnsafeUrlError("host resolves to loopback")
    try:
        ip = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        labels = lowered.split(".")
        if all(_NUMERIC_LABEL.fullmatch(label) for label in labels):
            raise UnsafeUrlError("ambiguous numeric host") from None
        return
    if _blocked_ip(ip):
        raise UnsafeUrlError("host is a non-public IP address")


def validate_base_url(
    url: str, *, allow_http: bool = False, allow_private_hosts: bool = False
) -> str:
    """Validate and normalize a configured endpoint. Returns the URL without a trailing slash."""
    parts = urlsplit(url)
    allowed = {"https", "http"} if allow_http else {"https"}
    if parts.scheme not in allowed:
        raise UnsafeUrlError(f"scheme must be one of {sorted(allowed)}")
    if parts.username or parts.password:
        raise UnsafeUrlError("credentials in URLs are not allowed")
    if not parts.hostname:
        raise UnsafeUrlError("URL has no host")
    if parts.query or parts.fragment:
        raise UnsafeUrlError("query strings and fragments are not allowed")
    if not allow_private_hosts:
        check_public_host(parts.hostname)
    return url.rstrip("/")


def _origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return (p.scheme, (p.hostname or "").lower(), port)


def same_origin(a: str, b: str) -> bool:
    return _origin(a) == _origin(b)
