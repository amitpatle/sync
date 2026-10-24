from __future__ import annotations

import pytest

from ghgl_sync.security.urls import UnsafeUrlError, same_origin, validate_base_url


def test_accepts_public_https_and_strips_slash() -> None:
    assert validate_base_url("https://api.github.com/") == "https://api.github.com"
    assert validate_base_url("https://ghe.example.com/api/v3") == "https://ghe.example.com/api/v3"


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com",  # plain http
        "https://user:pw@api.github.com",  # credentials
        "https://api.github.com?x=1",  # query
        "https://api.github.com#frag",
        "ftp://example.com",
        "https:///nohost",
        "https://localhost",
        "https://foo.localhost",
        "https://127.0.0.1",
        "https://10.1.2.3",
        "https://192.168.0.1",
        "https://169.254.169.254",  # cloud metadata
        "https://[::1]",
        "https://[::ffff:127.0.0.1]",
        "https://2130706433",  # decimal form of 127.0.0.1
        "https://0x7f.0.0.1",
        "https://0.0.0.0",
    ],
)
def test_rejects_unsafe(url: str) -> None:
    with pytest.raises(UnsafeUrlError):
        validate_base_url(url)


def test_private_hosts_allowed_only_when_opted_in() -> None:
    assert validate_base_url("https://10.0.0.5/api/v3", allow_private_hosts=True)
    assert validate_base_url("http://localhost:8080", allow_http=True, allow_private_hosts=True)


def test_same_origin() -> None:
    assert same_origin("https://api.github.com/a", "https://API.github.com:443/b")
    assert not same_origin("https://api.github.com", "https://evil.example.com")
    assert not same_origin("https://api.github.com", "http://api.github.com")
    assert not same_origin("https://api.github.com", "https://api.github.com:8443")
