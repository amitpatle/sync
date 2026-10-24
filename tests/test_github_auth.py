from __future__ import annotations

import json

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import SecretStr

from ghgl_sync.github.auth import DISCOVERY_PERMISSIONS, GitHubApp
from ghgl_sync.github.client import GitHubClient
from ghgl_sync.github.errors import AuthError, ProtocolError

from .conftest import BASE

TOKEN_URL = f"{BASE}/app/installations/42/access_tokens"


def _token_response(n: int, expires: str = "2099-01-01T00:00:00Z") -> httpx.Response:
    return httpx.Response(201, json={"token": f"ghs_{n}_{'t' * 30}", "expires_at": expires})


def test_jwt_claims_and_signature(app: GitHubApp, rsa_key: rsa.RSAPrivateKey) -> None:
    token = app.mint_jwt()
    claims = jwt.decode(token, rsa_key.public_key(), algorithms=["RS256"])
    assert claims["iss"] == "123"
    assert claims["exp"] - claims["iat"] <= 600  # GitHub's 10 minute maximum


def test_installation_token_is_cached_and_downscoped(app: GitHubApp) -> None:
    with respx.mock() as router:
        route = router.post(TOKEN_URL).mock(side_effect=[_token_response(1), _token_response(2)])
        auth = app.installation_auth(42, DISCOVERY_PERMISSIONS)
        h1, h2 = auth.header_value(), auth.header_value()
    assert h1 == h2
    assert route.call_count == 1
    assert json.loads(route.calls[0].request.content) == {"permissions": {"metadata": "read"}}
    assert route.calls[0].request.headers["authorization"].startswith("Bearer eyJ")  # app JWT


def test_token_refreshed_before_expiry(client: GitHubClient, rsa_pem: str) -> None:
    now = [1_000.0]
    app = GitHubApp(app_id=1, private_key=SecretStr(rsa_pem), client=client, clock=lambda: now[0])
    soon = "1970-01-01T00:20:00Z"  # epoch 1200
    with respx.mock() as router:
        route = router.post(TOKEN_URL).mock(
            side_effect=[_token_response(1, soon), _token_response(2)]
        )
        app.installation_token(42)
        now[0] = 1_100.0  # 100s left < 300s margin -> refresh
        second = app.installation_token(42)
    assert route.call_count == 2
    assert "ghs_2_" in second.get_secret_value()


def test_invalidate_forces_new_token(app: GitHubApp) -> None:
    with respx.mock() as router:
        route = router.post(TOKEN_URL).mock(side_effect=[_token_response(1), _token_response(2)])
        auth = app.installation_auth(42)
        auth.header_value()
        auth.invalidate()
        auth.header_value()
    assert route.call_count == 2


def test_different_permission_sets_are_cached_separately(app: GitHubApp) -> None:
    with respx.mock() as router:
        route = router.post(TOKEN_URL).mock(side_effect=[_token_response(1), _token_response(2)])
        app.installation_token(42, {"metadata": "read"})
        app.installation_token(42, {"contents": "read"})
    assert route.call_count == 2


def test_invalid_key_error_leaks_nothing(client: GitHubClient) -> None:
    junk = "-----BEGIN PRIVATE KEY-----\nSECRETFRAGMENT123\n-----END PRIVATE KEY-----"
    with pytest.raises(AuthError) as exc:
        GitHubApp(app_id=1, private_key=SecretStr(junk), client=client)
    assert "SECRETFRAGMENT" not in str(exc.value)
    assert "SECRETFRAGMENT" not in repr(exc.value.__cause__)


def test_non_rsa_key_rejected(client: GitHubClient) -> None:
    pem = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    with pytest.raises(AuthError, match="RSA"):
        GitHubApp(app_id=1, private_key=SecretStr(pem), client=client)


def test_malformed_token_response(app: GitHubApp) -> None:
    with respx.mock() as router:
        router.post(TOKEN_URL).mock(return_value=httpx.Response(201, json={"nope": 1}))
        with pytest.raises(ProtocolError):
            app.installation_token(42)


def test_token_never_in_secretstr_repr(app: GitHubApp) -> None:
    with respx.mock() as router:
        router.post(TOKEN_URL).mock(return_value=_token_response(7))
        tok = app.installation_token(42)
    assert "ghs_7" not in repr(tok)
    assert "ghs_7" not in str(tok)
