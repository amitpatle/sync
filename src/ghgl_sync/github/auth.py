"""GitHub App authentication.

* App JWTs are short-lived (RS256, <=9 min) and minted on demand.
* Installation tokens are cached in memory only, refreshed before expiry, and can be
  requested with a *downscoped* permission set (discovery uses metadata:read only).
* Tokens are never logged; invalidation (token rotation/revocation) clears the cache.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import SecretStr

from ghgl_sync.github.errors import AuthError, ProtocolError

if TYPE_CHECKING:
    from ghgl_sync.github.client import GitHubClient

log = logging.getLogger(__name__)

DISCOVERY_PERMISSIONS: Mapping[str, str] = {"metadata": "read"}


@dataclass
class _CachedToken:
    token: SecretStr
    expires_epoch: float


class AppJwtAuth:
    identity = "app"

    def __init__(self, app: GitHubApp) -> None:
        self._app = app

    def header_value(self) -> str:
        return f"Bearer {self._app.mint_jwt()}"

    def invalidate(self) -> None:  # JWTs are minted fresh each request
        return None


class InstallationAuth:
    def __init__(
        self, app: GitHubApp, installation_id: int, permissions: Mapping[str, str] | None
    ) -> None:
        self._app = app
        self._installation_id = installation_id
        self._permissions = dict(permissions) if permissions else None
        self.identity = f"installation:{installation_id}"

    def header_value(self) -> str:
        token = self._app.installation_token(self._installation_id, self._permissions)
        return f"Bearer {token.get_secret_value()}"

    def invalidate(self) -> None:
        self._app.drop_cached_token(self._installation_id, self._permissions)


def _cache_key(installation_id: int, permissions: Mapping[str, str] | None) -> tuple[Any, ...]:
    return (installation_id, tuple(sorted((permissions or {}).items())))


class GitHubApp:
    def __init__(
        self,
        *,
        app_id: int,
        private_key: SecretStr,
        client: GitHubClient,
        clock: Callable[[], float] = time.time,
        refresh_margin_seconds: float = 300.0,
    ) -> None:
        self._app_id = app_id
        self._client = client
        self._clock = clock
        self._margin = refresh_margin_seconds
        self._cache: dict[tuple[Any, ...], _CachedToken] = {}
        try:
            key = serialization.load_pem_private_key(
                private_key.get_secret_value().encode(), password=None
            )
        except (ValueError, TypeError) as exc:
            # Never include exception text: it can echo key material fragments.
            raise AuthError("GitHub App private key is not a valid unencrypted PEM key") from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise AuthError("GitHub App private key must be an RSA key")
        self._key = key

    def mint_jwt(self) -> str:
        now = int(self._clock())
        payload = {"iat": now - 60, "exp": now + 540, "iss": str(self._app_id)}
        return jwt.encode(payload, self._key, algorithm="RS256")

    def jwt_auth(self) -> AppJwtAuth:
        return AppJwtAuth(self)

    def installation_auth(
        self, installation_id: int, permissions: Mapping[str, str] | None = None
    ) -> InstallationAuth:
        return InstallationAuth(self, installation_id, permissions)

    def drop_cached_token(
        self, installation_id: int, permissions: Mapping[str, str] | None
    ) -> None:
        self._cache.pop(_cache_key(installation_id, permissions), None)

    def installation_token(
        self, installation_id: int, permissions: Mapping[str, str] | None = None
    ) -> SecretStr:
        key = _cache_key(installation_id, permissions)
        cached = self._cache.get(key)
        if cached and cached.expires_epoch - self._clock() > self._margin:
            return cached.token
        body = {"permissions": dict(permissions)} if permissions else None
        resp = self._client.request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            auth=self.jwt_auth(),
            json=body,
        )
        try:
            data = resp.json()
            token = SecretStr(str(data["token"]))
            expires = datetime.fromisoformat(str(data["expires_at"]).replace("Z", "+00:00"))
        except (ValueError, KeyError, TypeError) as exc:
            raise ProtocolError("malformed installation token response") from exc
        self._cache[key] = _CachedToken(token, expires.timestamp())
        log.info("installation token issued", extra={"installation_id": installation_id})
        return token
