"""GitHub REST client: retries with jittered backoff, primary/secondary rate-limit handling,
origin-checked pagination. Tokens are only ever placed in the Authorization header."""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from ghgl_sync.github.errors import (
    AuthError,
    ClientError,
    Gone,
    NotFound,
    PermissionDenied,
    ProtocolError,
    RateLimited,
    TransientError,
)
from ghgl_sync.security.redaction import redact_text
from ghgl_sync.security.urls import same_origin

log = logging.getLogger(__name__)


class Authenticator(Protocol):
    identity: str

    def header_value(self) -> str: ...

    def invalidate(self) -> None: ...


@dataclass
class RateLimitState:
    remaining: int | None = None
    reset_epoch: float | None = None
    limit: int | None = None


class GitHubClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_version: str,
        timeout: float = 30.0,
        http: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
        rng: Callable[[], float] = random.random,
        max_attempts: int = 5,
        backoff_base: float = 1.0,
        backoff_cap: float = 60.0,
        max_rate_limit_wait: float = 900.0,
        per_page: int = 100,
        max_pages: int = 10_000,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._api_version = api_version
        self._timeout = timeout
        self._http = http or httpx.Client(follow_redirects=False)
        self._sleep = sleep
        self._clock = clock
        self._rng = rng
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap
        self._max_rate_limit_wait = max_rate_limit_wait
        self._per_page = per_page
        self._max_pages = max_pages
        self.rate_limits: dict[str, RateLimitState] = {}
        self.request_count = 0

    @property
    def base_url(self) -> str:
        return self._base

    def close(self) -> None:
        self._http.close()

    # -- URL handling ----------------------------------------------------------------
    def _resolve(self, url: str) -> str:
        if url.startswith(("http://", "https://")):
            if not same_origin(url, self._base):
                raise ProtocolError("refusing to follow a URL on a different origin")
            return url
        return f"{self._base}/{url.lstrip('/')}"

    # -- backoff / rate limiting -----------------------------------------------------
    def _backoff(self, attempt: int) -> float:
        ceiling = min(self._backoff_cap, self._backoff_base * (2 ** (attempt - 1)))
        return float(ceiling * (0.5 + self._rng() / 2))  # "equal jitter"

    def _record_rate_limit(self, identity: str, resp: httpx.Response) -> None:
        h = resp.headers
        state = self.rate_limits.setdefault(identity, RateLimitState())
        try:
            if "x-ratelimit-remaining" in h:
                state.remaining = int(h["x-ratelimit-remaining"])
            if "x-ratelimit-reset" in h:
                state.reset_epoch = float(h["x-ratelimit-reset"])
            if "x-ratelimit-limit" in h:
                state.limit = int(h["x-ratelimit-limit"])
        except ValueError:
            log.warning("malformed rate limit headers", extra={"identity": identity})

    def _respect_rate_limit(self, identity: str) -> None:
        state = self.rate_limits.get(identity)
        if not state or state.remaining is None or state.reset_epoch is None:
            return
        if state.remaining > 0:
            return
        wait = state.reset_epoch - self._clock() + 1.0
        if wait <= 0:
            state.remaining = None
            return
        if wait > self._max_rate_limit_wait:
            raise RateLimited("primary rate limit exhausted; reset is too far away", wait)
        log.info("primary rate limit exhausted; sleeping", extra={"wait_seconds": round(wait, 1)})
        self._sleep(wait)
        state.remaining = None

    def _rate_limit_wait(self, resp: httpx.Response) -> float | None:  # noqa: PLR0911
        """Seconds to wait if this 403/429 is a rate limit, else None (a plain permission error)."""
        h = resp.headers
        if "retry-after" in h:
            try:
                return float(h["retry-after"]) + 1.0
            except ValueError:
                return 60.0
        if h.get("x-ratelimit-remaining") == "0" and "x-ratelimit-reset" in h:
            try:
                return max(0.0, float(h["x-ratelimit-reset"]) - self._clock()) + 1.0
            except ValueError:
                return 60.0
        message = ""
        try:
            body = resp.json()
            if isinstance(body, dict):
                message = str(body.get("message", ""))
        except ValueError:
            pass
        if "rate limit" in message.lower():
            return 60.0  # secondary limit without Retry-After: conservative default
        if resp.status_code == 429:
            return 60.0
        return None

    @staticmethod
    def _safe_message(resp: httpx.Response) -> str:
        try:
            body = resp.json()
            if isinstance(body, dict) and "message" in body:
                return redact_text(str(body["message"]))[:200]
        except ValueError:
            pass
        return ""

    # -- core request ----------------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        auth: Authenticator,
        params: Mapping[str, Any] | None = None,
        json: Mapping[str, Any] | None = None,
    ) -> httpx.Response:
        full = self._resolve(url)
        attempt = 0
        refreshed = False
        while True:
            attempt += 1
            self._respect_rate_limit(auth.identity)
            headers = {
                "Authorization": auth.header_value(),
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": self._api_version,
                "User-Agent": "ghgl-sync",
            }
            try:
                self.request_count += 1
                resp = self._http.request(
                    method, full, headers=headers, params=params, json=json, timeout=self._timeout
                )
            except httpx.TransportError as exc:
                if attempt >= self._max_attempts:
                    raise TransientError(f"{method} {url}: {type(exc).__name__}") from exc
                self._sleep(self._backoff(attempt))
                continue

            self._record_rate_limit(auth.identity, resp)
            status = resp.status_code
            if status < 300:
                return resp
            where = f"{method} {url} -> {status}"
            if status < 400:
                # Redirects are never followed (the target could be a foreign origin).
                # Callers address repositories by immutable ID, so GitHub should not redirect.
                raise ProtocolError(f"{where}: unexpected redirect")
            if status == 401:
                if not refreshed:
                    refreshed = True
                    auth.invalidate()
                    continue
                raise AuthError(f"{where}: credentials rejected")
            if status in (403, 429):
                wait = self._rate_limit_wait(resp)
                if wait is None:
                    raise PermissionDenied(f"{where}: {self._safe_message(resp)}")
                if wait > self._max_rate_limit_wait or attempt >= self._max_attempts:
                    raise RateLimited(f"{where}: rate limited", wait)
                self._sleep(wait)
                continue
            if status == 404:
                raise NotFound(where)
            if status == 410:
                raise Gone(where)
            if status >= 500:
                if attempt >= self._max_attempts:
                    raise TransientError(where)
                self._sleep(self._backoff(attempt))
                continue
            raise ClientError(f"{where}: {self._safe_message(resp)}")

    # -- pagination ------------------------------------------------------------------
    def paginate(
        self,
        path: str,
        *,
        auth: Authenticator,
        params: Mapping[str, Any] | None = None,
        items_key: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield every item across pages, following Link rel=next on the same origin only."""
        url: str | None = path
        query: Mapping[str, Any] | None = {"per_page": self._per_page, **(params or {})}
        pages = 0
        while url:
            pages += 1
            if pages > self._max_pages:
                raise ProtocolError("pagination exceeded max_pages")
            resp = self.request("GET", url, auth=auth, params=query)
            try:
                data = resp.json()
            except ValueError as exc:
                raise ProtocolError(f"GET {path}: response is not JSON") from exc
            items = data.get(items_key) if items_key and isinstance(data, dict) else data
            if not isinstance(items, list):
                raise ProtocolError(f"GET {path}: expected a JSON list of items")
            for item in items:
                if not isinstance(item, dict):
                    raise ProtocolError(f"GET {path}: item is not an object")
                yield item
            url = resp.links.get("next", {}).get("url")
            query = None  # the next URL already carries its query string
