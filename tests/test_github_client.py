from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from ghgl_sync.github.client import GitHubClient
from ghgl_sync.github.errors import (
    AuthError,
    ClientError,
    NotFound,
    PermissionDenied,
    ProtocolError,
    RateLimited,
    TransientError,
)

from .conftest import BASE

URL = f"{BASE}/thing"
NOW = 1_000_000.0


class StaticAuth:
    identity = "static"

    def __init__(self) -> None:
        self.invalidations = 0

    def header_value(self) -> str:
        return "Bearer ghs_" + "s" * 30

    def invalidate(self) -> None:
        self.invalidations += 1


@pytest.fixture
def auth() -> StaticAuth:
    return StaticAuth()


def test_sends_auth_and_version_headers(client: GitHubClient, auth: StaticAuth) -> None:
    with respx.mock() as router:
        route = router.get(URL).mock(return_value=httpx.Response(200, json={}))
        client.request("GET", "/thing", auth=auth)
    sent = route.calls[0].request.headers
    assert sent["authorization"].startswith("Bearer ghs_")
    assert sent["x-github-api-version"] == "2022-11-28"


def test_pagination_follows_links_across_250_items(client: GitHubClient, auth: StaticAuth) -> None:
    items = [{"id": i} for i in range(250)]

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        per = int(request.url.params["per_page"])
        headers = {}
        if page * per < len(items):
            headers["Link"] = f'<{BASE}/thing?per_page={per}&page={page + 1}>; rel="next"'
        return httpx.Response(200, json=items[(page - 1) * per : page * per], headers=headers)

    with respx.mock() as router:
        router.get(URL).mock(side_effect=handler)
        got = list(client.paginate("/thing", auth=auth))
    assert [g["id"] for g in got] == list(range(250))


def test_pagination_refuses_foreign_origin_link(client: GitHubClient, auth: StaticAuth) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(URL).mock(
            return_value=httpx.Response(
                200,
                json=[{"id": 1}],
                headers={"Link": '<https://evil.example.com/steal>; rel="next"'},
            )
        )
        evil = router.get("https://evil.example.com/steal").mock(return_value=httpx.Response(200))
        with pytest.raises(ProtocolError, match="different origin"):
            list(client.paginate("/thing", auth=auth))
        assert not evil.called


def test_pagination_rejects_non_list_payload(client: GitHubClient, auth: StaticAuth) -> None:
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json={"oops": 1}))
        with pytest.raises(ProtocolError):
            list(client.paginate("/thing", auth=auth))


def test_primary_rate_limit_sleeps_until_reset(
    client: GitHubClient, auth: StaticAuth, sleeps: list[float]
) -> None:
    exhausted = httpx.Response(
        200,
        json={},
        headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(NOW) + 30)},
    )
    with respx.mock() as router:
        router.get(URL).mock(side_effect=[exhausted, httpx.Response(200, json={})])
        client.request("GET", "/thing", auth=auth)
        client.request("GET", "/thing", auth=auth)
    assert sleeps == [31.0]


def test_retry_after_header_is_honoured(
    client: GitHubClient, auth: StaticAuth, sleeps: list[float]
) -> None:
    with respx.mock() as router:
        router.get(URL).mock(
            side_effect=[
                httpx.Response(403, json={"message": "x"}, headers={"retry-after": "2"}),
                httpx.Response(200, json={}),
            ]
        )
        client.request("GET", "/thing", auth=auth)
    assert sleeps == [3.0]


def test_secondary_rate_limit_without_headers_backs_off(
    client: GitHubClient, auth: StaticAuth, sleeps: list[float]
) -> None:
    body = {"message": "You have exceeded a secondary rate limit."}
    with respx.mock() as router:
        router.get(URL).mock(side_effect=[httpx.Response(403, json=body), httpx.Response(200)])
        client.request("GET", "/thing", auth=auth)
    assert sleeps == [60.0]


def test_rate_limit_longer_than_cap_raises_for_requeue(auth: StaticAuth) -> None:
    c = GitHubClient(
        base_url=BASE,
        api_version="v",
        sleep=lambda _s: pytest.fail("must not sleep"),
        clock=lambda: NOW,
        max_rate_limit_wait=100,
    )
    reset = str(int(NOW) + 3600)
    with respx.mock() as router:
        router.get(URL).mock(
            return_value=httpx.Response(
                403, json={}, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": reset}
            )
        )
        with pytest.raises(RateLimited) as exc:
            c.request("GET", "/thing", auth=auth)
    assert exc.value.retry_after == pytest.approx(3601.0)
    assert exc.value.retryable


def test_plain_403_is_permission_error_and_not_retried(
    client: GitHubClient, auth: StaticAuth
) -> None:
    with respx.mock() as router:
        route = router.get(URL).mock(
            return_value=httpx.Response(403, json={"message": "Resource not accessible"})
        )
        with pytest.raises(PermissionDenied) as exc:
            client.request("GET", "/thing", auth=auth)
    assert route.call_count == 1
    assert not exc.value.retryable
    assert exc.value.classification == "permission"


def test_5xx_retries_with_exponential_backoff(
    client: GitHubClient, auth: StaticAuth, sleeps: list[float]
) -> None:
    with respx.mock() as router:
        router.get(URL).mock(
            side_effect=[httpx.Response(502), httpx.Response(503), httpx.Response(200, json={})]
        )
        client.request("GET", "/thing", auth=auth)
    assert sleeps == [1.0, 2.0]  # rng fixed at 1.0 -> full ceiling


def test_5xx_gives_up_after_max_attempts(
    client: GitHubClient, auth: StaticAuth, sleeps: list[float]
) -> None:
    with respx.mock() as router:
        route = router.get(URL).mock(return_value=httpx.Response(500))
        with pytest.raises(TransientError):
            client.request("GET", "/thing", auth=auth)
    assert route.call_count == 5
    assert len(sleeps) == 4


def _const(value: float) -> Callable[[], float]:
    return lambda: value


def test_jitter_stays_within_bounds() -> None:
    for r in (0.0, 0.5, 1.0):
        c = GitHubClient(base_url=BASE, api_version="v", rng=_const(r), backoff_base=4.0)
        assert 2.0 <= c._backoff(1) <= 4.0


def test_transport_errors_are_retried(
    client: GitHubClient, auth: StaticAuth, sleeps: list[float]
) -> None:
    with respx.mock() as router:
        router.get(URL).mock(side_effect=[httpx.ConnectError("down"), httpx.Response(200, json={})])
        client.request("GET", "/thing", auth=auth)
    assert len(sleeps) == 1


def test_401_invalidates_and_retries_once(client: GitHubClient, auth: StaticAuth) -> None:
    with respx.mock() as router:
        router.get(URL).mock(side_effect=[httpx.Response(401), httpx.Response(200, json={})])
        client.request("GET", "/thing", auth=auth)
    assert auth.invalidations == 1


def test_persistent_401_raises_auth_error(client: GitHubClient, auth: StaticAuth) -> None:
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(401, json={"message": "Bad credentials"}))
        with pytest.raises(AuthError) as exc:
            client.request("GET", "/thing", auth=auth)
    assert not exc.value.retryable


def test_404_and_client_error_messages_redact_secrets(
    client: GitHubClient, auth: StaticAuth
) -> None:
    token = "ghp_" + "L0ngT0kenValue" * 3
    with respx.mock() as router:
        router.get(URL).mock(
            side_effect=[
                httpx.Response(404),
                httpx.Response(422, json={"message": f"bad value {token}"}),
            ]
        )
        with pytest.raises(NotFound):
            client.request("GET", "/thing", auth=auth)
        with pytest.raises(ClientError) as exc:
            client.request("GET", "/thing", auth=auth)
    assert token not in str(exc.value)


def test_redirects_are_not_followed(client: GitHubClient, auth: StaticAuth) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get(URL).mock(
            return_value=httpx.Response(302, headers={"location": "https://evil.example.com/"})
        )
        evil = router.get("https://evil.example.com/").mock(return_value=httpx.Response(200))
        with pytest.raises(ProtocolError, match="redirect"):
            client.request("GET", "/thing", auth=auth)
        assert not evil.called


def test_rate_limit_state_is_exposed(client: GitHubClient, auth: StaticAuth) -> None:
    hdrs: dict[str, Any] = {
        "x-ratelimit-remaining": "4999",
        "x-ratelimit-limit": "5000",
        "x-ratelimit-reset": "1700000000",
    }
    with respx.mock() as router:
        router.get(URL).mock(return_value=httpx.Response(200, json={}, headers=hdrs))
        client.request("GET", "/thing", auth=auth)
    assert client.rate_limits["static"].remaining == 4999
    assert client.rate_limits["static"].limit == 5000
