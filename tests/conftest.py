"""Shared fixtures: disposable Postgres schema, RSA key, and a fake GitHub API (respx)."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from typing import Any

import httpx
import psycopg
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from psycopg.rows import dict_row
from pydantic import SecretStr

from ghgl_sync.config import Settings
from ghgl_sync.db.connection import Connection
from ghgl_sync.db.migrate import migrate
from ghgl_sync.github.auth import GitHubApp
from ghgl_sync.github.client import GitHubClient

TEST_DB = os.environ.get(
    "GHGL_TEST_DATABASE_URL", "postgresql://postgres@/ghgl_test?host=/tmp&port=5433"
)
BASE = "https://api.github.com"


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_pem(rsa_key: rsa.RSAPrivateKey) -> str:
    return rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def conn() -> Iterator[Connection]:
    c: Connection = psycopg.connect(TEST_DB, row_factory=dict_row)
    c.execute("DROP SCHEMA public CASCADE")
    c.execute("CREATE SCHEMA public")
    c.commit()
    migrate(c)
    yield c
    c.rollback()
    c.close()


def make_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "database_url": SecretStr(TEST_DB),
        "github_app_id": 123,
        "_env_file": None,
    }
    base.update(overrides)
    return Settings(**base)


def make_repo(
    repo_id: int,
    full_name: str,
    *,
    private: bool = True,
    visibility: str | None = None,
    archived: bool = False,
    fork: bool = False,
    disabled: bool = False,
    owner_type: str = "User",
    default_branch: str = "main",
) -> dict[str, Any]:
    owner, name = full_name.split("/")
    return {
        "id": repo_id,
        "node_id": f"R_{repo_id}",
        "name": name,
        "full_name": full_name,
        "private": private,
        "visibility": visibility or ("private" if private else "public"),
        "owner": {"login": owner, "type": owner_type},
        "archived": archived,
        "fork": fork,
        "disabled": disabled,
        "default_branch": default_branch,
        "description": None,
        "topics": [],
        "has_wiki": True,
        "has_issues": True,
    }


class FakeGitHub:
    """Minimal GitHub App API: installations, installation tokens, installation repositories."""

    def __init__(self, router: respx.MockRouter) -> None:
        self.installations: dict[int, dict[str, Any]] = {}
        self.token_requests: list[dict[str, Any]] = []
        self.repo_status: dict[int, int] = {}  # installation id -> forced HTTP status
        self.installations_status: int | None = None
        self._tokens: dict[str, int] = {}
        router.get(f"{BASE}/app/installations").mock(side_effect=self._list_installations)
        router.post(url__regex=rf"{BASE}/app/installations/\d+/access_tokens").mock(
            side_effect=self._issue_token
        )
        router.get(f"{BASE}/installation/repositories").mock(side_effect=self._list_repos)

    def add_installation(
        self,
        installation_id: int,
        login: str,
        repos: list[dict[str, Any]],
        *,
        account_type: str = "User",
        suspended: bool = False,
    ) -> None:
        self.installations[installation_id] = {
            "login": login,
            "type": account_type,
            "repos": repos,
            "suspended": suspended,
        }

    @staticmethod
    def _page(
        request: httpx.Request, items: list[Any], path: str
    ) -> tuple[list[Any], dict[str, str]]:
        page = int(request.url.params.get("page", "1"))
        per = int(request.url.params.get("per_page", "30"))
        chunk = items[(page - 1) * per : page * per]
        headers: dict[str, str] = {}
        if page * per < len(items):
            headers["Link"] = f'<{BASE}{path}?per_page={per}&page={page + 1}>; rel="next"'
        return chunk, headers

    def _list_installations(self, request: httpx.Request) -> httpx.Response:
        if self.installations_status:
            return httpx.Response(self.installations_status, json={"message": "boom"})
        items = [
            {
                "id": iid,
                "account": {"login": v["login"], "type": v["type"]},
                "suspended_at": "2026-01-01T00:00:00Z" if v["suspended"] else None,
            }
            for iid, v in self.installations.items()
        ]
        chunk, headers = self._page(request, items, "/app/installations")
        return httpx.Response(200, json=chunk, headers=headers)

    def _issue_token(self, request: httpx.Request) -> httpx.Response:
        iid = int(request.url.path.split("/")[3])
        body = json.loads(request.content) if request.content else {}
        self.token_requests.append({"installation_id": iid, "body": body})
        token = f"ghs_{iid}_{'x' * 30}"
        self._tokens[token] = iid
        return httpx.Response(201, json={"token": token, "expires_at": "2099-01-01T00:00:00Z"})

    def _list_repos(self, request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        iid = self._tokens.get(token)
        if iid is None:
            return httpx.Response(401, json={"message": "Bad credentials"})
        if iid in self.repo_status:
            return httpx.Response(
                self.repo_status[iid], json={"message": "Resource not accessible"}
            )
        repos = self.installations[iid]["repos"]
        chunk, headers = self._page(request, repos, "/installation/repositories")
        return httpx.Response(
            200, json={"total_count": len(repos), "repositories": chunk}, headers=headers
        )


@pytest.fixture
def gh() -> Iterator[FakeGitHub]:
    with respx.mock(assert_all_called=False) as router:
        yield FakeGitHub(router)


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def client(sleeps: list[float]) -> GitHubClient:
    return GitHubClient(
        base_url=BASE,
        api_version="2022-11-28",
        sleep=sleeps.append,
        rng=lambda: 1.0,
        clock=lambda: 1_000_000.0,
    )


@pytest.fixture
def app(client: GitHubClient, rsa_pem: str) -> GitHubApp:
    return GitHubApp(app_id=123, private_key=SecretStr(rsa_pem), client=client)
