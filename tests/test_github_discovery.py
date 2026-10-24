from __future__ import annotations

from ghgl_sync.github.auth import GitHubApp
from ghgl_sync.github.client import GitHubClient
from ghgl_sync.github.discovery import discover

from .conftest import FakeGitHub, make_repo


def test_public_private_and_org_repos(gh: FakeGitHub, client: GitHubClient, app: GitHubApp) -> None:
    gh.add_installation(
        1, "alice", [make_repo(1, "alice/pub", private=False), make_repo(2, "alice/priv")]
    )
    gh.add_installation(
        2,
        "acme",
        [make_repo(3, "acme/internal", visibility="internal", owner_type="Organization")],
        account_type="Organization",
    )
    result = discover(client, app)
    by_name = {r.full_name: r for r in result.repos}
    assert set(by_name) == {"alice/pub", "alice/priv", "acme/internal"}
    assert by_name["alice/pub"].github_visibility == "public"
    assert by_name["alice/priv"].github_visibility == "private"
    assert by_name["acme/internal"].github_visibility == "internal"
    assert by_name["acme/internal"].owner_type == "Organization"
    assert result.complete
    assert result.scanned_installation_ids == {1, 2}


def test_pagination_across_more_than_100_repos(
    gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(i, f"alice/r{i}") for i in range(1, 131)])
    gh.add_installation(2, "acme", [make_repo(i, f"acme/r{i}") for i in range(1000, 1120)])
    result = discover(client, app)
    assert len(result.repos) == 250
    assert len({r.id for r in result.repos}) == 250


def test_discovery_token_is_downscoped_to_metadata_read(
    gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a")])
    discover(client, app)
    assert gh.token_requests == [
        {"installation_id": 1, "body": {"permissions": {"metadata": "read"}}}
    ]


def test_owner_allowlist_skips_unauthorized_installations(
    gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a")])
    gh.add_installation(2, "acme", [make_repo(2, "acme/b")])
    result = discover(client, app, allowed_owners=["ACME"])
    assert [r.full_name for r in result.repos] == ["acme/b"]
    assert result.skipped_installations == {1: "owner_not_authorized"}
    assert all(tr["installation_id"] != 1 for tr in gh.token_requests)  # never even got a token


def test_repo_reachable_via_two_installations_is_deduplicated(
    gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    shared = make_repo(5, "alice/shared")
    gh.add_installation(1, "alice", [shared])
    gh.add_installation(2, "acme", [shared, make_repo(6, "acme/own")])
    result = discover(client, app)
    assert sorted(r.id for r in result.repos) == [5, 6]


def test_failed_installation_is_reported_not_hidden(
    gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a")])
    gh.add_installation(2, "acme", [make_repo(2, "acme/b")])
    gh.repo_status[2] = 403  # permission revoked
    result = discover(client, app)
    assert [r.full_name for r in result.repos] == ["alice/a"]
    assert result.failed_installations == {2: "permission"}
    assert not result.complete
    assert 2 not in result.scanned_installation_ids


def test_suspended_installation_counts_as_failed(
    gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a")], suspended=True)
    result = discover(client, app)
    assert result.failed_installations == {1: "installation_suspended"}
    assert not result.complete


def test_malformed_repo_fails_the_installation_instead_of_being_skipped(
    gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    bad = make_repo(2, "alice/bad")
    del bad["owner"]
    gh.add_installation(1, "alice", [make_repo(1, "alice/ok"), bad])
    result = discover(client, app)
    assert result.failed_installations == {1: "protocol"}
    assert result.repos == []  # partial results from a failed installation are discarded
