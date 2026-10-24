"""Repository discovery via GitHub App installations (read-only, metadata:read token)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ghgl_sync.github.auth import DISCOVERY_PERMISSIONS, GitHubApp
from ghgl_sync.github.client import GitHubClient
from ghgl_sync.github.errors import GitHubError, ProtocolError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Installation:
    id: int
    account_login: str
    account_type: str
    suspended: bool


@dataclass(frozen=True)
class RepoInfo:
    id: int
    node_id: str
    owner: str
    owner_type: str
    name: str
    full_name: str
    github_visibility: str
    archived: bool
    is_fork: bool
    disabled: bool
    default_branch: str | None
    description: str | None
    topics: tuple[str, ...]
    has_wiki: bool
    has_issues: bool
    installation_id: int


@dataclass
class DiscoveryResult:
    repos: list[RepoInfo] = field(default_factory=list)
    listed_installation_ids: set[int] = field(default_factory=set)
    scanned_installation_ids: set[int] = field(default_factory=set)
    skipped_installations: dict[int, str] = field(default_factory=dict)
    failed_installations: dict[int, str] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return not self.failed_installations


def list_installations(client: GitHubClient, app: GitHubApp) -> list[Installation]:
    out: list[Installation] = []
    for item in client.paginate("/app/installations", auth=app.jwt_auth()):
        try:
            account = item["account"] or {}
            out.append(
                Installation(
                    id=int(item["id"]),
                    account_login=str(account["login"]),
                    account_type=str(account.get("type", "User")),
                    suspended=item.get("suspended_at") is not None,
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("malformed installation object") from exc
    return out


def parse_repo(item: dict[str, Any], installation_id: int) -> RepoInfo:
    try:
        owner = item["owner"]
        private = bool(item.get("private", True))
        visibility = str(item.get("visibility") or ("private" if private else "public"))
        return RepoInfo(
            id=int(item["id"]),
            node_id=str(item["node_id"]),
            owner=str(owner["login"]),
            owner_type=str(owner.get("type", "User")),
            name=str(item["name"]),
            full_name=str(item["full_name"]),
            github_visibility=visibility,
            archived=bool(item.get("archived", False)),
            is_fork=bool(item.get("fork", False)),
            disabled=bool(item.get("disabled", False)),
            default_branch=item.get("default_branch"),
            description=item.get("description"),
            topics=tuple(str(t) for t in item.get("topics") or ()),
            has_wiki=bool(item.get("has_wiki", False)),
            has_issues=bool(item.get("has_issues", False)),
            installation_id=installation_id,
        )
    except (KeyError, TypeError, ValueError) as exc:
        # Fail the installation scan loudly rather than silently skipping a repository.
        raise ProtocolError(f"malformed repository object (id={item.get('id')})") from exc


def discover(
    client: GitHubClient, app: GitHubApp, *, allowed_owners: list[str] | None = None
) -> DiscoveryResult:
    """Scan every authorized installation. Per-installation failures are recorded, not hidden."""
    allowed = {o.lower() for o in allowed_owners or []}
    result = DiscoveryResult()
    seen_ids: set[int] = set()

    for inst in list_installations(client, app):
        result.listed_installation_ids.add(inst.id)
        if allowed and inst.account_login.lower() not in allowed:
            result.skipped_installations[inst.id] = "owner_not_authorized"
            continue
        if inst.suspended:
            result.failed_installations[inst.id] = "installation_suspended"
            continue
        auth = app.installation_auth(inst.id, DISCOVERY_PERMISSIONS)
        scanned: list[RepoInfo] = []
        try:
            for item in client.paginate(
                "/installation/repositories", auth=auth, items_key="repositories"
            ):
                scanned.append(parse_repo(item, inst.id))
        except GitHubError as exc:
            log.warning(
                "installation scan failed",
                extra={"installation_id": inst.id, "classification": exc.classification},
            )
            result.failed_installations[inst.id] = exc.classification
            continue
        for repo in scanned:
            if allowed and repo.owner.lower() not in allowed:
                continue
            if repo.id in seen_ids:  # same repo reachable via two installations
                continue
            seen_ids.add(repo.id)
            result.repos.append(repo)
        result.scanned_installation_ids.add(inst.id)
    return result
