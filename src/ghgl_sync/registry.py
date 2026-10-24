"""Persistent repository registry: reconciles a discovery scan against stored state.

Invariants enforced here:
* Identity is the GitHub numeric repo ID; names are mutable attributes.
* A repo missing from a scan is only *counted* as missing, and only when its installation was
  scanned successfully. It becomes `source_deleted` after N consecutive misses. Nothing on the
  GitLab side is ever deleted by this module.
* Visibility may be narrowed automatically, but widening is held for human review.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ghgl_sync.config import VISIBILITY_RANK, Settings
from ghgl_sync.db.audit import append_audit
from ghgl_sync.db.connection import Connection
from ghgl_sync.github.discovery import DiscoveryResult, RepoInfo


@dataclass(frozen=True)
class Change:
    action: str
    github_repo_id: int | None
    full_name: str | None
    details: dict[str, Any]


# Column names below are constants (never user input); values are always bound parameters.
_MIRRORED_COLUMNS = (
    "github_node_id",
    "owner",
    "owner_type",
    "name",
    "full_name",
    "installation_id",
    "github_visibility",
    "archived",
    "is_fork",
    "disabled",
    "default_branch",
    "description",
    "topics",
    "has_wiki",
    "has_issues",
)


def _exclusion(settings: Settings, repo: RepoInfo) -> str | None:
    if repo.disabled:
        return "disabled"
    if repo.is_fork and settings.fork_policy == "exclude":
        return "fork"
    if repo.archived and settings.archived_policy == "skip":
        return "archived"
    return None


def _repo_values(repo: RepoInfo) -> dict[str, Any]:
    return {
        "github_node_id": repo.node_id,
        "owner": repo.owner,
        "owner_type": repo.owner_type,
        "name": repo.name,
        "full_name": repo.full_name,
        "installation_id": repo.installation_id,
        "github_visibility": repo.github_visibility,
        "archived": repo.archived,
        "is_fork": repo.is_fork,
        "disabled": repo.disabled,
        "default_branch": repo.default_branch,
        "description": repo.description,
        "topics": list(repo.topics),
        "has_wiki": repo.has_wiki,
        "has_issues": repo.has_issues,
    }


def _insert_repo(
    conn: Connection, settings: Settings, repo: RepoInfo, now: datetime
) -> list[Change]:
    exclusion = _exclusion(settings, repo)
    target = settings.target_visibility(repo.github_visibility)
    values = _repo_values(repo)
    values.update(
        target_visibility=target,
        lifecycle="excluded" if exclusion else "active",
        exclusion_reason=exclusion,
        github_repo_id=repo.id,
        last_seen_at=now,
    )
    columns = list(values)
    conn.execute(
        f"INSERT INTO repositories ({', '.join(columns)}) "
        f"VALUES ({', '.join('%(' + c + ')s' for c in columns)})",
        values,
    )
    changes = [
        Change(
            "repo.discovered",
            repo.id,
            repo.full_name,
            {
                "github_visibility": repo.github_visibility,
                "target_visibility": target,
                "excluded": exclusion or "",
                "archived": repo.archived,
                "is_fork": repo.is_fork,
            },
        )
    ]
    reused = conn.execute(
        "SELECT github_repo_id FROM repositories "
        "WHERE lower(full_name) = lower(%s) AND github_repo_id <> %s",
        (repo.full_name, repo.id),
    ).fetchall()
    if reused:
        changes.append(
            Change(
                "repo.name_reused",
                repo.id,
                repo.full_name,
                {"previous_repo_ids": [int(r["github_repo_id"]) for r in reused]},
            )
        )
    return changes


def _update_repo(
    conn: Connection, settings: Settings, row: dict[str, Any], repo: RepoInfo, now: datetime
) -> list[Change]:
    changes: list[Change] = []
    rid, name = repo.id, repo.full_name
    values = _repo_values(repo)
    diff = {c: values[c] for c in _MIRRORED_COLUMNS if row[c] != values[c]}

    if "full_name" in diff:
        kind = "transferred" if str(row["owner"]).lower() != repo.owner.lower() else "renamed"
        conn.execute(
            "INSERT INTO repository_name_history "
            "(github_repo_id, old_full_name, new_full_name, change_kind) VALUES (%s, %s, %s, %s)",
            (rid, row["full_name"], repo.full_name, kind),
        )
        changes.append(
            Change(
                f"repo.{kind}",
                rid,
                name,
                {"old_full_name": row["full_name"], "new_full_name": repo.full_name},
            )
        )
    if "archived" in diff:
        changes.append(Change("repo.archived_changed", rid, name, {"archived": repo.archived}))
    if "default_branch" in diff:
        changes.append(
            Change(
                "repo.default_branch_changed",
                rid,
                name,
                {"old": row["default_branch"] or "", "new": repo.default_branch or ""},
            )
        )
    if "github_visibility" in diff:
        changes.append(
            Change(
                "repo.visibility_changed",
                rid,
                name,
                {"old": row["github_visibility"], "new": repo.github_visibility},
            )
        )

    # Visibility policy: narrowing is applied, widening is held for review.
    policy_target = settings.target_visibility(repo.github_visibility)
    current_target = str(row["target_visibility"])
    extra: dict[str, Any] = {}
    if VISIBILITY_RANK[policy_target] > VISIBILITY_RANK[current_target]:
        if not row["visibility_review_required"]:
            changes.append(
                Change(
                    "repo.visibility_widening_requires_review",
                    rid,
                    name,
                    {"current_target": current_target, "requested_target": policy_target},
                )
            )
        extra["visibility_review_required"] = True
    else:
        if policy_target != current_target:
            changes.append(
                Change(
                    "repo.target_visibility_narrowed",
                    rid,
                    name,
                    {"old": current_target, "new": policy_target},
                )
            )
            extra["target_visibility"] = policy_target
        if row["visibility_review_required"]:
            extra["visibility_review_required"] = False

    # Lifecycle
    exclusion = _exclusion(settings, repo)
    was = str(row["lifecycle"])
    if was in ("missing", "source_deleted"):
        changes.append(Change("repo.reappeared", rid, name, {"was": was}))
    if exclusion and was != "excluded":
        changes.append(Change("repo.excluded", rid, name, {"reason": exclusion}))
    elif not exclusion and was == "excluded":
        changes.append(Change("repo.included", rid, name, {}))
    new_lifecycle = "excluded" if exclusion else "active"
    if was != new_lifecycle:
        extra["lifecycle"] = new_lifecycle
    if row["exclusion_reason"] != exclusion:
        extra["exclusion_reason"] = exclusion

    updates: dict[str, Any] = {**diff, **extra}
    sets = [f"{c} = %({c})s" for c in updates]
    sets += ["last_seen_at = %(_now)s", "missing_scans = 0"]
    if updates:
        sets.append("updated_at = now()")
    conn.execute(
        f"UPDATE repositories SET {', '.join(sets)} WHERE github_repo_id = %(_id)s",
        {**updates, "_now": now, "_id": rid},
    )
    return changes


def _mark_missing(
    conn: Connection, settings: Settings, result: DiscoveryResult, seen_ids: set[int]
) -> list[Change]:
    stored = conn.execute(
        "SELECT github_repo_id, full_name, owner, installation_id, lifecycle, missing_scans "
        "FROM repositories WHERE lifecycle IN ('active', 'missing') "
        "AND github_repo_id <> ALL(%s::bigint[]) FOR UPDATE",
        (list(seen_ids),),
    ).fetchall()
    if not stored:
        return []
    if not result.listed_installation_ids:
        # Zero installations visible is more likely an auth/API problem than "everything deleted".
        return [
            Change(
                "discovery.anomaly",
                None,
                None,
                {
                    "reason": "no_installations_listed",
                    "repos_not_evaluated": len(stored),
                },
            )
        ]
    changes: list[Change] = []
    untouchable = set(result.failed_installations) | set(result.skipped_installations)
    for row in stored:
        if int(row["installation_id"]) in untouchable:
            continue
        misses = int(row["missing_scans"]) + 1
        lifecycle = (
            "source_deleted"
            if misses >= settings.missing_scans_before_source_deleted
            else "missing"
        )
        conn.execute(
            "UPDATE repositories SET missing_scans = %s, lifecycle = %s, updated_at = now() "
            "WHERE github_repo_id = %s",
            (misses, lifecycle, row["github_repo_id"]),
        )
        if lifecycle != row["lifecycle"]:
            changes.append(
                Change(
                    f"repo.{lifecycle}",
                    int(row["github_repo_id"]),
                    str(row["full_name"]),
                    {"consecutive_missing_scans": misses, "reason": "absent_from_scan"},
                )
            )
    return changes


def apply_scan(
    conn: Connection,
    settings: Settings,
    result: DiscoveryResult,
    *,
    correlation_id: str,
    actor: str = "discovery",
) -> list[Change]:
    """Reconcile `result` into the registry in the caller's transaction, auditing each change."""
    now = datetime.now(UTC)
    changes: list[Change] = []
    seen_ids: set[int] = set()
    for repo in result.repos:
        seen_ids.add(repo.id)
        row = conn.execute(
            "SELECT * FROM repositories WHERE github_repo_id = %s FOR UPDATE", (repo.id,)
        ).fetchone()
        if row is None:
            changes.extend(_insert_repo(conn, settings, repo, now))
        else:
            changes.extend(_update_repo(conn, settings, row, repo, now))
    changes.extend(_mark_missing(conn, settings, result, seen_ids))
    for ch in changes:
        append_audit(
            conn,
            actor=actor,
            action=ch.action,
            github_repo_id=ch.github_repo_id,
            correlation_id=correlation_id,
            details={"full_name": ch.full_name or "", **ch.details},
        )
    return changes
