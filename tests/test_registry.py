from __future__ import annotations

from typing import Any

import pytest

from ghgl_sync.db.audit import verify_chain
from ghgl_sync.db.connection import Connection
from ghgl_sync.github.discovery import DiscoveryResult, parse_repo
from ghgl_sync.registry import Change, apply_scan

from .conftest import make_repo, make_settings

pytestmark = pytest.mark.db


def scan(
    conn: Connection,
    repos: list[dict[str, Any]],
    *,
    installation: int = 1,
    failed: dict[int, str] | None = None,
    skipped: dict[int, str] | None = None,
    listed: set[int] | None = None,
    **settings: Any,
) -> list[Change]:
    failed = failed or {}
    result = DiscoveryResult(
        repos=[parse_repo(r, installation) for r in repos],
        listed_installation_ids=listed if listed is not None else {installation},
        scanned_installation_ids={installation} - set(failed),
        failed_installations=failed,
        skipped_installations=skipped or {},
    )
    changes = apply_scan(conn, make_settings(**settings), result, correlation_id="test")
    conn.commit()
    return changes


def row(conn: Connection, repo_id: int) -> dict[str, Any]:
    r = conn.execute("SELECT * FROM repositories WHERE github_repo_id = %s", (repo_id,)).fetchone()
    assert r
    return r


def actions(changes: list[Change]) -> list[str]:
    return [c.action for c in changes]


def test_new_repo_is_registered_pending_and_private_by_default(conn: Connection) -> None:
    changes = scan(conn, [make_repo(1, "alice/pub", private=False)])
    assert actions(changes) == ["repo.discovered"]
    r = row(conn, 1)
    assert r["lifecycle"] == "active" and r["sync_state"] == "pending"
    assert r["github_visibility"] == "public" and r["target_visibility"] == "private"
    assert r["gitlab_project_id"] is None


def test_rescan_is_idempotent(conn: Connection) -> None:
    repos = [make_repo(1, "alice/a"), make_repo(2, "alice/b")]
    scan(conn, repos)
    updated = row(conn, 1)["updated_at"]
    assert scan(conn, repos) == []
    assert row(conn, 1)["updated_at"] == updated  # no write amplification


def test_rename_keeps_identity_and_records_history(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/old")])
    changes = scan(conn, [make_repo(1, "alice/new")])
    assert actions(changes) == ["repo.renamed"]
    assert row(conn, 1)["full_name"] == "alice/new"
    hist = conn.execute("SELECT * FROM repository_name_history").fetchall()
    assert [(h["old_full_name"], h["new_full_name"], h["change_kind"]) for h in hist] == [
        ("alice/old", "alice/new", "renamed")
    ]
    assert conn.execute("SELECT count(*) AS n FROM repositories").fetchone() == {"n": 1}


def test_transfer_to_another_owner_is_detected(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/proj")])
    changes = scan(conn, [make_repo(1, "acme/proj", owner_type="Organization")], installation=2)
    assert "repo.transferred" in actions(changes)
    r = row(conn, 1)
    assert r["owner"] == "acme" and r["installation_id"] == 2


def test_name_reuse_by_a_different_repo_id_is_flagged_not_merged(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/proj")])
    changes = scan(conn, [make_repo(1, "alice/proj"), make_repo(9, "alice/proj")])
    assert actions(changes) == ["repo.discovered", "repo.name_reused"]
    assert changes[1].details["previous_repo_ids"] == [1]
    assert conn.execute("SELECT count(*) AS n FROM repositories").fetchone() == {"n": 2}


def test_visibility_widening_is_held_for_review(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/a", private=True)])
    # GitHub repo becomes public AND the operator's policy now says "preserve public".
    changes = scan(conn, [make_repo(1, "alice/a", private=False)], visibility_public="public")
    assert "repo.visibility_changed" in actions(changes)
    assert "repo.visibility_widening_requires_review" in actions(changes)
    r = row(conn, 1)
    assert r["target_visibility"] == "private"  # NOT widened
    assert r["visibility_review_required"] is True
    # Re-scanning does not re-emit the review event.
    assert scan(conn, [make_repo(1, "alice/a", private=False)], visibility_public="public") == []


def test_visibility_narrowing_applies_immediately(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/a", private=False)], visibility_public="public")
    assert row(conn, 1)["target_visibility"] == "public"
    changes = scan(conn, [make_repo(1, "alice/a", private=True)], visibility_public="public")
    assert "repo.target_visibility_narrowed" in actions(changes)
    assert row(conn, 1)["target_visibility"] == "private"


def test_forks_excluded_by_default_and_includable(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/fork", fork=True), make_repo(2, "alice/own")])
    assert row(conn, 1)["lifecycle"] == "excluded" and row(conn, 1)["exclusion_reason"] == "fork"
    assert row(conn, 2)["lifecycle"] == "active"
    changes = scan(
        conn,
        [make_repo(1, "alice/fork", fork=True), make_repo(2, "alice/own")],
        fork_policy="include",
    )
    assert actions(changes) == ["repo.included"]
    assert row(conn, 1)["lifecycle"] == "active"


def test_archived_policy(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/old", archived=True)])
    assert row(conn, 1)["lifecycle"] == "active" and row(conn, 1)["archived"] is True
    scan(conn, [make_repo(2, "alice/old2", archived=True)], archived_policy="skip")
    assert (
        row(conn, 2)["lifecycle"] == "excluded" and row(conn, 2)["exclusion_reason"] == "archived"
    )


def test_archive_toggle_and_default_branch_change_are_audited(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/a")])
    changes = scan(conn, [make_repo(1, "alice/a", archived=True, default_branch="trunk")])
    assert set(actions(changes)) == {"repo.archived_changed", "repo.default_branch_changed"}


def test_disappearance_requires_consecutive_misses(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/a"), make_repo(2, "alice/b")])
    assert actions(scan(conn, [make_repo(2, "alice/b")])) == ["repo.missing"]
    assert row(conn, 1)["lifecycle"] == "missing"
    assert scan(conn, [make_repo(2, "alice/b")]) == []  # 2nd miss: still just missing
    assert actions(scan(conn, [make_repo(2, "alice/b")])) == ["repo.source_deleted"]
    assert row(conn, 1)["lifecycle"] == "source_deleted" and row(conn, 1)["missing_scans"] == 3


def test_reappearing_repo_resets_missing_state(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/a"), make_repo(2, "alice/b")])
    scan(conn, [make_repo(2, "alice/b")])
    changes = scan(conn, [make_repo(1, "alice/a"), make_repo(2, "alice/b")])
    assert actions(changes) == ["repo.reappeared"]
    assert row(conn, 1)["lifecycle"] == "active" and row(conn, 1)["missing_scans"] == 0


def test_failed_installation_never_causes_missing(conn: Connection) -> None:
    scan(conn, [make_repo(1, "acme/a")], installation=2, listed={1, 2})
    # Installation 2 fails (revoked token / outage); installation 1 is healthy and empty.
    for _ in range(5):
        changes = scan(conn, [], installation=1, failed={2: "permission"}, listed={1, 2})
        assert changes == []
    assert row(conn, 1)["lifecycle"] == "active" and row(conn, 1)["missing_scans"] == 0


def test_skipped_owner_is_left_untouched(conn: Connection) -> None:
    scan(conn, [make_repo(1, "acme/a")], installation=2, listed={1, 2})
    assert scan(conn, [], installation=1, skipped={2: "owner_not_authorized"}, listed={1, 2}) == []
    assert row(conn, 1)["lifecycle"] == "active"


def test_empty_installation_list_is_an_anomaly_not_mass_deletion(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/a"), make_repo(2, "alice/b")])
    changes = scan(conn, [], listed=set())
    assert actions(changes) == ["discovery.anomaly"]
    assert changes[0].details["repos_not_evaluated"] == 2
    assert row(conn, 1)["lifecycle"] == "active" and row(conn, 2)["missing_scans"] == 0


def test_every_change_is_audited_and_chain_stays_valid(conn: Connection) -> None:
    scan(conn, [make_repo(1, "alice/a"), make_repo(2, "alice/b")])
    scan(conn, [make_repo(1, "alice/renamed")])
    n = conn.execute("SELECT count(*) AS n FROM audit_events").fetchone()
    assert n and n["n"] == 4  # 2 discovered + 1 renamed + 1 missing
    assert verify_chain(conn).ok
