from __future__ import annotations

import psycopg
import pytest
from psycopg.rows import dict_row

from ghgl_sync.db.audit import verify_chain
from ghgl_sync.db.connection import Connection
from ghgl_sync.discovery_service import DISCOVERY_LOCK_ID, DiscoveryInProgress, run_discovery
from ghgl_sync.github.auth import GitHubApp
from ghgl_sync.github.client import GitHubClient
from ghgl_sync.github.errors import GitHubError

from .conftest import TEST_DB, FakeGitHub, make_repo, make_settings

pytestmark = pytest.mark.db


def count(conn: Connection, table: str) -> int:
    r = conn.execute(f"SELECT count(*) AS n FROM {table}").fetchone()
    assert r
    return int(r["n"])


def test_end_to_end_then_idempotent_second_run(
    conn: Connection, gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(i, f"alice/r{i}") for i in range(1, 121)])
    first = run_discovery(conn, make_settings(), client, app)
    assert first.repos_seen == 120 and first.complete
    assert first.change_summary == {"repo.discovered": 120}
    assert count(conn, "repositories") == 120

    second = run_discovery(conn, make_settings(), client, app)
    assert second.changes == []
    assert count(conn, "repositories") == 120
    assert count(conn, "discovery_runs") == 2
    assert verify_chain(conn).ok


def test_dry_run_previews_but_writes_nothing(
    conn: Connection, gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a"), make_repo(2, "alice/b")])
    report = run_discovery(conn, make_settings(), client, app, dry_run=True)
    assert report.dry_run and report.change_summary == {"repo.discovered": 2}
    assert count(conn, "repositories") == 0
    assert count(conn, "audit_events") == 0
    assert count(conn, "discovery_runs") == 0
    # A real run afterwards sees exactly what the preview promised.
    real = run_discovery(conn, make_settings(), client, app)
    assert real.change_summary == report.change_summary
    assert verify_chain(conn).ok


def test_concurrent_run_is_refused(
    conn: Connection, gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a")])
    other = psycopg.connect(TEST_DB, row_factory=dict_row, autocommit=True)
    try:
        other.execute("SELECT pg_advisory_lock(%s)", (DISCOVERY_LOCK_ID,))
        with pytest.raises(DiscoveryInProgress):
            run_discovery(conn, make_settings(), client, app)
        assert count(conn, "repositories") == 0
    finally:
        other.execute("SELECT pg_advisory_unlock(%s)", (DISCOVERY_LOCK_ID,))
        other.close()
    # Lock is released: the run now succeeds.
    assert run_discovery(conn, make_settings(), client, app).repos_seen == 1


def test_github_outage_is_recorded_and_changes_nothing(
    conn: Connection, gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a")])
    run_discovery(conn, make_settings(), client, app)
    gh.installations_status = 500
    with pytest.raises(GitHubError):
        run_discovery(conn, make_settings(), client, app)
    last = conn.execute(
        "SELECT action, details FROM audit_events ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    assert last and last["action"] == "discovery.failed"
    assert last["details"]["classification"] == "transient"
    r = conn.execute("SELECT lifecycle, missing_scans FROM repositories").fetchone()
    assert r == {"lifecycle": "active", "missing_scans": 0}
    assert verify_chain(conn).ok


def test_partial_failure_marks_run_incomplete_and_spares_failed_installation(
    conn: Connection, gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a")])
    gh.add_installation(2, "acme", [make_repo(2, "acme/b")])
    run_discovery(conn, make_settings(), client, app)

    gh.repo_status[2] = 403  # acme revoked our permission
    for _ in range(4):
        report = run_discovery(conn, make_settings(), client, app)
        assert not report.complete
        assert report.failed_installations == {2: "permission"}
    states = {
        r["full_name"]: r["lifecycle"]
        for r in conn.execute("SELECT full_name, lifecycle FROM repositories")
    }
    assert states == {"alice/a": "active", "acme/b": "active"}  # never wrongly "deleted"
    summary = conn.execute(
        "SELECT details FROM audit_events WHERE action = 'discovery.completed' "
        "ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    assert summary and "re-run" in summary["details"]["recovery"]


def test_real_deletion_is_detected_after_threshold_when_scan_is_healthy(
    conn: Connection, gh: FakeGitHub, client: GitHubClient, app: GitHubApp
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a"), make_repo(2, "alice/b")])
    run_discovery(conn, make_settings(), client, app)
    gh.installations[1]["repos"] = [make_repo(2, "alice/b")]
    for _ in range(3):
        run_discovery(conn, make_settings(), client, app)
    r = conn.execute(
        "SELECT lifecycle, gitlab_project_id FROM repositories WHERE github_repo_id = 1"
    )
    assert r.fetchone() == {"lifecycle": "source_deleted", "gitlab_project_id": None}
