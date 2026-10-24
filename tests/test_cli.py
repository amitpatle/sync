from __future__ import annotations

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ghgl_sync.cli import app as cli_app
from ghgl_sync.db.audit import append_audit
from ghgl_sync.db.connection import Connection

from .conftest import TEST_DB, FakeGitHub, make_repo

pytestmark = pytest.mark.db
runner = CliRunner()


@pytest.fixture
def cli_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, rsa_pem: str) -> None:
    key = tmp_path / "app.pem"
    key.write_text(rsa_pem)
    os.chmod(key, 0o600)
    monkeypatch.chdir(tmp_path)  # no stray .env
    monkeypatch.setenv("GHGL_DATABASE_URL", TEST_DB)
    monkeypatch.setenv("GHGL_GITHUB_APP_ID", "123")
    monkeypatch.setenv("GHGL_GITHUB_APP_PRIVATE_KEY_FILE", str(key))


def test_full_cli_flow(conn: Connection, gh: FakeGitHub, cli_env: None, rsa_pem: str) -> None:
    gh.add_installation(
        1, "alice", [make_repo(1, "alice/a"), make_repo(2, "alice/b", private=False)]
    )

    r = runner.invoke(cli_app, ["db", "migrate"])
    assert r.exit_code == 0 and "up to date" in r.output

    r = runner.invoke(cli_app, ["discover", "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "DRY RUN" in r.output and "repo.discovered: 2" in r.output
    assert "no repositories registered" in runner.invoke(cli_app, ["status"]).output

    r = runner.invoke(cli_app, ["discover"])
    assert r.exit_code == 0 and "applied" in r.output and "repo.discovered: 2" in r.output

    r = runner.invoke(cli_app, ["status"])
    assert r.exit_code == 0
    assert "active" in r.output and "pending" in r.output and "last discovery" in r.output

    r = runner.invoke(cli_app, ["audit", "verify"])
    assert r.exit_code == 0 and "audit chain OK" in r.output

    # No credential material anywhere in what the operator sees.
    assert "BEGIN" not in r.output and "ghs_" not in r.output
    assert "MII" not in r.output


def test_incomplete_scan_exits_nonzero_with_actionable_message(
    conn: Connection, gh: FakeGitHub, cli_env: None
) -> None:
    gh.add_installation(1, "alice", [make_repo(1, "alice/a")])
    gh.repo_status[1] = 403
    r = runner.invoke(cli_app, ["discover"])
    assert r.exit_code == 7
    assert "INCOMPLETE installation 1: permission" in r.output
    assert "not evaluated" in r.output


def test_github_outage_exit_code(conn: Connection, gh: FakeGitHub, cli_env: None) -> None:
    gh.installations_status = 500
    r = runner.invoke(cli_app, ["discover"])
    assert r.exit_code == 6 and "discovery failed [transient]" in r.output


def test_invalid_config_reports_field_names_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GHGL_DATABASE_URL", "postgresql://user:SuperSecretPw@host/db")
    monkeypatch.delenv("GHGL_GITHUB_APP_ID", raising=False)
    r = runner.invoke(cli_app, ["status"])
    assert r.exit_code == 2
    assert "github_app_id" in r.output
    assert "SuperSecretPw" not in r.output


def test_unreachable_database_message_has_no_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GHGL_DATABASE_URL", "postgresql://user:SuperSecretPw@127.0.0.1:1/db")
    monkeypatch.setenv("GHGL_GITHUB_APP_ID", "1")
    r = runner.invoke(cli_app, ["status"])
    assert r.exit_code == 3 and "SuperSecretPw" not in r.output


def test_tampered_audit_log_is_reported(conn: Connection, cli_env: None) -> None:
    append_audit(conn, actor="t", action="a")
    append_audit(conn, actor="t", action="b")
    conn.commit()
    conn.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
    conn.execute("UPDATE audit_events SET action = 'forged' WHERE action = 'a'")
    conn.commit()
    r = runner.invoke(cli_app, ["audit", "verify"])
    assert r.exit_code == 8 and "BROKEN" in r.output
