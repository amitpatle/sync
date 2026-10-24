from __future__ import annotations

from typing import Any

import psycopg
import pytest

from ghgl_sync.db.audit import GENESIS_HASH, append_audit, verify_chain
from ghgl_sync.db.connection import Connection
from ghgl_sync.db.migrate import MigrationError, load_migrations, migrate

pytestmark = pytest.mark.db


def test_migrations_are_idempotent(conn: Connection) -> None:
    assert migrate(conn) == []  # fixture already applied everything
    tables = {
        r["tablename"]
        for r in conn.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
    }
    assert {"repositories", "audit_events", "discovery_runs", "schema_migrations"} <= tables
    assert [m.version for m in load_migrations()] == [1]


def test_modified_migration_is_detected(conn: Connection) -> None:
    conn.execute("UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1")
    conn.commit()
    with pytest.raises(MigrationError, match="modified after being applied"):
        migrate(conn)


def test_registry_constraints(conn: Connection) -> None:
    sql = (
        "INSERT INTO repositories (github_repo_id, github_node_id, owner, owner_type, name, "
        "full_name, installation_id, github_visibility, target_visibility, last_seen_at{extra}) "
        "VALUES (1, 'n', 'o', 'User', 'r', 'o/r', 1, %s, 'private', now(){vals})"
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(sql.format(extra="", vals="").replace("%s", "'bogus'"))
    conn.rollback()
    conn.execute(sql.format(extra="", vals="").replace("%s", "'private'"))
    with pytest.raises(psycopg.errors.UniqueViolation):
        conn.execute(sql.format(extra="", vals="").replace("%s", "'private'"))


def _add(conn: Connection, n: int) -> None:
    for i in range(n):
        append_audit(
            conn, actor="t", action=f"a{i}", github_repo_id=i, correlation_id="c", details={"i": i}
        )
    conn.commit()


def test_chain_verifies(conn: Connection) -> None:
    assert verify_chain(conn).ok
    assert verify_chain(conn).head_hash == GENESIS_HASH
    _add(conn, 5)
    result = verify_chain(conn)
    assert result.ok and result.events_checked == 5 and result.head_hash != GENESIS_HASH


@pytest.mark.parametrize(
    "stmt",
    ["UPDATE audit_events SET actor = 'evil'", "DELETE FROM audit_events", "TRUNCATE audit_events"],
)
def test_audit_log_is_append_only(conn: Connection, stmt: str) -> None:
    _add(conn, 2)
    with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
        conn.execute(stmt)


def _tamper(conn: Connection, sql: str, params: tuple[Any, ...] = ()) -> None:
    # Simulates a privileged attacker who disables the triggers first.
    conn.execute("ALTER TABLE audit_events DISABLE TRIGGER USER")
    conn.execute(sql, params)
    conn.execute("ALTER TABLE audit_events ENABLE TRIGGER USER")
    conn.commit()


def test_modified_event_is_detected(conn: Connection) -> None:
    _add(conn, 4)
    seq = conn.execute("SELECT seq FROM audit_events ORDER BY seq OFFSET 2 LIMIT 1").fetchone()
    assert seq
    _tamper(conn, "UPDATE audit_events SET action = 'forged' WHERE seq = %s", (seq["seq"],))
    result = verify_chain(conn)
    assert not result.ok and result.first_bad_seq == seq["seq"]


def test_deleted_event_is_detected(conn: Connection) -> None:
    _add(conn, 4)
    seq = conn.execute("SELECT seq FROM audit_events ORDER BY seq OFFSET 1 LIMIT 1").fetchone()
    assert seq
    _tamper(conn, "DELETE FROM audit_events WHERE seq = %s", (seq["seq"],))
    assert not verify_chain(conn).ok


def test_rolled_back_events_leave_a_valid_chain(conn: Connection) -> None:
    _add(conn, 2)
    append_audit(conn, actor="t", action="dry", details={})
    conn.rollback()  # dry-run semantics: sequence gaps are fine, the chain must stay intact
    _add(conn, 1)
    assert verify_chain(conn).ok
    assert verify_chain(conn).events_checked == 3


def test_audit_details_are_redacted_before_storage(conn: Connection) -> None:
    token = "ghp_" + "S3cretT0ken" * 4
    append_audit(
        conn,
        actor="t",
        action="x",
        details={"note": f"leaked {token}", "authorization": "Bearer abcdefgh1234"},
    )
    conn.commit()
    row = conn.execute("SELECT details FROM audit_events").fetchone()
    assert row
    assert token not in str(row["details"]) and "abcdefgh1234" not in str(row["details"])
    assert verify_chain(conn).ok
