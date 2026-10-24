"""Minimal, versioned SQL migration runner with checksum verification.

Migrations are forward-only files named NNNN_description.sql. Applied migrations are
checksummed; editing an applied file is detected and refused.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from importlib import resources

from ghgl_sync.db.connection import Connection

MIGRATION_LOCK_ID = 7_300_001
_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode()).hexdigest()


def load_migrations() -> list[Migration]:
    found: list[Migration] = []
    root = resources.files("ghgl_sync.db") / "migrations"
    for entry in root.iterdir():
        match = _NAME.match(entry.name)
        if match:
            found.append(
                Migration(int(match.group(1)), match.group(2), entry.read_text(encoding="utf-8"))
            )
    found.sort(key=lambda m: m.version)
    versions = [m.version for m in found]
    if versions != list(range(1, len(versions) + 1)):
        raise MigrationError(f"migration versions are not contiguous from 1: {versions}")
    return found


def migrate(conn: Connection) -> list[int]:
    """Apply pending migrations. Returns the versions applied by this call."""
    applied_now: list[int] = []
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (MIGRATION_LOCK_ID,))
        conn.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                   version int PRIMARY KEY, name text NOT NULL,
                   checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())"""
        )
        done = {
            int(r["version"]): str(r["checksum"])
            for r in conn.execute("SELECT version, checksum FROM schema_migrations")
        }
        for mig in load_migrations():
            if mig.version in done:
                if done[mig.version] != mig.checksum:
                    raise MigrationError(
                        f"migration {mig.version:04d}_{mig.name} was modified after being applied"
                    )
                continue
            conn.execute(mig.sql)
            conn.execute(
                "INSERT INTO schema_migrations (version, name, checksum) VALUES (%s, %s, %s)",
                (mig.version, mig.name, mig.checksum),
            )
            applied_now.append(mig.version)
    return applied_now
