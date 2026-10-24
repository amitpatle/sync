"""Tamper-evident audit log: each row's hash covers its content and the previous row's hash.

Limits (see docs/THREAT_MODEL.md): a database superuser can rewrite the whole chain.
Mitigate by exporting `head_hash()` to an external system on a schedule and comparing.
`details` must contain only strings/ints/bools/lists/dicts (no floats): jsonb round-trips
would otherwise change the canonical form and break verification.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from psycopg.types.json import Jsonb

from ghgl_sync.db.connection import Connection
from ghgl_sync.security.redaction import redact_obj

AUDIT_LOCK_ID = 7_300_002
GENESIS_HASH = "0" * 64


def _canonical(
    ts: datetime,
    *,
    actor: str,
    action: str,
    repo_id: int | None,
    correlation_id: str | None,
    details: Any,
) -> str:
    return json.dumps(
        {
            "ts": ts.astimezone(UTC).isoformat(),
            "actor": actor,
            "action": action,
            "github_repo_id": repo_id,
            "correlation_id": correlation_id,
            "details": details,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def append_audit(
    conn: Connection,
    *,
    actor: str,
    action: str,
    github_repo_id: int | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> str:
    """Append an event (inside the caller's transaction). Returns the new hash."""
    safe_details = redact_obj(details or {})
    conn.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK_ID,))
    prev_row = conn.execute("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
    prev_hash = str(prev_row["hash"]) if prev_row else GENESIS_HASH
    now_row = conn.execute("SELECT clock_timestamp() AS now").fetchone()
    assert now_row is not None  # noqa: S101
    ts: datetime = now_row["now"]
    digest = _digest(
        prev_hash,
        _canonical(
            ts,
            actor=actor,
            action=action,
            repo_id=github_repo_id,
            correlation_id=correlation_id,
            details=safe_details,
        ),
    )
    conn.execute(
        """INSERT INTO audit_events
               (ts, actor, action, github_repo_id, correlation_id, details, prev_hash, hash)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (ts, actor, action, github_repo_id, correlation_id, Jsonb(safe_details), prev_hash, digest),
    )
    return digest


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    events_checked: int
    first_bad_seq: int | None = None
    head_hash: str = GENESIS_HASH


def verify_chain(conn: Connection) -> ChainVerification:
    prev = GENESIS_HASH
    checked = 0
    cur = conn.execute(
        """SELECT seq, ts, actor, action, github_repo_id, correlation_id, details, prev_hash, hash
           FROM audit_events ORDER BY seq"""
    )
    for row in cur:
        expected = _digest(
            prev,
            _canonical(
                row["ts"],
                actor=row["actor"],
                action=row["action"],
                repo_id=row["github_repo_id"],
                correlation_id=row["correlation_id"],
                details=row["details"],
            ),
        )
        if row["prev_hash"] != prev or row["hash"] != expected:
            return ChainVerification(False, checked, int(row["seq"]), prev)
        prev = str(row["hash"])
        checked += 1
    return ChainVerification(True, checked, None, prev)
