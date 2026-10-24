"""Orchestrates one discovery run: lock -> scan GitHub -> reconcile registry -> audit.

Dry-run executes the exact same code path, then rolls the transaction back, so a preview
cannot diverge from what a real run would do.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from ghgl_sync.config import Settings
from ghgl_sync.db.audit import append_audit
from ghgl_sync.db.connection import Connection
from ghgl_sync.github.auth import GitHubApp
from ghgl_sync.github.client import GitHubClient
from ghgl_sync.github.discovery import discover
from ghgl_sync.github.errors import GitHubError
from ghgl_sync.logging_setup import correlation_context
from ghgl_sync.registry import Change, apply_scan

log = logging.getLogger(__name__)

DISCOVERY_LOCK_ID = 7_300_003


class DiscoveryInProgress(RuntimeError):
    """Another discovery run holds the lock."""


@dataclass
class DiscoveryReport:
    run_id: UUID
    correlation_id: str
    dry_run: bool
    complete: bool
    installations_scanned: int
    repos_seen: int
    changes: list[Change] = field(default_factory=list)
    failed_installations: dict[int, str] = field(default_factory=dict)
    skipped_installations: dict[int, str] = field(default_factory=dict)

    @property
    def change_summary(self) -> dict[str, int]:
        return dict(Counter(c.action for c in self.changes))


def run_discovery(
    conn: Connection,
    settings: Settings,
    client: GitHubClient,
    app: GitHubApp,
    *,
    dry_run: bool = False,
) -> DiscoveryReport:
    got = conn.execute("SELECT pg_try_advisory_lock(%s) AS ok", (DISCOVERY_LOCK_ID,)).fetchone()
    conn.commit()
    if not got or not got["ok"]:
        raise DiscoveryInProgress("another discovery run is in progress")
    try:
        with correlation_context() as cid:
            return _run_locked(conn, settings, client, app, dry_run=dry_run, correlation_id=cid)
    finally:
        conn.rollback()
        conn.execute("SELECT pg_advisory_unlock(%s)", (DISCOVERY_LOCK_ID,))
        conn.commit()


def _run_locked(
    conn: Connection,
    settings: Settings,
    client: GitHubClient,
    app: GitHubApp,
    *,
    dry_run: bool,
    correlation_id: str,
) -> DiscoveryReport:
    started = datetime.now(UTC)
    run_id = uuid4()
    log.info("discovery started", extra={"run_id": str(run_id), "dry_run": dry_run})
    try:
        result = discover(client, app, allowed_owners=settings.github_allowed_owners)
    except GitHubError as exc:
        # Nothing was reconciled. Leave a durable record (real runs only) and re-raise.
        if not dry_run:
            append_audit(
                conn,
                actor="discovery",
                action="discovery.failed",
                correlation_id=correlation_id,
                details={"classification": exc.classification, "error": str(exc)},
            )
            conn.commit()
        raise

    try:
        changes = apply_scan(conn, settings, result, correlation_id=correlation_id)
        report = DiscoveryReport(
            run_id=run_id,
            correlation_id=correlation_id,
            dry_run=dry_run,
            complete=result.complete,
            installations_scanned=len(result.scanned_installation_ids),
            repos_seen=len(result.repos),
            changes=changes,
            failed_installations=dict(result.failed_installations),
            skipped_installations=dict(result.skipped_installations),
        )
        conn.execute(
            """INSERT INTO discovery_runs
                   (id, started_at, finished_at, dry_run, complete, installations_scanned,
                    repos_seen, change_summary, failed_installations)
               VALUES (%s, %s, now(), %s, %s, %s, %s, %s, %s)""",
            (
                run_id,
                started,
                dry_run,
                report.complete,
                report.installations_scanned,
                report.repos_seen,
                Jsonb(report.change_summary),
                Jsonb({str(k): v for k, v in report.failed_installations.items()}),
            ),
        )
        append_audit(
            conn,
            actor="discovery",
            action="discovery.completed",
            correlation_id=correlation_id,
            details={
                "run_id": str(run_id),
                "complete": report.complete,
                "installations_scanned": report.installations_scanned,
                "repos_seen": report.repos_seen,
                "changes": report.change_summary,
                "failed_installations": {str(k): v for k, v in report.failed_installations.items()},
                "recovery": (
                    "re-run `ghgl-sync discover`; incomplete installations are retried and "
                    "no repo is marked missing on their account"
                    if not report.complete
                    else ""
                ),
            },
        )
    except Exception:
        conn.rollback()
        raise
    if dry_run:
        conn.rollback()
    else:
        conn.commit()
    log.info(
        "discovery finished",
        extra={"run_id": str(run_id), "dry_run": dry_run, "repos_seen": report.repos_seen},
    )
    return report
