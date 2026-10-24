"""Operator CLI. Output goes to stdout; structured logs go to stderr. No command prints secrets."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager

import typer

from ghgl_sync.config import ConfigError, Settings
from ghgl_sync.db.audit import verify_chain
from ghgl_sync.db.connection import Connection, connect
from ghgl_sync.db.migrate import MigrationError, migrate
from ghgl_sync.discovery_service import DiscoveryInProgress, run_discovery
from ghgl_sync.github.auth import GitHubApp
from ghgl_sync.github.client import GitHubClient
from ghgl_sync.github.errors import GitHubError
from ghgl_sync.logging_setup import configure_logging
from ghgl_sync.security.redaction import redact_text

app = typer.Typer(help="One-way GitHub -> GitLab sync engine.", no_args_is_help=True)
db_app = typer.Typer(help="Database commands.")
audit_app = typer.Typer(help="Audit log commands.")
app.add_typer(db_app, name="db")
app.add_typer(audit_app, name="audit")


def _fail(message: str, code: int = 1) -> typer.Exit:
    typer.echo(f"error: {redact_text(message)}", err=True)
    return typer.Exit(code)


def _settings() -> Settings:
    try:
        settings = Settings()
    except Exception as exc:  # pydantic ValidationError: report field names only, not values
        fields = ", ".join(
            ".".join(str(p) for p in err["loc"]) for err in getattr(exc, "errors", lambda: [])()
        )
        raise _fail(f"invalid configuration ({fields or type(exc).__name__})", 2) from None
    configure_logging(settings.log_level)
    return settings


@contextmanager
def _db(settings: Settings) -> Iterator[Connection]:
    try:
        conn = connect(settings.database_url)
    except Exception as exc:
        raise _fail(f"cannot connect to the database ({type(exc).__name__})", 3) from None
    try:
        yield conn
    finally:
        conn.close()


@db_app.command("migrate")
def db_migrate() -> None:
    """Apply pending database migrations."""
    settings = _settings()
    with _db(settings) as conn:
        try:
            applied = migrate(conn)
        except MigrationError as exc:
            raise _fail(str(exc), 4) from None
    typer.echo(f"applied migrations: {applied}" if applied else "database is up to date")


@app.command()
def discover(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes; write nothing."),
) -> None:
    """Scan GitHub for authorized repositories and reconcile the registry."""
    settings = _settings()
    client = GitHubClient(
        base_url=settings.github_api_url,
        api_version=settings.github_api_version,
        timeout=settings.http_timeout_seconds,
        max_rate_limit_wait=settings.max_rate_limit_wait_seconds,
    )
    try:
        github_app = GitHubApp(
            app_id=settings.github_app_id,
            private_key=settings.load_github_private_key(),
            client=client,
        )
    except (ConfigError, GitHubError) as exc:
        raise _fail(str(exc), 2) from None
    with _db(settings) as conn:
        try:
            report = run_discovery(conn, settings, client, github_app, dry_run=dry_run)
        except DiscoveryInProgress as exc:
            raise _fail(str(exc), 5) from None
        except GitHubError as exc:
            raise _fail(f"discovery failed [{exc.classification}]: {exc}", 6) from None
    mode = "DRY RUN (nothing written)" if dry_run else "applied"
    typer.echo(f"discovery {mode}  run={report.run_id}  correlation={report.correlation_id}")
    typer.echo(
        f"installations scanned: {report.installations_scanned}  repos seen: {report.repos_seen}"
    )
    for action, count in sorted(report.change_summary.items()):
        typer.echo(f"  {action}: {count}")
    for inst, reason in report.failed_installations.items():
        typer.echo(f"  INCOMPLETE installation {inst}: {reason}", err=True)
    if not report.complete:
        typer.echo("scan incomplete: repos on failed installations were not evaluated.", err=True)
        raise typer.Exit(7)


@app.command()
def status() -> None:
    """Show registry counts and the most recent discovery run."""
    settings = _settings()
    with _db(settings) as conn:
        rows = conn.execute(
            "SELECT lifecycle, sync_state, count(*) AS n FROM repositories "
            "GROUP BY 1, 2 ORDER BY 1, 2"
        ).fetchall()
        review = conn.execute(
            "SELECT count(*) AS n FROM repositories WHERE visibility_review_required"
        ).fetchone()
        last = conn.execute(
            "SELECT id, started_at, complete, repos_seen FROM discovery_runs "
            "WHERE NOT dry_run ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
    typer.echo("lifecycle        sync_state    repos")
    for r in rows:
        typer.echo(f"{r['lifecycle']:<16} {r['sync_state']:<13} {r['n']}")
    if not rows:
        typer.echo("(no repositories registered; run `ghgl-sync discover`)")
    if review and review["n"]:
        typer.echo(f"\n{review['n']} repo(s) need visibility review (policy would widen exposure)")
    if last:
        state = "complete" if last["complete"] else "INCOMPLETE"
        typer.echo(f"\nlast discovery: {last['started_at']:%Y-%m-%d %H:%M:%S%z} {state}")
    else:
        typer.echo("\nno discovery has run yet")


@audit_app.command("verify")
def audit_verify() -> None:
    """Verify the audit log hash chain."""
    settings = _settings()
    with _db(settings) as conn:
        result = verify_chain(conn)
    if result.ok:
        typer.echo(f"audit chain OK: {result.events_checked} events, head={result.head_hash}")
        return
    typer.echo(f"AUDIT CHAIN BROKEN at seq {result.first_bad_seq}", err=True)
    raise typer.Exit(8)


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
    sys.exit(0)
